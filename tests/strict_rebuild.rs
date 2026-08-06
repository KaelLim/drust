// WS1b — boot-time STRICT rebuild of existing (legacy, non-STRICT) tenant
// collections. Builds a legacy data.sqlite by hand, runs the rebuild, and
// asserts: STRICT now, rows + FK edges + indexes + trigger + sqlite_sequence
// high-water all intact, a wrong-type insert is rejected, and a second run is
// a no-op (idempotent).

use rusqlite::Connection;
use std::path::Path;

/// Build a legacy (non-STRICT) tenant data.sqlite by hand.
fn seed_legacy(dir: &Path, tid: &str) {
    let p = dir.join("tenants").join(tid);
    std::fs::create_dir_all(&p).unwrap();
    let c = Connection::open(p.join("data.sqlite")).unwrap();
    c.execute_batch(
        r#"
        CREATE TABLE "users" ("id" INTEGER PRIMARY KEY AUTOINCREMENT,"name" TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE "posts" ("id" INTEGER PRIMARY KEY AUTOINCREMENT,"title" TEXT NOT NULL,
            "author" INTEGER REFERENCES "users"("id") ON DELETE RESTRICT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE INDEX "idx_posts_author" ON "posts"("author");
        CREATE TRIGGER "posts_updated_at" AFTER UPDATE ON "posts"
            BEGIN UPDATE "posts" SET updated_at = datetime('now') WHERE id = OLD.id; END;
        INSERT INTO "users"(name) VALUES ('a'),('b');
        INSERT INTO "posts"(title,author) VALUES ('hi',1);
        DELETE FROM "posts" WHERE id=1;             -- bump sqlite_sequence past max(id)
        INSERT INTO "posts"(title,author) VALUES ('yo',2);
    "#,
    )
    .unwrap();
}

#[test]
fn rebuild_makes_strict_and_preserves_everything_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    seed_legacy(dir.path(), "t1");

    drust::db::migrations::strict_rebuild_tenant(dir.path(), "t1").unwrap();

    let c = Connection::open(dir.path().join("tenants/t1/data.sqlite")).unwrap();
    // STRICT now.
    for t in ["users", "posts"] {
        let s: i64 = c
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name=?1",
                [t],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, 1, "{t} must be STRICT after rebuild");
    }
    // Rows preserved.
    let n: i64 = c
        .query_row("SELECT count(*) FROM posts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
    // Index + trigger preserved.
    let idx: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_posts_author'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx, 1);
    let trg: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='posts_updated_at'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(trg, 1);
    // sqlite_sequence high-water preserved (>= 2, the post that existed before deletion).
    let seq: i64 = c
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='posts'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        seq >= 2,
        "AUTOINCREMENT high-water must not regress, got {seq}"
    );
    // Native rejection: STRICT refuses a TEXT into the INTEGER author column.
    let bad = c.execute(
        "INSERT INTO posts(title,author) VALUES ('x','not-an-int')",
        [],
    );
    assert!(
        bad.is_err(),
        "STRICT must reject a string into an INTEGER column"
    );

    // FK edge still enforced after a fresh connection turns foreign_keys ON.
    c.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let orphan = c.execute("INSERT INTO posts(title,author) VALUES ('x',999)", []);
    assert!(orphan.is_err(), "FK RESTRICT must survive the rebuild");

    // Idempotent: a second run rebuilds nothing (tables already STRICT) and stays green.
    drust::db::migrations::strict_rebuild_tenant(dir.path(), "t1").unwrap();
    let n2: i64 = c
        .query_row("SELECT count(*) FROM posts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n2, 1, "second run must be a no-op");
}

/// A tenant with no data.sqlite (or a missing dir) is a silent no-op, not an error.
#[test]
fn rebuild_missing_tenant_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    drust::db::migrations::strict_rebuild_tenant(dir.path(), "ghost").unwrap();
}

/// M1 regression: a pre-existing FK orphan in ONE table must NOT block STRICT
/// migration of the OTHER (clean) tables in the same tenant. The pre-commit
/// `foreign_key_check` is scoped to the table being rebuilt, so only the
/// genuinely-dirty table is held back — clean tables still migrate.
#[test]
fn one_orphan_does_not_block_strict_rebuild_of_clean_tables() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("tenants").join("t-orphan");
    std::fs::create_dir_all(&p).unwrap();
    let c = Connection::open(p.join("data.sqlite")).unwrap();
    // This build bundles SQLite with foreign_keys defaulting ON, so plant the
    // orphan with enforcement OFF — exactly the legacy/restored shape (data
    // predating FK enforcement) this guard must tolerate.
    c.execute_batch(
        r#"
        PRAGMA foreign_keys=OFF;
        CREATE TABLE "widgets" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "label" TEXT);
        CREATE TABLE "users" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "name" TEXT);
        CREATE TABLE "posts" ("id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "author" INTEGER REFERENCES "users"("id") ON DELETE RESTRICT);
        INSERT INTO "users"(name) VALUES ('a');
        INSERT INTO "widgets"(label) VALUES ('w');
        INSERT INTO "posts"(author) VALUES (999);   -- ORPHAN: no user 999
    "#,
    )
    .unwrap();
    drop(c);

    drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-orphan").unwrap();

    let c = Connection::open(dir.path().join("tenants/t-orphan/data.sqlite")).unwrap();
    let strict = |t: &str| -> i64 {
        c.query_row(
            "SELECT strict FROM pragma_table_list WHERE name=?1",
            [t],
            |r| r.get(0),
        )
        .unwrap()
    };
    // Clean tables migrate despite the orphan elsewhere (the M1 fix).
    assert_eq!(
        strict("widgets"),
        1,
        "FK-free clean table must go STRICT despite an orphan in another table"
    );
    assert_eq!(strict("users"), 1, "clean referenced table must go STRICT");
    // The table holding its OWN orphan stays non-STRICT — acceptable, its data
    // is genuinely inconsistent — and its row is preserved (original intact).
    assert_eq!(
        strict("posts"),
        0,
        "table with its own FK orphan stays non-STRICT"
    );
    let n: i64 = c
        .query_row("SELECT count(*) FROM posts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "held-back table's row is preserved");
}

/// The shape that actually bit production (#926): a legacy import wrote the
/// empty string into an `INTEGER DEFAULT 0` column. A non-STRICT table accepts
/// that happily — INTEGER is an affinity, and `''` does not convert, so the
/// value simply stays TEXT — but the STRICT copy rejects it with
/// `cannot store TEXT value in INTEGER column`.
///
/// The contract under test is the fail-safe, NOT the rebuild: the dirty table
/// keeps every row and its original values, its clean siblings still migrate,
/// and the pass returns Ok so boot continues. Nothing here may coerce the
/// value — a boot migration that silently rewrites tenant data to satisfy a
/// schema change is a worse failure than the one it is fixing.
#[test]
fn type_violating_value_holds_one_table_back_without_touching_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("tenants").join("t-badtype");
    std::fs::create_dir_all(&p).unwrap();
    let c = Connection::open(p.join("data.sqlite")).unwrap();
    c.execute_batch(
        r#"
        CREATE TABLE "uploads" ("id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "label" TEXT, "sort_order" INTEGER DEFAULT 0);
        CREATE TABLE "sites" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "name" TEXT);
        INSERT INTO "uploads"(label, sort_order) VALUES ('legacy', '');
        INSERT INTO "uploads"(label, sort_order) VALUES ('clean', 3);
        INSERT INTO "sites"(name) VALUES ('s');
    "#,
    )
    .unwrap();
    drop(c);

    // Ok, not Err: one bad table must not abort the pass for the whole tenant.
    // But Ok must still CARRY the miss — for two months it did not, so the
    // caller's `if let Err(..)` never fired and the failure lived only in a log
    // line nobody read.
    let held_back = drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-badtype").unwrap();
    assert_eq!(
        held_back.len(),
        1,
        "the held-back table must come back as a value, not just a log line"
    );
    assert_eq!(held_back[0].0, "uploads");
    assert!(
        held_back[0].1.contains("cannot store TEXT value"),
        "the reported error must name the actual cause, got: {}",
        held_back[0].1
    );

    let c = Connection::open(dir.path().join("tenants/t-badtype/data.sqlite")).unwrap();
    let strict = |t: &str| -> i64 {
        c.query_row(
            "SELECT strict FROM pragma_table_list WHERE name=?1",
            [t],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        strict("uploads"),
        0,
        "table holding a type-violating value stays non-STRICT"
    );
    assert_eq!(
        strict("sites"),
        1,
        "clean sibling still migrates despite the bad value next door"
    );

    // Rows AND values survive verbatim — the copy-then-swap rolled back, so the
    // original table is still the one being read here.
    let rows: Vec<(String, String)> = c
        .prepare("SELECT label, quote(sort_order) FROM uploads ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            ("legacy".to_string(), "''".to_string()),
            ("clean".to_string(), "3".to_string()),
        ],
        "held-back table keeps every row with its value untouched"
    );

    // Idempotent: re-running must not accumulate debris from the failed attempt,
    // and must keep reporting the same miss rather than going quiet on retry.
    let again = drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-badtype").unwrap();
    assert_eq!(
        again.len(),
        1,
        "a retried miss must stay reported; going quiet on the second boot is how \
         this became invisible in the first place"
    );
    let leftovers: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE '_system_strict_tmp_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(leftovers, 0, "no temp table survives a rolled-back rebuild");
}

/// An FTS5 virtual table and its shadow tables must be left completely alone.
///
/// `sqlite_master.type` is `'table'` for a virtual table AND for every one of its
/// shadow tables, and the shadows are named after the virtual table
/// (`search_data`, `search_idx`, ...) — NOT with any `_system_` prefix, contrary
/// to what the scan's own comment claimed. So the name-prefix filter let all six
/// through: the rebuild would DROP and recreate them.
///
/// Most fail loudly (STRICT demands a datatype per column, which fts5 shadow DDL
/// omits, and `search_idx` would additionally lose its `WITHOUT ROWID` clause —
/// that clause sits after the last `)` that `make_strict_ddl` slices on). But
/// `search_data(id INTEGER PRIMARY KEY, block BLOB)` is fully typed and would
/// rebuild "successfully", dropping a live FTS index's storage out from under it.
///
/// drust never creates a virtual table itself and both authorizers deny
/// `CreateVtable`, so the only way one arrives is an imported or restored
/// database — which is exactly how the #926 data arrived. Scope by
/// `pragma_table_list.type`, not by name.
#[test]
fn a_virtual_table_and_its_shadows_are_out_of_scope() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("tenants").join("t-fts");
    std::fs::create_dir_all(&p).unwrap();
    let c = Connection::open(p.join("data.sqlite")).unwrap();
    c.execute_batch(
        r#"
        CREATE TABLE "notes" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "body" TEXT);
        INSERT INTO "notes"(body) VALUES ('hello'),('world');
        CREATE VIRTUAL TABLE "search" USING fts5(body);
        INSERT INTO "search"(body) VALUES ('hello'),('world');
    "#,
    )
    .unwrap();
    drop(c);

    let held = drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-fts").unwrap();
    assert!(
        held.is_empty(),
        "out-of-scope tables are skipped silently, not reported as degraded — \
         reporting them would make x-drust-boot-degraded permanently non-zero on \
         any tenant with an FTS index, training the operator to ignore it. got {held:?}"
    );

    let c = Connection::open(dir.path().join("tenants/t-fts/data.sqlite")).unwrap();
    // The ordinary collection still migrates.
    let strict: i64 = c
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE name='notes'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(strict, 1, "the real collection must still go STRICT");

    // The virtual table is intact and still a virtual table.
    let kind: String = c
        .query_row(
            "SELECT type FROM pragma_table_list WHERE name='search'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        kind, "virtual",
        "the virtual table must not become a plain one"
    );

    // And it still functions — the shadow storage was not rebuilt underneath it.
    let hits: i64 = c
        .query_row(
            "SELECT count(*) FROM search WHERE search MATCH 'hello'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hits, 1, "the FTS index must still answer a MATCH query");

    // Every shadow table is untouched (still non-STRICT, still present).
    for shadow in [
        "search_data",
        "search_idx",
        "search_content",
        "search_config",
    ] {
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM pragma_table_list WHERE name=?1 AND strict=0",
                [shadow],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "{shadow} must be present and untouched");
    }
}

/// A clean tenant must report NOTHING. The header this feeds is absent when the
/// count is zero, so a false positive here would make every healthy boot look
/// degraded and train the operator to ignore the signal.
#[test]
fn a_clean_tenant_holds_nothing_back() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("tenants").join("t-clean");
    std::fs::create_dir_all(&p).unwrap();
    let c = Connection::open(p.join("data.sqlite")).unwrap();
    c.execute_batch(
        r#"CREATE TABLE "notes" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "body" TEXT);
           INSERT INTO "notes"(body) VALUES ('hello');"#,
    )
    .unwrap();
    drop(c);

    let first = drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-clean").unwrap();
    assert!(first.is_empty(), "a successful rebuild reports no misses");
    // Second pass takes the already-STRICT skip branch — also silent.
    let second = drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-clean").unwrap();
    assert!(second.is_empty(), "the idempotent no-op reports no misses");
    // And a tenant with no database at all is not a miss either.
    let missing = drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-absent").unwrap();
    assert!(
        missing.is_empty(),
        "an absent tenant db is not a degradation"
    );
}

/// Regression: a tenant collection literally named `<x>__strict_tmp` must NOT
/// collide with the STRICT-rebuild temp table for `<x>`. The temp now uses a
/// `_system_`-prefixed name that no user collection can occupy, so both tables
/// migrate.
#[test]
fn collection_named_like_temp_table_does_not_block_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("tenants").join("t-collide");
    std::fs::create_dir_all(&p).unwrap();
    let c = Connection::open(p.join("data.sqlite")).unwrap();
    c.execute_batch(
        r#"
        CREATE TABLE "posts" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "title" TEXT);
        CREATE TABLE "posts__strict_tmp" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "note" TEXT);
        INSERT INTO "posts"(title) VALUES ('p');
        INSERT INTO "posts__strict_tmp"(note) VALUES ('n');
    "#,
    )
    .unwrap();
    drop(c);

    drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-collide").unwrap();

    let c = Connection::open(dir.path().join("tenants/t-collide/data.sqlite")).unwrap();
    for t in ["posts", "posts__strict_tmp"] {
        let s: i64 = c
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name=?1",
                [t],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, 1, "{t} must reach STRICT despite the name overlap");
    }
    // Data preserved in both.
    let np: i64 = c
        .query_row("SELECT count(*) FROM posts", [], |r| r.get(0))
        .unwrap();
    let nt: i64 = c
        .query_row("SELECT count(*) FROM \"posts__strict_tmp\"", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!((np, nt), (1, 1), "rows preserved in both tables");
}

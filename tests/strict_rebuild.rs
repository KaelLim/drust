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
    drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-badtype").unwrap();

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

    // Idempotent: re-running must not accumulate debris from the failed attempt.
    drust::db::migrations::strict_rebuild_tenant(dir.path(), "t-badtype").unwrap();
    let leftovers: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE '_system_strict_tmp_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(leftovers, 0, "no temp table survives a rolled-back rebuild");
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

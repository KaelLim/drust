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

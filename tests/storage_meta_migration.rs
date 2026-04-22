use rusqlite::Connection;
use tempfile::TempDir;

fn x_era_meta(conn: &Connection) {
    conn.execute_batch(r#"
        CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, name TEXT, created_at TEXT DEFAULT (datetime('now')), deleted_at TEXT, quota_db_mb INTEGER DEFAULT 500, quota_rows INTEGER DEFAULT 1000000);
        CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY, tenant_id TEXT, token_hash TEXT UNIQUE, label TEXT, created_at TEXT DEFAULT (datetime('now')), revoked_at TEXT);
        CREATE TABLE IF NOT EXISTS "_system_public_files" (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key TEXT NOT NULL UNIQUE,
          original_name TEXT NOT NULL,
          content_type TEXT,
          size_bytes INTEGER NOT NULL,
          content_disposition TEXT,
          uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
          uploader TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_public_files_uploaded_at ON "_system_public_files"(uploaded_at DESC);
        INSERT INTO "_system_public_files" (key, original_name, content_type, size_bytes, content_disposition, uploader)
          VALUES ('abc', 'a.png', 'image/png', 10, 'inline; filename="a.png"', 'admin');
        INSERT INTO "_system_public_files" (key, original_name, content_type, size_bytes, content_disposition, uploader)
          VALUES ('def', 'b.pdf', 'application/pdf', 200, 'attachment; filename="b.pdf"', 'admin');
    "#).unwrap();
}

#[test]
fn migration_renames_table_adds_columns_and_normalizes() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("meta.sqlite");
    {
        let conn = Connection::open(&path).unwrap();
        x_era_meta(&conn);
    }

    let _conn = drust::storage::meta::open_meta(&path).unwrap();

    let conn = Connection::open(&path).unwrap();
    let count_new: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_system_files'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let count_old: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_system_public_files'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count_new, 1, "new table present");
    assert_eq!(count_old, 0, "old table gone");

    let rows: Vec<(String, String, String)> = conn
        .prepare("SELECT key, visibility, content_disposition FROM _system_files ORDER BY key")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    assert_eq!(
        rows,
        vec![
            ("abc".into(), "public".into(), "inline".into()),
            ("def".into(), "public".into(), "attachment".into()),
        ]
    );

    let pending_revokes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_trash_pending_revokes'",
        [], |r| r.get(0)
    ).unwrap();
    let orphan_buckets: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_orphan_buckets'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending_revokes, 1);
    assert_eq!(orphan_buckets, 1);
}

#[test]
fn migration_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("meta.sqlite");

    // Seed X-era schema, then open_meta triggers the migration.
    {
        let conn = Connection::open(&path).unwrap();
        x_era_meta(&conn);
    }
    let _ = drust::storage::meta::open_meta(&path).unwrap();
    // Second + third open must not attempt to re-run the rename.
    let _ = drust::storage::meta::open_meta(&path).unwrap();
    let _ = drust::storage::meta::open_meta(&path).unwrap();

    let conn = Connection::open(&path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_system_files'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn fresh_install_creates_new_schema_directly() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("meta.sqlite");
    let _ = drust::storage::meta::open_meta(&path).unwrap();

    let conn = Connection::open(&path).unwrap();
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info('_system_files')")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    for expected in [
        "key",
        "original_name",
        "content_type",
        "size_bytes",
        "content_disposition",
        "visibility",
        "cache_control",
        "meta_json",
        "uploaded_at",
        "uploader",
    ] {
        assert!(
            columns.iter().any(|c| c == expected),
            "missing column: {expected}"
        );
    }
}

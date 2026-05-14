//! Verify `admins.email` is added on fresh tenants and on upgraded
//! existing meta.sqlite DBs (idempotent).

use rusqlite::Connection;

#[test]
fn admins_email_column_exists_on_fresh_meta() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let _conn = drust::storage::meta::open_meta(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    let mut stmt = conn.prepare("PRAGMA table_info(admins)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(cols.contains(&"email".to_string()), "missing email: {cols:?}");
}

#[test]
fn admins_email_partial_unique_index_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let _conn = drust::storage::meta::open_meta(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    let idx: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_admins_email'",
            [],
            |r| r.get(0),
        )
        .ok();
    assert_eq!(idx.as_deref(), Some("idx_admins_email"));
}

#[test]
fn admins_email_migration_idempotent_on_existing_db() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    // First open creates fresh schema.
    let _ = drust::storage::meta::open_meta(&path).unwrap();
    // Second open re-runs migration; must not error.
    let _ = drust::storage::meta::open_meta(&path).unwrap();
}

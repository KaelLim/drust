use drust::storage::meta::{bootstrap_admin, open_meta};
use tempfile::tempdir;

#[test]
fn opens_fresh_db_with_schema() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let conn = open_meta(&path).unwrap();
    let tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type='table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        tables,
        [
            "_system_public_files",
            "admins",
            "sessions",
            "tenants",
            "tokens"
        ]
    );
}

#[test]
fn system_public_files_schema_shape() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let conn = open_meta(&path).unwrap();

    let cols: Vec<(String, String, i64)> = conn
        .prepare("PRAGMA table_info(\"_system_public_files\")")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();

    let names: Vec<&str> = cols.iter().map(|(n, _, _)| n.as_str()).collect();
    assert!(names.contains(&"key"));
    assert!(names.contains(&"original_name"));
    assert!(names.contains(&"size_bytes"));
    assert!(names.contains(&"uploader"));

    // Index exists
    let idx_cnt: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='index' AND name='idx_public_files_uploaded_at'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx_cnt, 1);
}

#[test]
fn idempotent_open() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let _ = open_meta(&path).unwrap();
    let _ = open_meta(&path).unwrap();
}

#[test]
fn bootstrap_creates_admin_once() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let mut conn = open_meta(&path).unwrap();
    let first = bootstrap_admin(&mut conn, "root", "pw").unwrap();
    assert!(first, "first bootstrap installs admin");
    let second = bootstrap_admin(&mut conn, "root", "pw").unwrap();
    assert!(!second, "subsequent bootstrap skips");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM admins", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

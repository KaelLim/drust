use drust::storage::meta::{bootstrap_admin, open_meta};
use tempfile::tempdir;

#[test]
fn opens_fresh_db_with_schema() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let conn = open_meta(&path).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(tables, ["admins", "sessions", "tenants", "tokens"]);
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

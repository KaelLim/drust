use drust::auth::session::{create_session, purge_expired, validate_session};
use drust::storage::meta::{bootstrap_admin, open_meta};
use tempfile::tempdir;

fn make_db() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempdir().unwrap();
    let mut conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    (dir, conn)
}

#[test]
fn create_and_validate() {
    let (_d, mut conn) = make_db();
    let token = create_session(&mut conn, 1, 3600).unwrap();
    assert!(!token.is_empty());
    let admin_id = validate_session(&conn, &token).unwrap();
    assert_eq!(admin_id, Some(1));
}

#[test]
fn expired_returns_none() {
    let (_d, mut conn) = make_db();
    let token = create_session(&mut conn, 1, -1).unwrap();
    let admin_id = validate_session(&conn, &token).unwrap();
    assert_eq!(admin_id, None);
}

#[test]
fn purge_removes_expired() {
    let (_d, mut conn) = make_db();
    let _token = create_session(&mut conn, 1, -1).unwrap();
    let n = purge_expired(&mut conn).unwrap();
    assert_eq!(n, 1);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn unknown_token_none() {
    let (_d, conn) = make_db();
    assert_eq!(validate_session(&conn, "nonexistent").unwrap(), None);
}

use drust::query::authorizer::attach_readonly_authorizer;
use drust::storage::tenant_db::{open_read, open_write};
use tempfile::tempdir;

fn seed(name: &str) -> tempfile::TempDir {
    let d = tempdir().unwrap();
    let conn = open_write(d.path(), name).unwrap();
    conn.execute_batch("CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT);").unwrap();
    d
}

#[test]
fn select_allowed() {
    let d = seed("t");
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let mut stmt = conn.prepare("SELECT id, title FROM posts").unwrap();
    let _ = stmt.query_map([], |_| Ok(())).unwrap().count();
}

#[test]
fn attach_denied() {
    let d = seed("t");
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let err = conn
        .prepare("ATTACH DATABASE '/tmp/x.db' AS x")
        .unwrap_err();
    let msg = format!("{err}").to_lowercase();
    assert!(msg.contains("authoriz") || msg.contains("not authorized") || msg.contains("denied"));
}

#[test]
fn drop_table_denied() {
    let d = seed("t");
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    assert!(conn.prepare("DROP TABLE posts").is_err());
}

#[test]
fn insert_denied_at_authorizer() {
    let d = seed("t");
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    assert!(conn.prepare("INSERT INTO posts (title) VALUES ('x')").is_err());
}

#[test]
fn pragma_whitelisted() {
    let d = seed("t");
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    // Whitelisted pragmas should still work; we probe via a SELECT-style query
    let mut stmt = conn.prepare("SELECT * FROM pragma_table_info('posts')").unwrap();
    let _ = stmt.query_map([], |_| Ok(())).unwrap().count();
}

#[test]
fn sqlite_master_read_denied() {
    let d = seed("t");
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    // Reading sqlite_master directly (not via pragma_*) is blocked.
    assert!(conn.prepare("SELECT name FROM sqlite_master").is_err());
}

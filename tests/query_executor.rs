use drust::query::authorizer::attach_readonly_authorizer;
use drust::query::executor::{ExecError, execute_read_query};
use drust::storage::tenant_db::{open_read, open_write};
use tempfile::tempdir;

fn seed() -> tempfile::TempDir {
    let d = tempdir().unwrap();
    let conn = open_write(d.path(), "t").unwrap();
    conn.execute_batch(
        "CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT);
         INSERT INTO posts (title) VALUES ('a'), ('b'), ('c');",
    )
    .unwrap();
    d
}

#[test]
fn returns_rows_and_column_names() {
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let out =
        execute_read_query(&conn, "SELECT id, title FROM posts ORDER BY id", 10, 5_000).unwrap();
    assert_eq!(out.column_names, vec!["id", "title"]);
    assert_eq!(out.rows.len(), 3);
    assert!(!out.truncated);
}

#[test]
fn enforces_row_cap() {
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let out = execute_read_query(&conn, "SELECT * FROM posts", 2, 5_000).unwrap();
    assert_eq!(out.rows.len(), 2);
    assert!(out.truncated);
}

#[test]
fn rejects_too_large_sql() {
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let big = format!("SELECT * FROM posts /* {} */", "x".repeat(20_000));
    let err = execute_read_query(&conn, &big, 10, 5_000).unwrap_err();
    assert!(matches!(err, ExecError::TooLarge { .. }));
}

#[test]
fn forbidden_returns_forbidden_error() {
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let err = execute_read_query(&conn, "DROP TABLE posts", 10, 5_000).unwrap_err();
    assert!(matches!(err, ExecError::Forbidden { .. }));
}

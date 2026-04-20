use drust::storage::quota::{QuotaError, check_file_size, check_row_count};
use drust::storage::tenant_db::{open_write, tenant_data_path};
use tempfile::tempdir;

#[test]
fn file_size_under_limit_ok() {
    let dir = tempdir().unwrap();
    let _ = open_write(dir.path(), "t1").unwrap();
    let path = tenant_data_path(dir.path(), "t1");
    check_file_size(&path, 1).unwrap(); // 1 MB is plenty
}

#[test]
fn file_size_over_limit_err() {
    let dir = tempdir().unwrap();
    let conn = open_write(dir.path(), "t1").unwrap();
    conn.execute_batch("CREATE TABLE blob (v BLOB)").unwrap();
    // Insert some bytes to make the DB > 0.
    conn.execute(
        "INSERT INTO blob (v) VALUES (?1)",
        rusqlite::params![vec![0u8; 2048]],
    )
    .unwrap();
    drop(conn);
    let path = tenant_data_path(dir.path(), "t1");
    let err = check_file_size(&path, 0).unwrap_err(); // limit 0 MB
    matches!(err, QuotaError::FileSize { .. });
}

#[test]
fn row_count_ok() {
    let dir = tempdir().unwrap();
    let conn = open_write(dir.path(), "t1").unwrap();
    conn.execute_batch(
        "CREATE TABLE a (id INTEGER); INSERT INTO a VALUES (1); INSERT INTO a VALUES (2);",
    )
    .unwrap();
    check_row_count(&conn, 10).unwrap();
}

#[test]
fn row_count_over_limit_err() {
    let dir = tempdir().unwrap();
    let conn = open_write(dir.path(), "t1").unwrap();
    conn.execute_batch(
        "CREATE TABLE a (id INTEGER); INSERT INTO a VALUES (1); INSERT INTO a VALUES (2);",
    )
    .unwrap();
    let err = check_row_count(&conn, 1).unwrap_err();
    matches!(err, QuotaError::RowCount { .. });
}

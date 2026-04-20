use drust::storage::tenant_db::{open_read, open_write, tenant_dir};
use tempfile::tempdir;

#[test]
fn tenant_dir_layout() {
    let root = std::path::Path::new("/var/lib/drust");
    let d = tenant_dir(root, "blog-demo");
    assert_eq!(
        d.as_path(),
        std::path::Path::new("/var/lib/drust/tenants/blog-demo")
    );
}

#[test]
fn opens_fresh_write_db_with_pragmas() {
    let dir = tempdir().unwrap();
    let tenant = "blog";
    let conn = open_write(dir.path(), tenant).unwrap();
    let journal: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1);
}

#[test]
fn readonly_rejects_write() {
    let dir = tempdir().unwrap();
    let tenant = "blog";
    let _ = open_write(dir.path(), tenant).unwrap();
    let r = open_read(dir.path(), tenant).unwrap();
    let err = r.execute("CREATE TABLE x (id INTEGER)", []).unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("readonly")
            || format!("{err}").to_lowercase().contains("read only")
    );
}

#[test]
fn read_fails_if_missing() {
    let dir = tempdir().unwrap();
    let err = open_read(dir.path(), "nonexistent");
    assert!(err.is_err());
}

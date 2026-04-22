use drust::storage::{schema, tenant_db};
use tempfile::TempDir;

#[test]
fn new_tenant_db_has_system_files_table() {
    let tmp = TempDir::new().unwrap();
    let conn = tenant_db::open_write(tmp.path(), "sample").unwrap();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_system_files'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(exists, 1);

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
        "visibility",
        "content_disposition",
        "cache_control",
        "meta_json",
        "uploader",
    ] {
        assert!(
            columns.iter().any(|c| c == expected),
            "missing column: {}",
            expected
        );
    }
}

#[test]
fn system_files_is_protected_from_drop() {
    assert!(schema::is_protected_collection("_system_files"));
    assert!(schema::is_protected_collection("_system_public_files")); // legacy
    assert!(!schema::is_protected_collection("events"));
}

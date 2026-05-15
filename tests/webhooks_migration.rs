use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn new_tenant_db_has_webhooks_table_and_index() {
    let dir = tempdir().unwrap();
    let tid = "t-mig1";
    let _ = drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let path = dir.path().join("tenants").join(tid).join("data.sqlite");
    let conn = Connection::open(&path).unwrap();
    let exists: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_webhooks'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(exists, 1, "_system_webhooks must exist on fresh tenant");
    let idx: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_system_webhooks_collection'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx, 1, "active-only collection index must exist");
}

#[test]
fn existing_tenant_db_gets_webhooks_table_via_migrate() {
    let dir = tempdir().unwrap();
    let tid = "t-mig2";
    let _ = drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let path = dir.path().join("tenants").join(tid).join("data.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute("DROP TABLE _system_webhooks", []).unwrap();
    drop(conn);
    drust::db::migrations::migrate_tenant_db(dir.path(), tid).unwrap();
    let conn = Connection::open(&path).unwrap();
    let exists: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_webhooks'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(exists, 1, "migrate must recreate _system_webhooks");
}

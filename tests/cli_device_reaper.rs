use drust::db::migrations::run_migrations;
use drust::storage::meta::open_meta;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test]
async fn reaper_deletes_expired_keeps_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    run_migrations(&conn, dir.path()).unwrap(); // creates _cli_device_codes
    conn.execute(
        "INSERT INTO _cli_device_codes (device_code_hash,user_code,expires_at) \
         VALUES ('h1','AAAA-2345', datetime('now','-1 hour'))",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO _cli_device_codes (device_code_hash,user_code,expires_at) \
         VALUES ('h2','BBBB-2345', datetime('now','+1 hour'))",
        [],
    )
    .unwrap();
    let meta = Arc::new(Mutex::new(conn));
    let n = drust::mgmt::cli_device::sweep_expired_device_codes(&meta).await;
    assert_eq!(n, 1, "exactly the expired row is reaped");
    let left: i64 = meta
        .lock()
        .await
        .query_row("SELECT count(*) FROM _cli_device_codes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 1);
}

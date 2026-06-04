use rusqlite::Connection;
mod helpers;

#[tokio::test]
async fn boot_migration_creates_system_tables() {
    let (_router, _tenant, dir) = helpers::spin_up_tenant("t-mig").await;
    let p = dir.path().join("tenants").join("t-mig").join("data.sqlite");
    let c = Connection::open(&p).unwrap();
    let n_users: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_users'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let n_sess: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_sessions'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n_users, 1);
    assert_eq!(n_sess, 1);

    let cols: Vec<String> = c
        .prepare("PRAGMA table_info(_system_collection_meta)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(cols.contains(&"owner_field".to_string()));
    assert!(cols.contains(&"read_scope".to_string()));
}

#[tokio::test]
async fn boot_migration_idempotent_on_restart() {
    // spin_up_tenant calls run_migrations once. Calling it again on the same files must not panic.
    let (_router, _tenant, dir) = helpers::spin_up_tenant("t-mig2").await;
    // Re-open meta and re-run
    let meta = Connection::open(dir.path().join("meta.sqlite")).unwrap();
    let report = drust::db::migrations::run_migrations(&meta, dir.path()).unwrap();
    assert!(report.tenants_failed.is_empty());
    assert!(report.tenants_ok.contains(&"t-mig2".to_string()));
}

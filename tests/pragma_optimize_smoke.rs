use drust::storage::pool::TenantPool;
use drust::storage::tenant_db::open_write;
use std::sync::Arc;
use tempfile::tempdir;

/// Drive more than `DRUST_OPTIMIZE_EVERY` (1000) writes through `with_writer`
/// and assert: every write succeeds, the data is intact, and the bounded
/// `PRAGMA optimize` fired at least once (test-only `optimize_runs()` counter).
#[tokio::test]
async fn optimize_runs_after_threshold_without_breaking_writes() {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let _ = open_write(&data, "t1").unwrap();
    let pool = Arc::new(TenantPool::new(data.clone(), "t1", 2).unwrap());

    pool.with_writer(|c| c.execute_batch("CREATE TABLE k (v INTEGER)"))
        .await
        .unwrap();

    for i in 0..1100i64 {
        pool.with_writer(move |c| c.execute("INSERT INTO k(v) VALUES (?1)", [i]))
            .await
            .unwrap();
    }

    // Data intact through a fresh reader.
    let n: i64 = pool
        .with_reader(|c| c.query_row("SELECT count(*) FROM k", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 1100, "every write must have landed");

    // optimize fired at least once (1100 > 1000 threshold).
    assert!(
        pool.optimize_runs() >= 1,
        "PRAGMA optimize must have run at least once after 1100 writes, got {}",
        pool.optimize_runs()
    );
}

/// `with_writer_tx` (the transaction path) must ALSO drive the optimize counter
/// — the increment runs on the locked connection after `tx.commit()` returns.
#[tokio::test]
async fn optimize_runs_via_writer_tx_path() {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let _ = open_write(&data, "t1").unwrap();
    let pool = Arc::new(TenantPool::new(data.clone(), "t1", 2).unwrap());

    pool.with_writer(|c| c.execute_batch("CREATE TABLE k (v INTEGER)"))
        .await
        .unwrap();

    for i in 0..1100i64 {
        pool.with_writer_tx(move |tx| tx.execute("INSERT INTO k(v) VALUES (?1)", [i]).map(|_| ()))
            .await
            .unwrap();
    }

    let n: i64 = pool
        .with_reader(|c| c.query_row("SELECT count(*) FROM k", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 1100, "every tx write must have landed");
    assert!(
        pool.optimize_runs() >= 1,
        "PRAGMA optimize must have run via the tx path, got {}",
        pool.optimize_runs()
    );
}

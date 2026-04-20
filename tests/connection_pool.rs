use drust::storage::pool::TenantPool;
use drust::storage::tenant_db::open_write;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn writer_serializes_writes() {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    // Seed the tenant DB so read connections can be created later.
    let _ = open_write(&data, "t1").unwrap();
    let pool = Arc::new(TenantPool::new(data.clone(), "t1", 2).unwrap());

    pool.with_writer(|c| c.execute_batch("CREATE TABLE m (id INTEGER PRIMARY KEY)")).await.unwrap();

    // Two concurrent writes should both succeed without BUSY.
    let p1 = pool.clone();
    let p2 = pool.clone();
    let h1 = tokio::spawn(async move {
        for i in 0..50 {
            p1.with_writer(move |c| {
                c.execute("INSERT INTO m (id) VALUES (?)", rusqlite::params![i])
            })
            .await
            .unwrap();
        }
    });
    let h2 = tokio::spawn(async move {
        for i in 50..100 {
            p2.with_writer(move |c| {
                c.execute("INSERT INTO m (id) VALUES (?)", rusqlite::params![i])
            })
            .await
            .unwrap();
        }
    });
    h1.await.unwrap();
    h2.await.unwrap();

    let count: i64 = pool
        .with_reader(|c| c.query_row("SELECT COUNT(*) FROM m", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(count, 100);
}

#[tokio::test]
async fn readers_concurrent() {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let _ = open_write(&data, "t1").unwrap();
    let pool = Arc::new(TenantPool::new(data.clone(), "t1", 4).unwrap());
    pool.with_writer(|c| c.execute_batch("CREATE TABLE m (id INTEGER); INSERT INTO m VALUES (1);"))
        .await
        .unwrap();

    let mut handles = vec![];
    for _ in 0..10 {
        let p = pool.clone();
        handles.push(tokio::spawn(async move {
            let n: i64 = p.with_reader(|c| c.query_row("SELECT id FROM m", [], |r| r.get(0)))
                .await
                .unwrap();
            assert_eq!(n, 1);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

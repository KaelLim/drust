mod helpers;
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::exploration::{
    count_rows, describe_collection, list_collections, sample_rows,
};
use drust::storage::pool::TenantRegistry;
use helpers::seed_tenant_fs;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    let svc = reg.get_or_create("blog").await.unwrap();
    let pool = svc.inner().pool.clone();
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            INSERT INTO posts (title) VALUES ('a'), ('b'), ('c');",
        )
    })
    .await
    .unwrap();
    svc
}

#[tokio::test]
async fn list() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = list_collections(&s).await.unwrap();
    assert_eq!(v["collections"][0]["name"], "posts");
}

#[tokio::test]
async fn describe() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = describe_collection(&s, "posts").await.unwrap();
    assert_eq!(v["name"], "posts");
    assert!(
        v["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "title")
    );
}

#[tokio::test]
async fn sample_5() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = sample_rows(&s, "posts", 5).await.unwrap();
    assert_eq!(v["rows"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn count_all() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = count_rows(&s, "posts", None).await.unwrap();
    assert_eq!(v["count"], 3);
    let v2 = count_rows(&s, "posts", Some("title='b'")).await.unwrap();
    assert_eq!(v2["count"], 1);
}

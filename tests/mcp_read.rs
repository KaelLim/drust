mod helpers;
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::read::{explain, query};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    let s = reg.get_or_create("blog").await.unwrap();
    s.inner()
        .pool
        .with_writer(|c| {
            c.execute_batch("CREATE TABLE k (id INTEGER); INSERT INTO k VALUES (1),(2),(3);")
        })
        .await
        .unwrap();
    s
}

#[tokio::test]
async fn basic_query() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let v = query(&s, "SELECT id FROM k ORDER BY id").await.unwrap();
    assert_eq!(v["rows"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn explain_returns_plan_string() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let v = explain(&s, "SELECT id FROM k", false).await.unwrap();
    assert!(
        v["plan"].as_str().unwrap().contains("SCAN")
            || v["plan"].as_str().unwrap().contains("USING")
    );
}

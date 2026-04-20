use drust::mcp::server::McpRegistry;
use drust::storage::pool::TenantRegistry;
use drust::storage::tenant_db::open_write;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn registry_caches_services() {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let _ = open_write(&data, "blog").unwrap();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let reg = McpRegistry::new(tr.clone());
    let s1 = reg.get_or_create("blog").await.unwrap();
    let s2 = reg.get_or_create("blog").await.unwrap();
    assert!(Arc::ptr_eq(&s1.inner(), &s2.inner()));
}

mod helpers;

use drust::mcp::server::McpRegistry;
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn fixture(tenant: &str) -> (drust::mcp::server::DrustMcp, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let registry = Arc::new(TenantRegistry::new(data, 2));
    let reg = McpRegistry::new(registry);
    let svc = reg.get_or_create(tenant).await.unwrap();
    drust::mcp::tools::schema::create_collection(
        &svc,
        "posts",
        &[drust::mcp::tools::schema::FieldSpec {
            name: "author_id".into(),
            sql_type: "integer".into(),
            nullable: true,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    (svc, dir)
}

#[tokio::test]
async fn explain_returns_plan_for_simple_select() {
    let (svc, _d) = fixture("e1").await;
    let resp = drust::mcp::tools::index::explain_select(
        &svc,
        "SELECT * FROM posts WHERE author_id = 1",
    )
    .await
    .unwrap();
    let plan = resp["plan"].as_array().unwrap();
    assert!(!plan.is_empty(), "plan must have at least one row");
    let detail = plan[0]["detail"].as_str().unwrap();
    assert!(detail.contains("posts"), "plan should mention table name: {detail}");
}

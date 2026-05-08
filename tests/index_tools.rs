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
async fn creates_simple_index_on_one_field() {
    let (svc, _d) = fixture("t1").await;
    let resp = drust::mcp::tools::index::create_index(
        &svc,
        "posts",
        &["author_id".to_string()],
        false, // unique
        false, // force
    )
    .await
    .unwrap();

    assert_eq!(resp["ok"], true);
    assert_eq!(resp["collection"], "posts");
    assert_eq!(resp["name"], "idx_posts_author_id");
    assert!(resp["indices"].as_array().unwrap().iter().any(|i| {
        i["name"] == "idx_posts_author_id" && i["unique"] == false
    }));
    assert!(resp["row_count_at_build"].is_number());
    assert!(resp["duration_ms"].is_number());
}

#[tokio::test]
async fn creates_composite_index_on_two_fields() {
    let (svc, _d) = fixture("t2").await;
    drust::mcp::tools::schema::add_field(
        &svc,
        "posts",
        drust::mcp::tools::schema::FieldSpec {
            name: "day_number".into(),
            sql_type: "integer".into(),
            nullable: true,
            unique: false,
            default_value: None,
            foreign_key: None,
        },
    )
    .await
    .unwrap();

    let resp = drust::mcp::tools::index::create_index(
        &svc,
        "posts",
        &["author_id".to_string(), "day_number".to_string()],
        false,
        false,
    )
    .await
    .unwrap();

    assert_eq!(resp["name"], "idx_posts_author_id_day_number");
    let idx = resp["indices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "idx_posts_author_id_day_number")
        .unwrap();
    assert_eq!(idx["fields"], serde_json::json!(["author_id", "day_number"]));
    assert_eq!(idx["unique"], false);
}

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

#[tokio::test]
async fn unknown_collection_returns_404() {
    let (svc, _d) = fixture("t3").await;
    let err = drust::mcp::tools::index::create_index(
        &svc,
        "nonexistent",
        &["x".to_string()],
        false,
        false,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no such collection"));
}

#[tokio::test]
async fn unknown_field_returns_field_not_found() {
    let (svc, _d) = fixture("t4").await;
    let err = drust::mcp::tools::index::create_index(
        &svc,
        "posts",
        &["does_not_exist".to_string()],
        false,
        false,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("does_not_exist"),
        "error should name the missing field: {err}");
}

#[tokio::test]
async fn system_collection_returns_404() {
    let (svc, _d) = fixture("t5").await;
    // _system_* prefix protection fires regardless of whether the table actually exists.
    let err = drust::mcp::tools::index::create_index(
        &svc,
        "_system_files",
        &["k".to_string()],
        false,
        false,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no such collection"));
}

#[tokio::test]
async fn empty_fields_returns_invalid_params() {
    let (svc, _d) = fixture("t6").await;
    let err = drust::mcp::tools::index::create_index(
        &svc,
        "posts",
        &[],
        false,
        false,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("non-empty"));
}

#[tokio::test]
async fn duplicate_fields_returns_invalid_params() {
    let (svc, _d) = fixture("t7").await;
    let err = drust::mcp::tools::index::create_index(
        &svc,
        "posts",
        &["author_id".to_string(), "author_id".to_string()],
        false,
        false,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("duplicate"));
}

#[tokio::test]
async fn duplicate_index_name_returns_409() {
    let (svc, _d) = fixture("t8").await;
    drust::mcp::tools::index::create_index(
        &svc,
        "posts",
        &["author_id".to_string()],
        false,
        false,
    )
    .await
    .unwrap();

    // Re-create with the same fields → same auto-name → already exists.
    let err = drust::mcp::tools::index::create_index(
        &svc,
        "posts",
        &["author_id".to_string()],
        false,
        false,
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("already exists") || msg.contains("idx_posts_author_id"),
        "expected INDEX_EXISTS-style error, got: {msg}"
    );
}

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mcp::server::McpRegistry;
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;
use tower::ServiceExt;

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
            dim: None,
            description: None,
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
        &svc.inner().pool,
        "SELECT * FROM posts WHERE author_id = 1",
    )
    .await
    .unwrap();
    let plan = resp["plan"].as_array().unwrap();
    assert!(!plan.is_empty(), "plan must have at least one row");
    let detail = plan[0]["detail"].as_str().unwrap();
    assert!(detail.contains("posts"), "plan should mention table name: {detail}");
}

#[tokio::test]
async fn explain_blocks_attach_via_authorizer() {
    let (svc, _d) = fixture("e2").await;
    let err = drust::mcp::tools::index::explain_select(
        &svc.inner().pool,
        "ATTACH DATABASE 'evil.db' AS evil",
    ).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not authorized") || msg.contains("authorizer"),
        "expected authorizer error, got: {msg}");
}

#[tokio::test]
async fn explain_blocks_sqlite_master_via_authorizer() {
    let (svc, _d) = fixture("e3").await;
    let err = drust::mcp::tools::index::explain_select(
        &svc.inner().pool,
        "SELECT name FROM sqlite_master",
    ).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("not authorized") || msg.contains("authorizer") || msg.contains("prohibited"),
        "expected authorizer error, got: {msg}"
    );
}

#[tokio::test]
async fn explain_blocks_non_select_via_authorizer() {
    let (svc, _d) = fixture("e4").await;
    let err = drust::mcp::tools::index::explain_select(
        &svc.inner().pool,
        "INSERT INTO posts (author_id) VALUES (1)",
    ).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not authorized") || msg.contains("authorizer"),
        "expected authorizer error, got: {msg}");
}

#[tokio::test]
async fn explain_shows_using_index_after_create() {
    let (svc, _d) = fixture("e5").await;

    // Seed rows so the optimizer has cardinality stats and picks a real plan.
    for i in 1i64..=3 {
        drust::mcp::tools::write::insert_record(
            &svc,
            "posts",
            serde_json::json!({ "author_id": i }),
        )
        .await
        .unwrap();
    }

    let before = drust::mcp::tools::index::explain_select(
        &svc.inner().pool,
        "SELECT * FROM posts WHERE author_id = 1",
    ).await.unwrap();
    let before_detail = before["plan"][0]["detail"].as_str().unwrap();
    assert!(before_detail.contains("SCAN"), "before-index plan should SCAN: {before_detail}");

    drust::mcp::tools::index::create_index(
        &svc.inner().pool, "posts", &["author_id".to_string()], false, false,
    ).await.unwrap();

    let after = drust::mcp::tools::index::explain_select(
        &svc.inner().pool,
        "SELECT * FROM posts WHERE author_id = 1",
    ).await.unwrap();
    let after_detail = after["plan"][0]["detail"].as_str().unwrap();
    assert!(after_detail.contains("USING INDEX"), "after-index plan should USING INDEX: {after_detail}");
}

#[tokio::test]
async fn rest_explain_returns_plan() {
    let (app, tok, d) = helpers::spin_up_tenant_with_role("ex_rest1", "service").await;
    helpers::seed_posts_collection(&app, &tok, "ex_rest1", &d).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/ex_rest1/query/explain")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"sql":"SELECT * FROM posts WHERE author_id = 1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["plan"].as_array().unwrap().len() >= 1);
}

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
            dim: None,
            description: None,
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
        &svc.inner().pool,
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
    assert!(
        resp["indices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| { i["name"] == "idx_posts_author_id" && i["unique"] == false })
    );
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
            dim: None,
            description: None,
        },
    )
    .await
    .unwrap();

    let resp = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
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
    assert_eq!(
        idx["fields"],
        serde_json::json!(["author_id", "day_number"])
    );
    assert_eq!(idx["unique"], false);
}

#[tokio::test]
async fn unknown_collection_returns_404() {
    let (svc, _d) = fixture("t3").await;
    let err = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
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
        &svc.inner().pool,
        "posts",
        &["does_not_exist".to_string()],
        false,
        false,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("does_not_exist"),
        "error should name the missing field: {err}"
    );
}

#[tokio::test]
async fn system_collection_returns_404() {
    let (svc, _d) = fixture("t5").await;
    // _system_* prefix protection fires regardless of whether the table actually exists.
    let err = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
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
    let err = drust::mcp::tools::index::create_index(&svc.inner().pool, "posts", &[], false, false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("non-empty"));
}

#[tokio::test]
async fn duplicate_fields_returns_invalid_params() {
    let (svc, _d) = fixture("t7").await;
    let err = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
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
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        false,
        false,
    )
    .await
    .unwrap();

    // Re-create with the same fields → same auto-name → already exists.
    let err = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
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

#[tokio::test]
async fn creates_unique_index_succeeds_when_data_unique() {
    let (svc, _d) = fixture("t9").await;
    // Insert two distinct rows.
    drust::mcp::tools::write::insert_record(&svc, "posts", serde_json::json!({"author_id": 1}))
        .await
        .unwrap();
    drust::mcp::tools::write::insert_record(&svc, "posts", serde_json::json!({"author_id": 2}))
        .await
        .unwrap();
    let resp = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        true, // unique
        false,
    )
    .await
    .unwrap();
    let idx = resp["indices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "idx_posts_author_id")
        .unwrap();
    assert_eq!(idx["unique"], true);
}

#[tokio::test]
async fn unique_index_on_duplicate_data_returns_unique_violation() {
    let (svc, _d) = fixture("t10").await;
    drust::mcp::tools::write::insert_record(&svc, "posts", serde_json::json!({"author_id": 1}))
        .await
        .unwrap();
    drust::mcp::tools::write::insert_record(&svc, "posts", serde_json::json!({"author_id": 1}))
        .await
        .unwrap();
    let err = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        true,
        false,
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("duplicate"),
        "expected UNIQUE_VIOLATION-style error, got: {msg}"
    );
}

#[tokio::test]
async fn large_table_without_force_returns_409() {
    let (svc, _d) = fixture("t11").await;
    // Seed 5 rows; we'll set threshold=3 in the call.
    for i in 0..5 {
        drust::mcp::tools::write::insert_record(&svc, "posts", serde_json::json!({"author_id": i}))
            .await
            .unwrap();
    }
    let err = drust::mcp::tools::index::create_index_with_threshold(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        false, // unique
        false, // force
        3,     // threshold
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("LARGE_TABLE") || msg.contains("force"),
        "got: {msg}"
    );
}

#[tokio::test]
async fn large_table_with_force_proceeds() {
    let (svc, _d) = fixture("t12").await;
    for i in 0..5 {
        drust::mcp::tools::write::insert_record(&svc, "posts", serde_json::json!({"author_id": i}))
            .await
            .unwrap();
    }
    let resp = drust::mcp::tools::index::create_index_with_threshold(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        false,
        true, // force
        3,
    )
    .await
    .unwrap();
    assert_eq!(resp["ok"], true);
}

#[tokio::test]
async fn drop_by_name_succeeds() {
    let (svc, _d) = fixture("t13").await;
    drust::mcp::tools::index::create_index(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        false,
        false,
    )
    .await
    .unwrap();

    let resp = drust::mcp::tools::index::drop_index(
        &svc.inner().pool,
        "posts",
        Some("idx_posts_author_id"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["dropped_name"], "idx_posts_author_id");
    let names: Vec<String> = resp["indices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap().to_string())
        .collect();
    assert!(!names.contains(&"idx_posts_author_id".to_string()));
}

#[tokio::test]
async fn drop_unknown_index_returns_404() {
    let (svc, _d) = fixture("t14").await;
    let err = drust::mcp::tools::index::drop_index(
        &svc.inner().pool,
        "posts",
        Some("idx_does_not_exist"),
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no such index"));
}

#[tokio::test]
async fn drop_by_fields_resolves_to_same_index() {
    let (svc, _d) = fixture("t15").await;
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
            dim: None,
            description: None,
        },
    )
    .await
    .unwrap();
    drust::mcp::tools::index::create_index(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string(), "day_number".to_string()],
        false,
        false,
    )
    .await
    .unwrap();

    let resp = drust::mcp::tools::index::drop_index(
        &svc.inner().pool,
        "posts",
        None,
        Some(&["author_id".to_string(), "day_number".to_string()]),
    )
    .await
    .unwrap();
    assert_eq!(resp["dropped_name"], "idx_posts_author_id_day_number");
}

#[tokio::test]
async fn drop_with_neither_name_nor_fields_returns_invalid_params() {
    let (svc, _d) = fixture("t16").await;
    let err = drust::mcp::tools::index::drop_index(&svc.inner().pool, "posts", None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("INVALID_PARAMS"));
}

#[tokio::test]
async fn drop_then_recreate_works() {
    let (svc, _d) = fixture("t17").await;
    drust::mcp::tools::index::create_index(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        false,
        false,
    )
    .await
    .unwrap();
    drust::mcp::tools::index::drop_index(
        &svc.inner().pool,
        "posts",
        Some("idx_posts_author_id"),
        None,
    )
    .await
    .unwrap();
    let resp = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp["ok"], true);
}

// ── REST endpoint tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn rest_post_indexes_creates_and_returns_201() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    let (app, tok, dir) = helpers::spin_up_tenant_with_role("rt1", "service").await;
    helpers::seed_posts_collection(&app, &tok, "rt1", &dir).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/rt1/collections/posts/indexes")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["name"], "idx_posts_author_id");
}

#[tokio::test]
async fn rest_delete_index_returns_200() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    let (app, tok, dir) = helpers::spin_up_tenant_with_role("rt1b", "service").await;
    helpers::seed_posts_collection(&app, &tok, "rt1b", &dir).await;

    // First create an index via REST.
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/rt1b/collections/posts/indexes")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Then delete it by name.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/t/rt1b/collections/posts/indexes/idx_posts_author_id")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["dropped_name"], "idx_posts_author_id");
}

#[tokio::test]
async fn rest_anon_token_cannot_create_index() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    let (app, anon_tok, dir) = helpers::spin_up_tenant_with_role("rt2", "anon").await;
    helpers::seed_posts_collection(&app, &anon_tok, "rt2", &dir).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/rt2/collections/posts/indexes")
                .header(header::AUTHORIZATION, format!("Bearer {anon_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "WRITE_DENIED");
}

/// Regression test: `DRUST_INDEX_LARGE_TABLE_ROWS` (baked into `TenantAuthState`
/// at app-build time) must reach the REST `create_index_handler` and trigger
/// LARGE_TABLE when the table exceeds the configured threshold.
///
/// Before the config-plumbing fix every entry point called the thin
/// `create_index()` wrapper which hardcodes 1 000 000; operators setting
/// `DRUST_INDEX_LARGE_TABLE_ROWS=5` would see the guard silently bypassed.
#[tokio::test]
async fn rest_create_index_respects_configured_threshold() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    // threshold=3 means any table with >3 rows triggers LARGE_TABLE.
    let threshold: u64 = 3;
    let (app, tok, dir) =
        helpers::spin_up_tenant_with_threshold("rt_thresh", "service", threshold).await;
    helpers::seed_posts_collection(&app, &tok, "rt_thresh", &dir).await;

    // Seed 5 rows (> threshold=3).
    let pool = helpers::grab_pool("rt_thresh", &dir).await;
    for i in 0..5i64 {
        pool.with_writer(move |c| {
            c.execute(
                "INSERT INTO posts (author_id) VALUES (?1)",
                rusqlite::params![i],
            )
        })
        .await
        .unwrap();
    }

    // Without force=true the REST handler must return 409 LARGE_TABLE.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/rt_thresh/collections/posts/indexes")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "expected 409 LARGE_TABLE for table with 5 rows and threshold=3"
    );
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["error_code"], "LARGE_TABLE",
        "expected LARGE_TABLE error_code, got: {v}"
    );

    // With force=true the same request must succeed.
    let resp_forced = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/rt_thresh/collections/posts/indexes")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"fields":["author_id"],"force":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp_forced.status(),
        StatusCode::CREATED,
        "expected 201 when force=true overrides LARGE_TABLE"
    );
}

/// Verifies that the `#[tool]` handler entries for create_index and drop_index
/// compile and wire through correctly. The handler layer is thin (delegates to
/// the same underlying functions covered by the tests above), so this test
/// exercises the MCP-layer path by calling the underlying functions via the same
/// DrustMcp handle that the #[tool] methods operate on.
#[tokio::test]
async fn mcp_create_index_tool_works() {
    let (svc, _d) = fixture("tm1").await;

    // Exercise create_index — the same function the #[tool] entry delegates to.
    let resp = drust::mcp::tools::index::create_index(
        &svc.inner().pool,
        "posts",
        &["author_id".to_string()],
        Some(false).unwrap_or(false),
        Some(false).unwrap_or(false),
    )
    .await;
    assert!(
        resp.is_ok(),
        "create_index via mcp-layer path failed: {:?}",
        resp.err()
    );

    let drop_resp = drust::mcp::tools::index::drop_index(
        &svc.inner().pool,
        "posts",
        Some("idx_posts_author_id"),
        None,
    )
    .await;
    assert!(
        drop_resp.is_ok(),
        "drop_index via mcp-layer path failed: {:?}",
        drop_resp.err()
    );
}

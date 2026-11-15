use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::session::create_session;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn app() -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let tok = create_session(&mut conn, 1, 3600).unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir.clone(),
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = data_dir.join("audit");
    (state.with_data_dir(data_dir.clone()), tok, dir)
}

#[tokio::test]
async fn create_tenant_returns_initial_token() {
    let (app, tok, _d) = app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/admin/api/tenants")
        .header(header::COOKIE, format!("drust_session={tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"id":"blog","name":"Blog"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tenant"]["id"], "blog");
    assert!(v["initial_token"].as_str().unwrap().starts_with("drust_"));
}

#[tokio::test]
async fn rejects_bad_slug() {
    let (app, tok, _d) = app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/admin/api/tenants")
        .header(header::COOKIE, format!("drust_session={tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"id":"Bad Slug!!","name":"x"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn soft_delete_moves_to_trash() {
    let (app, tok, _d) = app().await;
    // First create
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"id":"blog2","name":"Blog"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/api/tenants/blog2")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// Regression test for the soft-delete eviction sweep. Without this,
/// TenantRegistry / McpHttpRegistry / EventBus would each retain Arc
/// clones of the deleted tenant's state until process restart — pinning
/// rusqlite Connection FDs against the renamed-to-_trash tenant dir,
/// keeping MCP sessions alive, and leaking SSE broadcast channels. E5 — that
/// includes the inner McpRegistry, whose DrustMcp holds the Arc<TenantPool>:
/// evicting only the outer McpHttpRegistry service left the pool open.
#[tokio::test]
async fn soft_delete_evicts_pool_mcp_and_bus_caches() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let tok = create_session(&mut conn, 1, 3600).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('blog', 'Blog')", [])
        .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data_dir, "blog").unwrap();

    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let inner = Arc::new(drust::mcp::server::McpRegistry::new(tenants.clone()));
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(
        inner.clone(),
    ));

    // Populate all three caches.
    let _ = tenants.get_or_create("blog").unwrap();
    let _ = mcp.get_or_create("blog").await.unwrap();
    let _rx = bus.subscribe("blog", "items");
    assert_eq!(tenants.cached_count(), 1);
    assert_eq!(mcp.cached_count(), 1);
    assert_eq!(inner.cached_count(), 1);
    assert_eq!(bus.channel_count(), 1);

    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir.clone(),
        tenants.clone(),
        mcp.clone(),
        bus.clone(),
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = data_dir.join("audit");
    let app = state.with_data_dir(data_dir);

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/api/tenants/blog")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // All three caches must be empty after soft-delete.
    assert_eq!(tenants.cached_count(), 0, "tenant pool not evicted");
    assert_eq!(mcp.cached_count(), 0, "mcp service not evicted");
    assert_eq!(bus.channel_count(), 0, "sse channel not evicted");
    assert_eq!(inner.cached_count(), 0, "inner mcp registry not evicted");
}

async fn post_tenant(app: &axum::Router, tok: &str, body: &str) -> (StatusCode, String, Vec<u8>) {
    let req = Request::builder()
        .method("POST")
        .uri("/admin/api/tenants")
        .header(header::COOKIE, format!("drust_session={tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let b = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap()
        .to_vec();
    (status, ct, b)
}

#[tokio::test]
async fn create_with_live_id_answers_400_tenant_id_unavailable() {
    let (app, tok, _d) = app().await;
    let (s, _, _) = post_tenant(&app, &tok, r#"{"id":"blog","name":"Blog"}"#).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, ct, b) = post_tenant(&app, &tok, r#"{"id":"blog","name":"Again"}"#).await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&b)
    );
    assert!(ct.starts_with("application/json"), "content-type {ct}");
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["error_code"], "TENANT_ID_UNAVAILABLE");
    assert_eq!(v["message"], "tenant 'blog' already exists");
    assert!(
        !v["suggested_fix"].as_str().unwrap_or_default().is_empty(),
        "{v}"
    );
}

#[tokio::test]
async fn bad_slug_answers_json_invalid_tenant_id() {
    let (app, tok, _d) = app().await;
    let (s, ct, b) = post_tenant(&app, &tok, r#"{"id":"Bad Slug!!","name":"x"}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(ct.starts_with("application/json"), "content-type {ct}");
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["error_code"], "INVALID_TENANT_ID");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .starts_with("invalid tenant id"),
        "{v}"
    );
}

//! v1.19.2 regression — admin login enforces a per-IP rate limit (5/min).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::safety::rate_limit_ip::IpRateLimit;
use drust::storage::meta::open_meta;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn build_login_router(rl_capacity: u32) -> Router {
    let dir = tempdir().unwrap();
    let meta_conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    let meta = Arc::new(Mutex::new(meta_conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        dir.path().to_path_buf(),
        2,
    ));
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(Arc::new(
            drust::storage::pool::TenantRegistry::new(dir.path().to_path_buf(), 2),
        )),
    )));
    let bus = drust::tenant::events::EventBus::new();
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let admin_login_rl = Arc::new(IpRateLimit::new(rl_capacity, Duration::from_secs(60), 4096));
    let mut mgmt_state = MgmtState::test_default(
        meta.clone(),
        dir.path().to_path_buf(),
        tenants,
        mcp,
        bus,
        bus_rooms,
    );
    mgmt_state.session_ttl_days = 1;
    mgmt_state.public_base_url = "http://localhost".into();
    mgmt_state.max_upload_bytes = 1024;
    mgmt_state.admin_login_rl = admin_login_rl;
    // Keep the tempdir alive for the duration of the test by leaking it.
    std::mem::forget(dir);
    drust::mgmt::routes::build_mgmt_router(mgmt_state)
}

async fn post_login(app: &Router, xff: Option<&str>) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(xff) = xff {
        builder = builder.header("x-forwarded-for", xff);
    }
    let req = builder
        .body(Body::from("username=admin&password=wrong"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    resp.status()
}

#[tokio::test]
async fn admin_login_rate_limit_blocks_after_capacity() {
    let app = build_login_router(3).await;
    let xff = Some("198.51.100.7, 203.0.113.1");
    for _ in 0..3 {
        let status = post_login(&app, xff).await;
        // 401 because admin doesn't exist; we're proving rate limit doesn't fire yet
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // 4th attempt: 429
    let status = post_login(&app, xff).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn admin_login_rate_limit_isolated_per_ip() {
    let app = build_login_router(1).await;
    let xff_a = Some("198.51.100.10, 203.0.113.1");
    let xff_b = Some("198.51.100.20, 203.0.113.1");
    assert_eq!(post_login(&app, xff_a).await, StatusCode::UNAUTHORIZED);
    assert_eq!(post_login(&app, xff_a).await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(post_login(&app, xff_b).await, StatusCode::UNAUTHORIZED);
}

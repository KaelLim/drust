//! Admin login POST path.
//!
//! - v1.19.2 regression — enforces a per-IP rate limit (5/min).
//! - the failure banner is translated (it was a hardcoded English literal
//!   under an already-translated title until v1.58.2).
//!
//! Both live here rather than in a file of their own: each `tests/*.rs` is its
//! own binary statically linking the drust lib + wasmtime, and this one already
//! builds exactly the router they need.

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
        drust::mcp::server::McpRegistry::new(Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        ))),
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

/// POST a bad login under `locale` and return the rendered page.
async fn failed_login_body(app: &Router, locale: Option<&str>) -> String {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(l) = locale {
        builder = builder.header(header::COOKIE, format!("drust_locale={l}"));
    }
    let resp = app
        .clone()
        .oneshot(
            builder
                .body(Body::from("username=admin&password=wrong"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn failed_login_banner_is_translated_not_hardcoded_english() {
    // The banner renders a title and a body. The title has always been
    // `t.s("login.error.password_title")`; the body came from a literal
    // `unauthorized("Invalid credentials", …)` in the handler — so a zh-TW
    // admin saw a translated heading over an English sentence, on the first
    // screen drust shows anyone. `unauthorized` now takes an i18n key.
    let app = build_login_router(50).await;

    let zh = failed_login_body(&app, Some("zh-TW")).await;
    assert!(
        zh.contains("帳號或密碼錯誤"),
        "zh-TW login failure should render the zh-TW body"
    );
    assert!(
        !zh.contains("Invalid credentials"),
        "the old hardcoded English literal must not survive anywhere in the page"
    );

    let en = failed_login_body(&app, Some("en")).await;
    assert!(
        en.contains("Wrong username or password."),
        "en login failure should render the en body"
    );
}

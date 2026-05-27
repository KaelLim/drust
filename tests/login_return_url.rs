//! Integration tests for drust_oauth_intent return-URL cookie (Task 11).
//!
//! Covers:
//! - login_submit redirects to the intent cookie target and clears the cookie
//! - login_submit falls back to /drust/admin/tenants when no intent cookie present
//! - login_submit ignores non-relative-path intent values (sanity check)

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::{MgmtState, build_mgmt_router};
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::oauth::ProviderRegistry;
use drust::safety::rate_limit_ip::IpRateLimit;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn build_app() -> axum::Router {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "admin@x.com", "hunter2").unwrap();
    std::mem::forget(dir);
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        audit_meta_read: Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        session_ttl_days: 7,
        garage: None,
        public_base_url: "http://localhost:8793".to_string(),
        max_upload_bytes: 52_428_800,
        garage_client_key_id: String::new(),
        disk_min_free_pct: 20,
        log_dir: std::env::temp_dir(),
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: String::new(),
        oauth_registry: Arc::new(ProviderRegistry::from_env_empty()),
        admin_login_rl: Arc::new(IpRateLimit::new(
            100,
            Duration::from_secs(60),
            4096,
        )),
        admin_oauth_callback_rl: Arc::new(IpRateLimit::new(
            100,
            Duration::from_secs(60),
            4096,
        )),
    };
    build_mgmt_router(state)
}

fn post_login(cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    builder
        .body(Body::from("username=admin@x.com&password=hunter2"))
        .unwrap()
}

/// Successful login with an intent cookie should redirect to the decoded intent
/// path (prepended with /drust) and clear the cookie (Max-Age=0).
#[tokio::test]
async fn login_redirects_to_intent_cookie_target() {
    // DRUST_DEV_NO_SECURE_COOKIES is unset in CI; tests that check Secure
    // attribute are deliberately avoided here.
    unsafe { std::env::set_var("DRUST_DEV_NO_SECURE_COOKIES", "1") };

    let app = build_app().await;
    let resp = app
        .oneshot(post_login(Some(
            "drust_oauth_intent=%2Foauth%2Fauthorize%3Fclient_id%3Dabc",
        )))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("should have Location header")
        .to_str()
        .unwrap();
    assert_eq!(
        location,
        "/drust/oauth/authorize?client_id=abc",
        "should redirect to intent target with /drust prefix"
    );

    // At least one Set-Cookie header must clear the intent cookie.
    let cleared = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| {
            let s = v.to_str().unwrap_or("");
            s.starts_with("drust_oauth_intent=") && s.contains("Max-Age=0")
        });
    assert!(cleared, "intent cookie should be cleared after consumption");
}

/// Successful login without an intent cookie falls back to /drust/admin/tenants.
#[tokio::test]
async fn login_falls_back_to_admin_tenants_without_intent() {
    unsafe { std::env::set_var("DRUST_DEV_NO_SECURE_COOKIES", "1") };

    let app = build_app().await;
    let resp = app.oneshot(post_login(None)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(location, "/drust/admin/tenants");
}

/// An intent cookie whose value does not start with '/' (absolute URL injection
/// attempt) must be ignored — fallback to /drust/admin/tenants.
#[tokio::test]
async fn login_ignores_non_relative_intent() {
    unsafe { std::env::set_var("DRUST_DEV_NO_SECURE_COOKIES", "1") };

    let app = build_app().await;
    // Encode "https://evil.example/steal" as the intent value.
    let resp = app
        .oneshot(post_login(Some(
            "drust_oauth_intent=https%3A%2F%2Fevil.example%2Fsteal",
        )))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        location,
        "/drust/admin/tenants",
        "non-relative intent should be ignored"
    );
}

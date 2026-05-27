//! Integration tests: RFC 7591 Dynamic Client Registration at POST /oauth/register.
//!
//! Covers:
//!   1. Successful registration returns 201 with client_id + RFC 7591 fields.
//!   2. Rate limit enforced at 10/hour per IP (11th request → 429).
//!   3. Invalid redirect_uri (non-https/non-localhost) rejected with 400.
//!
//! v1.29.0 — Task 13.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn build_state(conn: rusqlite::Connection, data_dir: PathBuf, log_dir: PathBuf) -> MgmtState {
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data_dir, 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    MgmtState {
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
        log_dir,
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: String::new(),
        oauth_registry: Arc::new(drust::oauth::ProviderRegistry::from_env_empty()),
        admin_login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            5,
            std::time::Duration::from_secs(60),
            4096,
        )),
        admin_oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            5,
            std::time::Duration::from_secs(60),
            4096,
        )),
        oauth_register_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            10,
            std::time::Duration::from_secs(3600),
            4096,
        )),
    }
}

async fn spin_up() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    let router = state.with_data_dir(data_dir);
    (router, dir)
}

fn register_request(body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/oauth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dynamic_registration_returns_client_id() {
    let (app, _dir) = spin_up().await;
    let resp = app
        .oneshot(register_request(serde_json::json!({
            "client_name": "Claude Desktop",
            "redirect_uris": ["http://localhost:55555/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 65536)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cid = json["client_id"].as_str().unwrap();
    assert!(
        cid.starts_with("drust_client_"),
        "client_id should start with drust_client_, got: {cid}"
    );
    assert_eq!(json["client_name"], "Claude Desktop");
    assert_eq!(json["token_endpoint_auth_method"], "none");
}

#[tokio::test]
async fn rate_limit_enforced_at_10_per_hour_per_ip() {
    let (_app, _dir) = spin_up().await;
    // Use a shared state so all 11 requests hit the same rate-limit bucket.
    // We rebuild the router once and clone it per request.
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    // Use capacity=10 so the 11th triggers the limit.
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data_dir.clone(), 2));
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
        log_dir,
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: String::new(),
        oauth_registry: Arc::new(drust::oauth::ProviderRegistry::from_env_empty()),
        admin_login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            5,
            std::time::Duration::from_secs(60),
            4096,
        )),
        admin_oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            5,
            std::time::Duration::from_secs(60),
            4096,
        )),
        // Capacity = 10: exactly 10 requests allowed, 11th denied.
        oauth_register_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            10,
            std::time::Duration::from_secs(3600),
            4096,
        )),
    };
    let router = state.with_data_dir(data_dir);

    for i in 0..10usize {
        let resp = router
            .clone()
            .oneshot(register_request(serde_json::json!({
                "client_name": format!("c{i}"),
                "redirect_uris": ["http://localhost/cb"],
            })))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "request {i} should succeed"
        );
    }

    // 11th request must be rate-limited.
    let resp = router
        .oneshot(register_request(serde_json::json!({
            "client_name": "11th",
            "redirect_uris": ["http://localhost/cb"],
        })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = axum::body::to_bytes(resp.into_body(), 65536)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["error_code"],
        "OAUTH_CLIENT_REGISTRATION_RATE_LIMIT"
    );
    drop(_dir); // keep dir alive past the last request
}

#[tokio::test]
async fn redirect_uri_must_be_https_or_localhost_http() {
    let (app, _dir) = spin_up().await;
    let resp = app
        .oneshot(register_request(serde_json::json!({
            "client_name": "x",
            "redirect_uris": ["ftp://evil/cb"],
        })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 65536)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error_code"], "INVALID_REDIRECT_URI");
}

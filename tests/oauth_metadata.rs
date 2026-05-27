//! Integration tests: RFC 8414 / RFC 9728 OAuth metadata endpoints.
//!
//! Covers:
//!   1. GET /.well-known/oauth-protected-resource — RFC 9728 shape.
//!   2. GET /.well-known/oauth-authorization-server — RFC 8414 shape.
//!
//! v1.29.0 — Task 16.

use axum::body::Body;
use axum::http::{Request, StatusCode};
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

// ─── tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn protected_resource_metadata_returns_rfc9728_shape() {
    let (app, _dir) = spin_up().await;
    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-protected-resource")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let j: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        j["authorization_servers"].as_array().unwrap().len() >= 1,
        "authorization_servers must be non-empty: {j}"
    );
    assert!(
        j["bearer_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("header")),
        "bearer_methods_supported must include 'header': {j}"
    );
}

#[tokio::test]
async fn authorization_server_metadata_returns_rfc8414_shape() {
    let (app, _dir) = spin_up().await;
    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let j: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        j["authorization_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/authorize"),
        "authorization_endpoint must end with /oauth/authorize: {j}"
    );
    assert!(
        j["token_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/token"),
        "token_endpoint must end with /oauth/token: {j}"
    );
    assert!(
        j["registration_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/register"),
        "registration_endpoint must end with /oauth/register: {j}"
    );
    assert!(
        j["code_challenge_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("S256")),
        "code_challenge_methods_supported must include S256: {j}"
    );
    assert!(
        j["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("authorization_code")),
        "grant_types_supported must include authorization_code: {j}"
    );
}

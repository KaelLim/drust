//! Integration tests: POST /oauth/token — refresh_token grant.
//!
//! Covers:
//!   (a) Happy path: valid refresh token → new access + refresh tokens issued,
//!       old refresh token marked rotated.
//!   (b) Reuse detection: presenting an already-rotated refresh token →
//!       400 invalid_grant + entire chain revoked (access + refresh tokens
//!       for that client_id + admin_id deleted from DB).
//!   (c) Unknown refresh token → 400 invalid_grant.
//!
//! v1.29.0 — Task 15.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::db::migrations::{
    SQL_CREATE_OAUTH_ACCESS_TOKENS_IF_NOT_EXISTS, SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS,
    SQL_CREATE_OAUTH_REFRESH_TOKENS_IF_NOT_EXISTS,
};
use drust::mgmt::oauth_server::storage::{sha256_b64, new_refresh_token};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── constants ───────────────────────────────────────────────────────────────

const CLIENT_ID:    &str = "drust_client_refreshtest001";
const RESOURCE_URI: &str = "https://tool.tzuchi-org.tw/drust/t/some-tenant/mcp";

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

async fn spin_up() -> (axum::Router, Arc<Mutex<rusqlite::Connection>>, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    conn.execute_batch(SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS).unwrap();
    conn.execute_batch(SQL_CREATE_OAUTH_ACCESS_TOKENS_IF_NOT_EXISTS).unwrap();
    conn.execute_batch(SQL_CREATE_OAUTH_REFRESH_TOKENS_IF_NOT_EXISTS).unwrap();

    conn.execute(
        "INSERT OR IGNORE INTO _oauth_clients (id, client_name, redirect_uris_json)
         VALUES (?1, 'RefreshApp', '[]')",
        params![CLIENT_ID],
    )
    .unwrap();

    let state = build_state(conn, data_dir.clone(), log_dir);
    let meta = state.meta.clone();
    let router = state.with_data_dir(data_dir);
    (router, meta, dir)
}

/// Insert a refresh token row directly. Returns the plaintext token.
async fn insert_refresh(
    meta: &Arc<Mutex<rusqlite::Connection>>,
    rotated_to_hash: Option<&str>,
    expired: bool,
) -> String {
    let token = new_refresh_token();
    let hash = sha256_b64(&token);
    let expires_at = if expired {
        (chrono::Utc::now() - chrono::Duration::minutes(1))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    } else {
        (chrono::Utc::now() + chrono::Duration::days(30))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    };
    let conn = meta.lock().await;
    conn.execute(
        "INSERT INTO _oauth_refresh_tokens
            (token_hash, client_id, admin_id, resource_uri, scope, expires_at, rotated_to_hash)
         VALUES (?1, ?2, 1, ?3, 'drust', ?4, ?5)",
        params![hash, CLIENT_ID, RESOURCE_URI, expires_at, rotated_to_hash],
    )
    .unwrap();
    token
}

/// Insert an access token row for the given client_id + admin_id.
async fn insert_access(meta: &Arc<Mutex<rusqlite::Connection>>) {
    let hash = sha256_b64("drust_at_dummy");
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let conn = meta.lock().await;
    // Ignore if already exists (idempotent across multiple test inserts).
    let _ = conn.execute(
        "INSERT OR IGNORE INTO _oauth_access_tokens
            (token_hash, client_id, admin_id, resource_uri, scope, expires_at)
         VALUES (?1, ?2, 1, ?3, 'drust', ?4)",
        params![hash, CLIENT_ID, RESOURCE_URI, expires_at],
    );
}

fn token_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ─── tests ───────────────────────────────────────────────────────────────────

/// (a) Happy path: valid refresh token → new access + refresh tokens.
#[tokio::test]
async fn refresh_grant_happy_path_returns_new_tokens() {
    let (app, meta, _dir) = spin_up().await;
    let rt = insert_refresh(&meta, None, false).await;

    let body = format!("grant_type=refresh_token&refresh_token={rt}");
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let new_at = json["access_token"].as_str().unwrap();
    let new_rt = json["refresh_token"].as_str().unwrap();
    assert!(
        new_at.starts_with("drust_at_"),
        "new access_token should start with drust_at_, got: {new_at}"
    );
    assert!(
        new_rt.starts_with("drust_rt_"),
        "new refresh_token should start with drust_rt_, got: {new_rt}"
    );
    // New tokens must differ from original token.
    assert_ne!(new_rt, rt, "new refresh_token must differ from original");
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 3600);
}

/// (a2) After rotation, the old row's rotated_to_hash must be set in the DB.
#[tokio::test]
async fn refresh_grant_marks_old_token_rotated() {
    let (app, meta, _dir) = spin_up().await;
    let rt = insert_refresh(&meta, None, false).await;
    let old_hash = sha256_b64(&rt);

    let body = format!("grant_type=refresh_token&refresh_token={rt}");
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify the old row now has rotated_to_hash set.
    let rotated_to_hash: Option<String> = {
        let conn = meta.lock().await;
        conn.query_row(
            "SELECT rotated_to_hash FROM _oauth_refresh_tokens WHERE token_hash = ?1",
            params![old_hash],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert!(
        rotated_to_hash.is_some(),
        "old refresh token should have rotated_to_hash set after rotation"
    );
}

/// (b) Reuse detection: presenting an already-rotated token → 400 + chain revoked.
#[tokio::test]
async fn refresh_grant_reuse_detection_revokes_chain() {
    let (app, meta, _dir) = spin_up().await;
    // Insert a token that has already been rotated (rotated_to_hash is set).
    let sentinel_hash = sha256_b64("drust_rt_already_rotated_target");
    let rt = insert_refresh(&meta, Some(&sentinel_hash), false).await;
    // Also insert an access token so we can assert it gets deleted.
    insert_access(&meta).await;

    let body = format!("grant_type=refresh_token&refresh_token={rt}");
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_grant");
    let desc = json["error_description"].as_str().unwrap_or("");
    assert!(
        desc.contains("reuse") || desc.contains("revoked"),
        "error_description should mention reuse/revoke, got: {desc}"
    );

    // All access tokens for this client_id + admin_id must be gone.
    let access_count: i64 = {
        let conn = meta.lock().await;
        conn.query_row(
            "SELECT count(*) FROM _oauth_access_tokens WHERE client_id = ?1 AND admin_id = 1",
            params![CLIENT_ID],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        access_count, 0,
        "all access tokens should be revoked after reuse detection"
    );

    // All refresh tokens for this client_id + admin_id must be gone.
    let refresh_count: i64 = {
        let conn = meta.lock().await;
        conn.query_row(
            "SELECT count(*) FROM _oauth_refresh_tokens WHERE client_id = ?1 AND admin_id = 1",
            params![CLIENT_ID],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        refresh_count, 0,
        "all refresh tokens should be revoked after reuse detection"
    );
}

/// (c) Unknown refresh token → 400 invalid_grant.
#[tokio::test]
async fn refresh_grant_unknown_token_returns_invalid_grant() {
    let (app, _meta, _dir) = spin_up().await;
    let body = "grant_type=refresh_token&refresh_token=drust_rt_completelyunknown";
    let resp = app.oneshot(token_request(body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

/// (d) Missing refresh_token → 400 invalid_request.
#[tokio::test]
async fn refresh_grant_missing_token_returns_invalid_request() {
    let (app, _meta, _dir) = spin_up().await;
    let body = "grant_type=refresh_token";
    let resp = app.oneshot(token_request(body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_request");
}

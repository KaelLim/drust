//! Integration tests: POST /oauth/token — authorization_code grant.
//!
//! Covers:
//!   (a) Happy path → 200 with access_token + refresh_token
//!   (b) PKCE verifier mismatch → 400 invalid_grant
//!   (c) Code consumed twice → 400 invalid_grant
//!   (d) Expired code → 400 invalid_grant
//!   (e) client_id mismatch → 400 invalid_grant
//!
//! RFC 7636 test vectors used throughout:
//!   verifier   = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
//!   challenge  = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
//!
//! v1.29.0 — Task 15.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::db::migrations::{
    SQL_CREATE_OAUTH_ACCESS_TOKENS_IF_NOT_EXISTS, SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS,
    SQL_CREATE_OAUTH_CODES_IF_NOT_EXISTS, SQL_CREATE_OAUTH_REFRESH_TOKENS_IF_NOT_EXISTS,
};
use drust::mgmt::oauth_server::storage::sha256_b64;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── RFC 7636 constants ───────────────────────────────────────────────────────

const PKCE_VERIFIER:   &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE:  &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_ID:       &str = "drust_client_tokentest001";
const REDIRECT_URI:    &str = "http://localhost:55555/callback";
const RESOURCE_URI:    &str = "https://tool.tzuchi-org.tw/drust/t/some-tenant/mcp";

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

/// Set up a router with one admin row + one OAuth client.
/// Returns (router, conn_for_inserts_already_consumed, dir).
/// Caller inserts their own code row into `_oauth_authorization_codes`.
async fn spin_up() -> (axum::Router, Arc<Mutex<rusqlite::Connection>>, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    conn.execute_batch(SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS).unwrap();
    conn.execute_batch(SQL_CREATE_OAUTH_CODES_IF_NOT_EXISTS).unwrap();
    conn.execute_batch(SQL_CREATE_OAUTH_ACCESS_TOKENS_IF_NOT_EXISTS).unwrap();
    conn.execute_batch(SQL_CREATE_OAUTH_REFRESH_TOKENS_IF_NOT_EXISTS).unwrap();

    conn.execute(
        "INSERT OR IGNORE INTO _oauth_clients (id, client_name, redirect_uris_json)
         VALUES (?1, 'TestApp', ?2)",
        params![CLIENT_ID, format!(r#"["{REDIRECT_URI}"]"#)],
    )
    .unwrap();

    let state = build_state(conn, data_dir.clone(), log_dir);
    let meta = state.meta.clone();
    let router = state.with_data_dir(data_dir);
    (router, meta, dir)
}

/// Insert a valid fresh auth code into the DB.
/// Returns the plaintext code string.
async fn insert_code(
    meta: &Arc<Mutex<rusqlite::Connection>>,
    consumed: bool,
    expired: bool,
    client_override: Option<&str>,
) -> String {
    use drust::mgmt::oauth_server::storage::new_auth_code;
    let code = new_auth_code();
    let code_hash = sha256_b64(&code);
    let client = client_override.unwrap_or(CLIENT_ID);
    let expires_at = if expired {
        // 10 minutes in the past
        (chrono::Utc::now() - chrono::Duration::minutes(10))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    } else {
        (chrono::Utc::now() + chrono::Duration::minutes(10))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    };
    let consumed_at: Option<String> = if consumed {
        Some(
            chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
        )
    } else {
        None
    };

    let conn = meta.lock().await;
    conn.execute(
        "INSERT INTO _oauth_authorization_codes
            (code_hash, client_id, admin_id, redirect_uri, pkce_challenge, pkce_challenge_method,
             resource_uri, scope, expires_at, consumed_at)
         VALUES (?1, ?2, 1, ?3, ?4, 'S256', ?5, 'drust', ?6, ?7)",
        params![
            code_hash,
            client,
            REDIRECT_URI,
            PKCE_CHALLENGE,
            RESOURCE_URI,
            expires_at,
            consumed_at,
        ],
    )
    .unwrap();
    code
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

/// (a) Happy path: valid code + PKCE verifier → 200 with access + refresh tokens.
#[tokio::test]
async fn code_grant_happy_path_returns_tokens() {
    let (app, meta, _dir) = spin_up().await;
    let code = insert_code(&meta, false, false, None).await;

    let body = format!(
        "grant_type=authorization_code\
         &code={code}\
         &code_verifier={PKCE_VERIFIER}\
         &client_id={CLIENT_ID}\
         &redirect_uri={redir}",
        redir = urlencoding::encode(REDIRECT_URI),
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let at = json["access_token"].as_str().unwrap();
    let rt = json["refresh_token"].as_str().unwrap();
    assert!(at.starts_with("drust_at_"), "access_token prefix, got: {at}");
    assert!(rt.starts_with("drust_rt_"), "refresh_token prefix, got: {rt}");
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 3600);
}

/// (b) PKCE verifier mismatch → 400 invalid_grant.
#[tokio::test]
async fn code_grant_pkce_mismatch_returns_invalid_grant() {
    let (app, meta, _dir) = spin_up().await;
    let code = insert_code(&meta, false, false, None).await;

    let body = format!(
        "grant_type=authorization_code\
         &code={code}\
         &code_verifier=WRONGVERIFIER\
         &client_id={CLIENT_ID}\
         &redirect_uri={redir}",
        redir = urlencoding::encode(REDIRECT_URI),
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

/// (c) Code consumed twice → first succeeds, second → 400 invalid_grant.
#[tokio::test]
async fn code_grant_second_use_returns_invalid_grant() {
    let (app, meta, _dir) = spin_up().await;
    let code = insert_code(&meta, false, false, None).await;

    let body = format!(
        "grant_type=authorization_code\
         &code={code}\
         &code_verifier={PKCE_VERIFIER}\
         &client_id={CLIENT_ID}\
         &redirect_uri={redir}",
        redir = urlencoding::encode(REDIRECT_URI),
    );

    // First use — must succeed.
    let resp1 = app
        .clone()
        .oneshot(token_request(&body))
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Second use — must be invalid_grant.
    let resp2 = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp2.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_grant");
    let desc = json["error_description"].as_str().unwrap_or("");
    assert!(
        desc.contains("already used") || desc.contains("unknown"),
        "error_description should indicate code is consumed, got: {desc}"
    );
}

/// (d) Expired code → 400 invalid_grant.
#[tokio::test]
async fn code_grant_expired_code_returns_invalid_grant() {
    let (app, meta, _dir) = spin_up().await;
    let code = insert_code(&meta, false, true /* expired */, None).await;

    let body = format!(
        "grant_type=authorization_code\
         &code={code}\
         &code_verifier={PKCE_VERIFIER}\
         &client_id={CLIENT_ID}\
         &redirect_uri={redir}",
        redir = urlencoding::encode(REDIRECT_URI),
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_grant");
    let desc = json["error_description"].as_str().unwrap_or("");
    assert!(
        desc.contains("expired"),
        "error_description should mention expired, got: {desc}"
    );
}

/// (e) client_id mismatch → 400 invalid_grant.
#[tokio::test]
async fn code_grant_client_id_mismatch_returns_invalid_grant() {
    let (app, meta, _dir) = spin_up().await;
    // Insert a second client so the FK constraint passes on the code row.
    {
        let conn = meta.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO _oauth_clients (id, client_name, redirect_uris_json)
             VALUES ('drust_client_other999', 'Other', '[]')",
            [],
        )
        .unwrap();
    }
    // Code belongs to CLIENT_ID, but we'll claim drust_client_other999 in the request.
    let code = insert_code(&meta, false, false, None).await;

    let body = format!(
        "grant_type=authorization_code\
         &code={code}\
         &code_verifier={PKCE_VERIFIER}\
         &client_id=drust_client_other999\
         &redirect_uri={redir}",
        redir = urlencoding::encode(REDIRECT_URI),
    );
    let resp = app.oneshot(token_request(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "invalid_grant");
    let desc = json["error_description"].as_str().unwrap_or("");
    assert!(
        desc.contains("client_id") || desc.contains("mismatch"),
        "error_description should mention client_id mismatch, got: {desc}"
    );
}

/// (f) Missing grant_type → 400 unsupported_grant_type.
#[tokio::test]
async fn missing_grant_type_returns_unsupported() {
    let (app, _meta, _dir) = spin_up().await;
    let body = "grant_type=password&username=foo&password=bar";
    let resp = app.oneshot(token_request(body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"], "unsupported_grant_type");
}

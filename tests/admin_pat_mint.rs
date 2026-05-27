//! Integration tests: PAT self-service mint/list/revoke via /admin/settings/tokens.
//!
//! Covers:
//!   1. Mint → list (plaintext gone) → revoke round-trip.
//!   2. Duplicate name rejected with 409 TOKEN_NAME_TAKEN.
//!   3. Admin cannot revoke another admin's token (404 TOKEN_NOT_FOUND).
//!
//! v1.29.0 — Task 8.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
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
    }
}

/// Spin up a mgmt router with one bootstrapped owner admin (username "root",
/// pw "hunter2"). Returns `(router, dir)`.
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

/// Insert an additional admin with a given email and role directly into the DB.
/// Returns (admin_id, session_cookie_string).
fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    )
    .unwrap();
    let admin_id = conn.last_insert_rowid();
    let session_token = {
        use base64::Engine;
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
    conn.execute(
        "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![session_token, admin_id, expires_at.to_rfc3339()],
    )
    .unwrap();
    (admin_id, format!("drust_session={session_token}"))
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mint_list_revoke_pat_round_trip() {
    let (app, dir) = spin_up().await;
    let (_admin_id, session) = insert_admin(&dir, "kael@x", "member");

    // Mint
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/tokens")
                .header(header::COOKIE, &session)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"laptop"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "mint should return 201");
    let body = body_json(resp).await;
    let plaintext = body["plaintext_token"].as_str().expect("must have plaintext_token").to_string();
    assert!(plaintext.starts_with("drust_pat_"), "token must start with drust_pat_");
    let token_id = body["id"].as_i64().expect("must have id");

    // List — plaintext must not appear
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/settings/tokens")
                .header(header::COOKIE, &session)
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let tokens = body["tokens"].as_array().expect("must have tokens array");
    assert_eq!(tokens.len(), 1, "exactly one token in list");
    assert_eq!(tokens[0]["name"], "laptop", "token name must match");
    assert!(
        tokens[0].get("plaintext_token").is_none(),
        "plaintext_token must NOT appear in list responses"
    );

    // Revoke
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/settings/tokens/{token_id}"))
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "revoke should return 200");
    let body = body_json(resp).await;
    assert_eq!(body["revoked"], true);

    // List again — should be empty
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/settings/tokens")
                .header(header::COOKIE, &session)
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let tokens = body["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 0, "list should be empty after revoke");
}

#[tokio::test]
async fn duplicate_name_rejected() {
    let (app, dir) = spin_up().await;
    let (_id, session) = insert_admin(&dir, "k@x", "member");

    // First mint succeeds
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/tokens")
                .header(header::COOKIE, &session)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "first mint should succeed");

    // Second mint with same name → 409
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/tokens")
                .header(header::COOKIE, &session)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "duplicate name must return 409");
    let body = body_json(resp).await;
    assert_eq!(
        body["error_code"], "TOKEN_NAME_TAKEN",
        "error_code must be TOKEN_NAME_TAKEN"
    );
}

#[tokio::test]
async fn admin_cannot_revoke_other_admin_token() {
    let (app, dir) = spin_up().await;
    let (_alice_id, alice_session) = insert_admin(&dir, "alice@x", "member");
    let (_bob_id, bob_session) = insert_admin(&dir, "bob@x", "member");

    // Alice mints a token
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/tokens")
                .header(header::COOKIE, &alice_session)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"a"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let token_id = body["id"].as_i64().expect("must have id");

    // Bob tries to revoke Alice's token → 404 (not 403, avoids id-enumeration)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/settings/tokens/{token_id}"))
                .header(header::COOKIE, &bob_session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "cross-admin revoke must return 404");
    let body = body_json(resp).await;
    assert_eq!(
        body["error_code"], "TOKEN_NOT_FOUND",
        "error_code must be TOKEN_NOT_FOUND"
    );

    // Bob's own token list should be empty (Alice's token not visible)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/settings/tokens")
                .header(header::COOKIE, &bob_session)
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(
        body["tokens"].as_array().unwrap().len(),
        0,
        "Bob should not see Alice's tokens"
    );
}

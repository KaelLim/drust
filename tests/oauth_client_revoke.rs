//! Integration tests: Owner-only /admin/oauth/clients list + revoke.
//!
//! v1.29.0 — Task 19.

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

/// Insert an admin with given role directly. Returns (admin_id, session_cookie).
fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    ).unwrap();
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
    ).unwrap();
    (admin_id, format!("drust_session={session_token}"))
}

/// Register an OAuth client via POST /oauth/register. Returns client_id.
async fn register_client(app: &axum::Router, name: &str, redirect_uris: &[&str]) -> String {
    let uris_json = serde_json::json!(redirect_uris);
    let body = serde_json::json!({
        "client_name": name,
        "redirect_uris": uris_json,
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "register failed");
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["client_id"].as_str().unwrap().to_string()
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn owner_revokes_client_kills_all_its_tokens() {
    let (app, dir) = spin_up().await;
    // Insert an owner admin and get a session cookie
    let (owner_id, session) = insert_admin(&dir, "k@x.com", "owner");
    let client_id = register_client(&app, "Claude", &["http://localhost/cb"]).await;

    // Issue an access token directly into the DB
    let token = drust::mgmt::oauth_server::storage::new_access_token();
    let token_hash = drust::mgmt::oauth_server::storage::sha256_b64(&token);
    {
        let meta_path = dir.path().join("meta.sqlite");
        let conn = rusqlite::Connection::open(&meta_path).unwrap();
        conn.execute(
            "INSERT INTO _oauth_access_tokens (token_hash, client_id, admin_id, resource_uri, expires_at)
             VALUES (?1, ?2, ?3, 'https://x/t/a/mcp', datetime('now', '+1 hour'))",
            params![&token_hash, &client_id, owner_id],
        ).unwrap();
    }

    // Revoke via DELETE /admin/oauth/clients/{client_id}
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/oauth/clients/{client_id}"))
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["revoked"], true);

    // Verify access token was hard-deleted
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _oauth_access_tokens WHERE client_id = ?1",
            params![&client_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "access token should be hard-deleted");

    // Verify client was soft-revoked
    let revoked_at: Option<String> = conn
        .query_row(
            "SELECT revoked_at FROM _oauth_clients WHERE id = ?1",
            params![&client_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(revoked_at.is_some(), "client should be soft-revoked");
}

#[tokio::test]
async fn member_cannot_revoke_client() {
    let (app, dir) = spin_up().await;
    let (_, member_session) = insert_admin(&dir, "m@x.com", "member");
    let client_id = register_client(&app, "X", &["http://localhost/cb"]).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/oauth/clients/{client_id}"))
                .header(header::COOKIE, &member_session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["error_code"], "NOT_OWNER");
}

#[tokio::test]
async fn owner_can_list_clients() {
    let (app, dir) = spin_up().await;
    let (_, session) = insert_admin(&dir, "k@x.com", "owner");
    let _ = register_client(&app, "c1", &["http://localhost/cb"]).await;
    let _ = register_client(&app, "c2", &["http://localhost/cb"]).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/clients")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let clients = body["clients"].as_array().unwrap();
    assert!(clients.len() >= 2, "should list at least 2 clients, got {}", clients.len());
}

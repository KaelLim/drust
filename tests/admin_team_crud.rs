//! End-to-end CRUD tests for /admin/team — list, invite, promote, demote, remove.
//!
//! v1.29.0 — Task 6.

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

/// Spin up a mgmt router with one bootstrapped owner admin (username "root",
/// pw "hunter2"). Returns `(router, dir)`.
async fn spin_up() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    // run_migrations ensures role column exists and backfills existing admin to owner
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    let router = state.with_data_dir(data_dir);
    (router, dir)
}

/// Insert an additional admin with a given email and role directly into the DB.
/// The admin has no password (OAuth-only sentinel) — they log in via a session
/// we create directly with `create_session`.
fn insert_admin(
    dir: &tempfile::TempDir,
    email: &str,
    role: &str,
) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    ).unwrap();
    let admin_id = conn.last_insert_rowid();
    // Create a session token for this admin directly.
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

/// Log in via the form endpoint and return the session cookie value string.
async fn login(app: &axum::Router, username: &str, password: &str) -> String {
    let form = format!("username={username}&password={password}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login failed");
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("no Set-Cookie on login")
        .to_str()
        .unwrap();
    // Extract just "drust_session=<token>" (first attribute before ';')
    sc.split(';').next().unwrap().to_string()
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ─── CRUD tests ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn owner_can_invite_admin() {
    let (app, _dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/team")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": "alice@example.com", "role": "member" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "invite should return 201");
    let body = body_json(resp).await;
    assert!(body["id"].as_i64().is_some(), "response should include new admin id");
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["role"], "member");
}

#[tokio::test]
async fn owner_can_list_admins() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;
    // Insert a second admin directly
    let _ = insert_admin(&dir, "bob@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/team")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let admins = body["admins"].as_array().expect("should have admins array");
    assert_eq!(admins.len(), 2, "should list both admins");
}

#[tokio::test]
async fn owner_can_promote_member_to_owner() {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/team/{alice_id}/role"))
                .header(header::COOKIE, &owner_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "role": "owner" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "promote should return 200");
    let body = body_json(resp).await;
    assert_eq!(body["role"], "owner");
}

#[tokio::test]
async fn owner_can_demote_owner_when_another_exists() {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice@example.com", "owner");

    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/team/{alice_id}/role"))
                .header(header::COOKIE, &owner_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "role": "member" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "demote with another owner should succeed");
}

#[tokio::test]
async fn owner_can_remove_member() {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/team/{alice_id}"))
                .header(header::COOKIE, &owner_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "remove should return 200");
    let body = body_json(resp).await;
    assert_eq!(body["removed"], true);
}

#[tokio::test]
async fn member_cannot_invite() {
    let (app, dir) = spin_up().await;
    let (_, member_cookie) = insert_admin(&dir, "alice@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/team")
                .header(header::COOKIE, &member_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": "bob@example.com", "role": "member" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "member must get 403");
    let body = body_json(resp).await;
    assert_eq!(body["error_code"], "NOT_OWNER");
}

#[tokio::test]
async fn member_cannot_remove() {
    let (app, dir) = spin_up().await;
    let (owner_id, _) = {
        // get the root owner's id
        let meta_path = dir.path().join("meta.sqlite");
        let conn = rusqlite::Connection::open(&meta_path).unwrap();
        let id: i64 = conn
            .query_row("SELECT id FROM admins WHERE username = 'root'", [], |r| r.get(0))
            .unwrap();
        (id, ())
    };
    let (_, member_cookie) = insert_admin(&dir, "alice@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/team/{owner_id}"))
                .header(header::COOKIE, &member_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "member must get 403");
    let body = body_json(resp).await;
    assert_eq!(body["error_code"], "NOT_OWNER");
}

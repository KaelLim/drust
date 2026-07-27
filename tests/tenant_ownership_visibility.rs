//! v1.50 Task 4 — admin tenant listings are ownership-scoped: an owner admin
//! sees every tenant (incl. NULL-owner orphans); a member admin sees only the
//! tenants they own, across all three list surfaces (`/admin/api/tenants`,
//! the `/admin/tenants` HTML page, and the cmd-K palette JSON).

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

fn build_state(conn: rusqlite::Connection, data_dir: PathBuf, log_dir: PathBuf) -> MgmtState {
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir,
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = log_dir;
    state
}

/// Mgmt router with one bootstrapped owner admin ("root"/"hunter2", id 1).
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
    sc.split(';').next().unwrap().to_string()
}

/// Insert a second admin directly (OAuth-only sentinel, no password) and mint
/// a session for them — same pattern as tests/tenant_ownership_create.rs.
fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) \
         VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    )
    .unwrap();
    let admin_id = conn.last_insert_rowid();
    let session_token = {
        use base64::Engine;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
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

async fn create_tenant_json(app: &axum::Router, cookie: &str, id: &str, name: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"id": id, "name": name}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "create {id} failed");
}

/// Seed: owner root (id 1) owns t-owner-a; member (id 2) owns t-member-b;
/// t-orphan-c has owner_admin_id NULL (direct meta insert). Returns
/// (app, dir, owner_cookie, member_cookie).
async fn seed_three_tenants() -> (axum::Router, tempfile::TempDir, String, String) {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (_member_id, member_cookie) = insert_admin(&dir, "alice@example.com", "member");
    create_tenant_json(&app, &owner_cookie, "t-owner-a", "AlphaCorp").await;
    create_tenant_json(&app, &member_cookie, "t-member-b", "BetaCorp").await;
    // Orphan tenant: no owner. Direct meta insert (listing reads meta only).
    {
        let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES ('t-orphan-c', 'GammaCorp')",
            [],
        )
        .unwrap();
    }
    (app, dir, owner_cookie, member_cookie)
}

async fn get_body(app: &axum::Router, cookie: &str, uri: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn json_ids(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v.as_array()
        .expect("array")
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect()
}

// ─── /admin/api/tenants (tenants_json) ───────────────────────────────────────

#[tokio::test]
async fn owner_api_json_lists_all_tenants() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &owner_cookie, "/admin/api/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    assert_eq!(
        ids,
        vec!["t-member-b", "t-orphan-c", "t-owner-a"],
        "owner must see owned, foreign, and orphan tenants"
    );
}

#[tokio::test]
async fn member_api_json_lists_only_owned() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &member_cookie, "/admin/api/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    assert_eq!(
        ids,
        vec!["t-member-b"],
        "member must see only the tenants they own"
    );
}

// ─── /admin/tenants (list_page_axum HTML) ────────────────────────────────────

#[tokio::test]
async fn owner_list_page_shows_all_tenants() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &owner_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("t-owner-a"), "owner page must list t-owner-a");
    assert!(
        html.contains("t-member-b"),
        "owner page must list t-member-b"
    );
    assert!(
        html.contains("t-orphan-c"),
        "owner page must list t-orphan-c"
    );
}

#[tokio::test]
async fn member_list_page_hides_foreign_tenants() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &member_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("t-member-b"),
        "member page must list their own tenant"
    );
    assert!(
        !html.contains("t-owner-a"),
        "member page must not leak a foreign tenant id"
    );
    assert!(
        !html.contains("t-orphan-c"),
        "member page must not leak an orphan tenant id"
    );
}

// ─── /admin/api/cmdk/tenants (cmdk_tenants_json) ─────────────────────────────

#[tokio::test]
async fn owner_cmdk_lists_all_tenants() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &owner_cookie, "/admin/api/cmdk/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    // cmdk sorts by name COLLATE NOCASE: Alpha, Beta, Gamma.
    assert_eq!(ids, vec!["t-owner-a", "t-member-b", "t-orphan-c"]);
}

#[tokio::test]
async fn member_cmdk_lists_only_owned() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &member_cookie, "/admin/api/cmdk/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    assert_eq!(
        ids,
        vec!["t-member-b"],
        "cmdk must be ownership-scoped for member admins"
    );
}

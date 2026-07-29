//! v1.57 — the host-wide files surface (`/admin/files*`) is owner-only.
//!
//! `public_files_router` is host-scoped: it lists/uploads/deletes objects in
//! the shared `public`/`private` buckets, and `/admin/files/reconcile` renders
//! tenant ids + names for every pending revoke / orphan bucket on the host.
//! It has no `{id}` param, so `tenant_ownership_layer` passes it through — the
//! same shape as backups, quota-review and metrics, which all carry
//! `require_owner_layer`. Without the guard a `member` (or the v1.57 `admin`)
//! role could enumerate every tenant from the reconcile page, defeating the
//! v1.50 visibility boundary. Regression-pinned here.

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
    resp.headers()
        .get(header::SET_COOKIE)
        .expect("no Set-Cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// Insert an admin row with the given role and mint a live session cookie for
/// it (mirrors `tests/tenant_ownership_hostwide.rs::insert_member`, widened to
/// take the role so the 3-tier matrix can be exercised).
fn insert_admin_session(dir: &tempfile::TempDir, email: &str, role: &str) -> String {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    let username = email.split('@').next().unwrap().to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) \
         VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    )
    .unwrap();
    let admin_id = conn.last_insert_rowid();
    let token = {
        use base64::Engine;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let exp = chrono::Utc::now() + chrono::Duration::days(7);
    conn.execute(
        "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token, admin_id, exp.to_rfc3339()],
    )
    .unwrap();
    format!("drust_session={token}")
}

async fn get_status(app: &axum::Router, cookie: &str, uri: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn post_status(app: &axum::Router, cookie: &str, uri: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn body_of(app: &axum::Router, cookie: &str, uri: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

#[tokio::test]
async fn member_admin_is_forbidden_on_host_files() {
    let (app, dir) = spin_up().await;
    let member = insert_admin_session(&dir, "member@example.com", "member");

    assert_eq!(
        get_status(&app, &member, "/admin/files").await,
        StatusCode::FORBIDDEN,
        "member must get 403 on GET /admin/files"
    );
    assert_eq!(
        get_status(&app, &member, "/admin/files/reconcile").await,
        StatusCode::FORBIDDEN,
        "member must get 403 on GET /admin/files/reconcile"
    );
    assert_eq!(
        post_status(&app, &member, "/admin/files/reconcile").await,
        StatusCode::FORBIDDEN,
        "member must get 403 on POST /admin/files/reconcile"
    );
}

#[tokio::test]
async fn admin_role_is_forbidden_on_host_files() {
    // Host-wide sensitive surfaces stay OWNER-only in the 3-tier model — the
    // middle `admin` tier sees every tenant but never backups/audit/metrics,
    // and reconcile is the same class of cross-tenant disclosure.
    let (app, dir) = spin_up().await;
    let mid = insert_admin_session(&dir, "mid@example.com", "admin");

    assert_eq!(
        get_status(&app, &mid, "/admin/files").await,
        StatusCode::FORBIDDEN,
        "admin-role must get 403 on GET /admin/files"
    );
    assert_eq!(
        get_status(&app, &mid, "/admin/files/reconcile").await,
        StatusCode::FORBIDDEN,
        "admin-role must get 403 on GET /admin/files/reconcile"
    );
    assert_eq!(
        post_status(&app, &mid, "/admin/files/reconcile").await,
        StatusCode::FORBIDDEN,
        "admin-role must get 403 on POST /admin/files/reconcile"
    );
}

#[tokio::test]
async fn owner_admin_reaches_host_files() {
    let (app, _dir) = spin_up().await;
    let owner = login(&app, "root", "hunter2").await;
    // Storage may be unconfigured in the test env (503) — the assertion is
    // only that the owner is never blocked by the role guard.
    let st = get_status(&app, &owner, "/admin/files").await;
    assert_ne!(
        st,
        StatusCode::FORBIDDEN,
        "owner must NOT be forbidden on /admin/files (got {st})"
    );
}

#[tokio::test]
async fn host_files_nav_hidden_from_member_shown_to_owner() {
    let (app, dir) = spin_up().await;
    let member = insert_admin_session(&dir, "navmember@example.com", "member");
    let owner = login(&app, "root", "hunter2").await;

    let member_html = body_of(&app, &member, "/admin/tenants").await;
    assert!(
        !member_html.contains("/admin/files"),
        "member sidebar must not link to the host files surface"
    );

    let owner_html = body_of(&app, &owner, "/admin/tenants").await;
    assert!(
        owner_html.contains("/admin/files"),
        "owner sidebar must still link to the host files surface"
    );
}

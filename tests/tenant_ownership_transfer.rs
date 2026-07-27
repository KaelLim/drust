//! v1.50 Task 7 — owner-only ownership transfer + orphan-on-remove.
//!
//! `PATCH /admin/tenants/{id}/owner` (+ `/admin/api/tenants/{id}/owner` twin)
//! reassigns `tenants.owner_admin_id` (i64 or null = orphan). Owner-only
//! (member → 403 NOT_OWNER); transfer to a nonexistent admin → 400; success
//! evicts BOTH the old and the new owner's PAT entries from the auth cache.
//! Removing an admin (`DELETE /admin/team/{id}`) orphans their tenants via
//! the `owner_admin_id … ON DELETE SET NULL` FK — pinned here against the
//! real meta connection to prove `PRAGMA foreign_keys` is live.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
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
/// Also returns the shared auth-cache handle so tests can observe evictions.
async fn spin_up() -> (axum::Router, tempfile::TempDir, Arc<AuthCache>) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    let cache = state.auth_cache.clone();
    let router = state.with_data_dir(data_dir);
    (router, dir, cache)
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
/// a session for them — same pattern as tests/tenant_ownership_visibility.rs.
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

/// Direct meta read of `tenants.owner_admin_id` for `tenant_id`.
fn owner_of(dir: &tempfile::TempDir, tenant_id: &str) -> Option<i64> {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row(
        "SELECT owner_admin_id FROM tenants WHERE id = ?1",
        params![tenant_id],
        |r| r.get(0),
    )
    .unwrap()
}

/// PATCH the ownership transfer endpoint. `uri` picks the page or API twin.
async fn patch_owner(
    app: &axum::Router,
    cookie: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
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

async fn get_status(app: &axum::Router, cookie: &str, uri: &str) -> StatusCode {
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
    resp.status()
}

/// Seed: root owner (id 1) + two member admins; member2 owns t-b.
/// Returns (app, dir, cache, owner_cookie, (m2_id, m2_cookie), (m3_id, m3_cookie)).
#[allow(clippy::type_complexity)]
async fn seed_transfer_fixture() -> (
    axum::Router,
    tempfile::TempDir,
    Arc<AuthCache>,
    String,
    (i64, String),
    (i64, String),
) {
    let (app, dir, cache) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (m2_id, m2_cookie) = insert_admin(&dir, "alice@example.com", "member");
    let (m3_id, m3_cookie) = insert_admin(&dir, "bob@example.com", "member");
    create_tenant_json(&app, &m2_cookie, "t-b", "BetaCorp").await;
    assert_eq!(owner_of(&dir, "t-b"), Some(m2_id), "seed: m2 owns t-b");
    (
        app,
        dir,
        cache,
        owner_cookie,
        (m2_id, m2_cookie),
        (m3_id, m3_cookie),
    )
}

// ─── owner transfers: visibility follows the new owner ───────────────────────

#[tokio::test]
async fn owner_transfer_moves_visibility_to_new_owner() {
    let (app, dir, _cache, owner_cookie, (_m2_id, m2_cookie), (m3_id, m3_cookie)) =
        seed_transfer_fixture().await;

    // Pre-transfer: m2 sees the tenant, m3 does not.
    assert_eq!(
        get_status(&app, &m2_cookie, "/admin/tenants/t-b/_overview").await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(&app, &m3_cookie, "/admin/tenants/t-b/_overview").await,
        StatusCode::NOT_FOUND
    );

    // Owner transfers m2 → m3 via the API twin.
    let (status, body) = patch_owner(
        &app,
        &owner_cookie,
        "/admin/api/tenants/t-b/owner",
        serde_json::json!({"owner_admin_id": m3_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "transfer failed: {body}");
    assert_eq!(owner_of(&dir, "t-b"), Some(m3_id));

    // Post-transfer: m3 sees it, m2 gets the canonical 404.
    assert_eq!(
        get_status(&app, &m3_cookie, "/admin/tenants/t-b/_overview").await,
        StatusCode::OK,
        "new owner must see the tenant"
    );
    assert_eq!(
        get_status(&app, &m2_cookie, "/admin/tenants/t-b/_overview").await,
        StatusCode::NOT_FOUND,
        "old owner must lose visibility"
    );
}

#[tokio::test]
async fn owner_transfer_to_null_orphans_tenant() {
    let (app, dir, _cache, owner_cookie, (_m2_id, m2_cookie), _) = seed_transfer_fixture().await;
    let (status, body) = patch_owner(
        &app,
        &owner_cookie,
        "/admin/tenants/t-b/owner",
        serde_json::json!({"owner_admin_id": null}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "orphan transfer failed: {body}");
    assert_eq!(owner_of(&dir, "t-b"), None, "null target must orphan");
    // Orphans are owner-only: the ex-owner member 404s, the owner still sees it.
    assert_eq!(
        get_status(&app, &m2_cookie, "/admin/tenants/t-b/_overview").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get_status(&app, &owner_cookie, "/admin/tenants/t-b/_overview").await,
        StatusCode::OK
    );
}

// ─── member cannot transfer (owner_guard) ────────────────────────────────────

#[tokio::test]
async fn member_transfer_is_403_on_owned_tenant() {
    let (app, dir, _cache, _owner_cookie, (m2_id, m2_cookie), (m3_id, _)) =
        seed_transfer_fixture().await;
    // m2 owns t-b, so the route guard passes — the handler's owner_guard denies.
    let (status, body) = patch_owner(
        &app,
        &m2_cookie,
        "/admin/tenants/t-b/owner",
        serde_json::json!({"owner_admin_id": m3_id}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "member transfer: {body}");
    assert!(body.contains("NOT_OWNER"), "expected NOT_OWNER, got {body}");
    assert_eq!(owner_of(&dir, "t-b"), Some(m2_id), "no mutation on deny");
}

#[tokio::test]
async fn member_transfer_is_404_on_foreign_tenant() {
    let (app, _dir, _cache, owner_cookie, _, (m3_id, m3_cookie)) = seed_transfer_fixture().await;
    create_tenant_json(&app, &owner_cookie, "t-a", "AlphaCorp").await;
    // m3 does not own t-a: the route guard 404s (no existence leak).
    let (status, body) = patch_owner(
        &app,
        &m3_cookie,
        "/admin/tenants/t-a/owner",
        serde_json::json!({"owner_admin_id": m3_id}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("no such tenant"), "got {body}");
}

// ─── bad targets ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn transfer_to_missing_admin_is_400() {
    let (app, dir, _cache, owner_cookie, (m2_id, _), _) = seed_transfer_fixture().await;
    let (status, body) = patch_owner(
        &app,
        &owner_cookie,
        "/admin/api/tenants/t-b/owner",
        serde_json::json!({"owner_admin_id": 9999}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    assert!(
        body.contains("ADMIN_NOT_FOUND"),
        "expected ADMIN_NOT_FOUND, got {body}"
    );
    assert_eq!(owner_of(&dir, "t-b"), Some(m2_id), "no mutation on 400");
}

#[tokio::test]
async fn transfer_on_missing_tenant_is_404() {
    let (app, _dir, _cache, owner_cookie, _, _) = seed_transfer_fixture().await;
    let (status, body) = patch_owner(
        &app,
        &owner_cookie,
        "/admin/tenants/t-nope/owner",
        serde_json::json!({"owner_admin_id": null}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("no such tenant"), "got {body}");
}

// ─── auth-cache eviction on transfer ─────────────────────────────────────────

fn pat_entry(tenant: &str, admin_id: i64) -> CachedAuth {
    CachedAuth::Bearer {
        bound_tenant_id: tenant.to_string(),
        role: CachedRole::AdminPat { admin_id },
        publish_user_allowed: false,
        publish_anon_allowed: false,
        email_snapshot: None,
        file_caps: Default::default(),
        expires_at: None,
        quota_tier: 1,
    }
}

#[tokio::test]
async fn transfer_evicts_old_and_new_owner_pat_cache_entries() {
    let (app, _dir, cache, owner_cookie, (m2_id, _), (m3_id, _)) = seed_transfer_fixture().await;
    // Warm the cache: one PAT entry each for the old owner (m2), the new
    // owner (m3), and an unrelated admin (root, id 1) as the control.
    cache.insert("h-old".to_string(), pat_entry("t-b", m2_id));
    cache.insert("h-new".to_string(), pat_entry("t-x", m3_id));
    cache.insert("h-ctl".to_string(), pat_entry("t-y", 1));

    let (status, body) = patch_owner(
        &app,
        &owner_cookie,
        "/admin/api/tenants/t-b/owner",
        serde_json::json!({"owner_admin_id": m3_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "transfer failed: {body}");

    assert!(
        cache.get("h-old").is_none(),
        "old owner's PAT entry must be evicted"
    );
    assert!(
        cache.get("h-new").is_none(),
        "new owner's PAT entry must be evicted"
    );
    assert!(
        cache.get("h-ctl").is_some(),
        "unrelated admin's PAT entry must survive"
    );
}

// ─── orphan-on-remove: FK ON DELETE SET NULL through the real meta conn ──────

#[tokio::test]
async fn remove_admin_orphans_their_tenants() {
    let (app, dir, _cache, owner_cookie, (m2_id, _), _) = seed_transfer_fixture().await;
    // Remove m2 through the real admin-team route — the DELETE runs on the
    // app's meta connection, so this pins BOTH the FK shape (ON DELETE SET
    // NULL) and that `PRAGMA foreign_keys` is live on that connection.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/team/{m2_id}"))
                .header(header::COOKIE, &owner_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "remove_admin failed");
    assert_eq!(
        owner_of(&dir, "t-b"),
        None,
        "removed admin's tenant must be orphaned (owner_admin_id SET NULL)"
    );
}

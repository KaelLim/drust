//! v1.50 Task 6 — route-layer ownership guard (`tenant_ownership_layer`).
//!
//! The guard is mounted on the two tenant-scoped admin sub-routers
//! (`tenants_router` + `admin_tenant_files_router`) and 404s a member admin's
//! request for any tenant they do not own BEFORE the handler runs. It is a
//! second, independent line of defense alongside the Task 5
//! `ensure_tenant_visible` handler choke point — the routes probed here
//! deliberately do NOT call the choke point, so only the guard can deny them.

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

/// Seed: owner root (id 1) owns t-owner-a; member (id 2) owns t-member-b;
/// t-orphan-c has owner_admin_id NULL (direct meta insert). Returns
/// (app, dir, owner_cookie, member_cookie).
async fn seed_three_tenants() -> (axum::Router, tempfile::TempDir, String, String) {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (_member_id, member_cookie) = insert_admin(&dir, "alice@example.com", "member");
    create_tenant_json(&app, &owner_cookie, "t-owner-a", "AlphaCorp").await;
    create_tenant_json(&app, &member_cookie, "t-member-b", "BetaCorp").await;
    // Orphan tenant: no owner. Direct meta insert.
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

/// One probe per router family. `(method, uri_suffix, json_body)` relative to
/// `/admin`-space; `{id}` substituted by the caller.
///  - `_overview` page          → tenants_router page family
///  - `collections/x/_list`     → tenants_router collections family (POST)
///  - `api/tenants/{id}/tokens` → tenants_router API family
///  - `files` legacy redirect   → tenants_router files family (no handler check)
///  - `files/nokey/bytes`       → admin_tenant_files_router family
fn probes(tenant: &str) -> Vec<(&'static str, String, Option<&'static str>)> {
    vec![
        ("GET", format!("/admin/tenants/{tenant}/_overview"), None),
        (
            "POST",
            format!("/admin/tenants/{tenant}/collections/x/_list"),
            Some("{}"),
        ),
        ("GET", format!("/admin/api/tenants/{tenant}/tokens"), None),
        ("GET", format!("/admin/tenants/{tenant}/files"), None),
        (
            "GET",
            format!("/admin/tenants/{tenant}/files/nokey/bytes"),
            None,
        ),
    ]
}

async fn probe(
    app: &axum::Router,
    cookie: &str,
    method: &str,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie);
    let body = match body {
        Some(b) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Assert the request got PAST the guard (handler ran). Handler outcomes per
/// probe: _overview → 200; _list on nonexistent collection → 404 "no such
/// collection"; tokens → 200; legacy files → 3xx redirect; files bytes with
/// garage=None → 503 "storage not configured". None of these is the guard's
/// 404 "no such tenant".
fn assert_passed_guard(status: StatusCode, body: &str, uri: &str) {
    assert!(
        !(status == StatusCode::NOT_FOUND && body.contains("no such tenant")),
        "guard must not deny {uri}: got {status} {body}"
    );
    // Belt-and-braces: pin the expected handler outcome per family.
    if uri.ends_with("/_overview") || uri.ends_with("/tokens") {
        assert_eq!(status, StatusCode::OK, "{uri} should render, got {body}");
    } else if uri.ends_with("/_list") {
        assert!(
            body.contains("no such collection"),
            "{uri} should reach the handler, got {status} {body}"
        );
    } else if uri.ends_with("/files") {
        assert!(
            status.is_redirection(),
            "{uri} should redirect, got {status}"
        );
    } else if uri.ends_with("/bytes") {
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{uri} should reach the files handler (no garage), got {body}"
        );
    }
}

// ─── member denied on foreign + orphan tenants, every router family ──────────

#[tokio::test]
async fn member_guard_denies_foreign_tenants_across_router_families() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    for tenant in ["t-owner-a", "t-orphan-c"] {
        for (method, uri, body) in probes(tenant) {
            let (status, resp_body) = probe(&app, &member_cookie, method, &uri, body).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "member {method} {uri} must 404, got {status} {resp_body}"
            );
            assert!(
                resp_body.contains("no such tenant"),
                "deny must be indistinguishable from a missing tenant on {uri}, got: {resp_body}"
            );
        }
    }
}

// ─── owner passes everywhere (zero regression) ───────────────────────────────

#[tokio::test]
async fn owner_guard_passes_all_tenants() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    for tenant in ["t-owner-a", "t-member-b", "t-orphan-c"] {
        for (method, uri, body) in probes(tenant) {
            let (status, resp_body) = probe(&app, &owner_cookie, method, &uri, body).await;
            assert_passed_guard(status, &resp_body, &uri);
        }
    }
}

// ─── member passes on their own tenant ───────────────────────────────────────

#[tokio::test]
async fn member_guard_passes_owned_tenant() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    for (method, uri, body) in probes("t-member-b") {
        let (status, resp_body) = probe(&app, &member_cookie, method, &uri, body).await;
        assert_passed_guard(status, &resp_body, &uri);
    }
}

// ─── missing tenant still 404s for everyone (same body) ──────────────────────

#[tokio::test]
async fn guard_404s_missing_tenant_for_owner_too() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, body) = probe(
        &app,
        &owner_cookie,
        "GET",
        "/admin/tenants/t-nope/_overview",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("no such tenant"),
        "missing tenant must 404 with the canonical body, got: {body}"
    );
}

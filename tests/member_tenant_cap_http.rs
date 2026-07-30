//! v1.57 — the tenant cap over HTTP, through both real creation entry points.
//!
//! `tests/member_tenant_cap.rs` drives `make_tenant_inner` directly, which
//! proves the gate but leaves the user-visible contract untested: that the
//! `TENANT_CAP_EXCEEDED` sentinel becomes a **403** on the JSON route and on the
//! form route, and that neither handler 500s on a missing request extension
//! (2026-07-30 adversarial review, finding 5b).
//!
//! Harness mirrors tests/three_tier_roles.rs — each integration test is its own
//! crate, so sharing the scaffold means re-inlining it.

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

fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
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

/// Give `admin_id` exactly `n` live tenants, straight into meta.sqlite — this is
/// seeding, so it deliberately bypasses the gate under test.
fn seed_tenants(dir: &tempfile::TempDir, admin_id: i64, n: i64) {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    for i in 0..n {
        conn.execute(
            "INSERT INTO tenants (id, name, owner_admin_id) VALUES (?1, ?2, ?3)",
            params![
                format!("seed-{admin_id}-{i}"),
                format!("Seed {i}"),
                admin_id
            ],
        )
        .unwrap();
    }
}

async fn body_text(resp: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

fn default_cap() -> i64 {
    drust::mgmt::tenant_cap::configured_default()
}

// ─── the JSON entry point ─────────────────────────────────────────────────────

#[tokio::test]
async fn json_route_returns_403_with_the_error_code_when_a_member_is_at_the_cap() {
    let (app, dir) = spin_up().await;
    let (member_id, cookie) = insert_admin(&dir, "mem@example.invalid", "member");
    seed_tenants(&dir, member_id, default_cap());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"Over The Line"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the sentinel must map to 403, not 400 or 500"
    );
    let body = body_text(resp).await;
    assert!(
        body.contains("TENANT_CAP_EXCEEDED"),
        "the machine-readable code must be present, got: {body}"
    );
}

#[tokio::test]
async fn json_route_lets_a_member_below_the_cap_create() {
    let (app, dir) = spin_up().await;
    let (member_id, cookie) = insert_admin(&dir, "mem2@example.invalid", "member");
    seed_tenants(&dir, member_id, default_cap() - 1);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"Last Slot"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "one slot remained, so this must succeed"
    );
}

/// An `owner` is uncapped, and this also proves neither handler depends on a
/// request extension that is absent for some roles (which would surface as a
/// 500 rather than the intended status).
#[tokio::test]
async fn json_route_never_caps_an_owner() {
    let (app, dir) = spin_up().await;
    let (owner_id, cookie) = insert_admin(&dir, "own@example.invalid", "owner");
    seed_tenants(&dir, owner_id, default_cap() + 5);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"Owner Unbounded"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
}

// ─── the form entry point ─────────────────────────────────────────────────────

#[tokio::test]
async fn form_route_returns_403_when_a_member_is_at_the_cap() {
    let (app, dir) = spin_up().await;
    let (member_id, cookie) = insert_admin(&dir, "mem3@example.invalid", "member");
    seed_tenants(&dir, member_id, default_cap());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/new")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=Over+The+Line"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the form route must also 403, not 400"
    );
    let body = body_text(resp).await;
    assert!(
        body.contains("TENANT_CAP_EXCEEDED"),
        "the browser-side handler keys on this code to show the localized \
         dialog instead of navigating to a bare error page, got: {body}"
    );
}

#[tokio::test]
async fn form_route_lets_a_member_below_the_cap_create() {
    let (app, dir) = spin_up().await;
    let (member_id, cookie) = insert_admin(&dir, "mem4@example.invalid", "member");
    seed_tenants(&dir, member_id, default_cap() - 1);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/new")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=Last+Slot"))
                .unwrap(),
        )
        .await
        .unwrap();

    // The form route redirects on success.
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "a successful form create redirects back to the list"
    );
}

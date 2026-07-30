//! v1.57 — the member cap-increase request flow.
//!
//! `POST /admin/tenant-cap/requests` is SELF-SCOPED: the subject is always the
//! authenticated caller, so there is no on-behalf-of parameter and therefore no
//! cross-admin surface to authorise. The validation posture is copied from
//! `quota_admin::create_quota_request` — numeric bounds first, then reason
//! normalisation (trim / ≤500 bytes / no control chars), then a
//! one-pending-request-per-admin check.
//!
//! Router harness mirrors tests/tenant_quota_requests.rs (each integration test
//! is its own crate, so sharing the scaffold means re-inlining it).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::mgmt::tenant_cap;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::{TempDir, tempdir};
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── router harness ───────────────────────────────────────────────────────────

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

async fn spin_up() -> (axum::Router, TempDir) {
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

/// Insert a member admin (OAuth-only sentinel) + a live session. Mirrors
/// tests/tenant_quota_requests.rs.
fn insert_member(dir: &TempDir, email: &str) -> (i64, String) {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) \
         VALUES (?1, '$oauth-only$', ?2, 'member')",
        params![username, email],
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

/// (app, dir, member_admin_id, member_cookie). The member carries no
/// `tenant_cap_bonus`, so their effective cap is the global default.
async fn seed() -> (axum::Router, TempDir, i64, String) {
    let (app, dir) = spin_up().await;
    let (mid, cookie) = insert_member(&dir, "alice@example.com");
    (app, dir, mid, cookie)
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    json_body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie);
    let body = match json_body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4_194_304)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// Every `tenant_cap_requests` row for one admin as
/// `(id, requested_cap, reason, status)`, oldest first.
fn cap_requests(dir: &TempDir, admin_id: i64) -> Vec<(i64, i64, Option<String>, String)> {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, requested_cap, reason, status FROM tenant_cap_requests \
             WHERE requester_admin_id = ?1 ORDER BY id",
        )
        .unwrap();
    let rows = stmt
        .query_map(params![admin_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    rows
}

// ─── happy path ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn member_files_a_request_and_it_is_pending() {
    let (app, dir, mid, member) = seed().await;
    let target = tenant_cap::configured_default() + 2;

    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenant-cap/requests",
        &member,
        Some(serde_json::json!({"requested_cap": target, "reason": "more projects"})),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "own-cap request must 201: {body}");
    assert_eq!(body["status"], "pending", "{body}");
    assert_eq!(body["requested_cap"], target, "{body}");
    let req_id = body["id"].as_i64().expect("response carries a request id");

    let rows = cap_requests(&dir, mid);
    assert_eq!(rows.len(), 1, "exactly one row was written: {rows:?}");
    assert_eq!(rows[0].0, req_id, "the row id matches the response");
    assert_eq!(rows[0].1, target, "the absolute target is stored verbatim");
    assert_eq!(rows[0].2.as_deref(), Some("more projects"));
    assert_eq!(rows[0].3, "pending", "a fresh request is pending");
}

// ─── validation ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_non_increase_is_rejected() {
    let (app, dir, mid, member) = seed().await;
    let cap = tenant_cap::configured_default();
    assert!(
        cap >= 2,
        "this test needs a default cap of at least 2 to have a `below` case, got {cap}"
    );

    // requested == effective cap, then requested < effective cap.
    for requested in [cap, cap - 1] {
        let (st, body) = send(
            &app,
            "POST",
            "/admin/tenant-cap/requests",
            &member,
            Some(serde_json::json!({"requested_cap": requested})),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "requested_cap={requested} (cap={cap}) must 400: {body}"
        );
        assert_eq!(
            body["error_code"], "TENANT_CAP_NOT_INCREASE",
            "requested_cap={requested}: {body}"
        );
    }

    assert!(
        cap_requests(&dir, mid).is_empty(),
        "a refused request must write no row"
    );
}

#[tokio::test]
async fn out_of_range_is_rejected() {
    let (app, dir, mid, member) = seed().await;

    for requested in [0, tenant_cap::MAX_CAP + 1] {
        let (st, body) = send(
            &app,
            "POST",
            "/admin/tenant-cap/requests",
            &member,
            Some(serde_json::json!({"requested_cap": requested})),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "requested_cap={requested} must 400: {body}"
        );
        assert_eq!(
            body["error_code"], "TENANT_CAP_INVALID",
            "requested_cap={requested}: {body}"
        );
    }

    assert!(
        cap_requests(&dir, mid).is_empty(),
        "an out-of-range request must write no row"
    );
}

#[tokio::test]
async fn a_second_pending_request_is_refused() {
    let (app, dir, mid, member) = seed().await;
    let cap = tenant_cap::configured_default();

    let (st1, body1) = send(
        &app,
        "POST",
        "/admin/tenant-cap/requests",
        &member,
        Some(serde_json::json!({"requested_cap": cap + 1})),
    )
    .await;
    assert_eq!(st1, StatusCode::CREATED, "first request must 201: {body1}");

    // A strictly larger target, so the refusal can only come from the
    // one-pending-per-admin rule and not from the non-increase check.
    let (st2, body2) = send(
        &app,
        "POST",
        "/admin/tenant-cap/requests",
        &member,
        Some(serde_json::json!({"requested_cap": cap + 2})),
    )
    .await;
    assert_eq!(
        st2,
        StatusCode::CONFLICT,
        "a second pending request must 409: {body2}"
    );
    assert_eq!(body2["error_code"], "TENANT_CAP_REQUEST_PENDING", "{body2}");

    let rows = cap_requests(&dir, mid);
    assert_eq!(rows.len(), 1, "only the first row exists: {rows:?}");
    assert_eq!(rows[0].1, cap + 1, "the stored target is the first one");
}

#[tokio::test]
async fn an_over_long_reason_is_rejected() {
    let (app, dir, mid, member) = seed().await;
    let cap = tenant_cap::configured_default();

    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenant-cap/requests",
        &member,
        Some(serde_json::json!({
            "requested_cap": cap + 1,
            "reason": "x".repeat(501),
        })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "a 501-byte reason must 400: {body}"
    );
    assert_eq!(body["error_code"], "TENANT_CAP_REASON_TOO_LONG", "{body}");
    assert!(
        cap_requests(&dir, mid).is_empty(),
        "a refused request must write no row"
    );
}

#[tokio::test]
async fn a_control_character_in_the_reason_is_rejected() {
    let (app, dir, mid, member) = seed().await;
    let cap = tenant_cap::configured_default();

    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenant-cap/requests",
        &member,
        Some(serde_json::json!({
            "requested_cap": cap + 1,
            "reason": "bad\u{0}reason",
        })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "a NUL in the reason must 400: {body}"
    );
    assert_eq!(body["error_code"], "TENANT_CAP_REASON_INVALID", "{body}");
    assert!(
        cap_requests(&dir, mid).is_empty(),
        "a refused request must write no row"
    );
}

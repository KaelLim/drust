//! v1.58 #920 — `tenant_cap_requests` grows without bound and has no submit
//! rate limit, so a member can loop request → rejected → request.
//!
//! Pending rows are NEVER auto-pruned: a pending request is a to-do item an
//! owner still has to act on, not a record.
//!
//! Router harness mirrors tests/member_tenant_cap_requests.rs (each integration
//! test is its own crate, so sharing the scaffold means re-inlining it).

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

// ─── retention / counting, straight against a meta connection ────────────────

fn setup() -> (rusqlite::Connection, TempDir) {
    let dir = tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) \
         VALUES (2, 'mem', 'h', 'member')",
        [],
    )
    .unwrap();
    (conn, dir)
}

fn insert_request(conn: &rusqlite::Connection, admin_id: i64, cap: i64, status: &str, age: &str) {
    conn.execute(
        "INSERT INTO tenant_cap_requests \
             (requester_admin_id, requested_cap, reason, status, created_at) \
         VALUES (?1, ?2, 'r', ?3, datetime('now', ?4))",
        params![admin_id, cap, status, age],
    )
    .unwrap();
}

#[test]
fn prune_removes_old_decided_requests_and_keeps_pending() {
    let (conn, _d) = setup();
    insert_request(&conn, 2, 5, "rejected", "-200 days");
    insert_request(&conn, 2, 6, "approved", "-200 days");
    insert_request(&conn, 2, 7, "pending", "-200 days");

    let n = tenant_cap::prune_decided_requests(&conn, 90).unwrap();
    assert_eq!(n, 2, "both decided rows should go");

    let left: i64 = conn
        .query_row("SELECT COUNT(*) FROM tenant_cap_requests", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        left, 1,
        "the pending request must survive — it is a to-do, not a record"
    );
    let status: String = conn
        .query_row("SELECT status FROM tenant_cap_requests", [], |r| r.get(0))
        .unwrap();
    assert_eq!(status, "pending");
}

#[test]
fn prune_keeps_decided_rows_inside_the_window() {
    let (conn, _d) = setup();
    insert_request(&conn, 2, 5, "rejected", "-10 days");
    assert_eq!(
        tenant_cap::prune_decided_requests(&conn, 90).unwrap(),
        0,
        "a 10-day-old rejection is well inside a 90-day window"
    );
}

#[test]
fn prune_is_a_noop_when_retention_is_zero() {
    let (conn, _d) = setup();
    insert_request(&conn, 2, 5, "rejected", "-9000 days");
    assert_eq!(tenant_cap::prune_decided_requests(&conn, 0).unwrap(), 0);
    let left: i64 = conn
        .query_row("SELECT COUNT(*) FROM tenant_cap_requests", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 1, "0 means keep forever, not delete everything");
}

/// A negative retention is operator error, not an instruction to delete the
/// table. It must fail CLOSED the same way `0` does.
#[test]
fn prune_is_a_noop_for_a_negative_retention() {
    let (conn, _d) = setup();
    insert_request(&conn, 2, 5, "rejected", "-9000 days");
    assert_eq!(tenant_cap::prune_decided_requests(&conn, -1).unwrap(), 0);
}

#[test]
fn submits_today_counts_only_this_admin_and_only_today() {
    let (conn, _d) = setup();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) \
         VALUES (3, 'other', 'h', 'member')",
        [],
    )
    .unwrap();
    insert_request(&conn, 2, 5, "rejected", "-0 days");
    insert_request(&conn, 2, 6, "rejected", "-2 days");
    insert_request(&conn, 3, 7, "pending", "-0 days");

    assert_eq!(tenant_cap::submits_today(&conn, 2).unwrap(), 1);
    assert_eq!(tenant_cap::submits_today(&conn, 3).unwrap(), 1);
    assert_eq!(
        tenant_cap::submits_today(&conn, 99).unwrap(),
        0,
        "an admin with no rows has submitted nothing"
    );
}

/// A rejected request still counts against the day's budget — that loop is the
/// whole reason the limit exists.
#[test]
fn submits_today_counts_decided_rows_too() {
    let (conn, _d) = setup();
    insert_request(&conn, 2, 5, "rejected", "-0 days");
    insert_request(&conn, 2, 6, "approved", "-0 days");
    insert_request(&conn, 2, 7, "pending", "-0 days");
    assert_eq!(tenant_cap::submits_today(&conn, 2).unwrap(), 3);
}

#[test]
fn env_knobs_have_the_documented_defaults() {
    // No env override is set in this process, so both read their constants.
    assert_eq!(
        tenant_cap::request_retention_days(),
        tenant_cap::DEFAULT_REQUEST_RETENTION_DAYS
    );
    assert_eq!(
        tenant_cap::daily_submit_limit(),
        tenant_cap::DEFAULT_DAILY_SUBMIT_LIMIT
    );
}

// ─── HTTP: the daily submit limit ────────────────────────────────────────────

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

/// Log the bootstrap admin in and return its session cookie. `root` is admin id
/// 1 and `run_migrations` promotes it to `owner`, so this is the owner cookie.
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

/// Insert a `member` admin (OAuth-only sentinel) plus a live session.
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

#[tokio::test]
async fn the_request_reject_request_loop_is_rate_limited() {
    let (app, dir) = spin_up().await;
    let owner = login(&app, "root", "hunter2").await;
    let (_mid, member) = insert_member(&dir, "alice@example.com");

    let limit = tenant_cap::daily_submit_limit();
    assert!(limit > 0, "the default limit must be enforcing");
    let base = tenant_cap::configured_default();

    // Burn the whole day's budget: file, get rejected, file again. The existing
    // duplicate-pending 409 does not stop this loop; only the daily limit does.
    for i in 0..limit {
        let (st, body) = send(
            &app,
            "POST",
            "/admin/tenant-cap/requests",
            &member,
            Some(serde_json::json!({"requested_cap": base + 1 + i})),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::CREATED,
            "attempt {i} must be accepted: {body}"
        );
        let req_id = body["id"].as_i64().expect("response carries a request id");
        let (st, body) = send(
            &app,
            "POST",
            &format!("/admin/tenant-cap-requests/{req_id}/decide"),
            &owner,
            Some(serde_json::json!({"action": "reject"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "rejection {i} must land: {body}");
    }

    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenant-cap/requests",
        &member,
        Some(serde_json::json!({"requested_cap": base + 1 + limit})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::TOO_MANY_REQUESTS,
        "the request after the day's budget must be refused: {body}"
    );
    assert_eq!(body["error_code"], "CAP_REQUEST_RATE_LIMITED");

    // The refused attempt wrote nothing.
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM tenant_cap_requests", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, limit, "the rate-limited attempt must not insert");
}

/// The limit is per-admin: one member exhausting the day must not lock another
/// member out.
#[tokio::test]
async fn the_daily_limit_is_per_admin() {
    let (app, dir) = spin_up().await;
    let owner = login(&app, "root", "hunter2").await;
    let (_a, alice) = insert_member(&dir, "alice@example.com");
    let (_b, bob) = insert_member(&dir, "bob@example.com");

    let limit = tenant_cap::daily_submit_limit();
    let base = tenant_cap::configured_default();
    for i in 0..limit {
        let (st, body) = send(
            &app,
            "POST",
            "/admin/tenant-cap/requests",
            &alice,
            Some(serde_json::json!({"requested_cap": base + 1 + i})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "alice attempt {i}: {body}");
        let req_id = body["id"].as_i64().unwrap();
        let (st, _) = send(
            &app,
            "POST",
            &format!("/admin/tenant-cap-requests/{req_id}/decide"),
            &owner,
            Some(serde_json::json!({"action": "reject"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    let (st, _) = send(
        &app,
        "POST",
        "/admin/tenant-cap/requests",
        &alice,
        Some(serde_json::json!({"requested_cap": base + 50})),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "alice is out of budget");

    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenant-cap/requests",
        &bob,
        Some(serde_json::json!({"requested_cap": base + 1})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "bob's own budget is untouched: {body}"
    );
}

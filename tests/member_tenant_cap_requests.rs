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

/// Log the bootstrap admin in and return its session cookie. `root` is admin
/// id 1 and `run_migrations` promotes it to `owner` (the "no owner exists yet"
/// backfill), so this is the owner cookie.
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

/// Insert an admin of `role` (OAuth-only sentinel) + a live session. Mirrors
/// tests/tenant_quota_requests.rs.
fn insert_admin_role(dir: &TempDir, email: &str, role: &str) -> (i64, String) {
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

fn insert_member(dir: &TempDir, email: &str) -> (i64, String) {
    insert_admin_role(dir, email, "member")
}

/// (app, dir, member_admin_id, member_cookie). The member carries no
/// `tenant_cap_bonus`, so their effective cap is the global default.
async fn seed() -> (axum::Router, TempDir, i64, String) {
    let (app, dir) = spin_up().await;
    let (mid, cookie) = insert_member(&dir, "alice@example.com");
    (app, dir, mid, cookie)
}

/// (app, dir, member_admin_id, member_cookie, owner_cookie).
async fn seed_with_owner() -> (axum::Router, TempDir, i64, String, String) {
    let (app, dir) = spin_up().await;
    let owner = login(&app, "root", "hunter2").await;
    let (mid, member) = insert_member(&dir, "alice@example.com");
    (app, dir, mid, member, owner)
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
    stmt.query_map(params![admin_id], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

/// The stored DELTA for one admin (`admins.tenant_cap_bonus`).
fn admin_bonus(dir: &TempDir, admin_id: i64) -> i64 {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row(
        "SELECT tenant_cap_bonus FROM admins WHERE id = ?1",
        params![admin_id],
        |r| r.get(0),
    )
    .unwrap()
}

/// `(status, decided_by_admin_id, decided_at)` for one request row.
fn decision(dir: &TempDir, req_id: i64) -> (String, Option<i64>, Option<String>) {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row(
        "SELECT status, decided_by_admin_id, decided_at FROM tenant_cap_requests \
         WHERE id = ?1",
        params![req_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .unwrap()
}

/// The bootstrap admin's id — `root`, promoted to `owner` by the migration.
fn owner_id(dir: &TempDir) -> i64 {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row("SELECT id FROM admins WHERE username = 'root'", [], |r| {
        r.get(0)
    })
    .unwrap()
}

/// File a request as `cookie` and return its id (asserting the 201).
async fn file_request(app: &axum::Router, cookie: &str, requested_cap: i64) -> i64 {
    let (st, body) = send(
        app,
        "POST",
        "/admin/tenant-cap/requests",
        cookie,
        Some(serde_json::json!({"requested_cap": requested_cap})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "filing a request for {requested_cap} must 201: {body}"
    );
    body["id"].as_i64().expect("response carries a request id")
}

async fn get_status(app: &axum::Router, uri: &str, cookie: &str) -> StatusCode {
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
    resp.status()
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

// ─── owner: decide a pending request ─────────────────────────────────────────

#[tokio::test]
async fn owner_approves_and_the_cap_rises() {
    let (app, dir, mid, member, owner) = seed_with_owner().await;
    let default = tenant_cap::configured_default();
    let req_id = file_request(&app, &member, default + 2).await;

    let (st, body) = send(
        &app,
        "POST",
        &format!("/admin/tenant-cap-requests/{req_id}/decide"),
        &owner,
        Some(serde_json::json!({"action": "approve"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "owner approve must 200: {body}");

    // The ABSOLUTE target the member asked for is stored as a DELTA.
    assert_eq!(
        admin_bonus(&dir, mid),
        2,
        "approving `default + 2` stores a +2 delta, never the absolute"
    );
    let (status, by, at) = decision(&dir, req_id);
    assert_eq!(status, "approved");
    assert_eq!(by, Some(owner_id(&dir)), "the deciding owner is recorded");
    assert!(at.is_some(), "decided_at is stamped");
}

#[tokio::test]
async fn owner_rejects_without_raising() {
    let (app, dir, mid, member, owner) = seed_with_owner().await;
    let default = tenant_cap::configured_default();
    let req_id = file_request(&app, &member, default + 2).await;

    let (st, body) = send(
        &app,
        "POST",
        &format!("/admin/tenant-cap-requests/{req_id}/decide"),
        &owner,
        Some(serde_json::json!({"action": "reject"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "owner reject must 200: {body}");

    assert_eq!(
        admin_bonus(&dir, mid),
        0,
        "a rejection must not touch the adjustment"
    );
    let (status, by, at) = decision(&dir, req_id);
    assert_eq!(status, "rejected");
    assert_eq!(by, Some(owner_id(&dir)));
    assert!(at.is_some(), "a rejection still stamps decided_at");
}

/// The F4 analogue. `quota_admin::decide_quota_request` carries a comment
/// recording adversarial finding F4 from the v1.50 review: approving a stale
/// pending row would silently DOWNGRADE. The identical hazard exists here —
/// a member files for `default + 1`, an owner then direct-sets them higher, and
/// approving the stale row must NOT lower them back.
#[tokio::test]
async fn approving_a_stale_request_cannot_downgrade() {
    let (app, dir, mid, member, owner) = seed_with_owner().await;
    let default = tenant_cap::configured_default();
    let req_id = file_request(&app, &member, default + 1).await;

    // Owner raises them past the pending request via a direct set.
    let (st, body) = send(
        &app,
        "PATCH",
        &format!("/admin/team/{mid}/tenant-cap"),
        &owner,
        Some(serde_json::json!({"cap": default + 3})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "owner direct set must 200: {body}");
    assert_eq!(admin_bonus(&dir, mid), 3, "direct set stored a +3 delta");

    // Approving the now-stale row must refuse rather than lower them.
    let (st, body) = send(
        &app,
        "POST",
        &format!("/admin/tenant-cap-requests/{req_id}/decide"),
        &owner,
        Some(serde_json::json!({"action": "approve"})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "approving a stale request must 409, never silently downgrade: {body}"
    );
    assert_eq!(body["error_code"], "TENANT_CAP_NOT_INCREASE", "{body}");

    assert_eq!(
        admin_bonus(&dir, mid),
        3,
        "the live cap must survive the refused approval"
    );
    let (status, by, at) = decision(&dir, req_id);
    assert_eq!(
        status, "pending",
        "the row stays pending so it can be rejected explicitly"
    );
    assert_eq!(by, None, "a refused approval records no decider");
    assert_eq!(at, None, "a refused approval stamps no decided_at");
}

#[tokio::test]
async fn deciding_an_already_decided_row_is_refused() {
    let (app, dir, mid, member, owner) = seed_with_owner().await;
    let default = tenant_cap::configured_default();
    let req_id = file_request(&app, &member, default + 2).await;
    let uri = format!("/admin/tenant-cap-requests/{req_id}/decide");

    let (st1, body1) = send(
        &app,
        "POST",
        &uri,
        &owner,
        Some(serde_json::json!({"action": "approve"})),
    )
    .await;
    assert_eq!(st1, StatusCode::OK, "first approve must 200: {body1}");

    let (st2, body2) = send(
        &app,
        "POST",
        &uri,
        &owner,
        Some(serde_json::json!({"action": "approve"})),
    )
    .await;
    assert_eq!(
        st2,
        StatusCode::CONFLICT,
        "a double-submitted approval must 409, not re-apply: {body2}"
    );
    assert_eq!(body2["error_code"], "TENANT_CAP_REQUEST_DECIDED", "{body2}");
    assert_eq!(
        admin_bonus(&dir, mid),
        2,
        "the second decision changed nothing"
    );
}

// ─── authorisation ────────────────────────────────────────────────────────────

#[tokio::test]
async fn member_and_admin_cannot_reach_the_review_queue() {
    let (app, dir, _mid, member, owner) = seed_with_owner().await;
    let (_aid, admin) = insert_admin_role(&dir, "carol@example.com", "admin");

    assert_eq!(
        get_status(&app, "/admin/tenant-cap-requests", &member).await,
        StatusCode::FORBIDDEN,
        "a member must not see the host-wide review queue"
    );
    assert_eq!(
        get_status(&app, "/admin/tenant-cap-requests", &admin).await,
        StatusCode::FORBIDDEN,
        "an admin must not see it either — allowance decisions are owner-only"
    );
    assert_eq!(
        get_status(&app, "/admin/tenant-cap-requests", &owner).await,
        StatusCode::OK,
        "the owner sees the queue"
    );
}

#[tokio::test]
async fn only_owner_can_direct_set_a_cap() {
    let (app, dir, mid, member, owner) = seed_with_owner().await;
    let (_aid, admin) = insert_admin_role(&dir, "carol@example.com", "admin");
    let default = tenant_cap::configured_default();
    let uri = format!("/admin/team/{mid}/tenant-cap");

    for (label, cookie) in [("admin", &admin), ("member", &member)] {
        let (st, body) = send(
            &app,
            "PATCH",
            &uri,
            cookie,
            Some(serde_json::json!({"cap": 7})),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::FORBIDDEN,
            "a {label} must not set a host allowance: {body}"
        );
        assert_eq!(
            admin_bonus(&dir, mid),
            0,
            "a refused {label} direct-set must change nothing"
        );
    }

    let (st, body) = send(
        &app,
        "PATCH",
        &uri,
        &owner,
        Some(serde_json::json!({"cap": 7})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "owner direct set must 200: {body}");
    assert_eq!(
        admin_bonus(&dir, mid),
        7 - default,
        "the absolute target is stored as a delta against the global default"
    );
}

#[tokio::test]
async fn direct_set_null_clears_the_adjustment() {
    let (app, dir, mid, _member, owner) = seed_with_owner().await;
    let default = tenant_cap::configured_default();
    let uri = format!("/admin/team/{mid}/tenant-cap");

    let (st, body) = send(
        &app,
        "PATCH",
        &uri,
        &owner,
        Some(serde_json::json!({"cap": default + 4})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(admin_bonus(&dir, mid), 4, "adjusted first");

    let (st, body) = send(
        &app,
        "PATCH",
        &uri,
        &owner,
        Some(serde_json::json!({"cap": null})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "clearing must 200: {body}");
    assert_eq!(
        admin_bonus(&dir, mid),
        0,
        "null clears the adjustment back to the global default"
    );
}

#[tokio::test]
async fn direct_set_rejects_out_of_range() {
    let (app, dir, mid, _member, owner) = seed_with_owner().await;
    let uri = format!("/admin/team/{mid}/tenant-cap");

    for cap in [0, tenant_cap::MAX_CAP + 1] {
        let (st, body) = send(
            &app,
            "PATCH",
            &uri,
            &owner,
            Some(serde_json::json!({"cap": cap})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "cap={cap} must 400: {body}");
        assert_eq!(
            body["error_code"], "TENANT_CAP_INVALID",
            "cap={cap}: {body}"
        );
        assert_eq!(
            admin_bonus(&dir, mid),
            0,
            "cap={cap} must leave the adjustment untouched"
        );
    }
}

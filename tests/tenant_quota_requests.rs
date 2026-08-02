//! v1.50 (Spec B, Task 6) — quota upgrade request / approve admin plane.
//!
//! Member admins file a `quota_requests` row against a tenant THEY OWN
//! (`POST /admin/tenants/{id}/quota/requests`); an owner admin reviews the
//! queue (`GET /admin/quota-requests`), approves/rejects each
//! (`POST /admin/quota-requests/{id}/decide`), or sets a tier directly
//! (`PATCH /admin/tenants/{id}/quota`). Config is admin-plane only — there is
//! deliberately NO per-tenant MCP tool (a tenant's service key must never
//! raise its own quota); that isolation is pinned in Task 7.
//!
//! Router harness mirrors tests/tenant_ownership_guard.rs: a bootstrapped
//! owner admin ("root", id 1) + a directly-inserted member ("alice", id 2),
//! each owning one tenant.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::{TempDir, tempdir};
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── process-global audit writer (approve emits `tenant.quota.set`) ───────────

fn ensure_global_audit_writer() -> &'static PathBuf {
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_quota_audit.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-quota-audit-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    drust::safety::audit_db::init_globals(writer);
                    let _ = tx_ready.send(());
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

/// Poll the global audit DB for at least one row matching (tenant, op).
async fn wait_for_audit_op(tenant: &str, op: &str) -> bool {
    let path = ensure_global_audit_writer();
    for _ in 0..25 {
        let r = open_audit_db_read(path).unwrap();
        let _ = r.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
        let n: i64 = r
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE tenant = ?1 AND op = ?2",
                params![tenant, op],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if n > 0 {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    false
}

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

/// Insert a member admin (OAuth-only sentinel) + a session. Mirrors
/// tests/tenant_ownership_guard.rs.
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

/// (app, dir, owner_cookie, member_cookie). Owner root (id 1) owns
/// `t-owner-a`; member alice (id 2) owns `t-member-b`. Both tenants start at
/// tier 1 (the migration default).
async fn seed() -> (axum::Router, TempDir, String, String) {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (_mid, member_cookie) = insert_member(&dir, "alice@example.com");
    create_tenant_json(&app, &owner_cookie, "t-owner-a", "AlphaCorp").await;
    create_tenant_json(&app, &member_cookie, "t-member-b", "BetaCorp").await;
    (app, dir, owner_cookie, member_cookie)
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

fn meta_tier(dir: &TempDir, tid: &str) -> i64 {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row(
        "SELECT quota_tier FROM tenants WHERE id = ?1",
        params![tid],
        |r| r.get(0),
    )
    .unwrap()
}

fn request_status(dir: &TempDir, id: i64) -> String {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row(
        "SELECT status FROM quota_requests WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )
    .unwrap()
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

// ─── member request path ──────────────────────────────────────────────────────

#[tokio::test]
async fn member_requests_upgrade_on_owned_tenant_201() {
    let (app, dir, _owner, member) = seed().await;
    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 2, "reason": "growing"})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "own-tenant request must 201: {body}"
    );
    assert!(
        body["id"].is_number(),
        "response carries request id: {body}"
    );
    assert_eq!(body["status"], "pending");
    // A pending row now exists.
    let id = body["id"].as_i64().unwrap();
    assert_eq!(request_status(&dir, id), "pending");
}

#[tokio::test]
async fn member_request_on_foreign_tenant_404() {
    // The Spec A ownership guard denies a member on a tenant they do not own —
    // pinned here so the quota route inherits it (indistinguishable 404).
    let (app, _dir, _owner, member) = seed().await;
    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-owner-a/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 2})),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "foreign tenant must 404");
    assert!(
        body.to_string().contains("no such tenant"),
        "deny is a missing-tenant 404: {body}"
    );
}

#[tokio::test]
async fn request_not_increasing_tier_400() {
    let (app, _dir, _owner, member) = seed().await;
    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 1})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_code"], "QUOTA_TIER_NOT_INCREASE", "{body}");
}

#[tokio::test]
async fn duplicate_pending_request_409() {
    let (app, _dir, _owner, member) = seed().await;
    let (st1, _) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 2})),
    )
    .await;
    assert_eq!(st1, StatusCode::CREATED);
    let (st2, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 3})),
    )
    .await;
    assert_eq!(st2, StatusCode::CONFLICT);
    assert_eq!(body["error_code"], "QUOTA_REQUEST_PENDING", "{body}");
}

// ─── owner-only decide / direct-set surfaces ──────────────────────────────────

#[tokio::test]
async fn member_cannot_patch_quota_directly_403() {
    let (app, dir, _owner, member) = seed().await;
    // Member OWNS t-member-b (guard passes) but only owner-role may set tier.
    let (st, _body) = send(
        &app,
        "PATCH",
        "/admin/tenants/t-member-b/quota",
        &member,
        Some(serde_json::json!({"tier": 5})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(meta_tier(&dir, "t-member-b"), 1, "tier must be unchanged");
}

#[tokio::test]
async fn member_cannot_decide_403() {
    let (app, _dir, _owner, member) = seed().await;
    let (st, _body) = send(
        &app,
        "POST",
        "/admin/quota-requests/1/decide",
        &member,
        Some(serde_json::json!({"action": "approve"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "member is not an owner");
}

#[tokio::test]
async fn owner_sees_review_page_member_forbidden() {
    let (app, _dir, owner, member) = seed().await;
    assert_eq!(
        get_status(&app, "/admin/quota-requests", &owner).await,
        StatusCode::OK,
        "owner review page renders"
    );
    assert_eq!(
        get_status(&app, "/admin/quota-requests", &member).await,
        StatusCode::FORBIDDEN,
        "member cannot reach the host-wide review page"
    );
}

#[tokio::test]
async fn owner_approve_sets_tier_and_emits_audit() {
    ensure_global_audit_writer();
    let (app, dir, owner, member) = seed().await;
    // Member files the request.
    let (_st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 2, "reason": "need room"})),
    )
    .await;
    let id = body["id"].as_i64().unwrap();

    // Owner approves.
    let (st, dbody) = send(
        &app,
        "POST",
        &format!("/admin/quota-requests/{id}/decide"),
        &owner,
        Some(serde_json::json!({"action": "approve"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "approve must 200: {dbody}");
    assert_eq!(dbody["status"], "approved");

    // Tier took effect + request closed.
    assert_eq!(meta_tier(&dir, "t-member-b"), 2, "quota_tier raised to 2");
    assert_eq!(request_status(&dir, id), "approved");

    // Audit row emitted.
    assert!(
        wait_for_audit_op("t-member-b", "tenant.quota.set").await,
        "approve must emit a tenant.quota.set audit row"
    );
}

#[tokio::test]
async fn approve_on_soft_deleted_tenant_404() {
    // v1.52 — a pending request whose tenant is soft-deleted before approval
    // must be refused, not silently "approved" with a tier change the
    // deleted_at-scoped UPDATE never applied. The request stays pending.
    let (app, dir, owner, member) = seed().await;
    let (_st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 3, "reason": "need room"})),
    )
    .await;
    let id = body["id"].as_i64().unwrap();

    // Soft-delete the tenant out from under the pending request.
    {
        let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
        conn.execute(
            "UPDATE tenants SET deleted_at = datetime('now') WHERE id = 't-member-b'",
            [],
        )
        .unwrap();
    }

    let (st, dbody) = send(
        &app,
        "POST",
        &format!("/admin/quota-requests/{id}/decide"),
        &owner,
        Some(serde_json::json!({"action": "approve"})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "approve on a soft-deleted tenant must 404: {dbody}"
    );
    assert_eq!(dbody["error_code"], "TENANT_NOT_FOUND");
    assert_eq!(
        request_status(&dir, id),
        "pending",
        "the request stays pending, not falsely approved"
    );
}

#[tokio::test]
async fn owner_reject_leaves_tier_unchanged() {
    let (app, dir, owner, member) = seed().await;
    let (_st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 4})),
    )
    .await;
    let id = body["id"].as_i64().unwrap();

    let (st, dbody) = send(
        &app,
        "POST",
        &format!("/admin/quota-requests/{id}/decide"),
        &owner,
        Some(serde_json::json!({"action": "reject"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "reject must 200: {dbody}");
    assert_eq!(dbody["status"], "rejected");
    assert_eq!(meta_tier(&dir, "t-member-b"), 1, "tier unchanged on reject");
    assert_eq!(request_status(&dir, id), "rejected");
}

#[tokio::test]
async fn owner_sets_tier_directly() {
    let (app, dir, owner, _member) = seed().await;
    let (st, body) = send(
        &app,
        "PATCH",
        "/admin/tenants/t-owner-a/quota",
        &owner,
        Some(serde_json::json!({"tier": 3})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "owner direct set must 200: {body}");
    assert_eq!(body["quota_tier"], 3);
    assert_eq!(meta_tier(&dir, "t-owner-a"), 3);
}

// ─── 2026-08-02 review: the queue's LIFETIME ─────────────────────────────────
//
// `quota_requests` is the table `tenant_cap_requests` was modelled on, and when
// the cap queue got a retention janitor and a submit budget this one got
// neither — while being strictly more exposed, because its pending gate is
// keyed on the tenant rather than the requester.

fn plain_meta() -> (rusqlite::Connection, TempDir) {
    let dir = tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    (conn, dir)
}

/// `filed` / `decided` are `datetime` modifiers; `decided` of `None` leaves
/// `decided_at` NULL (the hand-edited / legacy shape).
fn insert_quota_request(
    conn: &rusqlite::Connection,
    tenant: &str,
    tier: i64,
    status: &str,
    filed: &str,
    decided: Option<&str>,
) {
    match decided {
        Some(d) => conn.execute(
            "INSERT INTO quota_requests \
                 (tenant_id, requester_admin_id, requested_tier, status, created_at, \
                  decided_by_admin_id, decided_at) \
             VALUES (?1, 2, ?2, ?3, datetime('now', ?4), 1, datetime('now', ?5))",
            params![tenant, tier, status, filed, d],
        ),
        None => conn.execute(
            "INSERT INTO quota_requests \
                 (tenant_id, requester_admin_id, requested_tier, status, created_at) \
             VALUES (?1, 2, ?2, ?3, datetime('now', ?4))",
            params![tenant, tier, status, filed],
        ),
    }
    .unwrap();
}

fn count_quota_requests(dir: &TempDir) -> i64 {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row("SELECT COUNT(*) FROM quota_requests", [], |r| r.get(0))
        .unwrap()
}

fn admin_id_of(dir: &TempDir, email: &str) -> i64 {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row(
        "SELECT id FROM admins WHERE email = ?1",
        params![email],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn quota_prune_removes_old_decided_requests_and_keeps_pending() {
    let (conn, _d) = plain_meta();
    insert_quota_request(&conn, "t-a", 2, "rejected", "-200 days", Some("-200 days"));
    insert_quota_request(&conn, "t-a", 3, "approved", "-200 days", Some("-200 days"));
    insert_quota_request(&conn, "t-a", 4, "pending", "-200 days", None);

    assert_eq!(
        drust::mgmt::quota_admin::prune_decided_requests(&conn, 90).unwrap(),
        2,
        "both decided rows should go"
    );
    let status: String = conn
        .query_row("SELECT status FROM quota_requests", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        status, "pending",
        "the pending request must survive — it is a to-do, not a record"
    );
}

/// Same anchor rule as the cap queue: the retention clock starts at the
/// DECISION. A request that sat pending past the window must not be destroyed
/// by the first pass after someone finally acts on it.
#[test]
fn quota_retention_runs_from_the_decision_not_the_filing() {
    let (conn, _d) = plain_meta();
    insert_quota_request(&conn, "t-a", 2, "rejected", "-135 days", Some("-0 days"));
    assert_eq!(
        drust::mgmt::quota_admin::prune_decided_requests(&conn, 90).unwrap(),
        0
    );
    insert_quota_request(&conn, "t-a", 3, "approved", "-400 days", Some("-91 days"));
    assert_eq!(
        drust::mgmt::quota_admin::prune_decided_requests(&conn, 90).unwrap(),
        1,
        "an old DECISION goes, however recently it was filed"
    );
}

/// A decided row with no `decided_at` — only reachable by hand-editing, since
/// `decide_quota_request` always writes one — must still age out on
/// `created_at` rather than becoming immortal.
#[test]
fn quota_retention_falls_back_to_created_at_when_decided_at_is_null() {
    let (conn, _d) = plain_meta();
    insert_quota_request(&conn, "t-a", 2, "rejected", "-200 days", None);
    assert_eq!(
        drust::mgmt::quota_admin::prune_decided_requests(&conn, 90).unwrap(),
        1
    );
}

#[test]
fn quota_prune_is_a_noop_at_zero_and_for_a_negative() {
    let (conn, _d) = plain_meta();
    insert_quota_request(
        &conn,
        "t-a",
        2,
        "rejected",
        "-9000 days",
        Some("-9000 days"),
    );
    assert_eq!(
        drust::mgmt::quota_admin::prune_decided_requests(&conn, 0).unwrap(),
        0,
        "0 means keep forever, not delete everything"
    );
    assert_eq!(
        drust::mgmt::quota_admin::prune_decided_requests(&conn, -1).unwrap(),
        0,
        "a negative is operator error, not an instruction to empty the table"
    );
}

/// The budget is keyed on the TENANT, matching the one-pending-per-tenant 409.
#[test]
fn quota_submits_today_is_per_tenant_and_counts_decided_rows() {
    let (conn, _d) = plain_meta();
    insert_quota_request(&conn, "t-a", 2, "rejected", "-0 days", Some("-0 days"));
    insert_quota_request(&conn, "t-a", 3, "pending", "-0 days", None);
    insert_quota_request(&conn, "t-a", 4, "rejected", "-2 days", Some("-2 days"));
    insert_quota_request(&conn, "t-b", 2, "pending", "-0 days", None);

    assert_eq!(
        drust::mgmt::quota_admin::submits_today(&conn, "t-a").unwrap(),
        2,
        "today only, but a rejection still counts — that loop is why the limit exists"
    );
    assert_eq!(
        drust::mgmt::quota_admin::submits_today(&conn, "t-b").unwrap(),
        1
    );
    assert_eq!(
        drust::mgmt::quota_admin::submits_today(&conn, "t-nothing").unwrap(),
        0
    );
}

/// One janitor sweeps BOTH queues. Pinning it here is the point: the previous
/// pass shipped a janitor that swept only the cap queue.
#[test]
fn the_janitor_sweeps_both_request_queues_in_one_pass() {
    let (conn, _d) = plain_meta();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) \
         VALUES (2, 'mem', 'h', 'member')",
        [],
    )
    .unwrap();
    insert_quota_request(&conn, "t-a", 2, "rejected", "-200 days", Some("-200 days"));
    conn.execute(
        "INSERT INTO tenant_cap_requests \
             (requester_admin_id, requested_cap, status, created_at, \
              decided_by_admin_id, decided_at) \
         VALUES (2, 5, 'rejected', datetime('now','-200 days'), 1, datetime('now','-200 days'))",
        [],
    )
    .unwrap();

    let (cap, quota) = drust::mgmt::request_janitor::prune_once(&conn);
    assert_eq!(cap, 1, "the cap queue is swept");
    assert_eq!(quota, 1, "and so is the quota queue");
}

#[test]
fn quota_env_knobs_have_the_documented_defaults() {
    assert_eq!(
        drust::mgmt::quota_admin::request_retention_days(),
        drust::mgmt::quota_admin::DEFAULT_REQUEST_RETENTION_DAYS
    );
    assert_eq!(
        drust::mgmt::quota_admin::daily_submit_limit(),
        drust::mgmt::quota_admin::DEFAULT_DAILY_SUBMIT_LIMIT
    );
}

/// The 409 only stops two OPEN requests on one tenant; the reject → refile loop
/// walks straight past it and appends a row per iteration.
#[tokio::test]
async fn the_quota_reject_request_loop_is_rate_limited() {
    let (app, dir, owner, member) = seed().await;
    let limit = drust::mgmt::quota_admin::daily_submit_limit();
    assert!(limit > 0, "the default limit must be enforcing");

    for i in 0..limit {
        let (st, body) = send(
            &app,
            "POST",
            "/admin/tenants/t-member-b/quota/requests",
            &member,
            Some(serde_json::json!({"requested_tier": 2 + i})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "attempt {i}: {body}");
        let id = body["id"].as_i64().unwrap();
        let (st, body) = send(
            &app,
            "POST",
            &format!("/admin/quota-requests/{id}/decide"),
            &owner,
            Some(serde_json::json!({"action": "reject"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "rejection {i}: {body}");
    }

    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 2 + limit})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::TOO_MANY_REQUESTS,
        "the request after the day's budget must be refused: {body}"
    );
    assert_eq!(body["error_code"], "QUOTA_REQUEST_RATE_LIMITED");
    assert_eq!(
        count_quota_requests(&dir),
        limit,
        "the rate-limited attempt must not insert"
    );
}

/// Keyed on the tenant, so exhausting one tenant's budget must not lock the
/// same member out of another tenant they own.
#[tokio::test]
async fn the_quota_daily_limit_is_per_tenant() {
    let (app, _dir, owner, member) = seed().await;
    create_tenant_json(&app, &member, "t-member-c", "GammaCorp").await;
    let limit = drust::mgmt::quota_admin::daily_submit_limit();

    for i in 0..limit {
        let (st, body) = send(
            &app,
            "POST",
            "/admin/tenants/t-member-b/quota/requests",
            &member,
            Some(serde_json::json!({"requested_tier": 2 + i})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "attempt {i}: {body}");
        let id = body["id"].as_i64().unwrap();
        let (st, _) = send(
            &app,
            "POST",
            &format!("/admin/quota-requests/{id}/decide"),
            &owner,
            Some(serde_json::json!({"action": "reject"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    let (st, _) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 50})),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "t-member-b is spent");

    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-c/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 2})),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "the other tenant's budget is untouched: {body}"
    );
}

/// `remove_admin` deleted the removed admin's `tenant_cap_requests` but not
/// their `quota_requests`, so the recycled-rowid misattribution that fix was
/// written for was still live on the other queue.
///
/// `admins.id` is `INTEGER PRIMARY KEY` WITHOUT AUTOINCREMENT, so the next
/// invited teammate inherits the removed admin's id — and
/// `quota_requests_page` renders the requester by `LEFT JOIN admins a ON a.id =
/// q.requester_admin_id`. `decide_quota_request` re-validates the TENANT on
/// approve but never the requester, so on this queue there is no second layer:
/// the owner would approve a stranger's tier request under the new hire's name.
#[tokio::test]
async fn removing_an_admin_takes_their_quota_requests_with_them() {
    let (app, dir, owner, member) = seed().await;
    let alice_id = admin_id_of(&dir, "alice@example.com");

    let (st, body) = send(
        &app,
        "POST",
        "/admin/tenants/t-member-b/quota/requests",
        &member,
        Some(serde_json::json!({"requested_tier": 5, "reason": "growing"})),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    assert_eq!(count_quota_requests(&dir), 1);

    let (st, body) = send(
        &app,
        "DELETE",
        &format!("/admin/team/{alice_id}"),
        &owner,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "remove_admin must succeed: {body}");

    assert_eq!(
        count_quota_requests(&dir),
        0,
        "the orphan must not outlive its author"
    );

    // And prove the hazard it prevents: the next invited admin really does
    // inherit the freed rowid.
    let (bob_id, _bob) = insert_member(&dir, "bob@example.com");
    assert_eq!(
        bob_id, alice_id,
        "SQLite recycles the top rowid — this is why the delete above is mandatory"
    );
    let attributed_to_bob: i64 = {
        let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM quota_requests WHERE requester_admin_id = ?1",
            params![bob_id],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        attributed_to_bob, 0,
        "no queue row may be attributed to the new hire"
    );
}

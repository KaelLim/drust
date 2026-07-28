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

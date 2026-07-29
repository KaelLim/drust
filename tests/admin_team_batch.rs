//! Bulk-invite tests for `POST /admin/team/batch` — multi-email + role select.
//!
//! Mirrors the `admin_team_crud.rs` harness (bootstrap owner "root"/"hunter2",
//! run_migrations, cookie login). Verifies: bulk create + PATs, per-email skip
//! reporting (invalid / exists / duplicate), role selection, owner-only guard,
//! batch cap, and invalid-role rejection.

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

// ─── helpers (mirrored from admin_team_crud.rs) ──────────────────────────────

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

/// Insert an additional admin with a role, plus a session, returning the cookie.
fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, '$oauth-only$', ?2, ?3)",
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

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 262_144)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn batch(
    app: &axum::Router,
    cookie: &str,
    payload: serde_json::Value,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/team/batch")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn active_pat_count(dir: &tempfile::TempDir, admin_id: i64) -> i64 {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL",
        params![admin_id],
        |r| r.get(0),
    )
    .unwrap()
}

fn admin_role(dir: &tempfile::TempDir, email: &str) -> Option<String> {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    conn.query_row(
        "SELECT role FROM admins WHERE email = ?1 COLLATE NOCASE",
        params![email],
        |r| r.get(0),
    )
    .ok()
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn owner_bulk_invites_three_members() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;

    let resp = batch(
        &app,
        &cookie,
        serde_json::json!({
            "emails": ["a@example.com", "b@example.com", "c@example.com"],
            "role": "member"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "≥1 created → 201");
    let body = body_json(resp).await;
    let created = body["created"].as_array().unwrap();
    assert_eq!(created.len(), 3, "all three created: {body}");
    assert!(body["skipped"].as_array().unwrap().is_empty());

    for email in ["a@example.com", "b@example.com", "c@example.com"] {
        assert_eq!(admin_role(&dir, email).as_deref(), Some("member"));
    }
    // Each created admin has exactly one active PAT.
    for c in created {
        let id = c["id"].as_i64().unwrap();
        assert_eq!(active_pat_count(&dir, id), 1, "one PAT per created admin");
    }
}

#[tokio::test]
async fn batch_reports_existing_and_invalid_skips() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;
    // Pre-existing admin.
    insert_admin(&dir, "taken@example.com", "member");

    let resp = batch(
        &app,
        &cookie,
        serde_json::json!({
            "emails": ["fresh@example.com", "taken@example.com", "not-an-email"],
            "role": "member"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;

    let created = body["created"].as_array().unwrap();
    assert_eq!(created.len(), 1, "only the fresh one is created: {body}");
    assert_eq!(created[0]["email"], "fresh@example.com");

    let skipped = body["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 2, "two skipped: {body}");
    let reason_for = |email: &str| -> Option<String> {
        skipped
            .iter()
            .find(|s| s["email"] == email)
            .and_then(|s| s["reason"].as_str().map(String::from))
    };
    assert_eq!(reason_for("taken@example.com").as_deref(), Some("exists"));
    assert_eq!(reason_for("not-an-email").as_deref(), Some("invalid"));
}

#[tokio::test]
async fn batch_role_owner_creates_owners() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;

    let resp = batch(
        &app,
        &cookie,
        serde_json::json!({ "emails": ["boss@example.com"], "role": "owner" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        admin_role(&dir, "boss@example.com").as_deref(),
        Some("owner")
    );
}

#[tokio::test]
async fn batch_dedupes_within_request() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;

    let resp = batch(
        &app,
        &cookie,
        serde_json::json!({
            "emails": ["dup@example.com", "DUP@example.com", "dup@example.com"],
            "role": "member"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(
        body["created"].as_array().unwrap().len(),
        1,
        "created once: {body}"
    );
    // Within-batch duplicates are silently collapsed — no skip entries.
    assert_eq!(
        body["skipped"].as_array().unwrap().len(),
        0,
        "dupes deduped silently, not reported: {body}"
    );

    // Only one admin row exists for that address.
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let cnt: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM admins WHERE email = 'dup@example.com'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cnt, 1);
}

#[tokio::test]
async fn batch_rejects_malformed_addressbook_paste() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;

    // Angle-bracketed display-name form, double-@, and a dotless domain must all
    // be rejected as invalid — not silently turned into junk admin rows.
    let resp = batch(
        &app,
        &cookie,
        serde_json::json!({
            "emails": ["<alice@example.com>", "a@b@c.com", "bob@example", "carol@example.com"],
            "role": "member"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;

    let created = body["created"].as_array().unwrap();
    assert_eq!(
        created.len(),
        1,
        "only the well-formed address is created: {body}"
    );
    assert_eq!(created[0]["email"], "carol@example.com");

    let skipped = body["skipped"].as_array().unwrap();
    assert_eq!(
        skipped.len(),
        3,
        "three malformed addresses skipped: {body}"
    );
    assert!(
        skipped.iter().all(|s| s["reason"] == "invalid"),
        "all malformed → invalid: {body}"
    );

    // No junk admin row for the bracketed address.
    assert_eq!(admin_role(&dir, "<alice@example.com>"), None);
}

#[tokio::test]
async fn member_cannot_batch_invite() {
    let (app, dir) = spin_up().await;
    let (_, member_cookie) = insert_admin(&dir, "member@example.com", "member");

    let resp = batch(
        &app,
        &member_cookie,
        serde_json::json!({ "emails": ["x@example.com"], "role": "member" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    // v1.57 3-tier roles: a `member` caller is not a team manager. The gate is
    // now `require_manage_members` (owner|admin) → `NOT_A_MANAGER`, replacing
    // the former owner-only `NOT_OWNER`. Still a hard 403.
    assert_eq!(body["error_code"], "NOT_A_MANAGER");

    // Nothing was created.
    assert_eq!(admin_role(&dir, "x@example.com"), None);
}

#[tokio::test]
async fn batch_rejects_over_cap() {
    let (app, _dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;
    // Default cap is 50 → 51 emails is over.
    let emails: Vec<String> = (0..51).map(|i| format!("u{i}@example.com")).collect();

    let resp = batch(
        &app,
        &cookie,
        serde_json::json!({ "emails": emails, "role": "member" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error_code"], "TOO_MANY");
}

#[tokio::test]
async fn batch_rejects_invalid_role() {
    let (app, _dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;

    let resp = batch(
        &app,
        &cookie,
        serde_json::json!({ "emails": ["x@example.com"], "role": "superuser" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error_code"], "INVALID_ROLE");
}

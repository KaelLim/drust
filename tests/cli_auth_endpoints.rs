//! T6/T7 (CLI Phase 2 §S4) — CLI-PAT lifecycle endpoints + admin-UI management.
//!
//! Covers the three public self-authenticating endpoints
//!   GET    /auth/cli/whoami
//!   POST   /auth/cli/token/refresh
//!   DELETE /auth/cli/token
//! plus the cookie-gated admin-UI revoke route + settings-page listing.
//!
//! Helper shape modeled on `tests/admin_pat_reroll.rs` (spin_up / insert_admin /
//! body_json / OnceLock audit writer) and the labeled-CLI-PAT seeding from T4.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token::{generate_cli_token, hash_token};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::{TempDir, tempdir};
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── harness ────────────────────────────────────────────────────────────────

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

/// Spin up a mgmt router with one bootstrapped owner admin (id=1).
///
/// Production order (bootstrap_admin → run_migrations) so the backfill loop
/// mints admin 1's unlabeled UI PAT (with plaintext) — `ui_pat_of` reads it.
async fn spin_up() -> (axum::Router, TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    let app = state.with_data_dir(data_dir);
    (app, dir)
}

fn open_meta_ro(dir: &TempDir) -> Connection {
    Connection::open(dir.path().join("meta.sqlite")).unwrap()
}

/// Insert a labeled CLI PAT for `admin_id`; return `(row_id, plaintext)`.
/// Labeled rows do not collide with the unlabeled UI PAT under the relaxed
/// `uniq_admin_tokens_active` index.
fn insert_cli_pat(dir: &TempDir, admin_id: i64, label: &str) -> (i64, String) {
    let pt = generate_cli_token();
    let h = hash_token(&pt);
    let conn = open_meta_ro(dir);
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext, label, expires_at) \
         VALUES (?1, ?2, ?3, ?4, datetime('now','+1 day'))",
        params![admin_id, h, pt, label],
    )
    .unwrap();
    (conn.last_insert_rowid(), pt)
}

/// Seed a labeled CLI PAT for the bootstrapped admin (id=1). Returns
/// `(admin_id, plaintext)`.
fn seed_cli_pat(dir: &TempDir, label: &str) -> (i64, String) {
    let (_, pt) = insert_cli_pat(dir, 1, label);
    (1, pt)
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ─── T6 §4.3 — GET /auth/cli/whoami ──────────────────────────────────────────

#[tokio::test]
async fn whoami_returns_admin_consoles_and_tenants_endpoint() {
    let (app, dir) = spin_up().await;
    let (admin_id, pat) = seed_cli_pat(&dir, "cli:laptop");
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/cli/whoami")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = body_json(resp).await;
    assert_eq!(b["admin"]["id"], serde_json::json!(admin_id));
    assert_eq!(b["consoles"][0]["id"], "default");
    assert_eq!(b["tenants_endpoint"], "/admin/api/cmdk/tenants");
    assert!(b["consoles"].as_array().unwrap().len() == 1); // OSS cardinality 1
}

#[tokio::test]
async fn whoami_rejects_missing_bearer_with_json_401_not_redirect() {
    let (app, _dir) = spin_up().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/cli/whoami")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED); // JSON, never 303
    assert_eq!(body_json(resp).await["error_code"], "CLI_AUTH_REQUIRED");
}

// ─── read helpers (T6 refresh / logout / UI revoke) ───────────────────────────

fn hash_of(t: &str) -> String {
    hash_token(t)
}

fn post_bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// The bootstrapped admin's backfilled unlabeled UI PAT: `(admin_id, plaintext)`.
fn ui_pat_of(dir: &TempDir) -> (i64, String) {
    let conn = open_meta_ro(dir);
    conn.query_row(
        "SELECT admin_id, plaintext FROM _admin_tokens \
         WHERE revoked_at IS NULL AND label IS NULL",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

fn is_revoked(conn: &Connection, hash: &str) -> bool {
    let revoked: Option<String> = conn
        .query_row(
            "SELECT revoked_at FROM _admin_tokens WHERE token_hash = ?1",
            params![hash],
            |r| r.get(0),
        )
        .unwrap();
    revoked.is_some()
}

fn active_labeled_count(conn: &Connection, admin_id: i64) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM _admin_tokens \
         WHERE admin_id = ?1 AND label IS NOT NULL AND revoked_at IS NULL",
        params![admin_id],
        |r| r.get(0),
    )
    .unwrap()
}

// ─── T6 — POST /auth/cli/token/refresh ────────────────────────────────────────

#[tokio::test]
async fn refresh_mints_labeled_pat_and_revokes_only_the_old_one() {
    let (app, dir) = spin_up().await;
    let (admin_id, ui_pat) = ui_pat_of(&dir); // the backfilled unlabeled UI PAT
    let (_, old_cli) = seed_cli_pat(&dir, "cli:laptop");
    let old_hash = hash_of(&old_cli);
    let resp = app
        .oneshot(post_bearer("/auth/cli/token/refresh", &old_cli))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = body_json(resp).await;
    let new_tok = b["access_token"].as_str().unwrap();
    assert!(new_tok.starts_with("drust_pat_cli_")); // T4 generate_cli_token
    assert!(b["expires_at"].is_string());
    // old CLI PAT now revoked, new one active+labeled, UI PAT untouched
    let c = open_meta_ro(&dir);
    assert!(is_revoked(&c, &old_hash));
    assert_eq!(active_labeled_count(&c, admin_id), 1);
    assert!(!is_revoked(&c, &hash_of(&ui_pat))); // UI PAT survives
}

#[tokio::test]
async fn refresh_refuses_the_unlabeled_ui_pat() {
    let (app, dir) = spin_up().await;
    let (_, ui_pat) = ui_pat_of(&dir);
    let resp = app
        .oneshot(post_bearer("/auth/cli/token/refresh", &ui_pat))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["error_code"], "NOT_A_CLI_TOKEN");
}

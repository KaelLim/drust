//! v1.32 C1 — integration tests for GET /admin/_metrics.
//!
//! Test 1: with a valid admin session, returns 200 + body contains all 5
//!         counter/gauge names in Prometheus text format.
//! Test 2: without an admin session, returns 303 redirect to /drust/login
//!         (admin_session_layer gate).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn build_state(conn: rusqlite::Connection, data_dir: std::path::PathBuf) -> MgmtState {
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
        data_dir.clone(),
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = data_dir.join("audit");
    state
}

/// Spin up a full mgmt router with one bootstrapped owner admin and one
/// seeded tenant (so drust_tenant_db_bytes emits at least one label series
/// when the handler queries meta.sqlite). Returns the router + the temp dir.
async fn spin_up() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    std::fs::create_dir_all(data_dir.join("audit")).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    // Seed one tenant so tenant_db_bytes gauge has a label to emit.
    conn.execute(
        "INSERT INTO tenants (id, name, db_bytes) VALUES ('metrics-test-tenant-01', 'metrics-test', 4096)",
        [],
    )
    .unwrap();
    let state = build_state(conn, data_dir.clone());
    let router = state.with_data_dir(data_dir);
    (router, dir)
}

/// Insert a session row directly into meta.sqlite and return the cookie header
/// value `drust_session=<token>`.
fn insert_session(dir: &tempfile::TempDir) -> String {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let admin_id: i64 = conn
        .query_row("SELECT id FROM admins LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let token = "test_metrics_session_tok_AAAAAAAAAA";
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
    conn.execute(
        "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token, admin_id, expires_at.to_rfc3339()],
    )
    .unwrap();
    format!("drust_session={token}")
}

// ─── tests ────────────────────────────────────────────────────────────────────

/// Test 1: authenticated admin receives 200 with all 5 metric names in the body.
#[tokio::test]
async fn metrics_authenticated_returns_200_with_all_counter_names() {
    let (app, dir) = spin_up().await;
    let session = insert_session(&dir);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/_metrics")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "authenticated GET /admin/_metrics should return 200"
    );

    // Extract content-type before consuming the body.
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();

    // All 5 counter/gauge names must appear in the Prometheus exposition format.
    for name in &[
        "drust_audit_drops_total",
        "drust_bearer_denied_total",
        "drust_webhook_attempts_total",
        "drust_ws_connections_active",
        "drust_tenant_db_bytes",
    ] {
        assert!(
            body.contains(name),
            "Prometheus body missing metric {name}; excerpt:\n{}",
            &body[..body.len().min(2000)]
        );
    }

    // Content-Type should indicate Prometheus text exposition format.
    assert!(
        ct.contains("text/plain"),
        "Expected text/plain content-type for Prometheus format, got {ct:?}"
    );
    assert!(
        body.contains("# HELP") || body.contains("# TYPE"),
        "Prometheus body does not look like text exposition format"
    );
}

/// Test 2: unauthenticated request is rejected by admin_session_layer → 303.
#[tokio::test]
async fn metrics_unauthenticated_returns_303_redirect() {
    let (app, _dir) = spin_up().await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/_metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "unauthenticated GET /admin/_metrics should return 303; got {}",
        resp.status()
    );

    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.contains("login"),
        "303 redirect should point at login, got location={location:?}"
    );
}

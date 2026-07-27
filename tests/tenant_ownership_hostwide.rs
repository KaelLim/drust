//! v1.50 — host-wide sensitive admin surfaces are owner-only.
//!
//! Backups (all tenants' data + plaintext service/admin tokens), the host
//! audit view (row-level cross-tenant activity + full tenant roster), and host
//! metrics have no `{id}` param, so the tenant_ownership_layer passes them
//! through. They predate the member role; without an explicit owner gate a
//! member admin could enumerate every tenant and — via a backup download —
//! exfiltrate every tenant's credentials. Regression-pinned here.

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
    resp.headers()
        .get(header::SET_COOKIE)
        .expect("no Set-Cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn insert_member(dir: &tempfile::TempDir) -> String {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) \
         VALUES ('alice', '$oauth-only$', 'alice@example.com', 'member')",
        [],
    )
    .unwrap();
    let admin_id = conn.last_insert_rowid();
    let token = {
        use base64::Engine;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let exp = chrono::Utc::now() + chrono::Duration::days(7);
    conn.execute(
        "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token, admin_id, exp.to_rfc3339()],
    )
    .unwrap();
    format!("drust_session={token}")
}

async fn status_of(app: &axum::Router, cookie: &str, uri: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

// Backups (all tenants' data + plaintext tokens) and the host audit view
// (row-level cross-tenant activity) are owner-only. `/admin/_metrics` is NOT
// gated — Prometheus counters carry no tenant content/roster and the
// adversarial review did not flag it, so any authenticated admin may read it.
const HOST_WIDE: &[&str] = &["/admin/api/backups", "/admin/api/audit"];

#[tokio::test]
async fn member_admin_is_forbidden_on_host_wide_surfaces() {
    let (app, dir) = spin_up().await;
    let member = insert_member(&dir);
    for uri in HOST_WIDE {
        assert_eq!(
            status_of(&app, &member, uri).await,
            StatusCode::FORBIDDEN,
            "member must get 403 on host-wide surface {uri}"
        );
    }
}

#[tokio::test]
async fn owner_admin_reaches_host_wide_surfaces() {
    let (app, _dir) = spin_up().await;
    let owner = login(&app, "root", "hunter2").await;
    for uri in HOST_WIDE {
        let st = status_of(&app, &owner, uri).await;
        assert_ne!(
            st,
            StatusCode::FORBIDDEN,
            "owner must NOT be forbidden on {uri} (got {st})"
        );
    }
}

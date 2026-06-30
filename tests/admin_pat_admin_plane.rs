//! T5 end-to-end: a drust_pat_* bearer reaches host /admin/* on the full mgmt router.
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token;
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

/// Full mgmt router + admin id=1 + a known active PAT. Returns (router, pat).
async fn app() -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    conn.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') \
         WHERE admin_id = 1 AND revoked_at IS NULL",
        [],
    )
    .unwrap();
    let pat = admin_token::generate_token();
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (1, ?1)",
        params![admin_token::hash_token(&pat)],
    )
    .unwrap();
    let router = build_state(conn, data_dir.clone(), log_dir).with_data_dir(data_dir);
    (router, pat, dir)
}

#[tokio::test]
async fn pat_reaches_cmdk_tenants_json() {
    let (app, pat, _d) = app().await;
    let r = app
        .oneshot(
            Request::builder()
                .uri("/admin/api/cmdk/tenants")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "PAT must reach the admin plane");
}

#[tokio::test]
async fn pat_reaches_team_json_via_adminid_chain() {
    let (app, pat, _d) = app().await;
    let r = app
        .oneshot(
            Request::builder()
                .uri("/admin/team")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "AdminId->AdminProfileExt chain must resolve for a PAT caller"
    );
}

#[tokio::test]
async fn no_bearer_browser_302s_on_real_router() {
    let (app, _pat, _d) = app().await;
    let r = app
        .oneshot(
            Request::builder()
                .uri("/admin/api/cmdk/tenants")
                .header(header::ACCEPT, "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
}

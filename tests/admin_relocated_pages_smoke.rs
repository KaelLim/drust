//! Finding #4 relocation guard: GET→200 smoke for the two relocated admin pages
//! that had no dedicated coverage — `tenant_overview_page` (tenants/overview.rs)
//! and `tenant_files_admin_page` (tenants/files_page.rs). Drives the real
//! MgmtState admin router so the `pub use` re-export path is exercised end-to-end.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::session::create_session;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn app() -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let tok = create_session(&mut conn, 1, 3600).unwrap();
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
    (state.with_data_dir(data_dir.clone()), tok, dir)
}

async fn create_tenant(app: &axum::Router, tok: &str, id: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"id":"{id}","name":"Smoke"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "tenant create failed");
}

#[tokio::test]
async fn overview_page_renders_200() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "smoke1").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/tenants/smoke1/_overview")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "tenant_overview_page (tenants/overview.rs) must render 200 after relocation"
    );
}

#[tokio::test]
async fn files_admin_page_renders_200() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "smoke2").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/tenants/smoke2/_files")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "tenant_files_admin_page (tenants/files_page.rs) must render 200 after relocation"
    );
}

/// v1.36 — the new `ƒ _functions` admin page renders 200 on an empty tenant
/// (empty-state path), and the sidebar carries the `_functions` virtual entry.
/// Drives the real MgmtState router so the template + `TenantsState` field
/// plumbing (functions/functions_exec/fn_data_root) is exercised end-to-end —
/// the layer-stack/render bugs a oneshot catches but a unit test would miss.
#[tokio::test]
async fn functions_admin_page_renders_200() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "smoke3").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/tenants/smoke3/_functions")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("/admin/tenants/smoke3/_functions"),
        "sidebar must carry the _functions virtual entry"
    );
}

/// A delete on a non-existent function is idempotent — the admin handler 303s
/// back to the list rather than 500-ing.
#[tokio::test]
async fn functions_admin_delete_missing_redirects() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "smoke4").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/smoke4/_functions/nope/delete")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

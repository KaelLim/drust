//! Verifies legacy /admin/public-files routes 301 redirect to the new /admin/files paths.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn app() -> axum::Router {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    std::mem::forget(dir);
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
    state.log_dir = std::env::temp_dir();
    state.with_data_dir(data_dir)
}

#[tokio::test]
async fn legacy_public_files_redirects_to_files() {
    let app = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/public-files")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    // v1.56.2 deliberate contract change: this assertion used to pin the bare
    // `/admin/files`, i.e. the bug. `Location` is browser-facing, so it must
    // carry the external mount the proxy strips — every other redirect in the
    // codebase goes through `base_path::base`. This is the default-mode
    // oracle for that invariant; `tests/base_path_root.rs` covers empty mode.
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/drust/admin/files"
    );
}

#[tokio::test]
async fn legacy_public_files_reconcile_redirects() {
    let app = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/public-files/reconcile")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    // Same deliberate contract change as above — see the note there.
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/drust/admin/files/reconcile"
    );
}

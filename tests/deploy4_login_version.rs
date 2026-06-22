//! DEPLOY-4 follow-up (v1.41.3, found in adversarial review): `DRUST_HIDE_VERSION`
//! must also blank the version on the **unauthenticated** `/login` page, not just
//! the `x-drust-version` HTTP header. The login footer rendered `· v{{ version }}`
//! verbatim, so the build version leaked to any anonymous caller regardless of the
//! flag.
//!
//! This is the ONLY test in its own binary on purpose: `set_var`/`remove_var` mutate
//! process-global env, so both phases run sequentially in a single test to avoid
//! racing a parallel test in the same binary.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use drust::mgmt::routes::{MgmtState, build_mgmt_router};
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
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
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
    build_mgmt_router(state)
}

async fn login_body() -> String {
    let resp = app()
        .await
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn login_version_gated_by_hide_version_env() {
    let ver = env!("CARGO_PKG_VERSION");
    let needle = format!("v{ver}");

    // Phase 1 — flag unset (default): the login page DOES show the version.
    // SAFETY: single-test binary; no other test mutates env concurrently.
    unsafe {
        std::env::remove_var("DRUST_HIDE_VERSION");
    }
    let shown = login_body().await;
    assert!(
        shown.contains(&needle),
        "default /login must render the version ({needle}) in its footer"
    );

    // Phase 2 — flag set: the version is gone, but the page still renders.
    unsafe {
        std::env::set_var("DRUST_HIDE_VERSION", "1");
    }
    let hidden = login_body().await;
    assert!(
        !hidden.contains(&needle),
        "with DRUST_HIDE_VERSION set, /login must NOT render the version ({needle})"
    );
    assert!(
        hidden.contains("login") || hidden.contains("drust"),
        "/login must still render the login page when the version is hidden"
    );

    // Restore for any sibling work in this process.
    unsafe {
        std::env::remove_var("DRUST_HIDE_VERSION");
    }
}

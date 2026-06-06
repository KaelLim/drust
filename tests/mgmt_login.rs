use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::mgmt::routes::build_mgmt_router;
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

#[tokio::test]
async fn login_page_renders() {
    let app = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 256 KB cap — login page is ~80 KB post-v1.15 design overhaul
    // (mascot SVG + design tokens). Headroom for future polish.
    let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(s.contains("<form"));
    assert!(s.contains("name=\"username\""));
}

#[tokio::test]
async fn login_success_sets_cookie() {
    let app = app().await;
    let form = "username=root&password=hunter2";
    let resp = app
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
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(sc.starts_with("drust_session="));
    assert!(sc.contains("HttpOnly"));
}

#[tokio::test]
async fn login_bad_password_401() {
    let app = app().await;
    let form = "username=root&password=wrong";
    let resp = app
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
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_clears_cookie() {
    let app = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(sc.contains("Max-Age=0"));
}

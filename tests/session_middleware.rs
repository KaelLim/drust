use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use drust::auth::middleware::{admin_session_layer, AdminSessionState};
use drust::auth::session::create_session;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn test_app() -> (Router, String) {
    let dir = tempdir().unwrap();
    let mut conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    let token = create_session(&mut conn, 1, 3600).unwrap();
    let state = AdminSessionState { meta: Arc::new(Mutex::new(conn)) };
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(state.clone(), admin_session_layer))
        .with_state(state);
    // Leak dir handle to keep it alive
    std::mem::forget(dir);
    (app, token)
}

#[tokio::test]
async fn redirects_without_cookie() {
    let (app, _t) = test_app().await;
    let resp = app
        .oneshot(Request::builder().uri("/protected").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(resp.headers().get(header::LOCATION).is_some());
}

#[tokio::test]
async fn passes_with_valid_cookie() {
    let (app, t) = test_app().await;
    let req = Request::builder()
        .uri("/protected")
        .header(header::COOKIE, format!("drust_session={t}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn redirects_with_bad_cookie() {
    let (app, _t) = test_app().await;
    let req = Request::builder()
        .uri("/protected")
        .header(header::COOKIE, "drust_session=bogus")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

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
    let tok = create_session(&mut conn, 1, 3600).unwrap();
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        session_ttl_days: 7,
        garage: None,
        public_base_url: "http://localhost:8793".to_string(),
        max_upload_bytes: 52_428_800,
    };
    (state.with_data_dir(data_dir.clone()), tok, dir)
}

#[tokio::test]
async fn create_tenant_returns_initial_token() {
    let (app, tok, _d) = app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/admin/api/tenants")
        .header(header::COOKIE, format!("drust_session={tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"id":"blog","name":"Blog"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tenant"]["id"], "blog");
    assert!(v["initial_token"].as_str().unwrap().starts_with("drust_"));
}

#[tokio::test]
async fn rejects_bad_slug() {
    let (app, tok, _d) = app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/admin/api/tenants")
        .header(header::COOKIE, format!("drust_session={tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"id":"Bad Slug!!","name":"x"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn soft_delete_moves_to_trash() {
    let (app, tok, _d) = app().await;
    // First create
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"id":"blog2","name":"Blog"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/api/tenants/blog2")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

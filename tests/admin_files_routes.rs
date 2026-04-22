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
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        session_ttl_days: 7,
        garage: None,
        public_base_url: "http://localhost:8793".to_string(),
        max_upload_bytes: 52_428_800,
        garage_client_key_id: String::new(),
        disk_min_free_pct: 20,
    };
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
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/admin/files"
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
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/admin/files/reconcile"
    );
}

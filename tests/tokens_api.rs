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
    let data = dir.path().to_path_buf();
    let mut conn = open_meta(&data.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    let tok = create_session(&mut conn, 1, 3600).unwrap();
    // Pre-create a tenant to issue tokens against.
    conn.execute("INSERT INTO tenants (id, name) VALUES ('blog', 'b')", [])
        .unwrap();
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        session_ttl_days: 7,
    };
    (state.with_data_dir(data.clone()), tok, dir)
}

#[tokio::test]
async fn issue_token_returns_plaintext_once() {
    let (app, tok, _d) = app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/admin/api/tenants/blog/tokens")
        .header(header::COOKIE, format!("drust_session={tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"label":"prod"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["token"].as_str().unwrap().starts_with("drust_"));
    assert_eq!(v["label"], "prod");
}

#[tokio::test]
async fn revoke_token() {
    let (app, tok, _d) = app().await;
    // Issue
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants/blog/tokens")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id = v["id"].as_i64().unwrap();
    // Revoke
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/api/tenants/blog/tokens/{id}"))
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

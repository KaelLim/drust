//! v1.19.2 regression — user tokens cannot use `?filter` or `?sort` on
//! owner-scoped collections (SQL injection bypass of owner_field).

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use helpers::{register_and_login_via_app, spin_up_tenant_self_register};
use tower::ServiceExt;

async fn seed_owner_scoped_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = helpers::grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                owner_id TEXT NOT NULL REFERENCES _system_users(id),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json, owner_field, read_scope)
                  VALUES ('posts', '[\"select\"]', 'owner_id', 'own')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    owner_field = 'owner_id', read_scope = 'own';",
        )
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn user_filter_on_owner_scoped_returns_400() {
    let tid = "udeny-filter";
    let (app, _svc_tok, dir) = spin_up_tenant_self_register(tid).await;
    seed_owner_scoped_posts(&dir, tid).await;
    let user_tok = register_and_login_via_app(&app, tid, "u@example.com", "pw_long_enough").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/posts?filter=1%3D1)%20--%20"))
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 16_384)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error_code"], "USER_FILTER_DENIED_ON_OWNER_SCOPED");
}

#[tokio::test]
async fn user_sort_on_owner_scoped_returns_400() {
    let tid = "udeny-sort";
    let (app, _svc_tok, dir) = spin_up_tenant_self_register(tid).await;
    seed_owner_scoped_posts(&dir, tid).await;
    let user_tok = register_and_login_via_app(&app, tid, "u@example.com", "pw_long_enough").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/posts?sort=-title"))
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 16_384)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error_code"], "USER_FILTER_DENIED_ON_OWNER_SCOPED");
}

#[tokio::test]
async fn user_no_filter_on_owner_scoped_passes() {
    // Sanity: plain listing without filter/sort is allowed (owner clause
    // is auto-appended). No injection vector here.
    let tid = "udeny-plain";
    let (app, _svc_tok, dir) = spin_up_tenant_self_register(tid).await;
    seed_owner_scoped_posts(&dir, tid).await;
    let user_tok = register_and_login_via_app(&app, tid, "u@example.com", "pw_long_enough").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

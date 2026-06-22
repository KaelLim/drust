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

async fn seed_plain_notes(dir: &tempfile::TempDir, tenant: &str) {
    let pool = helpers::grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json, user_caps_json)
                  VALUES ('notes', '[\"select\"]', '[\"select\"]')
                  ON CONFLICT(collection_name) DO NOTHING;",
        )
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn user_filter_on_plain_collection_returns_403() {
    // F1 (audit 2026-06-22) — raw `?filter=` is denied for user tokens on ANY
    // collection, even a plain one with no owner_field/policy. The raw filter
    // is interpolated verbatim into build_list_sql and the read-only authorizer
    // allows reading any non-`_system_` sibling table, so a subquery bypasses
    // the per-collection cap boundary. Use POST /list (FilterAst) instead.
    let tid = "udeny-plain-f1";
    let (app, _svc_tok, dir) = spin_up_tenant_self_register(tid).await;
    seed_plain_notes(&dir, tid).await;
    let user_tok = register_and_login_via_app(&app, tid, "u@example.com", "pw_long_enough").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/notes?filter=1%3D1"))
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(resp.into_body(), 16_384)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error_code"], "RAW_FILTER_DENIED");
}

#[tokio::test]
async fn user_plain_list_on_plain_collection_passes() {
    // Sanity: a plain list with no filter/sort still works for a user token
    // (user_caps[select]); only the raw filter/sort param is denied.
    let tid = "uplain-ok-f1";
    let (app, _svc_tok, dir) = spin_up_tenant_self_register(tid).await;
    seed_plain_notes(&dir, tid).await;
    let user_tok = register_and_login_via_app(&app, tid, "u@example.com", "pw_long_enough").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/notes"))
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
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

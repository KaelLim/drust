//! RLS Phase 8 (Config) — service-only REST surface for managing per-op
//! policies: `PUT/GET /t/<id>/collections/<c>/policies` and
//! `DELETE /t/<id>/collections/<c>/policies/<op>`.
//!
//! - PUT replaces the policy set (one optional `Policy` per op); the body is
//!   validated against the live schema INSIDE the writer closure (TOCTOU-safe),
//!   so an unknown field reference is a 400 rather than a stored-but-broken
//!   policy.
//! - GET returns `{ "stored": CollectionPolicies }`.
//! - DELETE clears one op's policy column to NULL.
//! - The whole surface is service-only — anon/user are rejected with 403
//!   (matching the sibling `realtime` / `owner-field` collection-meta routes).
//!
//! Bare `/t/<id>/...` paths drive the axum Router via `oneshot` (Caddy is
//! bypassed in tests).

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use helpers::{grab_pool, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use tower::ServiceExt;

/// Create `posts(status TEXT)` via the pool (no REST create needed here).
async fn seed_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );",
        )
    })
    .await
    .unwrap();
}

/// PUT `/policies` with the given bearer, returning the status code.
async fn put_policies(app: &axum::Router, tid: &str, tok: &str, body: Value) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/t/{tid}/collections/posts/policies"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// GET `/policies` as service, returning the parsed JSON body.
async fn get_policies(app: &axum::Router, tid: &str, tok: &str) -> Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/collections/posts/policies"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET /policies should be 200");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// DELETE `/policies/<op>` as service, returning the status code.
async fn delete_policy(app: &axum::Router, tid: &str, tok: &str, op: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/t/{tid}/collections/posts/policies/{op}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn put_get_delete_policies_service_only() {
    let (app, tid, svc_tok, anon_tok, dir) = spin_up_dual_role_self_register("t-rlscfg1").await;
    seed_posts(&dir, &tid).await;

    let policy = json!({"select": {"using": {"status": "published"}}});

    // anon is rejected (service-only) before the handler does any work.
    assert_eq!(
        put_policies(&app, &tid, &anon_tok, policy.clone()).await,
        StatusCode::FORBIDDEN,
    );

    // service: set, read back, delete.
    assert_eq!(
        put_policies(&app, &tid, &svc_tok, policy.clone()).await,
        StatusCode::OK,
    );
    let got = get_policies(&app, &tid, &svc_tok).await;
    assert_eq!(got["stored"]["select"]["using"]["status"], "published");

    assert_eq!(
        delete_policy(&app, &tid, &svc_tok, "select").await,
        StatusCode::OK,
    );
    assert!(
        get_policies(&app, &tid, &svc_tok).await["stored"]["select"].is_null(),
        "select policy should be cleared after DELETE",
    );
}

#[tokio::test]
async fn put_policy_rejects_unknown_field() {
    let (app, tid, svc_tok, _anon_tok, dir) = spin_up_dual_role_self_register("t-rlscfg2").await;
    seed_posts(&dir, &tid).await;

    assert_eq!(
        put_policies(
            &app,
            &tid,
            &svc_tok,
            json!({"select": {"using": {"ghost": "x"}}}),
        )
        .await,
        StatusCode::BAD_REQUEST,
    );
}

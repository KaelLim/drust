//! v1.55 — REST `POST /t/<id>/collections/<c>/records:batch` tests (M2).
//!
//! Service-only bulk insert. anon/user → 403 WRITE_DENIED (they use single
//! `/records`). Atomicity + service owner_field-required are pinned here where
//! the REST harness (owner-field POST, /list) is convenient.

#[path = "helpers.rs"]
mod helpers;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

fn req(method: &str, tid: &str, path: &str, body: Option<Value>, token: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(
        body.map(|v| Body::from(v.to_string()))
            .unwrap_or(Body::empty()),
    )
    .unwrap()
}

async fn read_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn batch(app: &Router, tid: &str, body: Value, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(req(
            "POST",
            tid,
            "/collections/notes/records:batch",
            Some(body),
            token,
        ))
        .await
        .unwrap()
}

async fn setup_plain(tname: &str) -> (Router, String, tempfile::TempDir, String, String) {
    let (app, tid, svc, anon, dir) = helpers::spin_up_dual_role_self_register(tname).await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    helpers::create_collection_via_pool(&pool, "notes", &[("body", "text")]).await;
    (app, tid, dir, svc, anon)
}

#[tokio::test]
async fn service_batch_inserts_all() {
    let (app, tid, _dir, svc, _anon) = setup_plain("t-batch-svc").await;
    let r = batch(
        &app,
        &tid,
        json!({"records":[{"body":"a"},{"body":"b"}]}),
        &svc,
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(v["count"], 2);
    assert_eq!(v["inserted"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn anon_and_user_batch_denied() {
    let (app, tid, _dir, _svc, anon) = setup_plain("t-batch-deny").await;
    let r = batch(&app, &tid, json!({"records":[{"body":"x"}]}), &anon).await;
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "anon batch must be denied"
    );
    assert!(read_json(r).await.to_string().contains("WRITE_DENIED"));

    let ua = helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let r = batch(&app, &tid, json!({"records":[{"body":"y"}]}), &ua).await;
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "user batch must be denied"
    );
}

#[tokio::test]
async fn batch_atomic_bad_row_rolls_back() {
    let (app, tid, _dir, svc, _anon) = setup_plain("t-batch-atomic").await;
    // one good + one bad (unknown field) → the WHOLE batch fails, nothing lands.
    let r = batch(
        &app,
        &tid,
        json!({"records":[{"body":"ok"},{"nope":"x"}]}),
        &svc,
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // /list (service) confirms zero rows inserted.
    let r2 = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/collections/notes/list",
            Some(json!({})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(read_json(r2).await["total"], 0, "no partial insert");
}

#[tokio::test]
async fn service_owner_field_required_per_row() {
    let (app, tid, svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-batch-owner").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE notes (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id    TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                 body       TEXT,
                 created_at TEXT DEFAULT (datetime('now')),
                 updated_at TEXT DEFAULT (datetime('now'))
             );",
        )
    })
    .await
    .unwrap();
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/collections/notes/owner-field",
            Some(json!({"field":"user_id","read_scope":"own"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "set owner-field");

    // A batch row missing owner_field on an owner-scoped collection → 409.
    let r = batch(&app, &tid, json!({"records":[{"body":"x"}]}), &svc).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert!(
        read_json(r)
            .await
            .to_string()
            .contains("OWNER_FIELD_REQUIRED")
    );
}

//! v1.55 — REST `POST /t/<id>/collections/<c>/records:upsert` tests (M2).
//!
//! Service-only. anon/user → 403 WRITE_DENIED. Proves the insert-then-update
//! path, `UPSERT_NO_UNIQUE` on a non-declared conflict target, and
//! `UPSERT_MISSING_KEY` when a row omits the conflict key.

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

async fn upsert(
    app: &Router,
    tid: &str,
    records: Value,
    on_conflict: Value,
    token: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(req(
            "POST",
            tid,
            "/collections/products/records:upsert",
            Some(json!({"records": records, "on_conflict": on_conflict})),
            token,
        ))
        .await
        .unwrap()
}

/// `products(id PK, sku TEXT UNIQUE, name TEXT, created_at, updated_at)`.
async fn setup(tname: &str) -> (Router, String, tempfile::TempDir, String, String) {
    let (app, tid, svc, anon, dir) = helpers::spin_up_dual_role_self_register(tname).await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE products (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 sku        TEXT UNIQUE,
                 name       TEXT,
                 created_at TEXT DEFAULT (datetime('now')),
                 updated_at TEXT DEFAULT (datetime('now'))
             );",
        )
    })
    .await
    .unwrap();
    (app, tid, dir, svc, anon)
}

#[tokio::test]
async fn service_upsert_insert_then_update() {
    let (app, tid, _dir, svc, _anon) = setup("t-upsert-svc").await;

    // Insert two new rows.
    let r = upsert(
        &app,
        &tid,
        json!([{"sku":"a","name":"Apple"},{"sku":"b","name":"Banana"}]),
        json!(["sku"]),
        &svc,
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(v["count"], 2);
    assert!(
        v["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["op"] == "inserted"),
        "got {v}"
    );

    // Upsert same sku → update path.
    let r = upsert(
        &app,
        &tid,
        json!([{"sku":"a","name":"Apricot"}]),
        json!(["sku"]),
        &svc,
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(v["results"][0]["op"], "updated", "got {v}");
    assert_eq!(v["results"][0]["record"]["name"], "Apricot");

    // /list confirms exactly 2 rows (no duplicate).
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/collections/products/list",
            Some(json!({})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(read_json(r).await["total"], 2);
}

#[tokio::test]
async fn anon_and_user_upsert_denied() {
    let (app, tid, _dir, _svc, anon) = setup("t-upsert-deny").await;
    let r = upsert(
        &app,
        &tid,
        json!([{"sku":"a","name":"A"}]),
        json!(["sku"]),
        &anon,
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "anon upsert denied");
    assert!(read_json(r).await.to_string().contains("WRITE_DENIED"));

    let ua = helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let r = upsert(
        &app,
        &tid,
        json!([{"sku":"a","name":"A"}]),
        json!(["sku"]),
        &ua,
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "user upsert denied");
}

#[tokio::test]
async fn upsert_non_unique_target_rejected() {
    let (app, tid, _dir, svc, _anon) = setup("t-upsert-nouniq").await;
    // `name` is not unique → 400 UPSERT_NO_UNIQUE.
    let r = upsert(
        &app,
        &tid,
        json!([{"sku":"a","name":"A"}]),
        json!(["name"]),
        &svc,
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(read_json(r).await.to_string().contains("UPSERT_NO_UNIQUE"));
}

#[tokio::test]
async fn upsert_missing_key_rejected() {
    let (app, tid, _dir, svc, _anon) = setup("t-upsert-nokey").await;
    // Row omits the on_conflict key `sku` → 400 UPSERT_MISSING_KEY.
    let r = upsert(&app, &tid, json!([{"name":"NoSku"}]), json!(["sku"]), &svc).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(
        read_json(r)
            .await
            .to_string()
            .contains("UPSERT_MISSING_KEY")
    );
}

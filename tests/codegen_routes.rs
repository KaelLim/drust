//! v1.27 — verify the 3 codegen routes work end-to-end.

#[path = "helpers.rs"]
mod helpers;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use tower::ServiceExt;

const TENANT: &str = "acme";

/// Bring up a tenant with `posts` table + a description set on
/// `_system_collection_meta`, plus an anon token, returning
/// `(router, dir, service_bearer, anon_bearer)`.
async fn build_fixture_with_anon() -> (axum::Router, tempfile::TempDir, String, String) {
    // 1. Start with service-token bearer via the standard helper.
    let (app, svc_tok, dir) = helpers::spin_up_tenant_with_role(TENANT, "service").await;

    // 2. Add an anon token row to the same tenant.
    let meta_path = dir.path().join("meta.sqlite");
    let anon_tok = generate_token();
    rusqlite::Connection::open(&meta_path)
        .unwrap()
        .execute(
            "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'anon')",
            rusqlite::params![TENANT, hash_token(&anon_tok)],
        )
        .unwrap();

    // 3. Create the `posts` table + insert a description row into
    //    `_system_collection_meta` so we can prove anon strips it.
    let pool = helpers::grab_pool(TENANT, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL
            );
            INSERT INTO _system_collection_meta (collection_name, description)
                VALUES ('posts', 'DESCRIPTION_SHOULD_BE_HIDDEN')
                ON CONFLICT(collection_name) DO UPDATE SET description = excluded.description;",
        )
    })
    .await
    .unwrap();

    (app, dir, svc_tok, anon_tok)
}

#[tokio::test]
async fn openapi_route_returns_json_with_service_bearer() {
    let (app, _dir, svc_tok, _anon_tok) = build_fixture_with_anon().await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{TENANT}/openapi.json"))
                .header(header::AUTHORIZATION, format!("Bearer {svc_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "expected 200");
    let src = resp
        .headers()
        .get("X-Drust-Schema-Source")
        .expect("X-Drust-Schema-Source header missing")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(src, "service");

    let bytes = to_bytes(resp.into_body(), 1_048_576).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("body is JSON");
    assert_eq!(v["openapi"], "3.1.0", "openapi version: {v}");
    let paths = v["paths"].as_object().expect("paths is an object");
    let expected_path = format!("/t/{TENANT}/records/posts");
    assert!(
        paths.contains_key(&expected_path),
        "paths should contain {expected_path}; got keys: {:?}",
        paths.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn anon_does_not_see_description() {
    let (app, _dir, _svc_tok, anon_tok) = build_fixture_with_anon().await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{TENANT}/types.ts"))
                .header(header::AUTHORIZATION, format!("Bearer {anon_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "expected 200");
    let src = resp
        .headers()
        .get("X-Drust-Schema-Source")
        .expect("X-Drust-Schema-Source header missing")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(src, "anon");

    let bytes = to_bytes(resp.into_body(), 1_048_576).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !body.contains("DESCRIPTION_SHOULD_BE_HIDDEN"),
        "anon body leaked the description; body was:\n{body}"
    );
}

#[tokio::test]
async fn service_sees_description() {
    let (app, _dir, svc_tok, _anon_tok) = build_fixture_with_anon().await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{TENANT}/types.ts"))
                .header(header::AUTHORIZATION, format!("Bearer {svc_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "expected 200");

    let bytes = to_bytes(resp.into_body(), 1_048_576).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        body.contains("DESCRIPTION_SHOULD_BE_HIDDEN"),
        "service body should contain the description; body was:\n{body}"
    );
}

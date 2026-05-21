//! Integration tests for v1.19 schema description read paths.
//!
//! Tests (5 total):
//! 1. list_collections_omits_description_when_unset
//! 2. list_collections_includes_description_when_set
//! 3. describe_collection_carries_all_three_levels
//! 4. get_schema_overview_returns_collections_and_rpcs
//! 5. schema_overview_anon_denied

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use helpers::{grab_pool, spin_up_tenant_with_role};
use tower::ServiceExt;

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Perform a GET request with the given bearer token; return (status, body JSON).
async fn get_json(
    app: &axum::Router,
    uri: &str,
    tok: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Perform a PUT request with JSON body; return (status, body JSON).
async fn put_json(
    app: &axum::Router,
    uri: &str,
    tok: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Perform a POST request with JSON body; return (status, body JSON).
async fn post_json(
    app: &axum::Router,
    uri: &str,
    tok: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Seed a `posts` collection with a `title TEXT` field via raw SQL.
async fn seed_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta (collection_name, anon_caps_json)
             VALUES ('posts', '[\"select\"]')
             ON CONFLICT DO NOTHING;",
        )
    })
    .await
    .unwrap();
}

// ── Test 1 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_collections_omits_description_when_unset() {
    let tid = "rd-omit-desc";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    seed_posts(&dir, tid).await;

    let (status, body) = get_json(&app, &format!("/t/{tid}/collections"), &tok).await;
    assert_eq!(status, StatusCode::OK, "list failed: {body}");

    let arr = body["collections"].as_array().unwrap();
    let posts = arr.iter().find(|c| c["name"] == "posts").unwrap();
    assert!(
        posts.get("description").is_none() || posts["description"].is_null(),
        "description must be absent/null when unset; got {posts:?}"
    );
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_collections_includes_description_when_set() {
    let tid = "rd-list-has-desc";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    seed_posts(&dir, tid).await;

    let (set_status, set_body) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/description"),
        &tok,
        serde_json::json!({ "description": "User blog posts" }),
    )
    .await;
    assert_eq!(set_status, StatusCode::OK, "set description failed: {set_body}");

    let (status, body) = get_json(&app, &format!("/t/{tid}/collections"), &tok).await;
    assert_eq!(status, StatusCode::OK, "list failed: {body}");

    let arr = body["collections"].as_array().unwrap();
    let posts = arr.iter().find(|c| c["name"] == "posts").unwrap();
    assert_eq!(
        posts["description"],
        serde_json::json!("User blog posts"),
        "description missing from list; got {posts:?}"
    );
}

// ── Test 3 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn describe_collection_carries_all_three_levels() {
    let tid = "rd-three-levels";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    seed_posts(&dir, tid).await;

    // Set collection-level description.
    let (s, b) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/description"),
        &tok,
        serde_json::json!({ "description": "Blog posts" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "set coll desc: {b}");

    // Set field-level description on `title`.
    let (s, b) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/fields/title/description"),
        &tok,
        serde_json::json!({ "description": "Post title" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "set field desc: {b}");

    // Create an index on `title` so we can set an index description.
    let (s, b) = post_json(
        &app,
        &format!("/t/{tid}/collections/posts/indexes"),
        &tok,
        serde_json::json!({ "fields": ["title"] }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "create index: {b}");
    let idx_name = b["name"].as_str().unwrap().to_string();

    // Set index-level description.
    let (s, b) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/indexes/{idx_name}/description"),
        &tok,
        serde_json::json!({ "description": "Quick title lookup" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "set idx desc: {b}");

    // Describe the collection and check all three levels.
    let (status, cs) = get_json(&app, &format!("/t/{tid}/collections/posts"), &tok).await;
    assert_eq!(status, StatusCode::OK, "describe: {cs}");

    assert_eq!(cs["description"], serde_json::json!("Blog posts"), "collection desc");

    let title = cs["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "title")
        .unwrap();
    assert_eq!(title["description"], serde_json::json!("Post title"), "field desc");

    let idx = cs["indices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == idx_name.as_str())
        .unwrap();
    assert_eq!(idx["description"], serde_json::json!("Quick title lookup"), "index desc");
}

// ── Test 4 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_schema_overview_returns_collections_and_rpcs() {
    let tid = "rd-overview-ok";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    seed_posts(&dir, tid).await;

    let (s, b) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/description"),
        &tok,
        serde_json::json!({ "description": "Blog posts" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "set desc: {b}");

    let (status, body) = get_json(&app, &format!("/t/{tid}/schema/overview"), &tok).await;
    assert_eq!(status, StatusCode::OK, "overview failed: {body}");

    assert!(body["tenant"].is_string(), "tenant must be a string: {body}");
    assert!(body["collections"].is_array(), "collections must be an array: {body}");
    assert!(body["rpcs"].is_array(), "rpcs must be an array: {body}");

    let posts = body["collections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "posts")
        .unwrap();
    assert_eq!(posts["description"], serde_json::json!("Blog posts"), "description in overview");
}

// ── Test 5 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn schema_overview_anon_denied() {
    let tid = "rd-overview-anon";
    let (app, tok, _dir) = spin_up_tenant_with_role(tid, "anon").await;

    let (status, body) = get_json(&app, &format!("/t/{tid}/schema/overview"), &tok).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "expected 403, got: {status} {body}");
    assert_eq!(body["error_code"], "WRITE_DENIED");
}

//! Integration tests for v1.19 schema-description write surfaces:
//! REST PUT endpoints + create_collection/create_index description param.
//!
//! Tests (8 total):
//! 1. rest_set_collection_description_roundtrip
//! 2. rest_set_field_description_not_found_when_field_missing
//! 3. rest_set_index_description_not_found_when_index_missing
//! 4. rest_set_description_on_protected_returns_403
//! 5. rest_set_description_too_long_returns_422
//! 6. rest_set_description_anon_denied
//! 7. create_collection_with_description_persists
//! 8. drop_index_cleans_index_descriptions_blob

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use helpers::{grab_pool, spin_up_tenant_with_role};
use tower::ServiceExt;

/// Helper: PUT JSON body to a path, return (status, parsed JSON body).
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
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Seed a collection via raw SQL on the pool (bypasses MCP/REST path).
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

/// Seed a posts collection AND a named index.
async fn seed_posts_with_index(dir: &tempfile::TempDir, tenant: &str) -> String {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE INDEX IF NOT EXISTS idx_posts_title ON posts (title);
             INSERT INTO _system_collection_meta (collection_name, anon_caps_json)
             VALUES ('posts', '[\"select\"]')
             ON CONFLICT DO NOTHING;",
        )
    })
    .await
    .unwrap();
    "idx_posts_title".to_string()
}

// ── Test 1 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rest_set_collection_description_roundtrip() {
    let tid = "desc-coll-rt";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    seed_posts(&dir, tid).await;

    // Set description.
    let (status, body) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/description"),
        &tok,
        serde_json::json!({ "description": "Blog post entries" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "set failed: {body}");
    assert_eq!(body["description"], "Blog post entries");

    // Clear with empty string.
    let (status2, body2) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/description"),
        &tok,
        serde_json::json!({ "description": "" }),
    )
    .await;
    assert_eq!(status2, StatusCode::OK, "clear failed: {body2}");
    // After clearing, description should be null / absent.
    assert!(
        body2["description"].is_null(),
        "expected null description after clear, got: {body2}"
    );
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rest_set_field_description_not_found_when_field_missing() {
    let tid = "desc-field-404";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    seed_posts(&dir, tid).await;

    let (status, body) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/fields/nonexistent/description"),
        &tok,
        serde_json::json!({ "description": "Ghost field" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404, got: {status} {body}");
    assert_eq!(body["error_code"], "FIELD_NOT_FOUND");
}

// ── Test 3 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rest_set_index_description_not_found_when_index_missing() {
    let tid = "desc-idx-404";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    seed_posts(&dir, tid).await;

    let (status, body) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/indexes/idx_does_not_exist/description"),
        &tok,
        serde_json::json!({ "description": "Ghost index" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404, got: {status} {body}");
    assert_eq!(body["error_code"], "INDEX_NOT_FOUND");
}

// ── Test 4 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rest_set_description_on_protected_returns_403() {
    let tid = "desc-protected";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    // _system_files is a protected collection name (starts with _system_).
    // We don't need to create it — the protection check fires before existence.
    let _ = dir; // keep dir alive

    let (status, body) = put_json(
        &app,
        &format!("/t/{tid}/collections/_system_files/description"),
        &tok,
        serde_json::json!({ "description": "Should be rejected" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "expected 403, got: {status} {body}");
    assert_eq!(body["error_code"], "PROTECTED_COLLECTION");
}

// ── Test 5 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rest_set_description_too_long_returns_422() {
    let tid = "desc-toolong";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    seed_posts(&dir, tid).await;

    // 2049-byte string exceeds MAX_DESCRIPTION_BYTES (2048).
    let long_desc = "a".repeat(2049);
    let (status, body) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/description"),
        &tok,
        serde_json::json!({ "description": long_desc }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "expected 422, got: {status} {body}");
    assert_eq!(body["error_code"], "DESCRIPTION_TOO_LONG");
}

// ── Test 6 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rest_set_description_anon_denied() {
    let tid = "desc-anon";
    // Use anon role.
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "anon").await;
    seed_posts(&dir, tid).await;

    let (status, body) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/description"),
        &tok,
        serde_json::json!({ "description": "Anon should not set this" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "expected 403, got: {status} {body}");
    assert_eq!(body["error_code"], "WRITE_DENIED");
}

// ── Test 7 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_collection_with_description_persists() {
    use drust::mcp::server::McpRegistry;
    use drust::storage::pool::TenantRegistry;
    use std::sync::Arc;

    let d = tempfile::tempdir().unwrap();
    let data = d.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "desc-create").unwrap();
    let reg = McpRegistry::new(tr);
    let mcp = reg.get_or_create("desc-create").await.unwrap();

    drust::mcp::tools::schema::create_collection_with_desc(
        &mcp,
        "articles",
        &[drust::mcp::tools::schema::FieldSpec {
            name: "body".into(),
            sql_type: "text".into(),
            nullable: true,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
            description: None,
        }],
        Some("Article collection for tests"),
    )
    .await
    .unwrap();

    // Verify via describe_collection.
    let pool = mcp.inner().pool.clone();
    let schema = pool
        .with_reader(|c| drust::storage::schema::describe_collection(c, "articles"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        schema.description.as_deref(),
        Some("Article collection for tests"),
        "collection description not persisted"
    );
}

// ── Test 9 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_collection_with_per_field_description_persists() {
    use drust::mcp::server::McpRegistry;
    use drust::storage::pool::TenantRegistry;
    use std::sync::Arc;

    let d = tempfile::tempdir().unwrap();
    let data = d.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "desc-field-create").unwrap();
    let reg = McpRegistry::new(tr);
    let mcp = reg.get_or_create("desc-field-create").await.unwrap();

    drust::mcp::tools::schema::create_collection_with_desc(
        &mcp,
        "posts",
        &[
            drust::mcp::tools::schema::FieldSpec {
                name: "title".into(),
                sql_type: "text".into(),
                nullable: true,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: Some("Post title".into()),
            },
            drust::mcp::tools::schema::FieldSpec {
                name: "body".into(),
                sql_type: "text".into(),
                nullable: true,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: Some("Markdown body".into()),
            },
        ],
        Some("Blog posts"),
    )
    .await
    .unwrap();

    // Verify via describe_collection.
    let pool = mcp.inner().pool.clone();
    let schema = pool
        .with_reader(|c| drust::storage::schema::describe_collection(c, "posts"))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        schema.description.as_deref(),
        Some("Blog posts"),
        "collection description not persisted"
    );

    let title_field = schema.fields.iter().find(|f| f.name == "title").unwrap();
    assert_eq!(
        title_field.description.as_deref(),
        Some("Post title"),
        "title field description not persisted"
    );

    let body_field = schema.fields.iter().find(|f| f.name == "body").unwrap();
    assert_eq!(
        body_field.description.as_deref(),
        Some("Markdown body"),
        "body field description not persisted"
    );
}

// ── Test 8 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn drop_index_cleans_index_descriptions_blob() {
    let tid = "desc-drop-idx";
    let (app, tok, dir) = spin_up_tenant_with_role(tid, "service").await;
    let idx_name = seed_posts_with_index(&dir, tid).await;

    // Set a description on the auto-named index.
    let (status, body) = put_json(
        &app,
        &format!("/t/{tid}/collections/posts/indexes/{idx_name}/description"),
        &tok,
        serde_json::json!({ "description": "Index on title for fast lookups" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "set index desc failed: {body}");

    // Verify description was persisted in the blob.
    let pool = grab_pool(tid, &dir).await;
    let raw: Option<String> = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT index_descriptions_json FROM _system_collection_meta
                  WHERE collection_name = 'posts'",
                [],
                |r| r.get::<_, Option<String>>(0),
            )
        })
        .await
        .unwrap();
    let map: serde_json::Value = serde_json::from_str(raw.as_deref().unwrap_or("{}")).unwrap();
    assert!(
        map.get(&idx_name).is_some(),
        "description key should exist before drop"
    );

    // Drop the index via the tenant REST endpoint.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/t/{tid}/collections/posts/indexes/{idx_name}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "drop index failed");

    // Verify the key was removed from the blob.
    let raw2: Option<String> = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT index_descriptions_json FROM _system_collection_meta
                  WHERE collection_name = 'posts'",
                [],
                |r| r.get::<_, Option<String>>(0),
            )
        })
        .await
        .unwrap();
    let map2: serde_json::Value = serde_json::from_str(raw2.as_deref().unwrap_or("{}")).unwrap();
    assert!(
        map2.get(&idx_name).is_none(),
        "description key should be gone after drop_index, got: {map2}"
    );
}

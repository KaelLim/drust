//! Task 19 (RLS Phase 8 · Config) — integration tests for the admin-plane
//! policy editor route. Mirrors `tests/admin_description_write.rs`: mounts only
//! the policy route without admin-session middleware (handler-level assertions,
//! not auth-gate testing). The admin UI itself holds the admin session, so the
//! handler writes directly via `write_policy` + `schema_cache.invalidate` — the
//! same shape as `update_anon_caps` / `admin_update_collection_description`.
//!
//! Cases:
//!   1. happy path — set a select+update policy → 200 {"ok":true}, stored in DB
//!   2. _system_* collection → 403
//!   3. unknown collection → 404
//!   4. invalid policy (unknown field) → 400 POLICY_INVALID
//!   5. clear — null body clears all four columns → 200, read_policies empty

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::post;
use drust::mgmt::browse::admin_update_policies;
use drust::mgmt::tenants::TenantsState;
use drust::storage::meta::open_meta;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn build_app(tenant_id: &str) -> (Router, std::path::PathBuf, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant_id],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data_dir, tenant_id).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let state = TenantsState::test_default(meta, data_dir.clone(), tenants, mcp, bus, bus_rooms);
    let app = Router::new()
        .route(
            "/admin/tenants/{id}/collections/{coll}/policies",
            post(admin_update_policies),
        )
        .with_state(state);
    (app, data_dir, dir)
}

/// Seed a `posts` collection with a `status` text field so policies referencing
/// `status` validate.
async fn seed_posts(data_dir: &std::path::Path, tenant_id: &str) {
    let pool = drust::storage::pool::TenantRegistry::new(data_dir.to_path_buf(), 2);
    let pool = pool.get_or_open(tenant_id).unwrap();
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT,
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

async fn post_json(app: &Router, uri: &str, body: serde_json::Value) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn read_stored(data_dir: &std::path::Path, tenant_id: &str) -> drust::query::policy::CollectionPolicies {
    let pool = drust::storage::pool::TenantRegistry::new(data_dir.to_path_buf(), 2);
    let pool = pool.get_or_open(tenant_id).unwrap();
    pool.with_reader(|c| drust::storage::schema::read_policies(c, "posts"))
        .await
        .unwrap()
}

#[tokio::test]
async fn admin_set_policy_happy_path() {
    let tid = "admin-policy-happy";
    let (app, data_dir, _d) = build_app(tid).await;
    seed_posts(&data_dir, tid).await;

    let resp = post_json(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/policies"),
        serde_json::json!({
            "select": {"using": {"status": "published"}},
            "update": {"using": {"status": "draft"}, "check": {"status": "draft"}}
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "expected 200");

    let stored = read_stored(&data_dir, tid).await;
    assert!(stored.select.is_some(), "select policy persisted");
    assert!(stored.update.is_some(), "update policy persisted");
    assert!(stored.insert.is_none(), "insert left unset");
    assert!(stored.delete.is_none(), "delete left unset");
}

#[tokio::test]
async fn admin_set_policy_protected_returns_403() {
    let tid = "admin-policy-protected";
    let (app, _data_dir, _d) = build_app(tid).await;

    let resp = post_json(
        &app,
        &format!("/admin/tenants/{tid}/collections/_system_files/policies"),
        serde_json::json!({"select": {"using": {"status": "x"}}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "expected 403");
}

#[tokio::test]
async fn admin_set_policy_unknown_collection_404() {
    let tid = "admin-policy-404";
    let (app, _data_dir, _d) = build_app(tid).await;

    let resp = post_json(
        &app,
        &format!("/admin/tenants/{tid}/collections/ghost/policies"),
        serde_json::json!({"select": {"using": {"status": "x"}}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "expected 404");
}

#[tokio::test]
async fn admin_set_policy_invalid_field_400() {
    let tid = "admin-policy-invalid";
    let (app, data_dir, _d) = build_app(tid).await;
    seed_posts(&data_dir, tid).await;

    let resp = post_json(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/policies"),
        serde_json::json!({"select": {"using": {"no_such_field": "x"}}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "expected 400");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "POLICY_INVALID", "got: {v}");
}

#[tokio::test]
async fn admin_clear_policies_via_null_body() {
    let tid = "admin-policy-clear";
    let (app, data_dir, _d) = build_app(tid).await;
    seed_posts(&data_dir, tid).await;

    // First set a select policy.
    let resp = post_json(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/policies"),
        serde_json::json!({"select": {"using": {"status": "published"}}}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(read_stored(&data_dir, tid).await.select.is_some());

    // Empty body (all None) clears everything.
    let resp = post_json(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/policies"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = read_stored(&data_dir, tid).await;
    assert!(stored.is_empty(), "all policy columns cleared");
}

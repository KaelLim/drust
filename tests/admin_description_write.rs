//! v1.19.1 integration tests for admin POST description routes.
//! Mirrors the `tests/admin_webhook_handlers.rs` shape — mounts only the
//! description routes without admin-session middleware (handler-level
//! assertions, not auth-gate testing). 4 tests:
//!   1. collection description happy path → 303
//!   2. _system_* collection → 403 PROTECTED_COLLECTION
//!   3. unknown field → 404
//!   4. NUL byte → 303 with ?desc_error=DESCRIPTION_INVALID

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::post;
use drust::mgmt::browse::{
    admin_update_collection_description, admin_update_field_description,
    admin_update_index_description,
};
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
    // Materialise the tenant's data.sqlite so the schema is in place.
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
            "/admin/tenants/{id}/collections/{coll}/description",
            post(admin_update_collection_description),
        )
        .route(
            "/admin/tenants/{id}/collections/{coll}/fields/{field}/description",
            post(admin_update_field_description),
        )
        .route(
            "/admin/tenants/{id}/collections/{coll}/indexes/{idx}/description",
            post(admin_update_index_description),
        )
        .with_state(state);
    (app, data_dir, dir)
}

/// Seed a fresh `posts` collection in the tenant DB so the existence
/// checks pass.
async fn seed_posts(data_dir: &std::path::Path, tenant_id: &str) {
    let pool = drust::storage::pool::TenantRegistry::new(data_dir.to_path_buf(), 2);
    let pool = pool.get_or_open(tenant_id).unwrap();
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

async fn post_form(app: &Router, uri: &str, body: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn admin_set_collection_description_happy_path() {
    let tid = "admin-desc-coll";
    let (app, data_dir, _d) = build_app(tid).await;
    seed_posts(&data_dir, tid).await;

    let resp = post_form(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/description"),
        "description=Blog%20posts",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "expected 303");
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.contains(&format!("/collections/posts?tab=schema")),
        "got: {loc}"
    );
}

#[tokio::test]
async fn admin_set_description_on_protected_returns_403() {
    let tid = "admin-desc-protected";
    let (app, _data_dir, _d) = build_app(tid).await;

    let resp = post_form(
        &app,
        &format!("/admin/tenants/{tid}/collections/_system_files/description"),
        "description=nope",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "expected 403");
}

#[tokio::test]
async fn admin_set_field_description_404_when_field_missing() {
    let tid = "admin-desc-field-404";
    let (app, data_dir, _d) = build_app(tid).await;
    seed_posts(&data_dir, tid).await;

    let resp = post_form(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/fields/nonexistent/description"),
        "description=ghost",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "expected 404");
}

#[tokio::test]
async fn admin_set_description_nul_redirects_with_desc_error() {
    let tid = "admin-desc-nul";
    let (app, data_dir, _d) = build_app(tid).await;
    seed_posts(&data_dir, tid).await;

    let resp = post_form(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/description"),
        "description=hello%00world",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "expected 303");
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(loc.contains("desc_error=DESCRIPTION_INVALID"), "got: {loc}");
}

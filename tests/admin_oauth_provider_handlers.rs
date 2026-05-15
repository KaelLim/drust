//! T1: zombie-tenant guard on the admin-UI `_oauth_providers` POST handlers
//! (`upsert` and `<provider>/delete`). Both call `state.tenants.get_or_open`
//! which would otherwise materialise `tenants/<bogus_id>/data.sqlite` for
//! any admin-typed path. The GET render already runs `load_tenant_shell`
//! first; this test asserts the POST paths now share the same guard.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use drust::auth::middleware::AdminSessionState;
use drust::mgmt::tenants::{
    tenant_oauth_provider_delete, tenant_oauth_provider_upsert, tenant_oauth_providers_page,
    TenantsState,
};
use drust::storage::meta::open_meta;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Build a minimal `axum::Router` that mounts the three `_oauth_providers`
/// handlers without the admin-session middleware. Tests assert the
/// handler-level guard, not the auth gate.
fn build_app() -> (Router, std::path::PathBuf, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
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
    let session = AdminSessionState { meta: meta.clone() };
    let state = TenantsState {
        session,
        data_dir: data_dir.clone(),
        garage: None,
        garage_client_key_id: String::new(),
        max_upload_bytes: 1024 * 1024,
        disk_min_free_pct: 20,
        public_base_url: "http://localhost".to_string(),
        tenants,
        mcp,
        bus,
        log_dir: data_dir.join("logs"),
        index_large_table_rows: 1_000_000,
    };
    let app = Router::new()
        .route(
            "/admin/tenants/{id}/_oauth_providers",
            get(tenant_oauth_providers_page).post(tenant_oauth_provider_upsert),
        )
        .route(
            "/admin/tenants/{id}/_oauth_providers/{provider}/delete",
            post(tenant_oauth_provider_delete),
        )
        .with_state(state);
    (app, data_dir, dir)
}

#[tokio::test]
async fn delete_bogus_tenant_returns_404_and_does_not_create_dir() {
    let (app, data_dir, _td) = build_app();
    let bogus = "00000000-0000-4000-8000-000000000bad";

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/admin/tenants/{bogus}/_oauth_providers/google/delete"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "expected 404");

    let zombie = data_dir.join("tenants").join(bogus);
    assert!(
        !zombie.exists(),
        "zombie tenant dir was materialised at {zombie:?}"
    );
}

#[tokio::test]
async fn upsert_bogus_tenant_returns_404_and_does_not_create_dir() {
    let (app, data_dir, _td) = build_app();
    let bogus = "00000000-0000-4000-8000-000000bad002";

    let form_body = "provider=google\
                     &client_id=cid\
                     &client_secret=csec\
                     &allowed_redirect_uris=https%3A%2F%2Fapp.example.com%2Fcb";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/tenants/{bogus}/_oauth_providers"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "expected 404");

    let zombie = data_dir.join("tenants").join(bogus);
    assert!(
        !zombie.exists(),
        "zombie tenant dir was materialised at {zombie:?}"
    );
}

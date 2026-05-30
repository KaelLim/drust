//! v1.31.5 — integration tests for GET /admin/tenants/{id}/_broadcast.
//!
//! Asserts:
//!   1. 200 + render carries id="ws-url" with the load-bearing /drust prefix
//!      + hidden bearer field + tenant_id appears the expected number of times.
//!   2. Non-existent tenant id → 404.
//!   3. Tenant whose service token has no plaintext (legacy hash-only) →
//!      200 + bearer-missing banner + Connect button disabled.
//!   4. Cross-tenant render leak: render for tenant A, body contains no
//!      string of tenant B's id and no string of tenant B's service bearer.
//!   5. Invalid tenant id (validate_tenant_id rejects) → 400.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use drust::mgmt::admin_profile::AdminProfileExt;
use drust::mgmt::tenant_broadcast::broadcast_inspector_page;
use drust::mgmt::tenants::TenantsState;
use drust::storage::meta::open_meta;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Build a minimal `axum::Router` with the broadcast handler mounted directly
/// (no admin-session middleware — tests assert handler-level behaviour, not
/// the auth gate). Seeds three tenants:
///   - tenant-a-1234: has plaintext service bearer
///   - tenant-b-9999: has plaintext service bearer (separate string for the
///     cross-leak test)
///   - tenant-c-5555: legacy hash-only (plaintext IS NULL)
///
/// `AdminProfileExt::placeholder()` is injected as an extension because the
/// handler signature requires it; `LocaleHint` and `ThemeHint` have built-in
/// defaults via `FromRequestParts`, so no locale/theme middleware is needed.
async fn build_app() -> Router {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();

    // Tenant A: has plaintext service bearer.
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'alpha')",
        rusqlite::params!["tenant-a-1234"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, role, token_hash, plaintext) \
         VALUES (?1, 'service', 'hash_a', 'drust_service_alpha_PLAINTEXT')",
        rusqlite::params!["tenant-a-1234"],
    )
    .unwrap();

    // Tenant B: has plaintext service bearer (separate string so the
    // cross-leak test has something to grep against).
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'beta')",
        rusqlite::params!["tenant-b-9999"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, role, token_hash, plaintext) \
         VALUES (?1, 'service', 'hash_b', 'drust_service_beta_PLAINTEXT')",
        rusqlite::params!["tenant-b-9999"],
    )
    .unwrap();

    // Tenant C: legacy hash-only (plaintext IS NULL).
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'gamma-legacy')",
        rusqlite::params!["tenant-c-5555"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, role, token_hash, plaintext) \
         VALUES (?1, 'service', 'hash_c', NULL)",
        rusqlite::params!["tenant-c-5555"],
    )
    .unwrap();

    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let bus = drust::tenant::events::EventBus::new();
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let state = TenantsState::test_default(meta, data_dir.clone(), tenants, mcp, bus, bus_rooms);

    Router::new()
        .route(
            "/drust/admin/tenants/{id}/_broadcast",
            get(broadcast_inspector_page),
        )
        .with_state(state)
        // The handler reads Extension<AdminProfileExt>; inject a placeholder.
        // LocaleHint/ThemeHint extractors fall back to Locale::En / Theme::System
        // automatically when the layer didn't run.
        .layer(axum::Extension(AdminProfileExt::placeholder()))
}

#[tokio::test]
async fn renders_with_drust_prefixed_ws_url_and_hidden_bearer() {
    let app = build_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/drust/admin/tenants/tenant-a-1234/_broadcast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();

    // /drust prefix is mandatory for the browser hop.
    assert!(
        html.contains(r#"id="ws-url" value="/drust/t/tenant-a-1234/realtime""#),
        "ws-url missing /drust prefix or wrong tenant — body excerpt:\n{}",
        &html[..html.len().min(2000)]
    );

    // Bearer field rendered with the seeded plaintext.
    assert!(
        html.contains(r#"id="bearer-field" value="drust_service_alpha_PLAINTEXT""#),
        "hidden bearer field missing or value wrong"
    );

    // tenant-a-1234 appears in the bound positions (ws-url, tenant-id-field,
    // sidebar header, Evict URL template, etc.).
    assert!(html.contains("tenant-a-1234"));
}

#[tokio::test]
async fn missing_tenant_returns_404() {
    let app = build_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/drust/admin/tenants/tenant-does-not-exist/_broadcast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn legacy_hash_only_tenant_renders_bearer_missing_banner() {
    let app = build_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/drust/admin/tenants/tenant-c-5555/_broadcast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();

    // bearer field is empty.
    assert!(
        html.contains(r#"id="bearer-field" value="""#),
        "legacy tenant should render empty bearer field"
    );
    // banner is present.
    assert!(
        html.contains(r#"data-state="bearer-missing""#),
        "bearer-missing banner not rendered"
    );
    // Connect button disabled.
    assert!(
        html.contains(r#"id="btn-connect""#) && html.contains("disabled"),
        "Connect button should be disabled when bearer is missing"
    );
}

#[tokio::test]
async fn does_not_leak_other_tenant_id_or_bearer() {
    let app = build_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/drust/admin/tenants/tenant-a-1234/_broadcast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();

    assert!(
        !html.contains("tenant-b-9999"),
        "rendering for tenant A leaked tenant B's id"
    );
    assert!(
        !html.contains("drust_service_beta_PLAINTEXT"),
        "rendering for tenant A leaked tenant B's service bearer"
    );
    assert!(
        !html.contains("tenant-c-5555"),
        "rendering for tenant A leaked tenant C's id"
    );
}

#[tokio::test]
async fn invalid_tenant_id_returns_400() {
    let app = build_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/drust/admin/tenants/INVALID..ID/_broadcast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

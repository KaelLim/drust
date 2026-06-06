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
//!   6. Unauthenticated request → 303 redirect to /drust/login (regression
//!      of the `admin_session_layer` gate on this specific route).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use drust::auth::middleware::{AdminSessionState, admin_session_layer};
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

    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
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

    // v1.31.6 regression — the inline JS block must contain NO literal
    // `</script>` (HTML5 §8.2.4.6 terminates <script> on that pattern
    // regardless of JS comment/string context). The marker `(function ()`
    // narrows to the inspector's own IIFE, skipping the cmdk / mascot
    // inline scripts which legitimately don't contain stray closers.
    let inspector_start = html
        .rfind("<script>\n(function () {")
        .expect("inspector IIFE <script> opener missing");
    let inspector_end_rel = html[inspector_start..]
        .find("\n})();\n</script>")
        .expect("inspector IIFE close marker missing");
    let inspector_body = &html[inspector_start..inspector_start + inspector_end_rel];
    assert!(
        !inspector_body.contains("</script>"),
        "inline JS block contains literal </script> — will truncate at \
         the browser HTML parser. Use <\\/script> instead."
    );
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

    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
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
    // Connect button disabled. `html.contains("disabled")` alone is
    // meaningless — every page renders `disabled` on the optimistic
    // btn-subscribe / btn-send slots. We need the assertion to point
    // at the Connect button specifically, so window the search around
    // the `id="btn-connect"` token and require `disabled` to appear
    // inside that window (template binds it via the
    // `{% if bearer_missing %}disabled{% endif %}` branch).
    let connect_idx = html
        .find(r#"id="btn-connect""#)
        .expect("btn-connect element missing entirely");
    let window_end = (connect_idx + 200).min(html.len());
    let connect_window = &html[connect_idx..window_end];
    assert!(
        connect_window.contains("disabled"),
        "Connect button should be disabled when bearer is missing — window:\n{}",
        connect_window
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

    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
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

/// Spec Testing/integration #2: unauthenticated request → 303 redirect to
/// `/drust/login`.
///
/// This is the regression net for `admin_session_layer` on this specific
/// route. The other 5 tests in this file mount the handler directly (no
/// session layer) because they assert handler-level behaviour; if someone
/// were to accidentally hoist `_broadcast` outside `admin_session_layer`
/// in `src/mgmt/routes.rs`, those tests would not notice.
///
/// We mount the real `admin_session_layer` over the broadcast handler
/// route — same shape as `tests/session_middleware.rs::redirects_without_cookie`,
/// the canonical proof-of-pattern for this middleware — and send a request
/// with no `drust_session` cookie. The middleware must short-circuit with
/// `303 See Other` + `Location: /drust/login` before the handler ever
/// runs, exactly the way it does for every other admin page.
#[tokio::test]
async fn unauthenticated_request_redirects_to_drust_login() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
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
    let state =
        TenantsState::test_default(meta.clone(), data_dir.clone(), tenants, mcp, bus, bus_rooms);
    let session_state = AdminSessionState::test_default(meta);

    // Same shape as the production protected router: the broadcast route
    // sits inside a sub-router that gets `admin_session_layer` applied via
    // `.layer(from_fn_with_state(...))`. Mirrors src/mgmt/routes.rs:962-965.
    let app = Router::new()
        .route(
            "/drust/admin/tenants/{id}/_broadcast",
            get(broadcast_inspector_page),
        )
        .with_state(state)
        .layer(axum::Extension(AdminProfileExt::placeholder()))
        .layer(axum::middleware::from_fn_with_state(
            session_state,
            admin_session_layer,
        ));

    let res = app
        .oneshot(
            Request::builder()
                .uri("/drust/admin/tenants/tenant-a-1234/_broadcast")
                // No drust_session cookie → admin_session_layer short-circuits.
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::SEE_OTHER,
        "unauthenticated request should 303-redirect, got {}",
        res.status()
    );
    let loc = res
        .headers()
        .get(header::LOCATION)
        .expect("redirect must set Location header")
        .to_str()
        .expect("Location header must be ASCII");
    assert_eq!(
        loc, "/drust/login",
        "redirect target must be /drust/login (the browser-facing /drust prefix is load-bearing)"
    );
}

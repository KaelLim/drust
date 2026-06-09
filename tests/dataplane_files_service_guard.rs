//! Service-key-only guard for the data-plane files router (#1 security fix).
//!
//! Two layers of proof:
//!   - Section 1 (this file, first): unit-tests `require_service_layer`'s logic
//!     by injecting a real `TenantRef` (built like `tests/large_upload_tus.rs`)
//!     via an `Extension` layer — covers anon/user/service AND the fail-closed
//!     "no TenantRef in extensions" branch. No token seeding, no router stack.
//!   - Section 2 (added in Task 2): drives the REAL production router built by
//!     `build_tenant_router` with `files: Some(..)`, so the test fails until the
//!     guard is actually mounted in `src/tenant/mod.rs` — a genuine red→green on
//!     production wiring, not a replica.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use drust::storage::pool::TenantRegistry;
use drust::tenant::router::{TenantRef, TokenRole, require_service_layer};
use std::sync::Arc;
use tower::ServiceExt;

/// Pull `error_code` out of a JSON error body; returns "" for a non-JSON body
/// (e.g. the probe handler's plain-text success response).
async fn body_error_code(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    v["error_code"].as_str().unwrap_or("").to_string()
}

/// Build a real `TenantRef` (4 fields, incl. a real `pool`) for `role`, exactly
/// as `tests/large_upload_tus.rs::setup` does. The returned `TempDir` must be
/// kept alive for the life of the request (it backs the tenant db).
fn make_tref(tid: &str, role: TokenRole) -> (tempfile::TempDir, TenantRef) {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open(tid).unwrap();
    let tref = TenantRef {
        tenant_id: tid.to_string(),
        token_hint: "t".into(),
        pool,
        role,
    };
    (dir, tref)
}

/// Mount the guard over a probe handler, inject a `TenantRef` of `role` via an
/// `Extension` layer applied OUTER to the guard (so it lands in extensions
/// before the guard reads it — mirrors how `bearer_auth_layer` feeds the guard
/// in production). Returns (status, error_code).
async fn guard_status_for(role: TokenRole) -> (StatusCode, String) {
    let (_dir, tref) = make_tref("guard-probe", role);
    let app = Router::new()
        .route("/probe", get(|| async { "reached-handler" }))
        // guard: applied first -> INNER -> runs after the Extension injector.
        .layer(axum::middleware::from_fn(require_service_layer))
        // injector: applied last -> OUTER -> inserts TenantRef before the guard.
        .layer(axum::Extension(tref));
    let resp = app
        .oneshot(Request::builder().uri("/probe").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let code = body_error_code(resp).await;
    (status, code)
}

#[tokio::test]
async fn guard_denies_anon_403_write_denied() {
    let (status, code) = guard_status_for(TokenRole::Anon).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code, "WRITE_DENIED");
}

#[tokio::test]
async fn guard_denies_user_403_write_denied() {
    // The User arm is the second half of `require_service`'s
    // `matches!(role, Anon | User)` — exercised here without seeding a real
    // `_system_sessions` row (the full-stack path covers anon; user takes the
    // identical code path in the guard).
    let (status, code) = guard_status_for(TokenRole::User).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code, "WRITE_DENIED");
}

#[tokio::test]
async fn guard_passes_service_reaches_handler() {
    let (status, code) = guard_status_for(TokenRole::Service).await;
    assert_eq!(status, StatusCode::OK, "service must reach the handler");
    assert_eq!(code, "", "success body is plain text, not a WRITE_DENIED error");
}

/// Fail-closed: a request reaching the guard with NO `TenantRef` in extensions
/// (which should be impossible behind `bearer_auth_layer`, but proves the guard
/// never runs the handler "open" if the layer order is ever broken) is denied.
#[tokio::test]
async fn guard_fails_closed_without_tenantref() {
    let app = Router::new()
        .route("/probe", get(|| async { "reached-handler" }))
        .layer(axum::middleware::from_fn(require_service_layer));
    let resp = app
        .oneshot(Request::builder().uri("/probe").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_error_code(resp).await, "WRITE_DENIED");
}

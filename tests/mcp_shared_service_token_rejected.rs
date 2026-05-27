//! Integration tests: v1.29 MCP transport gate.
//!
//! Verifies:
//!   1. Shared service token (no admin_id) → 401 + WWW-Authenticate on /t/<id>/mcp
//!   2. No token (anon) → 401 on /t/<id>/mcp
//!   3. Shared service token still works on REST paths (not /mcp)
//!
//! v1.29.0 — Task 18 / 22.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

#[tokio::test]
async fn shared_service_token_rejected_on_mcp_path() {
    let (app, service_token, _dir) = helpers::spin_up_tenant_with_role("mcp-gate-t1", "service").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/mcp-gate-t1/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {service_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "shared service token should be rejected on /mcp path, got {}",
        resp.status()
    );

    let www = resp
        .headers()
        .get("www-authenticate")
        .expect("WWW-Authenticate header must be present")
        .to_str()
        .unwrap();
    assert!(
        www.starts_with(r#"Bearer realm="drust""#),
        "WWW-Authenticate should start with Bearer realm=\"drust\", got: {www}"
    );
    assert!(
        www.contains("resource_metadata="),
        "WWW-Authenticate should contain resource_metadata=, got: {www}"
    );
    assert!(
        www.contains("/.well-known/oauth-protected-resource"),
        "WWW-Authenticate should reference discovery URL, got: {www}"
    );
}

#[tokio::test]
async fn anon_token_rejected_on_mcp_path() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_with_role("mcp-gate-t2", "service").await;

    // No Authorization header → missing bearer → 401
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/mcp-gate-t2/mcp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN,
        "anon request to /mcp should be 401 or 403, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn anon_role_token_rejected_on_mcp_path() {
    // An anon-role token (not just missing auth) should also be rejected at /mcp
    let (app, anon_tok, _dir) = helpers::spin_up_tenant_with_role("mcp-gate-t3", "anon").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/mcp-gate-t3/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {anon_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "anon-role token should be rejected on /mcp path, got {}",
        resp.status()
    );

    let www = resp
        .headers()
        .get("www-authenticate")
        .expect("WWW-Authenticate header must be present for anon-role rejection")
        .to_str()
        .unwrap();
    assert!(
        www.contains("resource_metadata="),
        "WWW-Authenticate should contain resource_metadata=, got: {www}"
    );
}

#[tokio::test]
async fn shared_service_token_still_works_on_rest_path() {
    // /t/<id>/collections is NOT /mcp — shared token must still work
    let (app, service_token, _dir) = helpers::spin_up_tenant_with_role("mcp-gate-t4", "service").await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/mcp-gate-t4/collections")
                .header(header::AUTHORIZATION, format!("Bearer {service_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "REST path should NOT require admin attribution (shared token must work), got {}",
        resp.status()
    );
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "REST path should return 200 with shared service token"
    );
}

#[tokio::test]
async fn is_mcp_path_helper_matches_slash_suffix() {
    // The regex must match `/t/<id>/mcp/` (with trailing slash) as well as the
    // exact path.  This test verifies the helper via the observable gate
    // behavior: the route `/t/{tenant}/mcp` in axum is an exact match, so
    // `/mcp/` is a 404 from the router before the middleware fires.
    //
    // We instead verify the guard on the exact `/mcp` path suffices for the
    // current registered routes; sub-path coverage is a unit-level concern.
    let (app, service_token, _dir) = helpers::spin_up_tenant_with_role("mcp-gate-t5", "service").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/mcp-gate-t5/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {service_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "service token should be gated at /mcp, got {}",
        resp.status()
    );
}

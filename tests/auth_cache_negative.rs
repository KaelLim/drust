// tests/auth_cache_negative.rs — Spec test 8: unknown bearers never enter the map.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

#[tokio::test]
async fn unknown_bearer_not_cached() {
    // spin_up_tenant_with_role builds the real production router; its cache is
    // internal, but we assert behavior: two unknown-bearer hits both 401 and
    // the second is NOT served from a poisoned positive entry (still 401).
    let (app, _tok, _dir) = helpers::spin_up_tenant_with_role("t-neg", "service").await;
    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/t/t-neg/collections")
                    .header(header::AUTHORIZATION, "Bearer drust_totally-bogus-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

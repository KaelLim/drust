// tests/auth_cache_logout.rs — hooks 5/6.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

#[tokio::test]
async fn logout_drops_cached_user_entry() {
    // NOTE: spin_up_tenant_self_register returns (app, service_token, dir) —
    // the tenant id is the literal string we passed in.
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-logout").await;
    let tid = "t-logout";
    let token = helpers::register_and_login_via_app(&app, tid, "u@x.com", "pw-correct-horse").await;

    // First authed request fills the cache.
    let r1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r1.status().is_success(),
        "authed before logout: {}",
        r1.status()
    );

    // Logout.
    let rl = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/logout"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rl.status(), StatusCode::OK);

    // Next request with the now-logged-out token must 401 (cache cleared,
    // DB row deleted).
    let r2 = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::UNAUTHORIZED,
        "logout revoked the session"
    );
}

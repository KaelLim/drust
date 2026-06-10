// tests/auth_cache_change_password.rs — Spec test 7b (hook 9).
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

#[tokio::test]
async fn change_password_invalidates_old_session_cache() {
    // NOTE: spin_up_tenant_self_register returns (app, service_token, dir) —
    // the tenant id is the literal string we passed in.
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-pw").await;
    let tid = "t-pw";
    let old = helpers::register_and_login_via_app(&app, tid, "u@x.com", "old-password-123").await;

    // Fill the cache with the old session.
    let r1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {old}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(r1.status().is_success());

    // Change password (wipes all sessions, issues a fresh one).
    let rc = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/me/password"))
                .header(header::AUTHORIZATION, format!("Bearer {old}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "current_password": "old-password-123",
                        "new_password": "new-password-456"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rc.status(), StatusCode::OK, "password changed");

    // The OLD session must now 401 on its next request (cache cleared + row gone).
    let r2 = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {old}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::UNAUTHORIZED,
        "old session revoked by password change"
    );
}

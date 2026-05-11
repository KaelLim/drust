use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

mod helpers;
use helpers::spin_up_tenant;

#[tokio::test]
async fn unknown_bearer_returns_401() {
    let (app, _tok, _dir) = spin_up_tenant("t-bearer").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/t-bearer/collections")
                .header(header::AUTHORIZATION, "Bearer drust_user_definitelynotreal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn service_token_still_works_after_user_path_added() {
    let (app, tok, _dir) = spin_up_tenant("t-bearer2").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/t-bearer2/collections")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "got {}", resp.status());
}

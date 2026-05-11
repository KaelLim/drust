use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

mod helpers;

fn post_json(tid: &str, path: &str, body: serde_json::Value, xff: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(xff) = xff {
        b = b.header("X-Forwarded-For", xff);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn register_disabled_by_default_returns_403() {
    let (app, _tid, _dir) = helpers::spin_up_tenant("t-reg1").await;
    let resp = app
        .oneshot(post_json(
            "t-reg1",
            "/auth/register",
            json!({"email": "a@b.com", "password": "longpassword"}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn register_enabled_creates_user() {
    let (app, _tid, _dir) = helpers::spin_up_tenant_self_register("t-reg2").await;
    let resp = app
        .oneshot(post_json(
            "t-reg2",
            "/auth/register",
            json!({"email": "a@b.com", "password": "longpassword"}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn register_duplicate_email_returns_409() {
    let (app, _tid, _dir) = helpers::spin_up_tenant_self_register("t-reg3").await;
    let body = json!({"email": "dup@x.com", "password": "longpassword"});
    let _ = app
        .clone()
        .oneshot(post_json("t-reg3", "/auth/register", body.clone(), None))
        .await
        .unwrap();
    let resp = app
        .oneshot(post_json("t-reg3", "/auth/register", body, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("EMAIL_EXISTS"));
}

#[tokio::test]
async fn register_short_password_returns_422() {
    let (app, _tid, _dir) = helpers::spin_up_tenant_self_register("t-reg4").await;
    let resp = app
        .oneshot(post_json(
            "t-reg4",
            "/auth/register",
            json!({"email": "a@b.com", "password": "short"}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("PASSWORD_TOO_SHORT"));
}

#[tokio::test]
async fn register_oversize_profile_returns_413() {
    let (app, _tid, _dir) = helpers::spin_up_tenant_self_register("t-reg5").await;
    let big = "x".repeat(70 * 1024);
    let resp = app
        .oneshot(post_json(
            "t-reg5",
            "/auth/register",
            json!({"email": "a@b.com", "password": "longpassword", "profile": {"bio": big}}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("PROFILE_TOO_LARGE"));
}

#[tokio::test]
async fn register_per_ip_rate_limit_3_per_min() {
    let (app, _tid, _dir) = helpers::spin_up_tenant_self_register("t-reg6").await;
    for i in 0..3 {
        let _ = app
            .clone()
            .oneshot(post_json(
                "t-reg6",
                "/auth/register",
                json!({"email": format!("u{i}@x.com"), "password": "longpassword"}),
                Some("203.0.113.99, 192.0.2.221"),
            ))
            .await
            .unwrap();
    }
    let resp = app
        .oneshot(post_json(
            "t-reg6",
            "/auth/register",
            json!({"email": "u4@x.com", "password": "longpassword"}),
            Some("203.0.113.99, 192.0.2.221"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

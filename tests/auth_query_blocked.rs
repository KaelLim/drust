use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

mod helpers;

fn post_json(tid: &str, path: &str, body: serde_json::Value, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn register_and_login(app: &axum::Router, tid: &str, email: &str) -> String {
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/register"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"email": email, "password": "longpassword"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/login"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"email": email, "password": "longpassword"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let v = read_json(resp).await;
    v["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn query_rejects_user_token() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-q1").await;
    let token = register_and_login(&app, "t-q1", "a@b.com").await;
    let r = app
        .oneshot(post_json(
            "t-q1",
            "/query",
            json!({"sql": "SELECT 1"}),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(r.into_body(), 65536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("QUERY_USER_DENIED"),
        "body was: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn query_explain_rejects_user_token() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-q2").await;
    let token = register_and_login(&app, "t-q2", "a@b.com").await;
    let r = app
        .oneshot(post_json(
            "t-q2",
            "/query/explain",
            json!({"sql": "SELECT 1"}),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(r.into_body(), 65536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("QUERY_USER_DENIED"),
        "body was: {}",
        String::from_utf8_lossy(&bytes)
    );
}

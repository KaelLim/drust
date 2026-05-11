use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

mod helpers;

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
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn mcp_rejects_user_token() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-mcp1").await;
    let token = register_and_login(&app, "t-mcp1", "a@b.com").await;
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/t-mcp1/mcp"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(r.into_body(), 65536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("MCP_USER_DENIED"),
        "body was: {}",
        String::from_utf8_lossy(&bytes)
    );
}

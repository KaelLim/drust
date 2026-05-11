use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

mod helpers;

fn post_json(tid: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_bearer(tid: &str, path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn get_bearer(tid: &str, path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn register_and_login(app: &axum::Router, tid: &str, email: &str) -> String {
    let _ = app
        .clone()
        .oneshot(post_json(
            tid,
            "/auth/register",
            json!({"email": email, "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(post_json(
            tid,
            "/auth/login",
            json!({"email": email, "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    v["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn logout_invalidates_only_that_session() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-sess1").await;
    let t1 = register_and_login(&app, "t-sess1", "a@b.com").await;
    // Second login → second session
    let resp = app
        .clone()
        .oneshot(post_json(
            "t-sess1",
            "/auth/login",
            json!({"email": "a@b.com", "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    let t2 = v["token"].as_str().unwrap().to_string();

    let r = app
        .clone()
        .oneshot(post_bearer("t-sess1", "/auth/logout", &t1))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // t1 invalid — collections call now 401
    let r1 = app
        .clone()
        .oneshot(get_bearer("t-sess1", "/collections", &t1))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::UNAUTHORIZED);
    // t2 still valid — collections returns 200
    let r2 = app
        .oneshot(get_bearer("t-sess1", "/collections", &t2))
        .await
        .unwrap();
    assert!(r2.status().is_success(), "got {}", r2.status());
}

#[tokio::test]
async fn logout_all_invalidates_every_session() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-sess2").await;
    let t1 = register_and_login(&app, "t-sess2", "a@b.com").await;
    let resp = app
        .clone()
        .oneshot(post_json(
            "t-sess2",
            "/auth/login",
            json!({"email": "a@b.com", "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    let t2 = v["token"].as_str().unwrap().to_string();

    let r = app
        .clone()
        .oneshot(post_bearer("t-sess2", "/auth/logout-all", &t1))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = read_json(r).await;
    assert_eq!(body["revoked"].as_i64().unwrap(), 2);

    for t in [&t1, &t2] {
        let r = app
            .clone()
            .oneshot(get_bearer("t-sess2", "/collections", t))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
}

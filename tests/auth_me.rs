use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

mod helpers;

fn req_json(
    method: &str,
    tenant: &str,
    path: &str,
    body: Option<serde_json::Value>,
    token: Option<&str>,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("/t/{tenant}{path}"));
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(
        body.map(|v| Body::from(v.to_string()))
            .unwrap_or(Body::empty()),
    )
    .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn register_and_login(
    app: &axum::Router,
    tenant: &str,
    email: &str,
    pw: &str,
) -> String {
    let _ = app
        .clone()
        .oneshot(req_json(
            "POST",
            tenant,
            "/auth/register",
            Some(json!({"email": email, "password": pw})),
            None,
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(req_json(
            "POST",
            tenant,
            "/auth/login",
            Some(json!({"email": email, "password": pw})),
            None,
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    v["token"].as_str().unwrap().to_string()
}

// === Task 16 tests ===

#[tokio::test]
async fn me_returns_self_row() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-me1").await;
    let token = register_and_login(&app, "t-me1", "a@b.com", "longpassword").await;
    let resp = app
        .oneshot(req_json("GET", "t-me1", "/me", None, Some(&token)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = read_json(resp).await;
    assert_eq!(v["email"].as_str().unwrap(), "a@b.com");
    assert!(v["id"].as_str().unwrap().starts_with("u-"));
    assert!(
        v.get("password_hash").is_none(),
        "password_hash must never be exposed"
    );
    assert!(v["verified"].as_bool().is_some());
}

#[tokio::test]
async fn me_unauth_returns_401() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant("t-me2").await;
    let resp = app
        .oneshot(req_json("GET", "t-me2", "/me", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn patch_me_updates_profile_only() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-me3").await;
    let token = register_and_login(&app, "t-me3", "a@b.com", "longpassword").await;
    let r = app
        .clone()
        .oneshot(req_json(
            "PATCH",
            "t-me3",
            "/me",
            Some(json!({"profile": {"nickname": "alice", "color": "#fa0"}})),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // PATCH response itself should carry the full updated row.
    let patched = read_json(r).await;
    assert_eq!(patched["profile"]["nickname"].as_str().unwrap(), "alice");
    assert_eq!(patched["email"].as_str().unwrap(), "a@b.com");
    assert!(patched["id"].as_str().unwrap().starts_with("u-"));
    assert!(patched.get("password_hash").is_none());

    let resp = app
        .oneshot(req_json("GET", "t-me3", "/me", None, Some(&token)))
        .await
        .unwrap();
    let v = read_json(resp).await;
    assert_eq!(v["profile"]["nickname"].as_str().unwrap(), "alice");
}

#[tokio::test]
async fn me_rejects_service_token() {
    // Service / anon tokens must not access /me; only AuthCtx::User passes.
    let (app, svc_tok, _dir) = helpers::spin_up_tenant_with_role("t-me-svc", "service").await;
    let resp = app
        .oneshot(req_json("GET", "t-me-svc", "/me", None, Some(&svc_tok)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("NOT_USER_TOKEN"));
}

#[tokio::test]
async fn patch_me_oversize_profile_returns_413() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-me4").await;
    let token = register_and_login(&app, "t-me4", "a@b.com", "longpassword").await;
    let big = "x".repeat(70 * 1024);
    let r = app
        .oneshot(req_json(
            "PATCH",
            "t-me4",
            "/me",
            Some(json!({"profile": {"bio": big}})),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = axum::body::to_bytes(r.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("PROFILE_TOO_LARGE"));
}

// === Task 17 tests ===

#[tokio::test]
async fn change_password_revokes_old_sessions_returns_new_token() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-pw1").await;
    let old = register_and_login(&app, "t-pw1", "a@b.com", "longpassword").await;
    // second session
    let resp = app
        .clone()
        .oneshot(req_json(
            "POST",
            "t-pw1",
            "/auth/login",
            Some(json!({"email": "a@b.com", "password": "longpassword"})),
            None,
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    let other = v["token"].as_str().unwrap().to_string();

    let r = app
        .clone()
        .oneshot(req_json(
            "POST",
            "t-pw1",
            "/me/password",
            Some(json!({
                "current_password": "longpassword",
                "new_password": "longerpassword2"
            })),
            Some(&old),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = read_json(r).await;
    let new_token = body["token"].as_str().unwrap().to_string();
    assert_ne!(new_token, old);

    // Old tokens dead
    for t in [&old, &other] {
        let r = app
            .clone()
            .oneshot(req_json("GET", "t-pw1", "/me", None, Some(t)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    // New token works
    let r = app
        .clone()
        .oneshot(req_json("GET", "t-pw1", "/me", None, Some(&new_token)))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // New password works for fresh login
    let resp = app
        .oneshot(req_json(
            "POST",
            "t-pw1",
            "/auth/login",
            Some(json!({"email": "a@b.com", "password": "longerpassword2"})),
            None,
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    assert!(v["token"].is_string());
}

#[tokio::test]
async fn change_password_wrong_current_returns_422() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-pw2").await;
    let token = register_and_login(&app, "t-pw2", "a@b.com", "longpassword").await;
    let r = app
        .oneshot(req_json(
            "POST",
            "t-pw2",
            "/me/password",
            Some(json!({
                "current_password": "WRONG",
                "new_password": "longerpassword2"
            })),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = axum::body::to_bytes(r.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("WRONG_CURRENT_PASSWORD"));
}

#[tokio::test]
async fn change_password_short_new_returns_422() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-pw3").await;
    let token = register_and_login(&app, "t-pw3", "a@b.com", "longpassword").await;
    let r = app
        .oneshot(req_json(
            "POST",
            "t-pw3",
            "/me/password",
            Some(json!({
                "current_password": "longpassword",
                "new_password": "short"
            })),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = axum::body::to_bytes(r.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("PASSWORD_TOO_SHORT"));
}

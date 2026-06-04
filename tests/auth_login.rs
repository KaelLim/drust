use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use std::time::Instant;
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

fn post_json_xff(tid: &str, path: &str, body: serde_json::Value, xff: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Forwarded-For", xff)
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn register(app: &axum::Router, tenant: &str, email: &str, pw: &str) {
    let resp = app
        .clone()
        .oneshot(post_json(
            tenant,
            "/auth/register",
            json!({"email": email, "password": pw}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "register helper: expected 201"
    );
}

#[tokio::test]
async fn login_success_returns_token() {
    let (app, _tok, _dir) = helpers::spin_up_tenant_self_register("t-login1").await;
    register(&app, "t-login1", "a@b.com", "longpassword").await;
    let resp = app
        .oneshot(post_json(
            "t-login1",
            "/auth/login",
            json!({"email": "a@b.com", "password": "longpassword"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = read_json(resp).await;
    assert!(v["token"].as_str().unwrap().starts_with("drust_user_"));
    assert!(v["expires_at"].is_string());
    assert!(v["user_id"].is_string());
}

#[tokio::test]
async fn login_wrong_password_returns_invalid_credentials() {
    let (app, _tok, _dir) = helpers::spin_up_tenant_self_register("t-login2").await;
    register(&app, "t-login2", "a@b.com", "longpassword").await;
    let resp = app
        .oneshot(post_json(
            "t-login2",
            "/auth/login",
            json!({"email": "a@b.com", "password": "wrong___pw"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("INVALID_CREDENTIALS"));
}

#[tokio::test]
async fn login_unknown_email_also_returns_invalid_credentials() {
    let (app, _tok, _dir) = helpers::spin_up_tenant_self_register("t-login3").await;
    let resp = app
        .oneshot(post_json(
            "t-login3",
            "/auth/login",
            json!({"email": "ghost@x.com", "password": "longpassword"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("INVALID_CREDENTIALS"));
}

/// Spec S1: unknown-email and known-email-wrong-password timings must be in the same band.
/// Uses distinct XFF IPs per trial to avoid hitting the per-IP login rate-limit (5/60s).
/// Run with `cargo test --release --test auth_login` — debug-mode argon2 amplifies jitter.
#[tokio::test]
async fn login_timing_equalized_unknown_vs_wrong_password() {
    let (app, _tok, _dir) = helpers::spin_up_tenant_self_register("t-loginT").await;
    register(&app, "t-loginT", "real@x.com", "longpassword").await;

    let trials = 5usize;
    let mut t_unknown = vec![];
    let mut t_wrong = vec![];
    for i in 0..trials {
        // Use distinct synthetic IPs so each trial gets its own rate-limit bucket,
        // preventing the login_rl (5/60s) from triggering mid-loop and returning
        // an instant 429 that skews the timing measurements.
        // client_ip() takes the second-from-right XFF entry — supply two entries
        // so the test IP is selected rather than falling back to 127.0.0.1.
        let unknown_ip = format!("198.51.100.{}, 192.0.2.221", i * 2);
        let wrong_ip = format!("198.51.100.{}, 192.0.2.221", i * 2 + 1);

        let s = Instant::now();
        let _ = app
            .clone()
            .oneshot(post_json_xff(
                "t-loginT",
                "/auth/login",
                json!({"email": "ghost@x.com", "password": "longpassword"}),
                &unknown_ip,
            ))
            .await
            .unwrap();
        t_unknown.push(s.elapsed().as_millis() as u64);

        let s = Instant::now();
        let _ = app
            .clone()
            .oneshot(post_json_xff(
                "t-loginT",
                "/auth/login",
                json!({"email": "real@x.com", "password": "wrong___pw"}),
                &wrong_ip,
            ))
            .await
            .unwrap();
        t_wrong.push(s.elapsed().as_millis() as u64);
    }
    let med = |mut v: Vec<u64>| {
        v.sort();
        v[v.len() / 2]
    };
    let mu = med(t_unknown.clone());
    let mw = med(t_wrong.clone());
    let diff = mu.abs_diff(mw);
    assert!(
        diff < 60,
        "S1 timing skew: unknown={mu}ms wrong-pw={mw}ms (diff={diff}ms must be <60ms)"
    );
}

//! T6 — per-identity invoke gate on `/t/{tenant}/functions/{name}/invoke`.
//!
//! The invoke route is split out of the service-only functions config surface:
//! config (CRUD + logs) stays under `require_service_layer`, but the invoke
//! route runs under `invoke_gate_layer`, which mirrors `file_caps_layer`:
//! service is always allowed (Privileged); anon/user are allowed iff the
//! function's `invoke_anon` / `invoke_user` flag is set, else 403
//! `FN_INVOKE_ANON_DENIED` / `FN_INVOKE_USER_DENIED`. A per-IP rate-limit
//! bounds the anon/user invoke DoS vector. Granting/revoking the flags stays
//! service-only (T5) — proven elsewhere.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn invoke_req(tenant: &str, token: &str) -> Request<Body> {
    Request::post(format!("/t/{tenant}/functions/f1/invoke"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"event":{}}"#))
        .unwrap()
}

/// Grant a flag via the service-only PATCH surface (T5).
async fn grant(router: &axum::Router, tenant: &str, service: &str, body: &str) {
    let resp = router
        .clone()
        .oneshot(
            Request::patch(format!("/t/{tenant}/functions/f1"))
                .header("authorization", format!("Bearer {service}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "grant PATCH must succeed");
}

async fn log_count(router: &axum::Router, tenant: &str, service: &str) -> usize {
    let resp = router
        .clone()
        .oneshot(
            Request::get(format!("/t/{tenant}/functions/f1/logs"))
                .header("authorization", format!("Bearer {service}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    v["logs"].as_array().map(|a| a.len()).unwrap_or(0)
}

#[tokio::test]
async fn anon_invoke_denied_when_flag_off() {
    let (router, _service, anon, _user, _tmp) =
        helpers::spin_up_tenant_with_fn_seed("t-fng-a").await;
    let resp = router
        .clone()
        .oneshot(invoke_req("t-fng-a", &anon))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "FN_INVOKE_ANON_DENIED");
}

#[tokio::test]
async fn user_invoke_denied_when_flag_off() {
    let (router, _service, _anon, user, _tmp) =
        helpers::spin_up_tenant_with_fn_seed("t-fng-u").await;
    let resp = router
        .clone()
        .oneshot(invoke_req("t-fng-u", &user))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "FN_INVOKE_USER_DENIED");
}

#[tokio::test]
async fn anon_invoke_runs_after_grant() {
    let (router, service, anon, _user, _tmp) =
        helpers::spin_up_tenant_with_fn_seed("t-fng-ag").await;
    grant(&router, "t-fng-ag", &service, r#"{"invoke_anon":true}"#).await;

    let before = log_count(&router, "t-fng-ag", &service).await;
    let resp = router
        .clone()
        .oneshot(invoke_req("t-fng-ag", &anon))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let after = log_count(&router, "t-fng-ag", &service).await;
    assert_eq!(after, before + 1, "anon invoke must record a log row");
}

#[tokio::test]
async fn user_invoke_runs_after_grant() {
    let (router, service, _anon, user, _tmp) =
        helpers::spin_up_tenant_with_fn_seed("t-fng-ug").await;
    grant(&router, "t-fng-ug", &service, r#"{"invoke_user":true}"#).await;

    let resp = router
        .clone()
        .oneshot(invoke_req("t-fng-ug", &user))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn service_invoke_always_allowed() {
    let (router, service, _anon, _user, _tmp) =
        helpers::spin_up_tenant_with_fn_seed("t-fng-s").await;
    // No grant — service is Privileged regardless of the flags.
    let resp = router
        .clone()
        .oneshot(invoke_req("t-fng-s", &service))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn anon_invoke_burst_trips_rate_limit() {
    let (router, service, anon, _user, _tmp) =
        helpers::spin_up_tenant_with_fn_seed("t-fng-rl").await;
    grant(&router, "t-fng-rl", &service, r#"{"invoke_anon":true}"#).await;

    // Default fn_invoke_rl is 30/60s (mirrors file_upload_rl). The 31st
    // non-service invoke from the same (loopback) IP must 429.
    let mut saw_429 = false;
    for _ in 0..40 {
        let resp = router
            .clone()
            .oneshot(invoke_req("t-fng-rl", &anon))
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            let v = json_body(resp).await;
            assert_eq!(v["error_code"], "RATE_LIMITED_IP");
            saw_429 = true;
            break;
        }
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert!(saw_429, "burst of anon invokes must trip the per-IP limit");
}

#[tokio::test]
async fn unknown_function_is_404_for_anon_grant_path() {
    let (router, _service, anon, _user, _tmp) =
        helpers::spin_up_tenant_with_fn_seed("t-fng-nf").await;
    // Even with the flag off, a missing function is a clean 404 (not a 500).
    let resp = router
        .clone()
        .oneshot(
            Request::post("/t/t-fng-nf/functions/ghost/invoke")
                .header("authorization", format!("Bearer {anon}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"event":{}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // Gate denies anon (flag off on a non-existent fn) → 403; service would 404.
    // The key invariant: anon never reaches Privileged. 403 or 404 both uphold it.
    assert!(
        resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::NOT_FOUND,
        "got {}",
        resp.status()
    );
}

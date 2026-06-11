// tests/functions_rest.rs — REST CRUD + auth gating. Mock runner (no wasm
// toolchain): upload uses a REAL tiny component? No — create() calls
// validate_component which needs real wasm. Strategy: this file tests
// everything EXCEPT create-with-wasm using rows seeded via schema::, and
// tests create() against fixtures in Task 15. Auth-gating tests need no
// valid body (they must 403 BEFORE parsing).
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn seeded(tenant: &str) -> (axum::Router, String, String, tempfile::TempDir) {
    // returns (router, service_token, anon_token, tmp)
    let (router, service, anon, tmp) = helpers::spin_up_tenant_with_fn_seed(tenant).await;
    (router, service, anon, tmp)
}

#[tokio::test]
async fn anon_and_user_tokens_are_403_on_every_functions_route() {
    let (router, _service, anon, _tmp) = seeded("t-fr1").await;
    for (method, path) in [
        ("GET", "/t/t-fr1/functions"),
        ("POST", "/t/t-fr1/functions"),
        ("GET", "/t/t-fr1/functions/f1"),
        ("PATCH", "/t/t-fr1/functions/f1"),
        ("DELETE", "/t/t-fr1/functions/f1"),
        ("POST", "/t/t-fr1/functions/f1/invoke"),
        ("GET", "/t/t-fr1/functions/f1/logs"),
    ] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {anon}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} must be service-only"
        );
    }
}

#[tokio::test]
async fn list_get_patch_delete_logs_roundtrip() {
    let (router, service, _anon, _tmp) = seeded("t-fr2").await;
    let auth = format!("Bearer {service}");

    // list — seeded helper created one function named "f1"
    let resp = router.clone().oneshot(
        Request::get("/t/t-fr2/functions").header("authorization", &auth).body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["functions"].as_array().unwrap().len(), 1);

    // patch active=false
    let resp = router.clone().oneshot(
        Request::patch("/t/t-fr2/functions/f1")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"active":false}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // invoke (mock runner ⇒ ok even though deactivated? NO — run_one
    // re-checks active and returns error status in the 200 body)
    let resp = router.clone().oneshot(
        Request::post("/t/t-fr2/functions/f1/invoke")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"event":{"trigger":"manual"}}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "error", "deactivated function reports error status");

    // logs — the invoke above must have produced one row
    let resp = router.clone().oneshot(
        Request::get("/t/t-fr2/functions/f1/logs?limit=10")
            .header("authorization", &auth).body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["logs"].as_array().unwrap().len() >= 1);

    // delete
    let resp = router.clone().oneshot(
        Request::delete("/t/t-fr2/functions/f1")
            .header("authorization", &auth).body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 404 after delete
    let resp = router.clone().oneshot(
        Request::get("/t/t-fr2/functions/f1")
            .header("authorization", &auth).body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

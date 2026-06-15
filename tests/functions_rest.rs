// tests/functions_rest.rs — REST CRUD + auth gating against the mock (noop)
// runner, so no wasm toolchain is needed. Rows are seeded via `schema::`;
// create()-with-wasm (which needs a real component for validate_component) is
// exercised separately against fixtures in the isolation suite. Auth-gating
// tests need no valid body — they must reject BEFORE parsing.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn anon_and_user_tokens_are_403_on_every_functions_route() {
    // Both non-service roles must be rejected by `require_service`. They reach
    // it through DIFFERENT branches of `bearer_auth_layer` (anon-token vs
    // user-session), so assert BOTH bearers, not just anon.
    let (router, _service, anon, user, _tmp) = helpers::spin_up_tenant_with_fn_seed("t-fr1").await;
    for token in [&anon, &user] {
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
                        .header("authorization", format!("Bearer {token}"))
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{method} {path} must be service-only (token {token})"
            );
        }
    }
}

#[tokio::test]
async fn list_get_patch_delete_logs_roundtrip() {
    let (router, service, _anon, _user, _tmp) = helpers::spin_up_tenant_with_fn_seed("t-fr2").await;
    let auth = format!("Bearer {service}");

    // list — seeded helper created one function named "f1"
    let resp = router
        .clone()
        .oneshot(
            Request::get("/t/t-fr2/functions")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["functions"].as_array().unwrap().len(), 1);

    // patch active=false
    let resp = router
        .clone()
        .oneshot(
            Request::patch("/t/t-fr2/functions/f1")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"active":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // invoke — run_one re-checks the active flag at execution time, so the now
    // deactivated function reports an error status inside a 200 body.
    let resp = router
        .clone()
        .oneshot(
            Request::post("/t/t-fr2/functions/f1/invoke")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"event":{"trigger":"manual"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["status"], "error",
        "deactivated function reports error status"
    );

    // logs — the invoke above must have produced one row
    let resp = router
        .clone()
        .oneshot(
            Request::get("/t/t-fr2/functions/f1/logs?limit=10")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["logs"].as_array().unwrap().len() >= 1);

    // delete
    let resp = router
        .clone()
        .oneshot(
            Request::delete("/t/t-fr2/functions/f1")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 404 after delete
    let resp = router
        .clone()
        .oneshot(
            Request::get("/t/t-fr2/functions/f1")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// Regression: `create()` writes `{sha}.wasm` BEFORE create_function enforces
// the per-tenant cap, and a replace swaps a row's sha — both can leave an
// unreferenced blob on disk with no GC path (unbounded growth). The shared
// `gc_artifact_if_unreferenced` primitive closes it; prove it keeps a sha a
// live row references and removes an orphan. End-to-end create-route coverage
// (FN_LIMIT-then-no-orphan) lives in the isolation suite, which has a real
// component fixture to clear `validate_component`.
#[tokio::test]
async fn gc_keeps_referenced_artifact_removes_orphan() {
    use drust::functions::routes::gc_artifact_if_unreferenced;
    use drust::functions::schema::{self, CreateFunctionParams};
    use drust::storage::pool::TenantRegistry;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let reg = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = reg.get_or_open("t-gc").expect("open tenant pool");

    let referenced = "aa".repeat(32);
    let orphan = "bb".repeat(32);
    schema::create_function(
        &pool,
        CreateFunctionParams {
            name: "live".into(),
            wasm_sha256: referenced.clone(),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .expect("seed live function");

    let fdir = dir.path().join("tenants").join("t-gc").join("_functions");
    tokio::fs::create_dir_all(&fdir).await.unwrap();
    let p_ref = fdir.join(format!("{referenced}.wasm"));
    let p_orphan = fdir.join(format!("{orphan}.wasm"));
    tokio::fs::write(&p_ref, b"REF").await.unwrap();
    tokio::fs::write(&p_orphan, b"ORPHAN").await.unwrap();

    // A still-referenced sha must be kept; an unreferenced one must be removed.
    gc_artifact_if_unreferenced(&pool, dir.path(), "t-gc", &referenced).await;
    gc_artifact_if_unreferenced(&pool, dir.path(), "t-gc", &orphan).await;

    assert!(
        p_ref.exists(),
        "artifact referenced by a live row must be kept"
    );
    assert!(!p_orphan.exists(), "unreferenced artifact must be GC'd");
}

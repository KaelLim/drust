//! T5 — service-only invoke-ACL config surface (REST PATCH + MCP
//! `set_function_invoke_acl` + admin UI toggle). The invoke-ACL flags
//! (`invoke_anon` / `invoke_user`) are default-deny and config is service-only:
//! granting AND revoking both flow through the same surfaces, all gated to the
//! service key (REST: `require_service_layer`; MCP: dispatch rejects anon/user).

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Parse a JSON response body.
async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn service_patch_sets_invoke_acl_and_get_reflects() {
    let (router, service, _anon, _user, _tmp) =
        helpers::spin_up_tenant_with_fn_seed("t-acl1").await;
    let auth = format!("Bearer {service}");

    // Default-deny baseline: the seeded `f1` is service-only on both flags.
    let resp = router
        .clone()
        .oneshot(
            Request::get("/t/t-acl1/functions/f1")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["invoke_anon"], false, "fresh function default-deny anon");
    assert_eq!(v["invoke_user"], false, "fresh function default-deny user");

    // Grant user-invoke only via PATCH.
    let resp = router
        .clone()
        .oneshot(
            Request::patch("/t/t-acl1/functions/f1")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"invoke_user":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["invoke_user"], true, "PATCH response reflects user grant");
    assert_eq!(
        v["invoke_anon"], false,
        "anon untouched when only user sent"
    );

    // Follow-up GET confirms the grant persisted.
    let resp = router
        .clone()
        .oneshot(
            Request::get("/t/t-acl1/functions/f1")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = json_body(resp).await;
    assert_eq!(v["invoke_user"], true);
    assert_eq!(v["invoke_anon"], false);

    // Revoke user, grant anon in one PATCH — config covers both directions.
    let resp = router
        .clone()
        .oneshot(
            Request::patch("/t/t-acl1/functions/f1")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"invoke_user":false,"invoke_anon":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["invoke_user"], false, "user revoke reflected");
    assert_eq!(v["invoke_anon"], true, "anon grant reflected");
}

#[tokio::test]
async fn anon_and_user_patch_invoke_acl_are_403() {
    // Config is service-only — both non-service bearers are rejected by
    // `require_service_layer` BEFORE the body is parsed.
    let (router, _service, anon, user, _tmp) = helpers::spin_up_tenant_with_fn_seed("t-acl2").await;
    for token in [&anon, &user] {
        let resp = router
            .clone()
            .oneshot(
                Request::patch("/t/t-acl2/functions/f1")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invoke_anon":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "invoke-ACL config must be service-only (token {token})"
        );
    }
}

#[tokio::test]
async fn mcp_set_function_invoke_acl_happy_path() {
    use drust::functions::schema::{self, CreateFunctionParams};
    use drust::mcp::server::McpRegistry;
    use drust::mcp::tools::functions::set_function_invoke_acl;
    use drust::storage::pool::TenantRegistry;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    let s = reg.get_or_create("blog").await.unwrap();

    schema::create_function(
        &s.inner().pool,
        CreateFunctionParams {
            name: "f1".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();

    // Grant user, leave anon denied.
    let v = set_function_invoke_acl(&s, "f1", false, true)
        .await
        .unwrap();
    assert_eq!(v["name"], "f1");
    assert_eq!(v["invoke_anon"], false);
    assert_eq!(v["invoke_user"], true);

    let row = schema::get_function(&s.inner().pool, "f1")
        .await
        .unwrap()
        .unwrap();
    assert!(!row.invoke_anon);
    assert!(row.invoke_user);

    // Unknown function → FN_NOT_FOUND.
    let err = set_function_invoke_acl(&s, "ghost", true, true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("FN_NOT_FOUND"), "{err}");
}

#[test]
fn mcp_exposes_sixty_five_tools() {
    // v1.48 adds the four cron tools (create_cron_job, list_cron_jobs,
    // set_cron_job_active, delete_cron_job), bumping the documented MCP tool
    // count from 61 to 65. `tool_count()` is derived from the macro-generated
    // router, so this pins router reality to the spec'd number.
    assert_eq!(
        drust::mcp::handler::DrustMcpService::tool_count(),
        65,
        "MCP tool count must be 65 after adding the four cron tools"
    );
}

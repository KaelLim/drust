//! Task 6 — cron REST config surface: service-only CRUD under
//! `/t/<tenant>/cron`, validated create (name / schedule / payload / target /
//! cap), index reload-on-write, and the tenant soft-delete cron-index
//! invalidation hook. Layer stack mirrors the functions config router:
//! `require_service_layer` inner, `bearer_auth_layer` outer — anon AND user
//! bearers get the layer's `403 WRITE_DENIED` on every route.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn req(method: &str, uri: &str, token: &str, body: Option<serde_json::Value>) -> Request<Body> {
    let b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

/// Case 1: service creates a function-target job → 201; GET list shows it
/// with a non-null `next_fire`.
#[tokio::test]
async fn service_creates_function_job_and_list_shows_next_fire() {
    let (app, service, _anon, _user, _cron, _tmp) = helpers::spin_up_cron_stack("t-cr1").await;
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/t/t-cr1/cron",
            &service,
            Some(json!({
                "name": "tick",
                "schedule": "*/5 * * * *",
                "target_kind": "function",
                "target_name": "f1",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = json_body(resp).await;
    assert_eq!(v["name"], "tick");
    assert_eq!(v["schedule"], "*/5 * * * *");
    assert_eq!(v["active"], true, "active defaults to true");

    let resp = app
        .clone()
        .oneshot(req("GET", "/t/t-cr1/cron", &service, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    let jobs = v["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0]["name"], "tick");
    assert!(
        jobs[0]["next_fire"].is_string(),
        "list must compute a non-null next_fire, got {}",
        jobs[0]["next_fire"]
    );
}

/// Case 2: anon AND user bearers → 403 on EVERY cron route (the shared
/// `require_service_layer` deny — `WRITE_DENIED`).
#[tokio::test]
async fn anon_and_user_are_403_on_every_cron_route() {
    let (app, _service, anon, user, _cron, _tmp) = helpers::spin_up_cron_stack("t-cr2").await;
    let routes = [
        ("POST", "/t/t-cr2/cron"),
        ("GET", "/t/t-cr2/cron"),
        ("GET", "/t/t-cr2/cron/j"),
        ("PATCH", "/t/t-cr2/cron/j"),
        ("DELETE", "/t/t-cr2/cron/j"),
        ("GET", "/t/t-cr2/cron/j/runs"),
    ];
    for token in [&anon, &user] {
        for (m, uri) in routes {
            let resp = app.clone().oneshot(req(m, uri, token, None)).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{m} {uri} must be service-only"
            );
            let v = json_body(resp).await;
            assert_eq!(v["error_code"], "WRITE_DENIED", "{m} {uri}");
        }
    }
}

/// Case 3: invalid schedule → 400 CRON_INVALID_SCHEDULE; bad name →
/// 400 CRON_INVALID_NAME.
#[tokio::test]
async fn invalid_schedule_and_bad_name_are_400() {
    let (app, service, _anon, _user, _cron, _tmp) = helpers::spin_up_cron_stack("t-cr3").await;
    for sched in ["@daily", "* * * *"] {
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/t/t-cr3/cron",
                &service,
                Some(json!({
                    "name": "okname",
                    "schedule": sched,
                    "target_kind": "function",
                    "target_name": "f1",
                })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "schedule {sched}");
        let v = json_body(resp).await;
        assert_eq!(v["error_code"], "CRON_INVALID_SCHEDULE", "schedule {sched}");
    }
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/t/t-cr3/cron",
            &service,
            Some(json!({
                "name": "no spaces!",
                "schedule": "* * * * *",
                "target_kind": "function",
                "target_name": "f1",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "CRON_INVALID_NAME");
}

/// Case 4: missing target function → 404 CRON_TARGET_NOT_FOUND; an RPC
/// target declaring `user_id` → 409 CRON_RPC_USER_ID (cron has no user
/// identity to bind).
#[tokio::test]
async fn missing_target_404_and_user_id_rpc_409() {
    let (app, service, _anon, _user, _cron, tmp) = helpers::spin_up_cron_stack("t-cr4").await;
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/t/t-cr4/cron",
            &service,
            Some(json!({
                "name": "ghosted",
                "schedule": "* * * * *",
                "target_kind": "function",
                "target_name": "ghost",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "CRON_TARGET_NOT_FOUND");

    // Seed a read-mode RPC that declares :user_id.
    let pool = helpers::grab_pool("t-cr4", &tmp).await;
    pool.with_writer(|c| {
        Ok(drust::rpc::registry::create(
            c,
            "needs_user",
            "SELECT :user_id AS uid",
            r#"[{"name":"user_id","type":"text"}]"#,
            None,
            false,
            drust::rpc::registry::RpcMode::Read,
        ))
    })
    .await
    .unwrap()
    .unwrap();

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/t/t-cr4/cron",
            &service,
            Some(json!({
                "name": "userjob",
                "schedule": "* * * * *",
                "target_kind": "rpc",
                "target_name": "needs_user",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "CRON_RPC_USER_ID");
}

/// Case 5: duplicate name → 409 CRON_DUPLICATE; the 11th job (test cfg cap
/// is 10) → 409 CRON_JOB_LIMIT.
#[tokio::test]
async fn duplicate_and_job_limit_are_409() {
    let (app, service, _anon, _user, _cron, _tmp) = helpers::spin_up_cron_stack("t-cr5").await;
    let create = |name: String| {
        let app = app.clone();
        let service = service.clone();
        async move {
            app.oneshot(req(
                "POST",
                "/t/t-cr5/cron",
                &service,
                Some(json!({
                    "name": name,
                    "schedule": "* * * * *",
                    "target_kind": "function",
                    "target_name": "f1",
                })),
            ))
            .await
            .unwrap()
        }
    };

    let resp = create("dup".to_string()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = create("dup".to_string()).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "CRON_DUPLICATE");

    // 9 more (10 total) fit under the cap; the 11th is refused.
    for i in 1..10 {
        let resp = create(format!("cap{i}")).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "cap{i} under limit");
    }
    let resp = create("cap10".to_string()).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "CRON_JOB_LIMIT");
}

/// Case 6: PATCH toggles active + changes schedule; runs endpoint returns []
/// then reflects a seeded `record_run`; DELETE → 204 and GET → 404.
#[tokio::test]
async fn patch_runs_delete_lifecycle() {
    let (app, service, _anon, _user, _cron, tmp) = helpers::spin_up_cron_stack("t-cr6").await;
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/t/t-cr6/cron",
            &service,
            Some(json!({
                "name": "life",
                "schedule": "30 3 * * *",
                "target_kind": "function",
                "target_name": "f1",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = json_body(resp).await;
    let job_id = created["id"].as_i64().unwrap();

    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/t/t-cr6/cron/life",
            &service,
            Some(json!({"active": false, "schedule": "0 4 * * *"})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["active"], false, "PATCH toggled active off");
    assert_eq!(v["schedule"], "0 4 * * *", "PATCH changed schedule");

    let resp = app
        .clone()
        .oneshot(req("GET", "/t/t-cr6/cron/life/runs", &service, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["runs"].as_array().unwrap().len(), 0, "no runs yet");

    // Seed one run row directly through the store, then re-read.
    let pool = helpers::grab_pool("t-cr6", &tmp).await;
    pool.with_writer(move |c| {
        drust::cron::store::record_run(c, job_id, "2026-07-13T00:00Z", "ok", None, Some(3))
    })
    .await
    .unwrap();
    let resp = app
        .clone()
        .oneshot(req("GET", "/t/t-cr6/cron/life/runs", &service, None))
        .await
        .unwrap();
    let v = json_body(resp).await;
    let runs = v["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["status"], "ok");
    assert_eq!(runs[0]["fired_at"], "2026-07-13T00:00Z");

    let resp = app
        .clone()
        .oneshot(req("DELETE", "/t/t-cr6/cron/life", &service, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app
        .clone()
        .oneshot(req("GET", "/t/t-cr6/cron/life", &service, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "CRON_NOT_FOUND");
}

/// Case 7: index behavior — after create the state's index snapshot contains
/// the job; after PATCH active=false it does not (reload-on-write).
#[tokio::test]
async fn index_reloads_on_create_and_deactivate() {
    let (app, service, _anon, _user, cron, _tmp) = helpers::spin_up_cron_stack("t-cr7").await;
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/t/t-cr7/cron",
            &service,
            Some(json!({
                "name": "idxjob",
                "schedule": "* * * * *",
                "target_kind": "function",
                "target_name": "f1",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let snap = cron.index.snapshot();
    assert_eq!(snap.len(), 1, "index gained the tenant entry on create");
    assert_eq!(snap[0].0, "t-cr7");
    assert_eq!(snap[0].1.len(), 1);
    assert_eq!(snap[0].1[0].name, "idxjob");

    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/t/t-cr7/cron/idxjob",
            &service,
            Some(json!({"active": false})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        cron.index.snapshot().is_empty(),
        "deactivating the only job empties the index"
    );
}

// --- Task 7: MCP tools (direct-fn, the functions_invoke_acl_config.rs
// pattern). MCP dispatch is service-only by construction, so no per-tool
// role check is exercised here — the transport rejects anon/user bearers.

/// MCP create/list/toggle/delete round-trip against a `DrustMcp` sharing the
/// router's `CronState` (the `with_cron` plumbing main.rs uses): mutations
/// made over MCP are visible via REST AND reload the shared schedule index.
#[tokio::test]
async fn mcp_tools_crud_roundtrip_visible_via_rest_and_shared_index() {
    use drust::mcp::tools::cron as mcp_cron;
    use std::sync::Arc;

    let (app, service, _anon, _user, cron, tmp) = helpers::spin_up_cron_stack("t-cr-mcp").await;
    let tr = Arc::new(drust::storage::pool::TenantRegistry::new(
        tmp.path().to_path_buf(),
        2,
    ));
    let reg = drust::mcp::server::McpRegistry::new(tr).with_cron(cron.clone());
    let s = reg.get_or_create("t-cr-mcp").await.unwrap();

    // Create over MCP (payload riding along; explicit active=true).
    let v = mcp_cron::create_cron_job(
        &s,
        "mjob",
        "*/5 * * * *",
        "function",
        "f1",
        Some(r#"{"a":1}"#),
        true,
    )
    .await
    .unwrap();
    assert_eq!(v["name"], "mjob");
    assert_eq!(v["schedule"], "*/5 * * * *");
    assert_eq!(v["active"], true);
    assert!(
        v["next_fire"].is_string(),
        "create echoes a computed next_fire, got {}",
        v["next_fire"]
    );

    // Visible via REST list on the router.
    let resp = app
        .clone()
        .oneshot(req("GET", "/t/t-cr-mcp/cron", &service, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rest = json_body(resp).await;
    let jobs = rest["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0]["name"], "mjob");
    assert_eq!(jobs[0]["payload_json"], r#"{"a":1}"#);

    // The SHARED index gained the job (MCP reload-on-write).
    let snap = cron.index.snapshot();
    assert_eq!(
        snap.len(),
        1,
        "shared index gained the tenant on MCP create"
    );
    assert_eq!(snap[0].0, "t-cr-mcp");
    assert_eq!(snap[0].1[0].name, "mjob");

    // MCP list mirrors REST.
    let v = mcp_cron::list_cron_jobs(&s).await.unwrap();
    let jobs = v["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0]["next_fire"].is_string());

    // Toggle off over MCP → reflected over REST AND the index empties.
    let v = mcp_cron::set_cron_job_active(&s, "mjob", false)
        .await
        .unwrap();
    assert_eq!(v["active"], false);
    let resp = app
        .clone()
        .oneshot(req("GET", "/t/t-cr-mcp/cron/mjob", &service, None))
        .await
        .unwrap();
    let rest = json_body(resp).await;
    assert_eq!(rest["active"], false, "toggle visible via REST get");
    assert!(
        cron.index.snapshot().is_empty(),
        "deactivating the only job over MCP empties the shared index"
    );

    // Toggle back on → index regains it.
    let v = mcp_cron::set_cron_job_active(&s, "mjob", true)
        .await
        .unwrap();
    assert_eq!(v["active"], true);
    assert_eq!(cron.index.snapshot().len(), 1);

    // Delete over MCP → REST get 404 and index empty again.
    let v = mcp_cron::delete_cron_job(&s, "mjob").await.unwrap();
    assert_eq!(v["deleted"], true);
    assert_eq!(v["name"], "mjob");
    let resp = app
        .clone()
        .oneshot(req("GET", "/t/t-cr-mcp/cron/mjob", &service, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(cron.index.snapshot().is_empty());
}

/// MCP tools surface the SAME wire codes as REST (`bail_mcp` reads the code
/// off the `"<CODE>: <message>"` prefix).
#[tokio::test]
async fn mcp_tools_map_ops_errors_to_wire_codes() {
    use drust::mcp::tools::cron as mcp_cron;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let tr = Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "t-cr-mcperr").unwrap();
    let reg = drust::mcp::server::McpRegistry::new(tr);
    let s = reg.get_or_create("t-cr-mcperr").await.unwrap();

    // Seed one function target so the happy-path create (for duplicate) works.
    drust::functions::schema::create_function(
        &s.inner().pool,
        drust::functions::schema::CreateFunctionParams {
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

    let err = mcp_cron::create_cron_job(&s, "bad name!", "* * * * *", "function", "f1", None, true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().starts_with("CRON_INVALID_NAME"),
        "bad name → CRON_INVALID_NAME, got {err}"
    );

    let err = mcp_cron::create_cron_job(&s, "j", "@daily", "function", "f1", None, true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().starts_with("CRON_INVALID_SCHEDULE"),
        "alias schedule → CRON_INVALID_SCHEDULE, got {err}"
    );

    let err = mcp_cron::create_cron_job(&s, "j", "* * * * *", "function", "ghost", None, true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().starts_with("CRON_TARGET_NOT_FOUND"),
        "missing target → CRON_TARGET_NOT_FOUND, got {err}"
    );

    let err =
        mcp_cron::create_cron_job(&s, "j", "* * * * *", "function", "f1", Some("[1,2]"), true)
            .await
            .unwrap_err();
    assert!(
        err.to_string().starts_with("CRON_PAYLOAD_TOO_LARGE"),
        "non-object payload → CRON_PAYLOAD_TOO_LARGE, got {err}"
    );

    mcp_cron::create_cron_job(&s, "j", "* * * * *", "function", "f1", None, true)
        .await
        .unwrap();
    let err = mcp_cron::create_cron_job(&s, "j", "* * * * *", "function", "f1", None, true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().starts_with("CRON_DUPLICATE"),
        "duplicate name → CRON_DUPLICATE, got {err}"
    );

    let err = mcp_cron::set_cron_job_active(&s, "ghost", true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().starts_with("CRON_NOT_FOUND"),
        "toggle on missing job → CRON_NOT_FOUND, got {err}"
    );
    let err = mcp_cron::delete_cron_job(&s, "ghost").await.unwrap_err();
    assert!(
        err.to_string().starts_with("CRON_NOT_FOUND"),
        "delete on missing job → CRON_NOT_FOUND, got {err}"
    );
}

/// Tenant soft-delete hook: `soft_delete_tenant` must invalidate the cron
/// index so a deleted tenant's jobs stop being considered by the minute tick.
#[tokio::test]
async fn tenant_soft_delete_invalidates_cron_index() {
    use axum::extract::{Path as AxumPath, State};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    helpers::seed_tenant_fs(&dir, "t-cr-del");
    let data = dir.path().to_path_buf();
    let conn = drust::storage::meta::open_meta(&data.join("meta.sqlite")).unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let bus = drust::tenant::events::EventBus::new();
    let meta = Arc::new(tokio::sync::Mutex::new(conn));
    let state = drust::mgmt::tenants::TenantsState::test_default(
        meta,
        data,
        tenants.clone(),
        helpers::test_mcp_http(tenants.clone(), bus.clone()),
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );

    let pool = tenants.get_or_open("t-cr-del").unwrap();
    pool.with_writer(|c| {
        drust::cron::store::create_job(c, "j", "* * * * *", "function", "f", None, true)
    })
    .await
    .unwrap();
    state.cron.index.reload("t-cr-del", &pool).await;
    assert_eq!(state.cron.index.snapshot().len(), 1);

    let cron = state.cron.clone();
    let resp =
        drust::mgmt::tenants::soft_delete_tenant(State(state), AxumPath("t-cr-del".to_string()))
            .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        cron.index.snapshot().is_empty(),
        "soft delete must invalidate the tenant's cron index entry"
    );
}

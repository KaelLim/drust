//! v1.36 — MCP function tools, called directly against a `DrustMcp` built
//! from `McpRegistry` (same convention as tests/mcp_write_schema.rs). Service
//! gating itself lives at the MCP transport layer (anon/user rejected before
//! any tool runs); these tests exercise the tool-fn bodies + the
//! `functions: None` recursion-guard branch.

mod helpers;

use drust::functions::schema::{self, CreateFunctionParams, LogRow};
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::functions::{
    delete_function, get_function_logs, invoke_function, list_functions, set_function_active,
};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

/// Registry-built service (`functions: None` — the executor-absent surface).
async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

async fn seed_fn(s: &drust::mcp::server::DrustMcp, name: &str) {
    schema::create_function(
        &s.inner().pool,
        CreateFunctionParams {
            name: name.into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 7,
            triggers_json: "[]".into(),
            description: "seeded".into(),
        },
        10,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn list_shows_seeded_row() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    seed_fn(&s, "f1").await;
    let v = list_functions(&s).await.unwrap();
    let arr = v["functions"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "f1");
    assert_eq!(arr[0]["active"], true);
    assert_eq!(arr[0]["size_bytes"], 7);
}

#[tokio::test]
async fn set_active_reflects_in_row() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    seed_fn(&s, "f1").await;

    let v = set_function_active(&s, "f1", false).await.unwrap();
    assert_eq!(v["name"], "f1");
    assert_eq!(v["active"], false);

    let listed = list_functions(&s).await.unwrap();
    assert_eq!(listed["functions"][0]["active"], false);

    // Unknown name → FN_NOT_FOUND.
    let err = set_function_active(&s, "nope", true).await.unwrap_err();
    assert!(err.to_string().contains("FN_NOT_FOUND"), "{err}");
}

#[tokio::test]
async fn delete_then_second_delete_is_not_found() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    seed_fn(&s, "f1").await;

    let v = delete_function(&s, "f1").await.unwrap();
    assert_eq!(v["deleted"], "f1");

    let err = delete_function(&s, "f1").await.unwrap_err();
    assert!(err.to_string().contains("FN_NOT_FOUND"), "{err}");
}

#[tokio::test]
async fn get_logs_returns_inserted_rows() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    seed_fn(&s, "f1").await;
    let pool = s.inner().pool.clone();
    for st in ["ok", "error"] {
        schema::insert_log(
            &pool,
            LogRow {
                invocation_id: uuid::Uuid::new_v4().to_string(),
                function_name: "f1".into(),
                trigger: "manual".into(),
                status: st.into(),
                duration_ms: 1,
                log_text: format!("hello {st}"),
                result_json: Some("{}".into()),
            },
        )
        .await
        .unwrap();
    }
    let v = get_function_logs(&s, "f1", Some(10)).await.unwrap();
    let logs = v["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 2);
    // Newest first — "error" was inserted last.
    assert_eq!(logs[0]["status"], "error");
    assert!(logs[0]["log_text"].as_str().unwrap().contains("hello"));
}

#[tokio::test]
async fn invoke_without_dispatcher_is_unavailable() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    seed_fn(&s, "f1").await;
    // Registry-built state carries `functions: None` ⇒ no enqueue surface.
    let err = invoke_function(&s, "f1", serde_json::json!({"hi": 1}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("FN_UNAVAILABLE"), "{err}");
}

#[tokio::test]
async fn invoke_unknown_function_is_not_found() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = invoke_function(&s, "ghost", serde_json::json!({}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("FN_NOT_FOUND"), "{err}");
}

#[tokio::test]
async fn invoke_with_dispatcher_enqueues() {
    // Happy path: build a service carrying `Some(dispatcher)` via
    // `with_bus_and_storage`, then invoke — enqueue ack returned and the
    // dispatcher's per-tenant queue depth ticks up.
    let d = tempfile::tempdir().unwrap();
    let data = d.path().to_path_buf();
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let tr = Arc::new(TenantRegistry::new(data, 2));
    // Hold the receiver so the send succeeds (no executor drains it) — the
    // manual enqueue lands in the queue and per-tenant depth stays at 1.
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let dispatcher = drust::functions::dispatcher::FunctionDispatcher::new(
        tr.clone(),
        tx,
        drust::functions::FnConfig::test_default(),
    );
    let reg = McpRegistry::with_bus_and_storage(
        tr.clone(),
        drust::tenant::events::EventBus::new(),
        drust::tenant::WebhookDispatcher::new(tr.clone(), None),
        None,
        String::new(),
        Arc::new([0u8; 32]),
        None,
        12_345,
        1_000_000,
        Arc::new(tokio::sync::Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        drust::tenant::rooms::RoomBus::new(),
        drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        drust::tenant::rooms::RoomsConfig::test_defaults(),
        Arc::new(drust::tenant::auth_cache::AuthCache::new(
            std::time::Duration::from_secs(10),
            200_000,
        )),
        dispatcher.clone(),
    );
    let s = reg.get_or_create("blog").await.unwrap();
    seed_fn(&s, "f1").await;

    let v = invoke_function(&s, "f1", serde_json::json!({"hi": 1}))
        .await
        .unwrap();
    assert_eq!(v["enqueued"], "f1");

    // The manual enqueue accounted one queued invocation for this tenant.
    let depth = dispatcher
        .depth
        .get("blog")
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    assert_eq!(depth, 1, "manual enqueue must bump per-tenant depth");
}

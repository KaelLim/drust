//! v1.58 — `recent_writes` returned 50 rows while telling the model it returned
//! 100. The tool is used to reconcile after a failed or retried write, so a
//! model that believes it has seen the last 100 mutations when it has seen 50
//! will redo the ones that fell in the gap.
//!
//! The default lives in the MCP handler, not in `query_recent`, so the only
//! honest place to observe it is a real `tools/call` with no `limit` argument.
//! The fixture therefore keeps a handle on the very `meta_logs.sqlite`
//! connection the tenant's `DrustMcp` reads from, seeds it with more write rows
//! than any limit under test, and drives the tool over the MCP HTTP surface.

mod helpers;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus};
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Rows seeded into the audit DB — comfortably above the 200 clamp ceiling so
/// both the new default and the clamp are observable.
const SEEDED_WRITES: usize = 250;

/// Spin up a tenant router whose MCP registry is one we hold, so the test can
/// write into the same in-memory `meta_logs.sqlite` that `recent_writes` reads.
async fn spin_up_with_audit(
    tenant: &str,
) -> (Router, String, Arc<Mutex<Connection>>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        rusqlite::params![tenant, hash_token(&tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    let bus_rooms = helpers::shared_bus_rooms(&mut state);
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());

    // Hold the registry so the tenant's service (and therefore its audit
    // connection) is the same instance the HTTP surface will serve.
    let registry = Arc::new(McpRegistry::with_bus(
        tenants,
        bus.clone(),
        bus_rooms.clone(),
    ));
    let audit = registry
        .get_or_create(tenant)
        .await
        .unwrap()
        .inner()
        .audit_meta_read
        .clone();

    let stack = TenantStack {
        auth: state,
        bus,
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: Arc::new(McpHttpRegistry::new(registry)),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    (build_tenant_router(stack), tok, audit, dir)
}

/// Seed `SEEDED_WRITES` `insert_record` audit rows for `tenant`, ascending in
/// time so the newest-first ordering has something to cut.
async fn seed_writes(audit: &Arc<Mutex<Connection>>, tenant: &str) {
    let guard = audit.lock().await;
    for i in 0..SEEDED_WRITES {
        guard
            .execute(
                "INSERT INTO audit (ts, tenant, token_hint, op, status, duration_ms, extra) \
                 VALUES (?1, ?2, '-', 'insert_record', 'ok', 1, '{\"collection\":\"rows\"}')",
                rusqlite::params![
                    format!("2026-08-02T00:{:02}:{:02}.000Z", i / 60, i % 60),
                    tenant
                ],
            )
            .unwrap();
    }
}

fn mcp_req(tid: &str, token: &str, sid: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(sid) = sid {
        b = b.header("mcp-session-id", sid);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn parse_mcp_response(resp: axum::response::Response) -> Vec<serde_json::Value> {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.strip_prefix("data:").unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            out.push(v);
        }
    }
    out
}

async fn mcp_init(app: &Router, tid: &str, token: &str) -> String {
    let init = mcp_req(
        tid,
        token,
        None,
        serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      "clientInfo":{"name":"test","version":"0"}}
        }),
    );
    let r = app.clone().oneshot(init).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "initialize failed");
    let sid = r
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let _ = parse_mcp_response(r).await;
    let ack = mcp_req(
        tid,
        token,
        Some(&sid),
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    let _ = app.clone().oneshot(ack).await.unwrap();
    sid
}

/// Call `recent_writes` and return the row array it produced.
async fn call_recent_writes(
    app: &Router,
    tid: &str,
    token: &str,
    sid: &str,
    limit: Option<u32>,
) -> Vec<serde_json::Value> {
    let mut args = serde_json::Map::new();
    if let Some(l) = limit {
        args.insert("limit".into(), serde_json::json!(l));
    }
    let call = mcp_req(
        tid,
        token,
        Some(sid),
        serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"recent_writes","arguments":args}
        }),
    );
    let resp = app.clone().oneshot(call).await.unwrap();
    assert!(resp.status().is_success(), "tools/call {}", resp.status());
    let msgs = parse_mcp_response(resp).await;
    let text = msgs
        .iter()
        .find_map(|m| {
            m["result"]["content"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|c| c["text"].as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| panic!("no tool content in {msgs:?}"));
    serde_json::from_str::<Vec<serde_json::Value>>(&text)
        .unwrap_or_else(|e| panic!("recent_writes returned {text}: {e}"))
}

#[tokio::test]
async fn recent_writes_default_matches_its_advertised_limit() {
    let tenant = "rwlimit";
    let (app, tok, audit, _dir) = spin_up_with_audit(tenant).await;
    seed_writes(&audit, tenant).await;
    let sid = mcp_init(&app, tenant, &tok).await;

    let rows = call_recent_writes(&app, tenant, &tok, &sid, None).await;
    assert_eq!(
        rows.len(),
        100,
        "the default must match the 100 the tool description and the MCP \
         prologue both promise"
    );
}

/// The prologue tells the model "call `tools/list` for the canonical input
/// schema of every tool", and schemars publishes the `RecentWritesArgs::limit`
/// doc comment verbatim as that parameter's description. So the doc comment is
/// not prose — it is the machine-readable half of the same promise, and the one
/// most MCP clients render into the system prompt. If it disagrees with what
/// the handler actually does, the model holds two numbers for one parameter.
#[tokio::test]
async fn tools_list_schema_advertises_the_same_default() {
    let tenant = "rwlimit3";
    let (app, tok, _audit, _dir) = spin_up_with_audit(tenant).await;
    let sid = mcp_init(&app, tenant, &tok).await;

    let list = mcp_req(
        tenant,
        &tok,
        Some(&sid),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    );
    let resp = app.clone().oneshot(list).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "tools/list failed");
    let msgs = parse_mcp_response(resp).await;
    let tools = msgs
        .iter()
        .find_map(|m| m["result"]["tools"].as_array().cloned())
        .unwrap_or_else(|| panic!("no tools array in {msgs:?}"));
    let tool = tools
        .iter()
        .find(|t| t["name"] == "recent_writes")
        .unwrap_or_else(|| panic!("recent_writes missing from tools/list"));
    let desc = tool["inputSchema"]["properties"]["limit"]["description"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "no description on the limit property; schema was {}",
                tool["inputSchema"]
            )
        });

    assert!(
        !desc.contains("50"),
        "the published input schema still advertises the old default: {desc:?}"
    );
    assert!(
        desc.contains("100"),
        "the published input schema must state the real default of 100: {desc:?}"
    );
}

#[tokio::test]
async fn an_explicit_limit_still_wins_and_is_clamped() {
    let tenant = "rwlimit2";
    let (app, tok, audit, _dir) = spin_up_with_audit(tenant).await;
    seed_writes(&audit, tenant).await;
    let sid = mcp_init(&app, tenant, &tok).await;

    let rows = call_recent_writes(&app, tenant, &tok, &sid, Some(3)).await;
    assert_eq!(rows.len(), 3, "an explicit limit still wins");

    // Above the clamp ceiling: `query_recent` clamps to 1..=200.
    let rows = call_recent_writes(&app, tenant, &tok, &sid, Some(9_999)).await;
    assert_eq!(
        rows.len(),
        200,
        "clamped to the 200 ceiling, not {SEEDED_WRITES}"
    );
}

//! Smoke-level integration test for the rmcp Streamable HTTP endpoint
//! at `/t/{tenant}/mcp`. Exercises the real HTTP surface — JSON-RPC
//! initialize, tools/list, tools/call — without a full rmcp client.
//!
//! We keep it deliberately minimal: the goal is to prove the wiring is
//! real (rmcp handler → axum route → bearer auth → per-tenant service)
//! rather than to re-test every tool. Per-tool behavior is covered by
//! the in-process tests in `mcp_write_schema.rs`, `mcp_read.rs`,
//! `mcp_exploration.rs`.
//!
//! NOTE: every request that reaches rmcp must carry a loopback `Host`
//! header — rmcp's DNS-rebinding guard rejects anything else with 400
//! "missing Host header". In production Caddy sets this via
//! `header_up Host "127.0.0.1:47826"`. Tests must do it themselves.

mod helpers;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn mcp_stack(tenant: &str) -> (axum::Router, String, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let service_tok = generate_token();
    let anon_tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) \
         VALUES (?1, ?2, 'svc', 'service')",
        rusqlite::params![tenant, hash_token(&service_tok)],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) \
         VALUES (?1, ?2, 'anon', 'anon')",
        rusqlite::params![tenant, hash_token(&anon_tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    // Migrate so meta `tenants` gains the v1.32.5 allow_*_publish columns the
    // bearer-auth CTE reads (open_meta only creates the base schema).
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    let bus_rooms = helpers::shared_bus_rooms(&mut state);
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: helpers::test_mcp_http(tenants, bus, bus_rooms.clone()),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    });
    (app, service_tok, anon_tok, dir)
}

fn mcp_request(tenant: &str, bearer: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("/t/{tenant}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        // The MCP Streamable HTTP transport requires the client advertise
        // that it accepts both JSON and SSE responses on the POST.
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Parse the rmcp Streamable-HTTP response body. The server can answer
/// a POST in either `application/json` (single response) or
/// `text/event-stream` (one event per message). We normalise both
/// into a flat Vec<Value>.
async fn parse_mcp_body(resp: axum::response::Response) -> Vec<Value> {
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    if ct.starts_with("text/event-stream") {
        // SSE frames separated by blank line; each frame has `data: <json>` lines.
        let mut out = Vec::new();
        for frame in text.split("\n\n") {
            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    let trimmed = data.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let v: Value = serde_json::from_str(trimmed)
                        .unwrap_or_else(|e| panic!("bad SSE JSON {trimmed:?}: {e}"));
                    out.push(v);
                }
            }
        }
        out
    } else {
        vec![serde_json::from_str(&text).unwrap_or_else(|e| panic!("bad JSON {text:?}: {e}"))]
    }
}

#[tokio::test]
async fn initialize_then_tools_list_returns_core_tools() {
    let (app, service_tok, _anon, _dir) = mcp_stack("mcp1").await;

    // Step 1: MCP initialize handshake — this is required before any
    // other methods. The response MUST come back with a session ID
    // header that we echo on subsequent requests.
    let init = mcp_request(
        "mcp1",
        &service_tok,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "drust-test", "version": "0.0.0"}
            }
        }),
    );
    let init_resp = app.clone().oneshot(init).await.unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .expect("initialize response must set mcp-session-id header")
        .to_str()
        .unwrap()
        .to_string();
    let init_msgs = parse_mcp_body(init_resp).await;
    assert!(!init_msgs.is_empty());
    let result = &init_msgs[0]["result"];
    assert_eq!(result["serverInfo"]["name"], "drust");

    // Step 2: notifications/initialized — no response expected, just
    // acknowledge to the server that handshake is complete.
    let initd = Request::builder()
        .method(Method::POST)
        .uri("/t/mcp1/mcp")
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {}", service_tok))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .body(Body::from(
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            })
            .to_string(),
        ))
        .unwrap();
    let ack = app.clone().oneshot(initd).await.unwrap();
    // 202 Accepted for notification (no response body).
    assert!(ack.status() == StatusCode::ACCEPTED || ack.status() == StatusCode::OK);

    // Step 3: tools/list — assert the core read/write/schema tools are
    // present. We do NOT assert the total count: new tools (set_anon_caps,
    // whoami, …) get added over time and a strict count just rots.
    let tl_req = Request::builder()
        .method(Method::POST)
        .uri("/t/mcp1/mcp")
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {}", service_tok))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .body(Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();
    let tl_resp = app.clone().oneshot(tl_req).await.unwrap();
    assert_eq!(tl_resp.status(), StatusCode::OK);
    let tl_msgs = parse_mcp_body(tl_resp).await;
    let tools = tl_msgs
        .iter()
        .find_map(|m| m["result"]["tools"].as_array().cloned())
        .expect("tools/list must return a tools array");
    let names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    for expected in [
        "list_collections",
        "describe_collection",
        "query",
        "explain",
        "create_collection",
        "add_field",
        "drop_field",
        "drop_collection",
        "insert_record",
        "update_record",
        "delete_record",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing tool {expected:?}; got {names:?}"
        );
    }
}

#[tokio::test]
async fn anon_bearer_is_rejected_with_403() {
    let (app, _svc, anon_tok, _dir) = mcp_stack("mcp2").await;
    let req = mcp_request(
        "mcp2",
        &anon_tok,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "x", "version": "0"}
            }
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "WRITE_DENIED");
}

#[tokio::test]
async fn missing_bearer_is_rejected_with_401() {
    let (app, _svc, _anon, _dir) = mcp_stack("mcp3").await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/t/mcp3/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tools_call_list_collections_succeeds() {
    let (app, service_tok, _anon, _dir) = mcp_stack("mcp4").await;
    // Seed a table so list_collections has something to report.
    let pool = helpers::grab_pool("mcp4", &_dir).await;
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE stuff (id INTEGER PRIMARY KEY AUTOINCREMENT, x TEXT);")
    })
    .await
    .unwrap();

    // Initialize + notifications/initialized + call list_collections.
    let init = mcp_request(
        "mcp4",
        &service_tok,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "x", "version": "0"}
            }
        }),
    );
    let init_resp = app.clone().oneshot(init).await.unwrap();
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    // drain body
    let _ = parse_mcp_body(init_resp).await;

    let ack = Request::builder()
        .method(Method::POST)
        .uri("/t/mcp4/mcp")
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {}", service_tok))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .body(Body::from(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        ))
        .unwrap();
    let _ = app.clone().oneshot(ack).await.unwrap();

    let call = Request::builder()
        .method(Method::POST)
        .uri("/t/mcp4/mcp")
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {}", service_tok))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .body(Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": { "name": "list_collections", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();
    let call_resp = app.clone().oneshot(call).await.unwrap();
    assert_eq!(call_resp.status(), StatusCode::OK);
    let msgs = parse_mcp_body(call_resp).await;
    let content = msgs
        .iter()
        .find_map(|m| m["result"]["content"].as_array().cloned())
        .expect("tools/call must return a content array");
    let text = content[0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).unwrap();
    let cols = parsed["collections"].as_array().unwrap();
    assert!(
        cols.iter().any(|c| c["name"] == "stuff"),
        "expected `stuff` in collections list, got {parsed:?}"
    );
}

/// initialize + notifications/initialized, returning the session id and the
/// initialize `result` (instructions, capabilities, serverInfo).
async fn open_session(app: &axum::Router, tenant: &str, tok: &str) -> (String, Value) {
    let init = mcp_request(
        tenant,
        tok,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "drust-test", "version": "0.0.0"}
            }
        }),
    );
    let init_resp = app.clone().oneshot(init).await.unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .expect("initialize response must set mcp-session-id header")
        .to_str()
        .unwrap()
        .to_string();
    let result = parse_mcp_body(init_resp)
        .await
        .into_iter()
        .find_map(|m| m.get("result").cloned())
        .expect("initialize must return a result");
    let ack = session_request(
        tenant,
        tok,
        &session_id,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    let ack = app.clone().oneshot(ack).await.unwrap();
    assert!(ack.status() == StatusCode::ACCEPTED || ack.status() == StatusCode::OK);
    (session_id, result)
}

fn session_request(tenant: &str, bearer: &str, session_id: &str, body: Value) -> Request<Body> {
    let mut req = mcp_request(tenant, bearer, body);
    req.headers_mut()
        .insert("mcp-session-id", session_id.parse().unwrap());
    req
}

/// The annotations Claude Code acts on (auto-resend after a dropped connection
/// for readOnly OR idempotent tools) as they actually leave the server —
/// `Some(false)` must serialize, not vanish into the spec default.
#[tokio::test]
async fn tools_list_wire_annotations_for_retry_sensitive_tools() {
    let (app, service_tok, _anon, _dir) = mcp_stack("mcpann").await;
    let (sid, _) = open_session(&app, "mcpann", &service_tok).await;
    let req = session_request(
        "mcpann",
        &service_tok,
        &sid,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tools = parse_mcp_body(resp)
        .await
        .iter()
        .find_map(|m| m["result"]["tools"].as_array().cloned())
        .expect("tools/list must return a tools array");
    let ann = |name: &str| -> Value {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("tool {name} missing from tools/list"))["annotations"]
            .clone()
    };
    for (tool, key, want) in [
        ("update_record", "idempotentHint", false),
        ("upsert_records", "idempotentHint", false),
        ("call_rpc", "readOnlyHint", true),
        ("list_records", "openWorldHint", false),
        ("invoke_function", "openWorldHint", true),
        ("set_file_visibility", "destructiveHint", true),
    ] {
        let a = ann(tool);
        assert_eq!(
            a[key],
            Value::Bool(want),
            "{tool}.annotations.{key} on the wire; got annotations {a}"
        );
    }
}

/// M1 (B6): a tool-execution failure leaves the server as an `isError: true`
/// result — not `isError: false` with an error object in the text.
#[tokio::test]
async fn tools_call_describe_missing_collection_is_error_on_wire() {
    let (app, service_tok, _anon, _dir) = mcp_stack("mcpiserr").await;
    let (sid, _) = open_session(&app, "mcpiserr", &service_tok).await;
    let req = session_request(
        "mcpiserr",
        &service_tok,
        &sid,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "describe_collection", "arguments": {"collection": "nope"} }
        }),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let result = parse_mcp_body(resp)
        .await
        .into_iter()
        .find_map(|m| m.get("result").cloned())
        .expect("tools/call must return a result");
    assert_eq!(
        result["isError"],
        Value::Bool(true),
        "result on the wire: {result}"
    );
    let text = result["content"][0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["error_code"], "COLLECTION_NOT_FOUND", "{parsed}");
}

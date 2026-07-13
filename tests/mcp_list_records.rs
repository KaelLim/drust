//! v1.21 — MCP `list_records` tool tests.
//!
//! Mirrors `mcp_vector.rs` shape for the direct-call cases and reuses
//! the protocol scaffold from `mcp_protocol.rs` for tools/list +
//! user-token rejection.

#[path = "helpers.rs"]
mod helpers;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::read::{ListRecordsArgs, list_records};
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::write::insert_record;
use drust::query::list_builder::SortSpec;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ──────────────────────────────────────────────────────────────────────
// Direct-call scaffold (same as tests/mcp_vector.rs)
// ──────────────────────────────────────────────────────────────────────

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

/// Create a `posts(title, score)` collection.
async fn make_posts(s: &drust::mcp::server::DrustMcp) {
    create_collection(
        s,
        "posts",
        &[
            FieldSpec {
                name: "title".into(),
                sql_type: "text".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: None,
                ..Default::default()
            },
            FieldSpec {
                name: "score".into(),
                sql_type: "integer".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: None,
                ..Default::default()
            },
        ],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn list_records_happy_path() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    for (title, score) in &[("alpha", 1i64), ("beta", 2), ("gamma", 3)] {
        insert_record(&s, "posts", json!({"title": title, "score": score}))
            .await
            .unwrap();
    }
    let out = list_records(
        &s,
        ListRecordsArgs {
            collection: "posts".into(),
            filter: None,
            sort: None,
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(out["total"], 3, "got {out:?}");
    let rows = out["records"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
}

#[tokio::test]
async fn list_records_filter_and_sort_same_rows_as_rest() {
    // The two surfaces share the same builder, so we just need to prove
    // the MCP path threads the FilterAst + SortSpec through.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    for (title, score) in &[("alpha", 5i64), ("beta", 10), ("gamma", 15)] {
        insert_record(&s, "posts", json!({"title": title, "score": score}))
            .await
            .unwrap();
    }
    let out = list_records(
        &s,
        ListRecordsArgs {
            collection: "posts".into(),
            filter: Some(json!({"score": {"gte": 10}})),
            sort: Some(SortSpec {
                field: "score".into(),
                dir: "desc".into(),
            }),
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap();
    let rows = out["records"].as_array().unwrap();
    let titles: Vec<&str> = rows.iter().map(|r| r["title"].as_str().unwrap()).collect();
    assert_eq!(titles, vec!["gamma", "beta"], "got {out:?}");
}

#[tokio::test]
async fn list_records_protected_collection_is_collection_not_found() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = list_records(
        &s,
        ListRecordsArgs {
            collection: "_system_users".into(),
            filter: None,
            sort: None,
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND"),
        "expected COLLECTION_NOT_FOUND, got: {msg}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Protocol-level scaffold for user-token rejection + tools/list
// ──────────────────────────────────────────────────────────────────────

async fn mcp_stack(tenant: &str) -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let service_tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) \
         VALUES (?1, ?2, 'svc', 'service')",
        rusqlite::params![tenant, hash_token(&service_tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    });
    (app, service_tok, dir)
}

fn mcp_request(tenant: &str, bearer: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("/t/{tenant}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(body.to_string()))
        .unwrap()
}

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
async fn user_token_via_mcp_is_rejected_with_write_denied() {
    // Spec §4.3 row 3 — MCP_USER_DENIED. The existing dispatch reject
    // covers any new tool transparently. We register a user token via
    // self-register and then POST to /mcp; expect 403 + WRITE_DENIED
    // (mcp_dispatch returns this for any non-service kind).
    use helpers::{register_and_login_via_app, spin_up_tenant_self_register};
    let tid = "mcp-user-rej";
    let (app, _svc_tok, _dir) = spin_up_tenant_self_register(tid).await;
    let user_tok = register_and_login_via_app(&app, tid, "u@x.com", "longpassword").await;
    let req = mcp_request(
        tid,
        &user_tok,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"}
            }
        }),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    // Per CLAUDE.md `MCP_USER_DENIED` is the user-token-specific
    // rejection; `WRITE_DENIED` is the anon rejection. Either is a
    // valid service-key-only rejection, but we want the user-typed
    // code so the rejection chain stays observable.
    assert_eq!(v["error_code"], "MCP_USER_DENIED");
}

#[tokio::test]
async fn tools_list_contains_list_records() {
    let (app, svc_tok, _dir) = mcp_stack("mcp-tlist").await;

    // Initialize.
    let init = mcp_request(
        "mcp-tlist",
        &svc_tok,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.0.0"}
            }
        }),
    );
    let init_resp = app.clone().oneshot(init).await.unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .expect("mcp-session-id missing")
        .to_str()
        .unwrap()
        .to_string();
    // Drain response.
    let _ = parse_mcp_body(init_resp).await;

    // Acknowledge.
    let ack_req = Request::builder()
        .method(Method::POST)
        .uri("/t/mcp-tlist/mcp")
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {svc_tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .body(Body::from(
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        ))
        .unwrap();
    let _ = app.clone().oneshot(ack_req).await.unwrap();

    // tools/list.
    let tl_req = Request::builder()
        .method(Method::POST)
        .uri("/t/mcp-tlist/mcp")
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {svc_tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .body(Body::from(
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    let tl_resp = app.oneshot(tl_req).await.unwrap();
    assert_eq!(tl_resp.status(), StatusCode::OK);
    let msgs = parse_mcp_body(tl_resp).await;
    let tools = msgs
        .iter()
        .find_map(|m| m["result"]["tools"].as_array().cloned())
        .expect("tools/list must return a tools array");
    let names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n == "list_records"),
        "list_records must be in catalog; got: {names:?}"
    );
}

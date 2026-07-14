//! Task 3 (v1.49) — service-only egress-allowlist config surface.
//!
//! Covers all three faces sharing one transport-agnostic core
//! (`tenant::egress_config::set_allowlist` / `get_allowlist`):
//!   • REST `PUT/GET /t/{tenant}/egress-allowlist` — service-only whole-list
//!     replace; anon/user → 403 (require_service_layer).
//!   • config-time validation → typed 400 codes EGRESS_BAD_ORIGIN /
//!     EGRESS_BAD_SYSTEM / EGRESS_TOO_MANY.
//!   • MCP `set_egress_allowlist` reflected via the REST GET (shared store).
//!   • an audit row (op `tenant.egress.set`) lands on every mutation.
//! The 65 → 67 MCP tool-count bump is pinned by the derived lib test
//! (`cargo test --lib mcp::handler`); this file drives the two new tools
//! end-to-end over the Streamable-HTTP endpoint.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── global audit writer (pattern copied from rpc_v2_mutation.rs) ────────────

/// Initialise the process-wide audit writer once and return the DB path. The
/// writer runs on a dedicated std::thread so its task outlives individual
/// `#[tokio::test]` runtimes. `try_send` is a no-op until this runs, so tests
/// asserting an audit row must call this before the mutation.
fn ensure_global_audit_writer() -> &'static PathBuf {
    use drust::safety::audit_db::{AuditWriter, init_globals, open_audit_db_write};
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_egress_config_audit.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-egress-audit-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    init_globals(writer);
                    let _ = tx_ready.send(());
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

/// Drain audit rows for `tenant` from the global SQLite audit DB, flattening
/// `extra` into top-level keys.
async fn read_audit_lines(tenant: &str) -> Vec<serde_json::Value> {
    use drust::safety::audit_db::open_audit_db_read;
    let path = ensure_global_audit_writer();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let r = open_audit_db_read(path).unwrap();
    let _ = r.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
    let mut stmt = r
        .prepare("SELECT tenant, status, op, extra FROM audit WHERE tenant = ?1 ORDER BY id ASC")
        .unwrap();
    stmt.query_map(rusqlite::params![tenant], |r| {
        let tenant: Option<String> = r.get(0)?;
        let status: Option<String> = r.get(1)?;
        let op: Option<String> = r.get(2)?;
        let extra_json: Option<String> = r.get(3)?;
        let mut map = serde_json::Map::new();
        if let Some(t) = tenant {
            map.insert("tenant".into(), serde_json::Value::String(t));
        }
        if let Some(s) = status {
            map.insert("status".into(), serde_json::Value::String(s));
        }
        if let Some(o) = op {
            map.insert("op".into(), serde_json::Value::String(o));
        }
        if let Some(extra_str) = extra_json
            && let Ok(serde_json::Value::Object(extra_map)) =
                serde_json::from_str::<serde_json::Value>(&extra_str)
        {
            for (k, v) in extra_map {
                map.entry(k).or_insert(v);
            }
        }
        Ok(serde_json::Value::Object(map))
    })
    .unwrap()
    .filter_map(Result::ok)
    .collect()
}

// ─── heavy harness: a tenant router with MCP meta wired ──────────────────────

/// Build a tenant stack whose MCP registry has `meta` wired (the standard
/// `test_mcp_http` helper does NOT), so the `set_egress_allowlist` /
/// `get_egress_allowlist` tools — which read `self.state.meta()` — work over
/// the Streamable-HTTP endpoint AND write to the same meta the REST routes
/// read. Returns `(app, service, anon, user, dir)`; the dir is returned so
/// the caller keeps the on-disk meta alive.
async fn spin_up_egress(tid: &str) -> (axum::Router, String, String, String, tempfile::TempDir) {
    use drust::auth::bearer::{generate_token, hash_token};
    use drust::mcp::http_registry::McpHttpRegistry;
    use drust::mcp::server::McpRegistry;
    use drust::storage::meta::open_meta;
    use drust::storage::pool::TenantRegistry;
    use drust::tenant::router::TenantAuthState;
    use drust::tenant::{TenantStack, build_tenant_router, events::EventBus};

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tid],
    )
    .unwrap();
    let service = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        rusqlite::params![tid, hash_token(&service)],
    )
    .unwrap();
    let anon = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'anon')",
        rusqlite::params![tid, hash_token(&anon)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tid).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);
    let meta_arc = Arc::new(Mutex::new(conn));

    // Seed a `_system_users` row + active session so the user-token 403 path is
    // exercised with a real `drust_user_*` bearer.
    let pool = tenants.get_or_open(tid).unwrap();
    let user_token = pool
        .with_writer(|c| {
            c.execute(
                "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
                 VALUES ('u-egress', 'u@x', 'h', datetime('now'), datetime('now'))",
                [],
            )?;
            drust::auth::user_session::create_session(c, "u-egress", None, 30)
        })
        .await
        .unwrap();

    let mcp_reg = Arc::new(McpRegistry::with_bus_and_storage(
        tenants.clone(),
        bus.clone(),
        webhooks.clone(),
        None,
        String::new(),
        Arc::new([0u8; 32]),
        Some(meta_arc.clone()),
        52_428_800,
        1_000_000,
        Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        drust::tenant::rooms::RoomBus::new(),
        drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        drust::tenant::rooms::RoomsConfig::test_defaults(),
        Arc::new(drust::tenant::auth_cache::AuthCache::new(
            std::time::Duration::from_secs(10),
            200_000,
        )),
        drust::functions::dispatcher::FunctionDispatcher::new(
            tenants.clone(),
            tokio::sync::mpsc::channel(8).0,
            drust::functions::FnConfig::test_default(),
        ),
    ));
    let state = TenantAuthState::test_default(meta_arc.clone(), tenants.clone());
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: Arc::new(McpHttpRegistry::new(mcp_reg)),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, service, anon, user_token, dir)
}

// ─── REST helpers ────────────────────────────────────────────────────────────

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn put_req(tid: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/t/{tid}/egress-allowlist"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_req(tid: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/t/{tid}/egress-allowlist"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

// ─── MCP helpers (copied from admin_users.rs) ────────────────────────────────

fn mcp_req_with_session(
    tid: &str,
    token: &str,
    session_id: &str,
    body: serde_json::Value,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", session_id)
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn parse_mcp_response(resp: axum::response::Response) -> Vec<serde_json::Value> {
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
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
                    if let Ok(v) = serde_json::from_str(trimmed) {
                        out.push(v);
                    }
                }
            }
        }
        out
    } else if text.is_empty() {
        vec![]
    } else {
        vec![serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)]
    }
}

async fn mcp_init(app: &axum::Router, tid: &str, token: &str) -> String {
    let init = Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"}
                }
            })
            .to_string(),
        ))
        .unwrap();
    let init_resp = app.clone().oneshot(init).await.unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK, "MCP initialize failed");
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .expect("initialize must set mcp-session-id")
        .to_str()
        .unwrap()
        .to_string();
    let _ = parse_mcp_response(init_resp).await;
    let ack = mcp_req_with_session(
        tid,
        token,
        &session_id,
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    let _ = app.clone().oneshot(ack).await.unwrap();
    session_id
}

async fn mcp_call_tool(
    app: &axum::Router,
    tid: &str,
    token: &str,
    session_id: &str,
    name: &str,
    args: serde_json::Value,
) -> String {
    let call = mcp_req_with_session(
        tid,
        token,
        session_id,
        serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":name,"arguments":args}
        }),
    );
    let resp = app.clone().oneshot(call).await.unwrap();
    assert!(
        resp.status().is_success(),
        "tools/call {name} HTTP status: {}",
        resp.status()
    );
    let msgs = parse_mcp_response(resp).await;
    msgs.iter()
        .find_map(|m| {
            m["result"]["content"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|c| c["text"].as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| serde_json::to_string(&msgs).unwrap())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn service_put_valid_then_get_returns_normalized() {
    let tid = "t-egr1";
    let (app, service, _anon, _user, _dir) = spin_up_egress(tid).await;

    // Mixed-case host + path + default port — must normalize on store.
    let resp = app
        .clone()
        .oneshot(put_req(
            tid,
            &service,
            serde_json::json!({"entries":[
                {"system":"webhook","uri":"https://GitLab.com/hook?q=1"},
                {"system":"function","uri":"https://api.github.com:443"}
            ]}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["entries"][0]["uri"], "https://gitlab.com");
    assert_eq!(v["entries"][0]["system"], "webhook");
    assert_eq!(v["entries"][1]["uri"], "https://api.github.com");
    assert_eq!(v["entries"][1]["system"], "function");

    // GET reflects the normalized stored value.
    let resp = app.oneshot(get_req(tid, &service)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["entries"].as_array().unwrap().len(), 2);
    assert_eq!(v["entries"][0]["uri"], "https://gitlab.com");
}

#[tokio::test]
async fn anon_and_user_put_are_403() {
    let tid = "t-egr2";
    let (app, _service, anon, user, _dir) = spin_up_egress(tid).await;
    for token in [&anon, &user] {
        let resp = app
            .clone()
            .oneshot(put_req(
                tid,
                token,
                serde_json::json!({"entries":[{"system":"webhook","uri":"https://a.com"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "egress config must be service-only (token {token})"
        );
    }
    // A non-service GET is likewise blocked.
    let resp = app.oneshot(get_req(tid, &anon)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bad_origin_returns_400_egress_bad_origin() {
    let tid = "t-egr3";
    let (app, service, _anon, _user, _dir) = spin_up_egress(tid).await;
    let resp = app
        .oneshot(put_req(
            tid,
            &service,
            serde_json::json!({"entries":[{"system":"webhook","uri":"a.com"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "EGRESS_BAD_ORIGIN");
}

#[tokio::test]
async fn bad_system_returns_400_egress_bad_system() {
    let tid = "t-egr4";
    let (app, service, _anon, _user, _dir) = spin_up_egress(tid).await;
    let resp = app
        .oneshot(put_req(
            tid,
            &service,
            serde_json::json!({"entries":[{"system":"bogus","uri":"https://a.com"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "EGRESS_BAD_SYSTEM");
}

#[tokio::test]
async fn fifty_first_entry_returns_400_egress_too_many() {
    let tid = "t-egr5";
    let (app, service, _anon, _user, _dir) = spin_up_egress(tid).await;
    let entries: Vec<serde_json::Value> = (0..51)
        .map(|i| serde_json::json!({"system":"function","uri":format!("https://h{i}.example.com")}))
        .collect();
    let resp = app
        .oneshot(put_req(
            tid,
            &service,
            serde_json::json!({ "entries": entries }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert_eq!(v["error_code"], "EGRESS_TOO_MANY");
}

#[tokio::test]
async fn mcp_set_egress_allowlist_reflected_via_rest_get() {
    let tid = "t-egr6";
    let (app, service, _anon, _user, _dir) = spin_up_egress(tid).await;
    let sid = mcp_init(&app, tid, &service).await;

    let txt = mcp_call_tool(
        &app,
        tid,
        &service,
        &sid,
        "set_egress_allowlist",
        serde_json::json!({"entries":[{"system":"function","uri":"https://api.github.com/"}]}),
    )
    .await;
    assert!(
        txt.contains("api.github.com"),
        "MCP set_egress_allowlist response: {txt}"
    );

    // REST GET reflects what the MCP tool wrote (shared meta store).
    let resp = app.clone().oneshot(get_req(tid, &service)).await.unwrap();
    let v = json_body(resp).await;
    assert_eq!(v["entries"][0]["uri"], "https://api.github.com");
    assert_eq!(v["entries"][0]["system"], "function");

    // The MCP get tool returns the same view.
    let txt = mcp_call_tool(
        &app,
        tid,
        &service,
        &sid,
        "get_egress_allowlist",
        serde_json::json!({}),
    )
    .await;
    assert!(txt.contains("api.github.com"), "MCP get returned: {txt}");
}

#[tokio::test]
async fn mutation_emits_audit_row_tenant_egress_set() {
    ensure_global_audit_writer();
    let tid = "t-egr-audit";
    let (app, service, _anon, _user, _dir) = spin_up_egress(tid).await;
    let resp = app
        .oneshot(put_req(
            tid,
            &service,
            serde_json::json!({"entries":[{"system":"webhook","uri":"https://a.com"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = read_audit_lines(tid).await;
    assert!(
        rows.iter().any(|r| r["op"] == "tenant.egress.set"),
        "expected an audit row op=tenant.egress.set, got: {rows:?}"
    );
}

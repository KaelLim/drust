// tests/auth_cache_mcp_publish_policy.rs — hook 11 (MCP face) + the #955
// rooms eviction on that same face.
//
// `patch_publish_policy` (REST admin) fires a tenant-scoped clear (hook 11),
// but the publish-policy flags have a SECOND production writer: the MCP
// `set_publish_policy` tool (src/mcp/tools/owner_field.rs). Same seam as the
// hooks 7/8 MCP tools: the tool fn takes `Option<&AuthCache>` and invalidates
// inside the fn, so the wiring is exercised directly here. Without the clear,
// a model flipping `allow_user_publish` via MCP leaves every cached entry
// serving the OLD policy for up to the safety TTL.
//
// #955 gave the SAME station a second obligation, and this file pins it on
// this face for the same reason it pins hook 11 here: a live rooms WS socket
// captures its `TenantPublishPolicy` once at upgrade, so turning
// `allow_anon_publish` OFF over `/t/<id>/mcp` — the natural way for a tenant
// to stop publish abuse — must close those sockets, exactly as the REST PATCH
// does (`tests/auth_cache_publish_policy.rs`).
mod helpers;

use drust::storage::meta::open_meta;
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use drust::tenant::rooms::RoomBus;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;
use tokio::sync::Mutex;

fn bearer_entry(tenant: &str) -> CachedAuth {
    CachedAuth::Bearer {
        bound_tenant_id: tenant.to_string(),
        role: CachedRole::Service,
        publish_user_allowed: false,
        publish_anon_allowed: false,
        email_snapshot: None,
        file_caps: Default::default(),
        expires_at: None,
        quota_tier: 1,
    }
}

fn user_entry(tenant: &str) -> CachedAuth {
    CachedAuth::User {
        tenant_id: tenant.to_string(),
        user_id: "u-1".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        publish_user_allowed: false,
        publish_anon_allowed: false,
        file_caps: Default::default(),
        quota_tier: 1,
    }
}

#[tokio::test]
async fn mcp_set_publish_policy_clears_tenant_scoped_entries() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    // migrations add tenants.allow_user_publish / allow_anon_publish
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-pp', 'x')", [])
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert("svc".to_string(), bearer_entry("t-pp"));
    cache.insert("usr".to_string(), user_entry("t-pp"));
    // A different tenant's entry must survive the tenant-scoped clear.
    cache.insert("other".to_string(), bearer_entry("t-other"));

    let v = drust::mcp::tools::owner_field::set_publish_policy(
        &meta,
        "t-pp",
        Some(true),
        None,
        Some(&*cache),
        &RoomBus::new(),
    )
    .await
    .unwrap();
    assert_eq!(v["allow_user_publish"], true);

    assert!(
        cache.get("svc").is_none() && cache.get("usr").is_none(),
        "MCP set_publish_policy must clear t-pp's cached entries (hook 11 MCP face)"
    );
    assert!(
        cache.get("other").is_some(),
        "tenant-scoped clear must spare other tenants' entries"
    );
}

#[tokio::test]
async fn mcp_set_publish_policy_noop_call_still_clears_nothing_foreign() {
    // A call that changes neither flag (both None) performs no UPDATE; it
    // must not clear anything (no auth state changed).
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    // migrations add tenants.allow_user_publish / allow_anon_publish
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-pp', 'x')", [])
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert("svc".to_string(), bearer_entry("t-pp"));

    let _ = drust::mcp::tools::owner_field::set_publish_policy(
        &meta,
        "t-pp",
        None,
        None,
        Some(&*cache),
        &RoomBus::new(),
    )
    .await
    .unwrap();
    assert!(
        cache.get("svc").is_some(),
        "a no-op policy call (no flag supplied) must not evict cached entries"
    );
}

/// #955 — the rooms half of this station, on the MCP face.
///
/// The REST PATCH's twin lives in `tests/auth_cache_publish_policy.rs`; both
/// are non-`#[ignore]`d and need no socket, because the whole behaviour is
/// visible as a per-tenant epoch bump. The evict lives in the TOOL FN rather
/// than in the `#[tool]` wrapper (where the #952 `delete_user` /
/// `revoke_user_sessions` evicts sit) for ONE reason: the change detection it
/// is conditional on can only be done under the meta lock the tool fn holds.
///
/// This test calls the tool fn DIRECTLY with a bus it owns, so it proves the
/// FN's behaviour and says nothing about which bus the `#[tool]` wrapper hands
/// it — that half is
/// `mcp_tools_call_set_publish_policy_evicts_the_stacks_own_bus` below, which
/// drives the wrapper over `tools/call`.
///
/// Driving the wrapper needs a registry built with `Some(meta)`: the standard
/// helper ctor `McpRegistry::with_bus` passes `meta: None`, so under every
/// `helpers::spin_up_*` stack `tools/call set_publish_policy` short-circuits
/// with `-32603 "meta connection not available in this context"` and leaves the
/// epoch at 0. That is why the wrapper test below carries its own fixture
/// instead of reusing a helper. An earlier version of this comment said no
/// integration test could reach a `#[tool]` method at all; that was false and
/// is corrected here (#955 T3 round 2).
#[tokio::test]
async fn mcp_set_publish_policy_real_change_evicts_rooms_noop_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-pp', 'x')", [])
        .unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-other', 'y')", [])
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let bus = RoomBus::new();
    // Captured BEFORE the first call — the same handle a live WS socket holds
    // from its upgrade until it closes.
    let epoch = bus.tenant_epoch_handle("t-pp");
    let other = bus.tenant_epoch_handle("t-other");
    let e0 = epoch.load(SeqCst);

    let call =
        |u, a| drust::mcp::tools::owner_field::set_publish_policy(&meta, "t-pp", u, a, None, &bus);

    // false → true: a REAL change closes every socket holding the old policy.
    call(None, Some(true)).await.unwrap();
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a real flag change over MCP must evict the tenant's rooms (epoch +1)"
    );

    // Same value again — a model re-asserting the current policy must not
    // thunder-herd the tenant's subscribers.
    call(None, Some(true)).await.unwrap();
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a no-op MCP call must NOT evict (epoch unmoved)"
    );

    // A call supplying neither flag writes nothing at all.
    call(None, None).await.unwrap();
    assert_eq!(epoch.load(SeqCst), e0 + 1, "an empty call must not evict");

    // The OTHER flag moving is a real change too — the comparison is on the
    // effective (user, anon) PAIR, not on the field the args mention.
    call(Some(true), None).await.unwrap();
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 2,
        "moving the user flag is a real change as well"
    );

    assert_eq!(
        other.load(SeqCst),
        0,
        "eviction must stay scoped to the tenant that changed"
    );
}

// ═══ #955 — the `#[tool]` WRAPPER's bus, driven over `/t/<id>/mcp` ═══════════
//
// Everything above calls `mcp::tools::owner_field::set_publish_policy`
// directly, handing it a `RoomBus` the test owns. That proves the FN evicts on
// a real change and not on a no-op — and proves NOTHING about the argument the
// `#[tool]` wrapper in `src/mcp/handler.rs` actually passes it. The wrapper
// forwards `&inner.bus_rooms` (the registry's bus, which production and
// `helpers::shared_bus_rooms` make the same instance the WS handler's sockets
// sit on). The #955 T3 round-3 review MEASURED what that gap cost: swapping
// that one expression for a fresh `RoomBus::new()` compiled and left the whole
// tree green, while silently turning the MCP face of #955 off in production —
// a tenant switching `allow_anon_publish` off over MCP would evict a bus no
// socket is on.
//
// The tests below close it by EXECUTION rather than by scanning source: each
// captures the epoch handle from the stack's own bus BEFORE the call, then
// drives `tools/call`. Under the mutant the wrapper bumps a bus that dies with
// the call and the captured handle never moves — re-measured for all three
// wrapper arms, one mutant at a time (`left: 0, right: 1`).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// A tenant router whose MCP registry carries `Some(meta)` — required for
/// `set_publish_policy`'s wrapper to get past its meta short-circuit — and
/// whose registry, auth state and stack all share ONE `RoomBus` (the
/// production wiring, see `helpers::shared_bus_rooms`).
///
/// Returns that shared bus so the test can capture an epoch handle from the
/// side a WS socket would, never from anything the registry hands back.
async fn spin_up_publish_policy_mcp(
    tid: &str,
) -> (axum::Router, String, RoomBus, tempfile::TempDir) {
    use drust::auth::bearer::{generate_token, hash_token};
    use drust::mcp::http_registry::McpHttpRegistry;
    use drust::mcp::server::McpRegistry;
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
    let _ = drust::storage::tenant_db::open_write(&data, tid).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);
    let meta_arc = Arc::new(Mutex::new(conn));

    // The auth state is built FIRST so its bus can be threaded into the MCP
    // registry and the stack below — one instance, three consumers, exactly as
    // `src/main.rs` wires it.
    let mut state = TenantAuthState::test_default(meta_arc.clone(), tenants.clone());
    let bus_rooms = helpers::shared_bus_rooms(&mut state);
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
        bus_rooms.clone(),
        drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        drust::tenant::rooms::RoomsConfig::test_defaults(),
        Arc::new(drust::tenant::auth_cache::AuthCache::new(
            Duration::from_secs(10),
            200_000,
        )),
        drust::functions::dispatcher::FunctionDispatcher::new(
            tenants.clone(),
            tokio::sync::mpsc::channel(8).0,
            drust::functions::FnConfig::test_default(),
        ),
    ));
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: Arc::new(McpHttpRegistry::new(mcp_reg)),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, service, bus_rooms, dir)
}

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
        for line in text.lines() {
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
        out
    } else if text.is_empty() {
        vec![]
    } else {
        vec![serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)]
    }
}

/// initialize + notifications/initialized → the session id.
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

/// `tools/call` one tool; returns the parsed `content[0].text`, and PANICS if
/// the call did not produce one — a JSON-RPC error (the `-32603` meta
/// short-circuit above all) must never read as a quiet "no epoch moved".
async fn mcp_call_tool_json(
    app: &axum::Router,
    tid: &str,
    token: &str,
    session_id: &str,
    name: &str,
    args: serde_json::Value,
) -> serde_json::Value {
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
    let text = msgs
        .iter()
        .find_map(|m| {
            m["result"]["content"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|c| c["text"].as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| {
            panic!(
                "tools/call {name} returned no result content — the tool errored, so any \
                 assertion about its side effects below would be vacuous: {msgs:?}"
            )
        });
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("tools/call {name} content is not JSON ({e}): {text}"))
}

/// #955, EXECUTED — the `#[tool]` wrapper hands the tool fn the STACK's bus.
///
/// The pair above pins `mcp::tools::owner_field::set_publish_policy`'s own
/// decision (evict on a real change, stay put on a no-op). This one pins the
/// wire between the wrapper and that fn: `&inner.bus_rooms` in
/// `src/mcp/handler.rs`. It is the only test in the tree that executes that
/// expression, and the one thing it asserts is that the epoch a WS socket
/// compares against — captured here from the bus the STACK holds, before the
/// call — is the epoch the tool moved.
///
/// What it does NOT cover: the #952 `delete_user` / `revoke_user_sessions`
/// wrapper evicts, which pass the same `inner.bus_rooms` from their own arms
/// and have no executed bus-identity pin of their own; and the `no matching
/// tenant` / error paths, which never reach the evict at all.
#[tokio::test]
async fn mcp_tools_call_set_publish_policy_evicts_the_stacks_own_bus() {
    let tid = "t-ppwrap";
    let (app, svc, bus_rooms, _dir) = spin_up_publish_policy_mcp(tid).await;

    // Captured BEFORE the call, from the stack's bus — the same handle a live
    // socket holds from its upgrade until it closes.
    let epoch = bus_rooms.tenant_epoch_handle(tid);
    let e0 = epoch.load(SeqCst);

    let sid = mcp_init(&app, tid, &svc).await;
    let v = mcp_call_tool_json(
        &app,
        tid,
        &svc,
        &sid,
        "set_publish_policy",
        serde_json::json!({"allow_anon_publish": true}),
    )
    .await;
    assert_eq!(
        v["allow_anon_publish"], true,
        "the tool must really have flipped the flag: {v}"
    );
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a real flag change over `tools/call` must evict the bus the STACK is on — the wrapper \
         passes `&inner.bus_rooms`, and a default/private bus there would leave live sockets \
         holding the old publish policy"
    );

    // Same value again: the wrapper still forwards, the fn still declines.
    let v = mcp_call_tool_json(
        &app,
        tid,
        &svc,
        &sid,
        "set_publish_policy",
        serde_json::json!({"allow_anon_publish": true}),
    )
    .await;
    assert_eq!(v["allow_anon_publish"], true);
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a no-op `tools/call` must not thunder-herd the tenant's subscribers"
    );
}

/// #952, EXECUTED — the other two `#[tool]` wrapper arms on this same bus.
///
/// `delete_user` and `revoke_user_sessions` call `inner.bus_rooms.evict_tenant`
/// from their own arms (`src/mcp/handler.rs`), and until #955 T3 round 3 no
/// test executed those expressions either: `tests/admin_users.rs` drives both
/// tools over `tools/call` but asserts only their JSON, and the harness's
/// registry bus was a private one until T2 round 4. Same fixture, same
/// one-line-mutant question — is the bus these arms move the bus the stack's
/// sockets are on — so the answer belongs next to its twin above rather than in
/// a scan of the handler's source text.
#[tokio::test]
async fn mcp_tools_call_user_revocations_evict_the_stacks_own_bus() {
    let tid = "t-ppwrap-users";
    let (app, svc, bus_rooms, _dir) = spin_up_publish_policy_mcp(tid).await;

    let epoch = bus_rooms.tenant_epoch_handle(tid);
    let e0 = epoch.load(SeqCst);
    let sid = mcp_init(&app, tid, &svc).await;

    // `revoke_user_sessions` is documented safe on an unknown user (revoked: 0)
    // and evicts on every Ok — the blunt tenant-wide evict #952 chose because
    // there is no per-user room index. No seeding needed.
    let v = mcp_call_tool_json(
        &app,
        tid,
        &svc,
        &sid,
        "revoke_user_sessions",
        serde_json::json!({"user_id": "u-nobody"}),
    )
    .await;
    assert_eq!(v["revoked"], 0, "unexpected revoke result: {v}");
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "revoke_user_sessions must evict the bus the STACK is on"
    );

    // `delete_user` evicts only on Ok, so it needs a real user.
    let u = mcp_call_tool_json(
        &app,
        tid,
        &svc,
        &sid,
        "create_user",
        serde_json::json!({"email": "w@x.com", "password": "longpassword"}),
    )
    .await;
    let uid = u["user_id"]
        .as_str()
        .unwrap_or_else(|| panic!("create_user returned no user_id: {u}"))
        .to_string();
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "creating a user revokes nothing and must not evict"
    );

    let v = mcp_call_tool_json(
        &app,
        tid,
        &svc,
        &sid,
        "delete_user",
        serde_json::json!({"user_id": uid}),
    )
    .await;
    assert!(
        v.get("deleted_records").is_some(),
        "unexpected delete_user result: {v}"
    );
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 2,
        "delete_user must evict the bus the STACK is on"
    );
}

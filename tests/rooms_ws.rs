//! v1.31 WebSocket multiplex integration tests.
//!
//! Boots a real axum server on 127.0.0.1:0, connects via tokio-tungstenite,
//! exercises subscribe / publish / cap / ping / cross-tenant isolation.
//!
//! ## EVERY SOCKET test in this file is `#[ignore]`d — read before unignoring
//!
//! No count, deliberately: this heading said "All 9" while the file held 10,
//! then 15, and the number is the part a reader trusts least once it has
//! drifted. `cargo test --test g_rooms -- --ignored --list` is the count.
//!
//! **What that means for the gate:** `make test-all` runs none of them.
//! Everything that opens a real socket is opt-in, one at a time, by hand. So
//! when you are deciding whether some WS behaviour is covered, such a test is
//! evidence that it WORKED when someone last ran it — not that it still works
//! today. The two exceptions are the wiring tests
//! (`mcp_registry_and_ws_stack_share_one_bus_instance` and
//! `every_test_stack_shares_one_room_bus_with_its_auth_state`), which need no
//! socket and therefore DO run in every gate.
//!
//! For the #955 eviction checkpoints specifically, the in-gate coverage is
//! `src/tenant/rooms/ws.rs`'s lib tests, which drive the real `handle_socket`
//! loop over an in-memory duplex (`evicted_conn_loop_closes_1008_and_never_dispatches_the_frame`,
//! `evicted_idle_conn_loop_closes_on_the_keepalive_tick`, plus the structural
//! pin `epoch_checkpoints_sit_before_dispatch_and_on_the_keepalive_tick`).
//! What only the tests below cover is the same behaviour over a REAL socket:
//! the upgrade, the wire frames as tungstenite decodes them, and the
//! interaction with the live auth stack. Add checkpoint coverage in BOTH
//! places — a behaviour whose only test is in this file is a behaviour with
//! no gate.
//!
//! Each test uses `#[tokio::test]` which creates a fresh tokio runtime per
//! test. The test spawns `axum::serve(...)` as a background task on that
//! runtime, then opens a WS client via `tokio_tungstenite::connect_async`.
//!
//! When `cargo test` runs many such tests in the same binary (parallel or
//! serial), the per-test runtimes contend with each other's worker threads.
//! Under contention, the spawned server's `WebSocketUpgrade::on_upgrade`
//! closure can be starved between when the client's HTTP 101 response is
//! sent and when the server starts the WS read loop. The client's first
//! `send()` then either succeeds-but-vanishes (TCP buffer absorbs it) or
//! blocks on backpressure, and `recv` waits forever. The result: a
//! NON-DETERMINISTIC subset of these tests hangs each run (1–4 tests, no
//! pattern — even the simplest "ping/pong" can hang).
//!
//! Each test PASSES individually — and #925 merged this file into the
//! `g_rooms` group harness, so that is the target name now:
//!     cargo test --test g_rooms ping_returns_pong_with_ref -- --ignored --nocapture
//!
//! Run them ONE AT A TIME. Several ignored WS tests in a single invocation
//! reproduce exactly the starvation described above.
//!
//! The v1.31 handler itself was verified by running each test individually
//! (all green at ~0.04–0.1s each). Production smoke also confirms the
//! `/t/<id>/realtime` route works end-to-end.
//!
//! Root cause: tokio-rs/tokio#2374 (no public API to share a runtime across
//! `#[tokio::test]` instances). Proper fix is to migrate this file to the
//! `axum-test` crate or build a lazy_static shared runtime + `block_on`
//! harness. Tracked as a v1.31.x follow-up.

use axum::Router;
use futures::{SinkExt, StreamExt};
use serde_json::json;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message as TM;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

mod helpers;

const TENANT: &str = "ba10b1a4-0000-0000-0000-000000000001";

type WsClient = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Spin up a router on an ephemeral port. Returns the bound addr + the
/// router's owning helpers tuple so the TempDir lives until test end.
async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Official axum testing-websockets pattern: spawn the Future directly via
    // `.into_future()` rather than wrapping in an async block. The latter adds
    // a layer of indirection that, combined with multi-runtime test
    // parallelism, can starve the spawned server task's poll under contention.
    tokio::spawn(axum::serve(listener, app).into_future());
    addr
}

fn ws_url(addr: SocketAddr, tenant: &str, token: &str) -> String {
    format!("ws://{addr}/t/{tenant}/realtime?token={token}")
}

async fn recv_json(ws: &mut WsClient) -> serde_json::Value {
    loop {
        let item = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("ws recv timeout")
            .expect("ws recv produced None")
            .expect("ws recv error");
        match item {
            TM::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            TM::Ping(p) => {
                ws.send(TM::Pong(p)).await.unwrap();
            }
            TM::Close(_) => panic!("ws closed unexpectedly"),
            _ => {}
        }
    }
}

async fn send_op(ws: &mut WsClient, v: serde_json::Value) {
    ws.send(TM::Text(v.to_string())).await.unwrap();
}

/// #955 (T2 review rounds 3–4) — the split-`RoomBus` trap.
///
/// `TenantAuthState::test_default` builds its OWN `RoomBus::default()`
/// (`src/tenant/router.rs`), so a stack literal that ALSO passes a fresh
/// `RoomBus::new()` runs two buses where production runs one
/// (`src/main.rs` threads a single instance into the auth state, the stack and
/// the MCP registry). Every eviction surface then splits: the #952
/// `revoke_user_realtime` funnel and the #955 token reroll / tenant-delete
/// paths move the state's bus, while the WS handler's sockets and the SSE
/// subscribers sit on the stack's. A test written against a split stack evicts
/// a bus no socket is on and **passes while proving nothing** — a vacuous
/// green, which is the failure mode no assertion in the test itself can catch.
///
/// Round 3 wired every helper in `tests/helpers.rs` through
/// `helpers::shared_bus_rooms` and pinned it — but pinned it by
/// `include_str!("helpers.rs")`, i.e. over ONE file, while claiming the trap was
/// "disarmed for good". Round 4 measured what that missed: 19 stack literals in
/// OTHER test files still minted their own bus, and every helper stack —
/// `spin_up_tenant_rooms` included — ALSO ran a second bus inside its MCP
/// registry, because `test_mcp_http` built one from `test_rooms_defaults()`.
/// That last one is not cosmetic: `delete_user` and `revoke_user_sessions` are
/// MCP tools, 2 of the 5 sites `RoomBus::evict_tenant`'s doc enumerates, so a
/// "revoke over MCP, assert the socket died" test could not have failed.
///
/// So the scan is now the whole `tests/` tree, and `test_mcp_http` takes the
/// bus as a parameter (checked below). The #955 harness itself is covered by
/// something better than a scan:
/// `mcp_registry_and_ws_stack_share_one_bus_instance` runs
/// `spin_up_tenant_rooms` and compares the two buses by `Arc` identity.
///
/// **What this does NOT cover**, stated so the next reader is not told the
/// ground is bigger than it is:
///
/// * Any OTHER fixture that builds its MCP registry inline still has to pass
///   the right bus by hand. What forces the author to think is the ctor:
///   `McpRegistry::with_bus` now REQUIRES the bus, and `McpRegistry::new` —
///   which still mints a private one — is documented as "never for a
///   `TenantStack`". Neither is checked here.
/// * Admin-plane fixtures (`MgmtState` / `TenantsState`) are out of scope: they
///   carry a `bus_rooms` too, and the ones sharing a fixture with a stack were
///   fixed by hand, but no assertion holds them to it.
/// * It is a source-text scan. It proves how the stacks are WRITTEN, not that
///   any particular test exercises eviction.
///
/// This and the identity test below it are the only NON-ignored tests in this
/// file (everything else needs a real socket — see the module doc), so they run
/// in `cargo test --test g_rooms` and in `make test-all`.
#[test]
fn every_test_stack_shares_one_room_bus_with_its_auth_state() {
    // Both needles are assembled at runtime so this file's own source cannot
    // satisfy the scan it performs — the pin reads `tests/*.rs`, itself
    // included.
    let stack_lit = ["TenantStack", " {"].concat();
    let wire = ["shared_bus_rooms(", "&mut "].concat();

    let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&tests_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", tests_dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rs"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 200,
        "vacuity guard: only {} `.rs` files found under {} — the scan lost its input, which \
         would make every assertion below trivially true",
        files.len(),
        tests_dir.display(),
    );

    let mut stacks = 0usize;
    let mut wires = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        wires += src.matches(&wire).count();
        for (at, _) in src.match_indices(&stack_lit) {
            stacks += 1;
            // The struct has no `Default`, so the first `bus_rooms:` line after
            // the literal opens is always that literal's own field.
            let field = src[at..]
                .lines()
                .find(|l| l.trim_start().starts_with("bus_rooms:"))
                .unwrap_or_else(|| panic!("{name}: a tenant-stack literal sets no bus_rooms"))
                .trim();
            if !matches!(field, "bus_rooms: bus_rooms.clone()," | "bus_rooms,") {
                offenders.push(format!("{name}: `{field}`"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these tenant-stack literals mint their own RoomBus: {offenders:?}. Take it from \
         `helpers::shared_bus_rooms`, passing the stack's auth state, instead — a stack with \
         its own bus \
         leaves the auth state (and the MCP registry) on a DIFFERENT bus than the WS handler, \
         so every revoke-then-assert test on it goes green without exercising anything.",
    );
    assert!(
        stacks >= 27,
        "expected at least the 27 known tenant-stack literals across tests/, found {stacks} — \
         the scanner's anchor probably stopped matching, which would make this pin silently \
         vacuous",
    );
    assert_eq!(
        wires, stacks,
        "one `shared_bus_rooms` call per tenant-stack literal ({stacks} stacks, {wires} calls). \
         A stack that reuses another's variable would satisfy the field check above while still \
         leaving ITS auth state on a private bus",
    );

    // The MCP half of the same trap: the registry a stack mounts must be handed
    // the stack's bus, not build one from `test_rooms_defaults()`.
    let helpers_src = std::fs::read_to_string(tests_dir.join("helpers.rs")).unwrap();
    let at = helpers_src
        .find("pub fn test_mcp_http(")
        .expect("helpers::test_mcp_http was renamed — update this pin");
    let f = &helpers_src[at..at + helpers_src[at..].find("\n}\n").expect("unterminated fn")];
    assert!(
        f.contains("bus_rooms: drust::tenant::rooms::RoomBus"),
        "test_mcp_http must TAKE the stack's RoomBus as a parameter. While it defaulted one, \
         every helper stack ran a second bus inside its MCP surface, so the MCP eviction sites \
         (`delete_user`, `revoke_user_sessions`) moved a bus no socket was on:\n{f}",
    );
    // Signature and body are checked separately: `bus_rooms` in the parameter
    // list proves only that the caller was asked for one. Taking it and then
    // handing the registry a fresh bus is the same no-op with a nicer
    // signature, and it is what the assertion above alone would allow.
    let body_at = f
        .find(") -> Arc<McpHttpRegistry> {")
        .expect("test_mcp_http's return type changed — update this pin");
    let body = &f[body_at..];
    assert!(
        body.contains("McpRegistry::with_bus(") && body.contains("bus_rooms"),
        "test_mcp_http must FORWARD the bus it was given into the registry:\n{body}",
    );
    assert!(
        !body.contains("RoomBus::new()") && !body.contains("test_rooms_defaults"),
        "test_mcp_http must not mint a RoomBus of its own — that is exactly the default the \
         round-4 review found putting every helper stack's MCP surface on a bus no socket was \
         on:\n{body}",
    );
}

/// #955, EXECUTED — the MCP half of the split-bus trap, proven by running the
/// harness rather than by reading its source.
///
/// The scan above is source text; this is the property itself, on the harness
/// the #955 WS tests actually use. Two `RoomBus` clones are the same instance
/// iff `tenant_epoch_handle` hands back the same `Arc` — the epoch map lives
/// behind the shared `Arc<DashMap>`, so this is an identity probe that needs no
/// new accessor on `RoomBus`.
///
/// It matters because `delete_user` and `revoke_user_sessions` are MCP tools
/// that call `evict_tenant` directly (`src/mcp/handler.rs`), i.e. 2 of the 5
/// call sites `RoomBus::evict_tenant`'s doc enumerates. While `test_mcp_http`
/// defaulted the registry's bus, those two tools moved an epoch no socket in
/// the harness was watching, and a "revoke over MCP, assert the socket died"
/// test could not have failed.
///
/// Not `#[ignore]`d: no socket is involved, so it runs in every gate.
#[tokio::test]
async fn mcp_registry_and_ws_stack_share_one_bus_instance() {
    let h = helpers::spin_up_tenant_rooms(
        TENANT,
        "service",
        drust::tenant::rooms::RoomsConfig::test_defaults(),
    )
    .await;
    let svc = h.mcp.get_or_create(TENANT).await.unwrap();
    let mcp_bus = svc.inner().bus_rooms.clone();

    assert!(
        std::sync::Arc::ptr_eq(
            &mcp_bus.tenant_epoch_handle(TENANT),
            &h.bus_rooms.tenant_epoch_handle(TENANT),
        ),
        "the MCP surface must sit on the SAME RoomBus as the WS handler: the MCP eviction tools \
         would otherwise bump an epoch no socket is watching",
    );

    // And the consequence, not just the pointer: an evict driven through the
    // MCP-side handle is visible to a baseline captured from the WS-side one.
    let seen_by_ws = h.bus_rooms.tenant_epoch_handle(TENANT);
    let before = seen_by_ws.load(std::sync::atomic::Ordering::SeqCst);
    mcp_bus.evict_tenant(TENANT);
    assert_eq!(
        seen_by_ws.load(std::sync::atomic::Ordering::SeqCst),
        before + 1,
        "an evict on the MCP side must move the epoch the WS sockets compare against",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn subscribe_then_receive_publish_from_rest() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "service").await;
    let addr = serve(app).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &tok)).await.unwrap();

    send_op(&mut ws, json!({"op":"subscribe","room":"chat","ref":"c1"})).await;
    let ack = recv_json(&mut ws).await;
    assert_eq!(ack["kind"], "ack");
    assert_eq!(ack["ref"], "c1");
    assert_eq!(ack["op"], "subscribe");

    // Publish via REST in-process.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/t/{TENANT}/rooms/chat"))
        .bearer_auth(&tok)
        .json(&json!({"hello":"world"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let msg = recv_json(&mut ws).await;
    assert_eq!(msg["kind"], "message");
    assert_eq!(msg["room"], "chat");
    assert_eq!(msg["payload"]["hello"], "world");
    assert!(msg["ts"].as_i64().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn multi_room_demux_routes_to_correct_room() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "service").await;
    let addr = serve(app).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &tok)).await.unwrap();

    send_op(&mut ws, json!({"op":"subscribe","room":"a","ref":"sa"})).await;
    let _ = recv_json(&mut ws).await;
    send_op(&mut ws, json!({"op":"subscribe","room":"b","ref":"sb"})).await;
    let _ = recv_json(&mut ws).await;

    // Publish to "b" only.
    reqwest::Client::new()
        .post(format!("http://{addr}/t/{TENANT}/rooms/b"))
        .bearer_auth(&tok)
        .json(&json!({"r":"b-payload"}))
        .send()
        .await
        .unwrap();

    let msg = recv_json(&mut ws).await;
    assert_eq!(msg["room"], "b");
    assert_eq!(msg["payload"]["r"], "b-payload");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn ws_publish_with_service_key_fans_out() {
    let (app, svc_tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "service").await;
    let addr = serve(app).await;
    // Both sockets use the same service token. The "subscriber" is just a
    // separate WS conn that subscribes; both are AuthCtx::Service.
    let (mut sub, _) = connect_async(ws_url(addr, TENANT, &svc_tok)).await.unwrap();
    let (mut publisher, _) = connect_async(ws_url(addr, TENANT, &svc_tok)).await.unwrap();

    send_op(&mut sub, json!({"op":"subscribe","room":"x","ref":"s"})).await;
    let _ = recv_json(&mut sub).await;

    send_op(
        &mut publisher,
        json!({"op":"publish","room":"x","payload":{"k":1},"ref":"p1"}),
    )
    .await;
    let ack = recv_json(&mut publisher).await;
    assert_eq!(ack["kind"], "ack");
    assert_eq!(ack["op"], "publish");
    assert_eq!(ack["delivered_to"], 1);

    let msg = recv_json(&mut sub).await;
    assert_eq!(msg["kind"], "message");
    assert_eq!(msg["payload"]["k"], 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn ws_publish_with_anon_succeeds_when_allow_anon_publish_is_on() {
    // v1.32.5 — admin flips `allow_anon_publish=1`; anon WS publish now
    // returns an `ack` instead of `error`. Defense-in-depth check that the
    // policy plumbing (CTE → extension → gate) survives a real WS round-trip.
    let (app, tok, dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    {
        let c = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
        c.execute(
            "UPDATE tenants SET allow_anon_publish = 1 WHERE id = ?1",
            rusqlite::params![TENANT],
        )
        .unwrap();
    }
    let addr = serve(app).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &tok)).await.unwrap();
    send_op(
        &mut ws,
        json!({"op":"publish","room":"chat","payload":{"x":1},"ref":"p1"}),
    )
    .await;
    let ack = recv_json(&mut ws).await;
    assert_eq!(ack["kind"], "ack");
    assert_eq!(ack["op"], "publish");
    assert_eq!(ack["ref"], "p1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn ws_publish_with_anon_returns_ws_publish_denied() {
    // v1.32.5 — anon publish is opt-in. With the default
    // `allow_anon_publish = 0` flag, the WS gate emits
    // `WS_PUBLISH_ANON_DENIED` (role-specific). The pre-v1.32.5
    // wire code `WS_PUBLISH_DENIED` is retained in `codes::` for
    // any client that still pattern-matches it but is no longer
    // emitted by handle_text_frame.
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    let addr = serve(app).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &tok)).await.unwrap();

    send_op(
        &mut ws,
        json!({"op":"publish","room":"x","payload":{},"ref":"p1"}),
    )
    .await;
    let err = recv_json(&mut ws).await;
    assert_eq!(err["kind"], "error");
    assert_eq!(err["code"], "WS_PUBLISH_ANON_DENIED");
    assert_eq!(err["ref"], "p1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn protected_room_prefix_rejected_at_subscribe() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    let addr = serve(app).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &tok)).await.unwrap();

    send_op(
        &mut ws,
        json!({"op":"subscribe","room":"_system_chat","ref":"c1"}),
    )
    .await;
    let err = recv_json(&mut ws).await;
    assert_eq!(err["code"], "PROTECTED_ROOM");
    assert_eq!(err["ref"], "c1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn ping_returns_pong_with_ref() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    let addr = serve(app).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &tok)).await.unwrap();

    send_op(&mut ws, json!({"op":"ping","ref":"p1"})).await;
    let pong = recv_json(&mut ws).await;
    assert_eq!(pong["kind"], "pong");
    assert_eq!(pong["ref"], "p1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn unknown_op_returns_malformed_frame() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    let addr = serve(app).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &tok)).await.unwrap();

    send_op(&mut ws, json!({"op":"wat","room":"x"})).await;
    let err = recv_json(&mut ws).await;
    assert_eq!(err["kind"], "error");
    assert_eq!(err["code"], "MALFORMED_FRAME");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn unsubscribe_is_idempotent_acked() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    let addr = serve(app).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &tok)).await.unwrap();

    send_op(
        &mut ws,
        json!({"op":"unsubscribe","room":"ghost","ref":"u1"}),
    )
    .await;
    let ack = recv_json(&mut ws).await;
    assert_eq!(ack["kind"], "ack");
    assert_eq!(ack["op"], "unsubscribe");
    assert_eq!(ack["ref"], "u1");
}

// ---------------------------------------------------------------------------
// #955 — eviction closes live sockets (epoch lazy close).
//
// `evict_tenant` used to drop only the broadcast CHANNELS: the socket itself,
// and the `AuthCtx` it captured at upgrade, survived — so a revoked holder
// could re-subscribe (and re-publish) indefinitely on a live connection. Each
// conn now captures the tenant epoch at connect and compares it before every
// inbound frame and on every keepalive tick.
//
// These tests carry the same `#[ignore]` as the rest of the file (see the
// module doc) — run them ONE AT A TIME with `-- --ignored`.
// ---------------------------------------------------------------------------

/// The post-eviction wire contract: the typed error first (so the client knows
/// WHY), then a Close with 1008 Policy Violation.
///
/// `recv_json` panics on Close, so the close frame is read raw.
async fn expect_conn_evicted_then_close(ws: &mut WsClient) {
    let err = recv_json(ws).await;
    assert_eq!(err["kind"], "error", "expected an error frame, got {err}");
    assert_eq!(err["code"], "CONN_EVICTED", "got {err}");
    let nxt = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("timed out waiting for the Close frame")
        .expect("stream ended without a Close frame")
        .expect("ws error while waiting for Close");
    match nxt {
        TM::Close(Some(cf)) => assert_eq!(
            u16::from(cf.code),
            1008,
            "an evicted socket must be closed with 1008 Policy Violation"
        ),
        other => panic!("expected Close(1008) right after CONN_EVICTED, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn evicted_conn_gets_conn_evicted_and_close_on_next_subscribe() {
    let h = helpers::spin_up_tenant_rooms(
        TENANT,
        "anon",
        drust::tenant::rooms::RoomsConfig::test_defaults(),
    )
    .await;
    let addr = serve(h.app.clone()).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &h.token)).await.unwrap();

    send_op(&mut ws, json!({"op":"subscribe","room":"chat","ref":"c1"})).await;
    let ack = recv_json(&mut ws).await;
    assert_eq!(ack["kind"], "ack", "baseline subscribe must work");

    h.bus_rooms.evict_tenant(TENANT);

    // Pre-#955 this re-subscribe succeeded on the live socket with no re-auth.
    send_op(&mut ws, json!({"op":"subscribe","room":"chat","ref":"c2"})).await;
    expect_conn_evicted_then_close(&mut ws).await;

    // T2 review round 1 — side-effect assertion, not just wire shape: with the
    // `break` deleted from checkpoint (a), the server still writes error+Close
    // FIRST and then runs the subscribe anyway, so every wire assertion above
    // stays green while the evicted socket re-creates the channel evict just
    // dropped. Measured red under that mutant, green on HEAD.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        h.bus_rooms.tenant_channel_count(TENANT),
        0,
        "evicted socket landed one more subscribe behind the Close frame"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn evicted_conn_is_closed_on_a_publish_frame_too() {
    // Service role, so publish is allowed by the gate — which is the point:
    // the checkpoint must fire BEFORE `check_publish_allowed`, not instead of
    // a denial. The pre-evict publish proves the gate would have said yes.
    let h = helpers::spin_up_tenant_rooms(
        TENANT,
        "service",
        drust::tenant::rooms::RoomsConfig::test_defaults(),
    )
    .await;
    let addr = serve(h.app.clone()).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &h.token)).await.unwrap();

    send_op(
        &mut ws,
        json!({"op":"publish","room":"x","payload":{"n":1},"ref":"p1"}),
    )
    .await;
    let ack = recv_json(&mut ws).await;
    assert_eq!(ack["kind"], "ack", "baseline service publish must work");

    h.bus_rooms.evict_tenant(TENANT);

    send_op(
        &mut ws,
        json!({"op":"publish","room":"x","payload":{"n":2},"ref":"p2"}),
    )
    .await;
    expect_conn_evicted_then_close(&mut ws).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn idle_socket_is_closed_within_two_keepalive_ticks_after_evict() {
    // The frame checkpoint only helps a socket that keeps talking. A silent
    // subscriber reaches ONE checkpoint — the keepalive tick — so this test is
    // what bounds an evicted idle socket's life, and the only end-to-end pin
    // on the `keepalive_secs` wiring (`ws::keepalive_interval`'s unit test
    // pins the period selection; only this one proves the tick actually
    // closes an evicted socket).
    let mut cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    cfg.keepalive_secs = 1;
    let h = helpers::spin_up_tenant_rooms(TENANT, "anon", cfg).await;
    let addr = serve(h.app.clone()).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &h.token)).await.unwrap();

    send_op(&mut ws, json!({"op":"subscribe","room":"chat","ref":"c1"})).await;
    assert_eq!(recv_json(&mut ws).await["kind"], "ack");

    h.bus_rooms.evict_tenant(TENANT);

    // Send NOTHING from here on.
    let (saw_evicted, close_frame) = tokio::time::timeout(Duration::from_secs(4), async {
        let mut saw_evicted = false;
        loop {
            match ws.next().await {
                Some(Ok(TM::Ping(p))) => ws.send(TM::Pong(p)).await.unwrap(),
                Some(Ok(TM::Text(t))) => {
                    let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
                    assert_eq!(v["code"], "CONN_EVICTED", "unexpected text frame: {v}");
                    saw_evicted = true;
                }
                Some(Ok(TM::Close(frame))) => return (saw_evicted, frame),
                Some(Ok(_)) => {}
                Some(Err(e)) => panic!("ws error before the Close: {e}"),
                None => panic!("stream ended without a Close frame"),
            }
        }
    })
    .await
    .expect("an evicted IDLE socket must close within 2 keepalive ticks (4 s at 1 s/tick)");

    assert!(
        saw_evicted,
        "the close must be preceded by the typed CONN_EVICTED error"
    );
    assert_eq!(
        u16::from(close_frame.expect("close frame must carry a code").code),
        1008
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn valid_token_reconnects_after_evict_with_no_sticky_kill() {
    // Eviction is tenant-wide and blunt by design (there is no per-user room
    // index), so an innocent bystander gets closed too. What must NOT happen
    // is a sticky kill: the epoch is a baseline, not a tombstone, so a
    // reconnect with the SAME still-valid token works normally.
    let h = helpers::spin_up_tenant_rooms(
        TENANT,
        "anon",
        drust::tenant::rooms::RoomsConfig::test_defaults(),
    )
    .await;
    let addr = serve(h.app.clone()).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &h.token)).await.unwrap();
    send_op(&mut ws, json!({"op":"subscribe","room":"chat","ref":"c1"})).await;
    assert_eq!(recv_json(&mut ws).await["kind"], "ack");

    h.bus_rooms.evict_tenant(TENANT);

    send_op(&mut ws, json!({"op":"ping","ref":"k1"})).await;
    expect_conn_evicted_then_close(&mut ws).await;

    // Same token, new socket: the bus evict is not a token revocation.
    let (mut ws2, _) = connect_async(ws_url(addr, TENANT, &h.token)).await.unwrap();
    send_op(&mut ws2, json!({"op":"subscribe","room":"chat","ref":"c2"})).await;
    let ack = recv_json(&mut ws2).await;
    assert_eq!(ack["kind"], "ack", "reconnect must subscribe normally");
    assert_eq!(ack["ref"], "c2");
    // ...and stays alive: the new baseline is the CURRENT epoch, so the old
    // eviction must not follow it.
    send_op(&mut ws2, json!({"op":"ping","ref":"k2"})).await;
    let pong = recv_json(&mut ws2).await;
    assert_eq!(pong["kind"], "pong", "sticky kill: got {pong}");
    assert_eq!(pong["ref"], "k2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn rest_logout_closes_that_users_live_ws_socket() {
    // The #952 semantic completion, end to end through a REAL revocation
    // surface rather than a direct `bus.evict_tenant` call: REST logout →
    // `TenantAuthState::revoke_user_realtime` → `evict_tenant` → epoch bump →
    // the live socket closes at its next frame. Before #955 the session was
    // gone from `_system_sessions` while this socket kept subscribing and
    // publishing under the dead token.
    //
    // This is also the test that would catch the harness regressing to two
    // separate `RoomBus` instances (auth state vs stack): with split buses the
    // logout evicts a bus nothing is subscribed on and the ping below answers
    // `pong`.
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

    let h = helpers::spin_up_tenant_rooms(
        TENANT,
        "service",
        drust::tenant::rooms::RoomsConfig::test_defaults(),
    )
    .await;
    let user_token =
        helpers::register_and_login_via_app(&h.app, TENANT, "ws-evict@example.com", "longpassword")
            .await;

    let addr = serve(h.app.clone()).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &user_token))
        .await
        .unwrap();
    send_op(&mut ws, json!({"op":"subscribe","room":"chat","ref":"c1"})).await;
    assert_eq!(
        recv_json(&mut ws).await["kind"],
        "ack",
        "an end-user session must be able to subscribe"
    );

    let logout = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{TENANT}/auth/logout"))
                .header(header::AUTHORIZATION, format!("Bearer {user_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), 200, "logout should succeed");

    send_op(&mut ws, json!({"op":"ping","ref":"k1"})).await;
    expect_conn_evicted_then_close(&mut ws).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn publish_policy_change_evicts_live_socket_noop_does_not() {
    // #955 T3 — the second same-root-cause site. A rooms connection captures
    // its `TenantPublishPolicy` once at upgrade and never re-reads it, so an
    // admin turning `allow_anon_publish` OFF used to leave every live socket
    // publishing under the old flag until it disconnected on its own. The
    // PATCH handler now evicts on a REAL change — and, just as load-bearing,
    // does NOT evict on a no-op, because an admin page that re-submits
    // unchanged checkboxes must not kick every subscriber the tenant has.
    //
    // The handler is called DIRECTLY (axum handlers are plain async fns)
    // against admin-plane state built over the harness's OWN meta, auth cache
    // and RoomBus — going through the admin router would need an admin
    // session and would prove nothing extra. Sharing all three is what makes
    // the assertions real: a `TenantsState` with a private bus or a private
    // cache would evict something no socket is on and go green.
    //
    // Spec sketched this with `allow_user_publish`; anon exercises the
    // identical mechanism (pre-image → change detection → evict) without
    // minting an end-user session, which `rest_logout_closes_that_users_live_ws_socket`
    // already covers.
    use axum::extract::{Path as AxPath, State as AxState};
    use drust::auth::middleware::AdminId;
    use drust::mgmt::tenants::{PublishPolicyPatch, TenantsState};
    use std::sync::atomic::Ordering::SeqCst;

    let h = helpers::spin_up_tenant_rooms(
        TENANT,
        "anon",
        drust::tenant::rooms::RoomsConfig::test_defaults(),
    )
    .await;

    // Admin-plane state over the SAME meta + RoomBus + auth cache as the WS
    // stack. `test_default` mints its own cache, hence the overwrite.
    let mut ts = TenantsState::test_default(
        h.meta.clone(),
        h.data_dir.clone(),
        h.tenants.clone(),
        helpers::test_mcp_http(
            h.tenants.clone(),
            drust::tenant::events::EventBus::new(),
            h.bus_rooms.clone(),
        ),
        drust::tenant::events::EventBus::new(),
        h.bus_rooms.clone(),
    );
    ts.auth_cache = h.auth_cache.clone();

    let patch = |ts: TenantsState, allow_anon: bool| async move {
        drust::mgmt::tenants::patch_publish_policy(
            AxState(ts),
            AxPath(TENANT.to_string()),
            axum::Extension(AdminId(1)),
            axum::Json(PublishPolicyPatch {
                allow_user_publish: None,
                allow_anon_publish: Some(allow_anon),
            }),
        )
        .await
    };

    // Turn anon publish ON. A real change, but no sockets exist yet, so the
    // eviction it triggers is a no-op in practice.
    assert!(
        patch(ts.clone(), true).await.status().is_success(),
        "enabling anon publish should succeed"
    );

    let addr = serve(h.app.clone()).await;
    let (mut ws, _) = connect_async(ws_url(addr, TENANT, &h.token)).await.unwrap();
    send_op(
        &mut ws,
        json!({"op":"publish","room":"chat","payload":{"x":1},"ref":"p1"}),
    )
    .await;
    assert_eq!(
        recv_json(&mut ws).await["kind"],
        "ack",
        "anon publish must be allowed under the policy this socket connected with"
    );

    // The epoch this socket is comparing against. Asserting on it directly
    // makes the no-op half deterministic: "the socket still answers" proves
    // no eviction was DELIVERED, this proves none was ISSUED.
    let epoch = h.bus_rooms.tenant_epoch_handle(TENANT);
    let before_noop = epoch.load(SeqCst);

    // NO-OP PATCH: same value → no evict, socket stays alive.
    assert!(
        patch(ts.clone(), true).await.status().is_success(),
        "the no-op PATCH should still return 200"
    );
    assert_eq!(
        epoch.load(SeqCst),
        before_noop,
        "a PATCH that changes nothing must not bump the epoch"
    );
    send_op(&mut ws, json!({"op":"ping","ref":"k1"})).await;
    let pong = recv_json(&mut ws).await;
    assert_eq!(pong["kind"], "pong", "no-op PATCH must not evict: {pong}");
    assert_eq!(pong["ref"], "k1");

    // REAL change: anon publish OFF → this socket's captured policy is now
    // wrong, so it must die at its next frame.
    assert!(
        patch(ts.clone(), false).await.status().is_success(),
        "disabling anon publish should succeed"
    );
    assert_eq!(
        epoch.load(SeqCst),
        before_noop + 1,
        "a real flag change must bump the epoch exactly once"
    );
    send_op(&mut ws, json!({"op":"ping","ref":"k2"})).await;
    expect_conn_evicted_then_close(&mut ws).await;

    // Reconnect: the token was never revoked, so the socket comes back — but
    // under the NEW policy, which is the whole point of closing it. This also
    // pins hook 11 (the auth-cache clear), measured: with `clear_tenant`
    // deleted from the handler the reconnect resolves through the CACHED
    // entry, publishes under the old flags and answers `ack`. It does NOT pin
    // the clear-before-evict ORDER — by the time the client reconnects both
    // statements have long since run, and no test here can separate them.
    let (mut ws2, _) = connect_async(ws_url(addr, TENANT, &h.token)).await.unwrap();
    send_op(
        &mut ws2,
        json!({"op":"publish","room":"chat","payload":{"x":2},"ref":"p2"}),
    )
    .await;
    let denied = recv_json(&mut ws2).await;
    assert_eq!(denied["kind"], "error", "got {denied}");
    assert_eq!(
        denied["code"], "WS_PUBLISH_ANON_DENIED",
        "the reconnect must see the NEW policy: {denied}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "tokio/2374 — per-test runtime starvation; run individually with --ignored"]
async fn unauth_ws_upgrade_returns_failure_pre_handshake() {
    let (app, _tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    let addr = serve(app).await;
    // No ?token=, no Authorization header → bearer_auth_layer 401 pre-upgrade.
    let result = connect_async(format!("ws://{addr}/t/{TENANT}/realtime")).await;
    assert!(result.is_err(), "unauth upgrade should fail");
}

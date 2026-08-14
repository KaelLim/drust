//! v1.31 WebSocket multiplex integration tests.
//!
//! Boots a real axum server on 127.0.0.1:0, connects via tokio-tungstenite,
//! exercises subscribe / publish / cap / ping / cross-tenant isolation.
//!
//! ## All 9 tests marked `#[ignore]` — read before unignoring
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
//! Each test PASSES individually:
//!     cargo test --test rooms_ws ping_returns_pong_with_ref -- --ignored --nocapture
//!
//! The v1.31 handler itself was verified by running each test individually
//! (all 9 green at ~0.04–0.1s each). Production smoke also confirms the
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
async fn unauth_ws_upgrade_returns_failure_pre_handshake() {
    let (app, _tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    let addr = serve(app).await;
    // No ?token=, no Authorization header → bearer_auth_layer 401 pre-upgrade.
    let result = connect_async(format!("ws://{addr}/t/{TENANT}/realtime")).await;
    assert!(result.is_err(), "unauth upgrade should fail");
}

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
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

mod helpers;

const TENANT: &str = "ba10b1a4-0000-0000-0000-000000000001";

type WsClient = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Spin up a router on an ephemeral port. Returns the bound addr + the
/// router's owning helpers tuple so the TempDir lives until test end.
async fn serve(
    app: Router,
) -> SocketAddr {
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
    ws.send(TM::Text(v.to_string().into())).await.unwrap();
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
async fn ws_publish_with_anon_returns_ws_publish_denied() {
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
    assert_eq!(err["code"], "WS_PUBLISH_DENIED");
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

    send_op(&mut ws, json!({"op":"unsubscribe","room":"ghost","ref":"u1"})).await;
    let ack = recv_json(&mut ws).await;
    assert_eq!(ack["kind"], "ack");
    assert_eq!(ack["op"], "unsubscribe");
    assert_eq!(ack["ref"], "u1");
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

//! v1.31 WebSocket multiplex handler — GET /t/{tenant}/realtime.
//!
//! One WS conn ⇒ N rooms. Per-conn task drives `tokio::select!` over:
//!   (a) upstream `WebSocket::recv()` — demux client op
//!   (b) `StreamMap<String, BroadcastStream<RoomMessage>>` — fan-in
//!   (c) keepalive ticker (30s)
//!
//! Auth at upgrade: bearer resolved by `bearer_auth_layer` upstream
//! (which itself reads the Authorization header rewritten from
//! `?token=` by `ws_query_token_adapter`). Anon / User / Service all
//! may subscribe; only `AuthCtx::Service { .. }` may `op:publish`.

use crate::auth::middleware::AuthCtx;
use crate::tenant::rooms::audit::{write_publish_audit, write_publish_audit_failure};
use crate::tenant::rooms::bus::RoomMessage;
use crate::tenant::rooms::envelope::{codes, ClientOp, ServerMessage};
use crate::tenant::rooms::policy::validate_room_name;
use crate::tenant::rooms::rest::{publish_into_bus, PublishCtx, PublishError};
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Path};
use axum::response::Response;
use futures::stream::{SplitSink, StreamExt};
use futures::SinkExt;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamMap;

/// GET /t/{tenant}/realtime — WS multiplex upgrade.
pub async fn ws_handler(
    pc: PublishCtx,
    Extension(ctx): Extension<AuthCtx>,
    Path((tenant,)): Path<(String,)>,
    ws: WebSocketUpgrade,
) -> Response {
    // v1.31.2 F10 — honor DRUST_BROADCAST_PAYLOAD_MAX_BYTES at the WS
    // frame layer. Pre-fix this was hardcoded 128 KiB, silently capping
    // below env config. The wire-level PAYLOAD_TOO_LARGE error in
    // handle_text_frame::Publish stays — it gives clean errors below
    // this hard ceiling.
    let cap = pc.cfg.payload_max_bytes;
    ws.max_message_size(cap)
        .max_frame_size(cap)
        .on_upgrade(move |socket| handle_socket(socket, ctx, pc, tenant))
}

/// RAII guard that increments `drust_ws_connections_active` on construction
/// and decrements it on drop — regardless of how `handle_socket` exits.
struct WsConnGuard;

impl WsConnGuard {
    fn new() -> Self {
        crate::mgmt::metrics::metrics().ws_connections_active.inc();
        WsConnGuard
    }
}

impl Drop for WsConnGuard {
    fn drop(&mut self) {
        crate::mgmt::metrics::metrics().ws_connections_active.dec();
    }
}

/// Per-connection event loop. Returns when the conn closes for any
/// reason (client disconnect / LAGGED / send error).
async fn handle_socket(socket: WebSocket, ctx: AuthCtx, pc: PublishCtx, tenant: String) {
    let _conn_guard = WsConnGuard::new(); // v1.32 C1 — tracks active WS connections
    let (mut sink, mut stream) = socket.split();

    // v1.31.2 F6 — drop the separate `subscribed: HashSet<String>`. The
    // StreamMap itself IS the source of truth for which rooms this
    // connection is subscribed to. Pre-fix, evict_tenant could drop the
    // StreamMap entry while the HashSet still claimed it, making
    // re-Subscribe a silent no-op.
    let mut stream_map: StreamMap<String, BroadcastStream<RoomMessage>> = StreamMap::new();
    let mut ka = interval(Duration::from_secs(30));
    ka.tick().await; // consume immediate first tick

    let token_hint = match &ctx {
        AuthCtx::Service { .. } => "service",
        AuthCtx::User { .. } => "user",
        AuthCtx::Anon => "anon",
    };
    let admin_id = ctx.admin_id();

    loop {
        tokio::select! {
            // Branch (a): upstream WS frame
            maybe_frame = stream.next() => {
                let frame = match maybe_frame {
                    None => break,                                   // clean disconnect
                    Some(Ok(f)) => f,                                // normal frame
                    Some(Err(e)) => {                                // v1.31.3 F11.5
                        tracing::warn!(
                            error = ?e,
                            tenant = %tenant,
                            token_hint = %token_hint,
                            "ws protocol error",
                        );
                        break;
                    }
                };
                match frame {
                    Message::Text(text) => {
                        if !handle_text_frame(
                            text.as_str(), &ctx, &pc, &tenant, token_hint, admin_id,
                            &mut stream_map, &mut sink,
                        ).await {
                            break;
                        }
                    }
                    Message::Ping(p) => {
                        if sink.send(Message::Pong(p)).await.is_err() { break; }
                    }
                    Message::Close(_) => break,
                    Message::Binary(_) | Message::Pong(_) => {}
                }
            }
            // Branch (b): downstream broadcast fan-in.
            // v1.31.2 F5 — `, if !stream_map.is_empty()` gate. Empty
            // StreamMap's `.next()` returns Poll::Ready(None) immediately;
            // pre-fix `continue` made this a hot loop pegging a CPU core
            // until the client subscribed to its first room.
            maybe_msg = stream_map.next(), if !stream_map.is_empty() => {
                let Some((room, item)) = maybe_msg else { continue; };
                match item {
                    Ok(rmsg) => {
                        // v1.32.2 D8 — frame pre-serialized at publish
                        // time (see publish_into_bus + rest.rs::tests
                        // wire-identity assertion). Forward bytes verbatim
                        // rather than rebuild + re-serialize per subscriber.
                        let text = Utf8Bytes::try_from(rmsg.frame_bytes.clone())
                            .unwrap_or_default();
                        if sink.send(Message::Text(text)).await.is_err() { break; }
                    }
                    // v1.31.2 F8 — per-room recovery instead of conn-wide
                    // break. A single noisy room used to drop all of the
                    // client's other subscriptions. Now the lagging room
                    // is removed from the StreamMap; client can op:subscribe
                    // again with the same name to resync.
                    Err(BroadcastStreamRecvError::Lagged(n)) => {
                        let env = ServerMessage::Error {
                            client_ref: None,
                            code: codes::LAGGED,
                            msg: format!("dropped {n} messages on room {room}; resubscribe to recover"),
                            room: Some(room.clone()),
                        };
                        if send_json(&mut sink, &env).await.is_err() { break; }
                        // Drop the lagging stream; keep the connection.
                        stream_map.remove(&room);
                    }
                }
            }
            // Branch (c): keepalive
            _ = ka.tick() => {
                if sink.send(Message::Ping(axum::body::Bytes::new())).await.is_err() { break; }
            }
        }
    }
}

/// Handle one upstream text frame. Returns `true` to continue the
/// outer loop, `false` to close the conn.
async fn handle_text_frame(
    text: &str,
    ctx: &AuthCtx,
    pc: &PublishCtx,
    tenant: &str,
    token_hint: &'static str,
    admin_id: Option<i64>,
    stream_map: &mut StreamMap<String, BroadcastStream<RoomMessage>>,
    sink: &mut SplitSink<WebSocket, Message>,
) -> bool {
    let op: ClientOp = match serde_json::from_str(text) {
        Ok(o) => o,
        Err(_) => {
            return send_error(
                sink,
                None,
                codes::MALFORMED_FRAME,
                "frame is not valid JSON or missing required fields",
                None,
            )
            .await
            .is_ok();
        }
    };

    match op {
        ClientOp::Subscribe { room, client_ref } => {
            if let Err(code) = validate_room_name(&room) {
                return send_error(
                    sink,
                    client_ref,
                    code,
                    "room name does not match ^[a-zA-Z][a-zA-Z0-9_:.-]{0,127}$",
                    Some(room),
                )
                .await
                .is_ok();
            }
            // v1.31.2 F6 — use stream_map.len() instead of a separate set.
            if !stream_map.contains_key(&room) && stream_map.len() >= pc.cfg.client_room_max {
                return send_error(
                    sink,
                    client_ref,
                    codes::CLIENT_ROOM_MAX,
                    "this connection has subscribed to too many rooms",
                    Some(room),
                )
                .await
                .is_ok();
            }
            // Per-room subscriber cap. We exempt re-subscribe (already in
            // map) so idempotent subscribes don't fail at the cap edge.
            if !stream_map.contains_key(&room) {
                let current = pc.bus.current_subscriber_count(tenant, &room);
                if current >= pc.cfg.room_subscriber_max {
                    return send_error(
                        sink,
                        client_ref,
                        codes::ROOM_FULL,
                        "room subscriber cap reached",
                        Some(room),
                    )
                    .await
                    .is_ok();
                }
                let rx = pc.bus.subscribe(tenant, &room);
                stream_map.insert(room.clone(), BroadcastStream::new(rx));
            }
            send_ack(sink, client_ref, "subscribe", Some(room), None)
                .await
                .is_ok()
        }
        ClientOp::Unsubscribe { room, client_ref } => {
            // v1.31.2 F6 — stream_map is authoritative.
            stream_map.remove(&room);
            send_ack(sink, client_ref, "unsubscribe", Some(room), None)
                .await
                .is_ok()
        }
        ClientOp::Publish {
            room,
            payload,
            client_ref,
        } => {
            if !matches!(ctx, AuthCtx::Service { .. }) {
                return send_error(
                    sink,
                    client_ref,
                    codes::WS_PUBLISH_DENIED,
                    "service token required to publish",
                    Some(room),
                )
                .await
                .is_ok();
            }
            let started = Instant::now();
            let byte_count = serde_json::to_vec(&payload).map(|v| v.len()).unwrap_or(0);
            match publish_into_bus(pc, tenant, &room, payload, "ws") {
                Ok(n) => {
                    let ms = started.elapsed().as_millis() as u64;
                    write_publish_audit(tenant, token_hint, ms, &room, byte_count, "ws", n, admin_id);
                    send_ack(sink, client_ref, "publish", Some(room), Some(n))
                        .await
                        .is_ok()
                }
                Err(e) => {
                    let (code, msg) = match e {
                        PublishError::RoomNameInvalid => {
                            (codes::ROOM_NAME_INVALID, "room name invalid".to_string())
                        }
                        PublishError::ProtectedRoom => (
                            codes::PROTECTED_ROOM,
                            "_system_ prefix forbidden".to_string(),
                        ),
                        PublishError::PayloadTooLarge => {
                            (codes::PAYLOAD_TOO_LARGE, "payload too large".to_string())
                        }
                        PublishError::RateLimited(d) => (
                            codes::RATE_LIMITED,
                            format!("retry after {}ms", d.as_millis()),
                        ),
                    };
                    let ms = started.elapsed().as_millis() as u64;
                    write_publish_audit_failure(
                        tenant, token_hint, ms, &room, byte_count, "ws", code, admin_id,
                    );
                    send_error(sink, client_ref, code, &msg, Some(room))
                        .await
                        .is_ok()
                }
            }
        }
        ClientOp::Ping { client_ref } => {
            let env = ServerMessage::Pong { client_ref };
            send_json(sink, &env).await.is_ok()
        }
    }
}

async fn send_json(
    sink: &mut SplitSink<WebSocket, Message>,
    env: &ServerMessage,
) -> Result<(), axum::Error> {
    let s = serde_json::to_string(env)
        .unwrap_or_else(|_| r#"{"kind":"error","code":"INTERNAL","msg":""}"#.to_string());
    sink.send(Message::Text(Utf8Bytes::from(s))).await
}

/// Emit `ack` only when client supplied `ref` — keeps the wire quiet
/// for fire-and-forget clients.
async fn send_ack(
    sink: &mut SplitSink<WebSocket, Message>,
    client_ref: Option<String>,
    op: &'static str,
    room: Option<String>,
    delivered_to: Option<usize>,
) -> Result<(), axum::Error> {
    if client_ref.is_none() {
        return Ok(());
    }
    let env = ServerMessage::Ack {
        client_ref,
        op,
        room,
        delivered_to,
    };
    send_json(sink, &env).await
}

async fn send_error(
    sink: &mut SplitSink<WebSocket, Message>,
    client_ref: Option<String>,
    code: &'static str,
    msg: &str,
    room: Option<String>,
) -> Result<(), axum::Error> {
    let env = ServerMessage::Error {
        client_ref,
        code,
        msg: msg.to_string(),
        room,
    };
    send_json(sink, &env).await
}

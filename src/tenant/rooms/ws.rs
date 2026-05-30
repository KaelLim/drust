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
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Path};
use axum::response::Response;
use futures::stream::{SplitSink, StreamExt};
use futures::SinkExt;
use std::collections::HashSet;
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
    ws.max_message_size(128 * 1024)
        .max_frame_size(128 * 1024)
        .on_upgrade(move |socket| handle_socket(socket, ctx, pc, tenant))
}

/// Per-connection event loop. Returns when the conn closes for any
/// reason (client disconnect / LAGGED / send error).
async fn handle_socket(socket: WebSocket, ctx: AuthCtx, pc: PublishCtx, tenant: String) {
    let (mut sink, mut stream) = socket.split();

    let mut subscribed: HashSet<String> = HashSet::new();
    let mut stream_map: StreamMap<String, BroadcastStream<RoomMessage>> = StreamMap::new();
    let mut ka = interval(Duration::from_secs(30));
    ka.tick().await; // consume immediate first tick

    let token_hint = match &ctx {
        AuthCtx::Service { .. } => "service",
        AuthCtx::User { .. } => "user",
        AuthCtx::Anon => "anon",
    };

    loop {
        tokio::select! {
            // Branch (a): upstream WS frame
            maybe_frame = stream.next() => {
                let Some(Ok(frame)) = maybe_frame else { break; };
                match frame {
                    Message::Text(text) => {
                        if !handle_text_frame(
                            text.as_str(), &ctx, &pc, &tenant, token_hint,
                            &mut subscribed, &mut stream_map, &mut sink,
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
            // Branch (b): downstream broadcast fan-in
            maybe_msg = stream_map.next() => {
                let Some((room, item)) = maybe_msg else { continue; };
                match item {
                    Ok(rmsg) => {
                        let env = ServerMessage::Message {
                            room: room.clone(),
                            payload: (*rmsg.payload).clone(),
                            ts: rmsg.ts_ms,
                        };
                        if send_json(&mut sink, &env).await.is_err() { break; }
                    }
                    Err(BroadcastStreamRecvError::Lagged(n)) => {
                        let env = ServerMessage::Error {
                            client_ref: None,
                            code: codes::LAGGED,
                            msg: format!("dropped {n} messages on room {room}; reconnect"),
                            room: Some(room.clone()),
                        };
                        let _ = send_json(&mut sink, &env).await;
                        let _ = sink.send(Message::Close(Some(CloseFrame {
                            code: 1011,
                            reason: Utf8Bytes::from_static("lagged"),
                        }))).await;
                        break;
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
    subscribed: &mut HashSet<String>,
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
            if !subscribed.contains(&room) && subscribed.len() >= pc.cfg.client_room_max {
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
            // Per-room subscriber cap. We exempt re-subscribe (already in set)
            // so idempotent subscribes don't fail at the cap edge.
            if !subscribed.contains(&room) {
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
                subscribed.insert(room.clone());
            }
            send_ack(sink, client_ref, "subscribe", Some(room), None)
                .await
                .is_ok()
        }
        ClientOp::Unsubscribe { room, client_ref } => {
            if subscribed.remove(&room) {
                stream_map.remove(&room);
            }
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
                    write_publish_audit(tenant, token_hint, ms, &room, byte_count, "ws", n);
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
                        tenant, token_hint, ms, &room, byte_count, "ws", code,
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

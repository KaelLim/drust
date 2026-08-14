//! v1.31 WebSocket multiplex handler — GET /t/{tenant}/realtime.
//!
//! One WS conn ⇒ N rooms. Per-conn task drives `tokio::select!` over:
//!   (a) upstream `WebSocket::recv()` — demux client op
//!   (b) `StreamMap<String, BroadcastStream<RoomMessage>>` — fan-in
//!   (c) keepalive ticker (`RoomsConfig.keepalive_secs`, default 30 s,
//!       clamped into 1..=300 — see `keepalive_interval`)
//!
//! Auth at upgrade: bearer resolved by `bearer_auth_layer` upstream
//! (which itself reads the Authorization header rewritten from
//! `?token=` by `ws_query_token_adapter`). Anon / User / Service all
//! may subscribe; `op:publish` is gated by `check_publish_allowed`
//! against the per-tenant `TenantPublishPolicy` (v1.32.5 — was
//! service-only pre-v1.32.5).
//!
//! #955 — that upgrade-time identity is captured ONCE and never
//! re-resolved, so revocation reaches a LIVE socket only through the
//! tenant eviction epoch: `ws_handler` captures
//! `RoomBus::tenant_epoch_handle` + its value BEFORE the upgrade and hands
//! both to `handle_socket`, which compares on branch (a) — on EVERY inbound
//! frame, before the `match` that dispatches it — and on branch (c) every
//! tick. A mismatch sends [`codes::CONN_EVICTED`] and closes 1008.
//!
//! Checkpoint (a) sits above the frame `match`, not inside the `Text` arm,
//! deliberately. Only Text carries a privileged effect today, so the narrow
//! placement was not a hole — but it made the covered set an ENUMERATION of
//! arms (Ping / Binary / Pong were unchecked), and the next op carried on a
//! Binary frame would have joined the unchecked side silently. Above the
//! match there is nothing to enumerate: every frame that reaches the server
//! is checked, and the structural pin anchors on `match frame {` so the
//! placement cannot regress into an arm.
//!
//! Branch (b) deliberately does NOT check — but not because nothing can
//! arrive there post-revocation. `RoomBus::evict_tenant`'s own doc spells
//! out the residual: a socket whose epoch load happened before the bump
//! can still reach `subscribe()` AFTER `channels.remove` and RE-CREATE the
//! tenant's channel, and any later publish from a legitimate connection
//! (REST, MCP broadcast, another WS) is then delivered over branch (b) to
//! the revoked socket. What bounds it is that socket's NEXT checkpoint:
//! one keepalive tick, which `DRUST_BROADCAST_KEEPALIVE_SECS` clamps into
//! 1..=300 s — so up to 5 minutes on a configured-slow tenant, not the
//! 30 s default a reader would assume. That is the same accepted
//! micro-race as spec §隔離與資安不變量 item 4; checking branch (b) would
//! not remove it, only shorten it, at the cost of a load per delivered
//! message on every healthy connection.

use crate::auth::middleware::AuthCtx;
use crate::tenant::rooms::audit::{write_publish_audit, write_publish_audit_failure};
use crate::tenant::rooms::bus::RoomMessage;
use crate::tenant::rooms::envelope::{ClientOp, ServerMessage, codes};
use crate::tenant::rooms::policy::{
    PublishGate, TenantPublishPolicy, check_publish_allowed, validate_room_name,
};
use crate::tenant::rooms::rest::{PublishCtx, PublishError, publish_into_bus};
use axum::extract::ws::{Message, Utf8Bytes, WebSocketUpgrade};
use axum::extract::{Extension, Path};
use axum::response::Response;
use futures::SinkExt;
use futures::stream::StreamExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::time::{Duration, Instant};
use tokio::time::interval;
use tokio_stream::StreamMap;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

/// GET /t/{tenant}/realtime — WS multiplex upgrade.
pub async fn ws_handler(
    pc: PublishCtx,
    Extension(ctx): Extension<AuthCtx>,
    // v1.32.5 — optional so tests / dev routers that mount without
    // bearer_auth_layer fall through to the safe default (service-only).
    policy: Option<Extension<TenantPublishPolicy>>,
    Path((tenant,)): Path<(String,)>,
    ws: WebSocketUpgrade,
) -> Response {
    // v1.31.2 F10 — honor DRUST_BROADCAST_PAYLOAD_MAX_BYTES at the WS
    // frame layer. Pre-fix this was hardcoded 128 KiB, silently capping
    // below env config. The wire-level PAYLOAD_TOO_LARGE error in
    // handle_text_frame::Publish stays — it gives clean errors below
    // this hard ceiling.
    let cap = pc.cfg.payload_max_bytes;
    let policy = policy.map(|Extension(p)| p).unwrap_or_default();

    // #955 — capture this connection's eviction baseline HERE, before the
    // upgrade, not inside the `on_upgrade` closure.
    //
    // `on_upgrade` runs its closure only after this handler returns, the 101
    // response is serialized and written to the socket, hyper completes the
    // upgrade, and the spawned task is scheduled — network I/O plus a task
    // hand-off, which this repo has measured being starved long enough to
    // HANG tests (see `tests/rooms_ws.rs`'s module doc on tokio/2374). The
    // consequence is not proportional to the window's length: an evict that
    // lands inside it is adopted as this socket's BASELINE, so the socket is
    // permanently immune to THAT revocation and survives until some unrelated
    // later evict — "revocation silently did not happen", the exact class
    // #955 exists to close.
    //
    // Capturing here leaves only the await-free middleware→handler hop, and
    // moving the capture EARLIER is strictly fail-closed: an older baseline
    // can only cause an extra close, never a missed one. The no-sticky-kill
    // property is unchanged because a reconnect takes its own fresh baseline
    // (`handle_taken_after_evict_reads_current_epoch_no_false_eviction`).
    // The residual is now the handler hop itself, which is the smallest this
    // design can make it without re-resolving identity per frame.
    let epoch = pc.bus.tenant_epoch_handle(&tenant);
    let epoch0 = epoch.load(SeqCst);

    ws.max_message_size(cap)
        .max_frame_size(cap)
        .on_upgrade(move |socket| {
            // Splitting HERE rather than inside `handle_socket` is what makes
            // the conn loop generic over its two halves, and therefore
            // drivable by an in-memory duplex in a lib test — see
            // `handle_socket`'s doc for why that mattered enough to change
            // the signature.
            let (sink, stream) = socket.split();
            handle_socket(sink, stream, ctx, pc, tenant, policy, epoch, epoch0)
        })
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

/// #955 — the keepalive ticker actually installed on a connection.
///
/// A named function rather than an inline `interval(...)` so the WIRING is
/// testable: the knob's producer (`RoomsConfig::from_env`) had unit tests
/// while this consumer had none, and reverting the period to the pre-#955
/// hardcoded 30 s left every targeted gate green — a documented env var that
/// did nothing, which is the exact defect this change set exists to fix.
/// `keepalive_interval_tracks_config_not_a_hardcoded_period` goes red on that
/// revert.
///
/// `from_env` already clamps into `1..=300`; the `.max(1)` covers any OTHER
/// `RoomsConfig` constructor (test literals build the struct directly)
/// because `tokio::time::interval` panics on a zero period.
fn keepalive_interval(cfg: &crate::tenant::rooms::state::RoomsConfig) -> tokio::time::Interval {
    interval(Duration::from_secs(cfg.keepalive_secs.max(1)))
}

/// Per-connection event loop. Returns when the conn closes for any
/// reason (client disconnect / LAGGED / send error).
///
/// Generic over the two socket halves rather than taking a `WebSocket`,
/// for one reason: a `WebSocket` cannot be constructed without a real
/// upgraded connection, and **every** WS integration test in this repo is
/// `#[ignore]`d (tokio/2374 — see `tests/rooms_ws.rs`), so `make test-all`
/// runs none of them. Before this signature change the #955 checkpoints had
/// no EXECUTED coverage at all: the only tests that could see them were a
/// source-text pin (which any sufficiently creative mutant eventually
/// out-runs — three rounds of that arms race are recorded on the pin) and
/// ignored integration tests. With the halves generic, the real loop can be
/// driven end-to-end over an in-memory duplex in a lib test that every gate
/// runs — see `evicted_conn_loop_closes_1008_and_never_dispatches_the_frame`.
async fn handle_socket<Si, St, E>(
    mut sink: Si,
    mut stream: St,
    ctx: AuthCtx,
    pc: PublishCtx,
    tenant: String,
    policy: TenantPublishPolicy,
    // #955 — the eviction baseline, captured in `ws_handler` BEFORE the
    // upgrade (see there for why not here). Passed in rather than taken here
    // so every checkpoint below is a bare atomic load against a FIXED
    // connect-time value: no map lookup, no lock, nothing on the hot path —
    // and, load-bearing, no way to re-read `epoch0` per frame, which would
    // make the comparison vacuous and close nothing.
    epoch: Arc<AtomicU64>,
    epoch0: u64,
) where
    Si: futures::Sink<Message> + Unpin,
    St: futures::Stream<Item = Result<Message, E>> + Unpin,
    E: std::fmt::Debug,
{
    let _conn_guard = WsConnGuard::new(); // v1.32 C1 — tracks active WS connections

    // v1.31.2 F6 — drop the separate `subscribed: HashSet<String>`. The
    // StreamMap itself IS the source of truth for which rooms this
    // connection is subscribed to. Pre-fix, evict_tenant could drop the
    // StreamMap entry while the HashSet still claimed it, making
    // re-Subscribe a silent no-op.
    let mut stream_map: StreamMap<String, BroadcastStream<RoomMessage>> = StreamMap::new();
    let mut ka = keepalive_interval(&pc.cfg);
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
                // #955 checkpoint (a) — above the match, so EVERY inbound frame
                // is checked before it is dispatched at all: subscribe /
                // unsubscribe / publish / op:ping (all Text), the WS control
                // Ping we answer with a Pong, and any future op carried on a
                // Binary frame. An evicted socket cannot land one more op on
                // the way out, and the covered set is not an enumeration of
                // match arms that a new arm can silently fall outside of.
                if check_epoch_evicted(&mut sink, &epoch, epoch0).await { break; }
                match frame {
                    Message::Text(text) => {
                        if !handle_text_frame(
                            text.as_str(), &ctx, &pc, &tenant, token_hint, admin_id,
                            &policy, &mut stream_map, &mut sink,
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
                // #955 checkpoint (c) — this is the ONLY checkpoint an IDLE
                // socket ever reaches, so it is what bounds post-evict life
                // to one keepalive period instead of "until the client
                // happens to disconnect".
                if check_epoch_evicted(&mut sink, &epoch, epoch0).await { break; }
                if sink.send(Message::Ping(axum::body::Bytes::new())).await.is_err() { break; }
            }
        }
    }
}

/// Handle one upstream text frame. Returns `true` to continue the
/// outer loop, `false` to close the conn.
///
/// Generic over the sink for the same reason as [`handle_socket`] — so the
/// loop that calls it can be driven by an in-memory duplex under test.
async fn handle_text_frame<S>(
    text: &str,
    ctx: &AuthCtx,
    pc: &PublishCtx,
    tenant: &str,
    token_hint: &'static str,
    admin_id: Option<i64>,
    policy: &TenantPublishPolicy,
    stream_map: &mut StreamMap<String, BroadcastStream<RoomMessage>>,
    sink: &mut S,
) -> bool
where
    S: futures::Sink<Message> + Unpin,
{
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
            // v1.32.5 — gate via shared helper. Default (both flags off)
            // preserves the historical service-only behavior; admin can
            // opt in user / anon publish via PATCH publish-policy. MCP
            // `broadcast` does NOT consume this — MCP dispatch is already
            // service-only by construction (defense in depth ≥ 2).
            match check_publish_allowed(ctx, policy) {
                PublishGate::Allow => {}
                PublishGate::DenyUser => {
                    return send_error(
                        sink,
                        client_ref,
                        codes::WS_PUBLISH_USER_DENIED,
                        "user tokens cannot publish on this tenant; \
                         admin must enable `allow_user_publish`",
                        Some(room),
                    )
                    .await
                    .is_ok();
                }
                PublishGate::DenyAnon => {
                    return send_error(
                        sink,
                        client_ref,
                        codes::WS_PUBLISH_ANON_DENIED,
                        "anon tokens cannot publish on this tenant; \
                         admin must enable `allow_anon_publish`",
                        Some(room),
                    )
                    .await
                    .is_ok();
                }
            }
            let started = Instant::now();
            let byte_count = serde_json::to_vec(&payload).map(|v| v.len()).unwrap_or(0);
            match publish_into_bus(pc, tenant, &room, payload, "ws") {
                Ok(n) => {
                    let ms = started.elapsed().as_millis() as u64;
                    write_publish_audit(
                        tenant, token_hint, ms, &room, byte_count, "ws", n, admin_id,
                    );
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

/// #955 — the connection-level eviction checkpoint.
///
/// Returns `true` when the caller must break its conn loop: the tenant's
/// epoch moved since `epoch0` was captured at connect, meaning something
/// revoked or invalidated the identity this socket is still running under.
/// The bump happens in [`crate::tenant::rooms::bus::RoomBus::evict_tenant`],
/// whose doc enumerates the call sites (token reroll, the #952 user-session
/// revoke funnel, tenant soft-delete, admin evict-all …) — do not duplicate
/// that list here, it drifts.
///
/// Both sends are best-effort — the point is to CLOSE, and a client that
/// already vanished cannot be told why. Order matters: the typed error
/// goes first so a client that respects close frames still learns it was
/// evicted rather than disconnected.
///
/// Generic over the sink purely so the wire behaviour is unit-testable: a
/// `SplitSink<WebSocket, _>` cannot be built without a real upgraded
/// socket, and every WS integration test in this repo is `#[ignore]`d.
async fn check_epoch_evicted<S>(sink: &mut S, epoch: &AtomicU64, epoch0: u64) -> bool
where
    S: futures::Sink<Message> + Unpin,
{
    if epoch.load(SeqCst) == epoch0 {
        return false;
    }
    let _ = send_error(
        sink,
        None,
        codes::CONN_EVICTED,
        "connection evicted; reconnect and re-authenticate",
        None,
    )
    .await;
    let _ = sink
        .send(Message::Close(Some(axum::extract::ws::CloseFrame {
            code: axum::extract::ws::close_code::POLICY, // 1008
            reason: Utf8Bytes::from_static("evicted"),
        })))
        .await;
    true
}

async fn send_json<S>(sink: &mut S, env: &ServerMessage) -> Result<(), S::Error>
where
    S: futures::Sink<Message> + Unpin,
{
    let s = serde_json::to_string(env)
        .unwrap_or_else(|_| r#"{"kind":"error","code":"INTERNAL","msg":""}"#.to_string());
    sink.send(Message::Text(Utf8Bytes::from(s))).await
}

/// Emit `ack` only when client supplied `ref` — keeps the wire quiet
/// for fire-and-forget clients.
async fn send_ack<S>(
    sink: &mut S,
    client_ref: Option<String>,
    op: &'static str,
    room: Option<String>,
    delivered_to: Option<usize>,
) -> Result<(), S::Error>
where
    S: futures::Sink<Message> + Unpin,
{
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

async fn send_error<S>(
    sink: &mut S,
    client_ref: Option<String>,
    code: &'static str,
    msg: &str,
    room: Option<String>,
) -> Result<(), S::Error>
where
    S: futures::Sink<Message> + Unpin,
{
    let env = ServerMessage::Error {
        client_ref,
        code,
        msg: msg.to_string(),
        room,
    };
    send_json(sink, &env).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::rooms::srcpin;
    use crate::tenant::rooms::state::RoomsConfig;

    /// #955 — pin the CONSUMER of `RoomsConfig.keepalive_secs`.
    ///
    /// Round 1 of this change set shipped the env var with the WS loop still
    /// on a hardcoded 30 s; round 2's tests then covered only the producer
    /// (`from_env`), so the same mutant — `interval(Duration::from_secs(30))`
    /// — was still green across `cargo test --lib rooms::` and
    /// `cargo test --test g_rooms`. This asserts the period the loop actually
    /// installs, so that revert now fails here.
    ///
    /// Scope, stated honestly: this pins the period SELECTION, not the
    /// end-to-end behaviour. Only the T2 integration test (`keepalive_secs =
    /// 1`, evict, expect Close well inside 30 s) proves an evicted idle socket
    /// really closes on that tick.
    #[tokio::test]
    async fn keepalive_interval_tracks_config_not_a_hardcoded_period() {
        let mut cfg = RoomsConfig::test_defaults();
        assert_eq!(cfg.keepalive_secs, 30, "test_defaults must stay 30");
        assert_eq!(
            keepalive_interval(&cfg).period(),
            Duration::from_secs(30),
            "default path"
        );

        // The values the #955 tests and a chatter-averse operator actually use.
        for secs in [1u64, 5, 7, 300] {
            cfg.keepalive_secs = secs;
            assert_eq!(
                keepalive_interval(&cfg).period(),
                Duration::from_secs(secs),
                "keepalive period must follow the config, not a literal",
            );
        }

        // A 0 from a hand-built `RoomsConfig` (only `from_env` clamps) must
        // not panic `tokio::time::interval`.
        cfg.keepalive_secs = 0;
        assert_eq!(keepalive_interval(&cfg).period(), Duration::from_secs(1));
    }

    /// #955 — the wire behaviour of the eviction checkpoint, pinned at the
    /// LIB level.
    ///
    /// Why this is not left to the integration tests: every WS test in
    /// `tests/rooms_ws.rs` is `#[ignore]`d (tokio/2374), so `make test-all`
    /// runs NONE of them. Without this test the only executed coverage of
    /// "what an evicted socket actually receives" would be a test nobody's
    /// gate runs.
    ///
    /// Three properties, all load-bearing: an UNCHANGED epoch must emit
    /// nothing at all (a checkpoint that chattered would fire on every frame
    /// of every healthy connection), a MOVED epoch must emit the typed
    /// `CONN_EVICTED` error BEFORE the Close (a bare close leaves the client
    /// guessing whether it was evicted or the network died), and the close
    /// code must be 1008 Policy Violation rather than a normal 1000 — the
    /// client is being refused, not dismissed.
    #[tokio::test]
    async fn check_epoch_evicted_is_silent_until_the_epoch_moves_then_errors_and_closes_1008() {
        let (mut sink, mut frames) = futures::channel::mpsc::unbounded::<Message>();
        let epoch = AtomicU64::new(7);

        // Baseline == current: no frames, keep the conn.
        assert!(
            !check_epoch_evicted(&mut sink, &epoch, 7).await,
            "an unmoved epoch must not close the connection"
        );
        assert!(
            frames.try_recv().is_err(),
            "an unmoved epoch must put NOTHING on the wire"
        );

        // The evict.
        epoch.fetch_add(1, SeqCst);
        assert!(
            check_epoch_evicted(&mut sink, &epoch, 7).await,
            "a moved epoch must tell the caller to break the conn loop"
        );

        let first = frames.try_recv().expect("expected an error frame");
        let Message::Text(t) = first else {
            panic!("expected the CONN_EVICTED error frame first, got {first:?}");
        };
        let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
        assert_eq!(v["kind"], "error");
        assert_eq!(v["code"], codes::CONN_EVICTED);
        assert!(
            v["msg"].as_str().unwrap().contains("reconnect"),
            "the message must tell the client what to do next: {v}"
        );

        let second = frames.try_recv().expect("expected a close frame");
        match second {
            Message::Close(Some(cf)) => assert_eq!(
                cf.code,
                axum::extract::ws::close_code::POLICY,
                "must close 1008 Policy Violation, not a normal close"
            ),
            other => panic!("expected Close(1008) after the error, got {other:?}"),
        }
        assert!(
            frames.try_recv().is_err(),
            "exactly two frames: the typed error, then the close"
        );
    }

    /// #955 — structural pin for WHERE the baseline is captured, WHERE the two
    /// checkpoints sit, and that each checkpoint actually BREAKS the loop.
    ///
    /// The same reasoning as `bus.rs::evict_tenant_bumps_epoch_before_dropping_channels`:
    /// the only behavioural coverage of the checkpoint POSITIONS lives in
    /// `#[ignore]`d WS integration tests, so deleting either call site — or
    /// moving the frame checkpoint to AFTER `handle_text_frame`, which would
    /// let an evicted socket land one more subscribe/publish before dying,
    /// the exact hole #955 closes — leaves every gate green.
    ///
    /// Round 1 of the T2 review MEASURED two mutants that the first version of
    /// this pin let through, both turning #955 into a silent no-op with every
    /// executed gate green:
    ///
    /// 1. Re-capture the baseline PER FRAME (delete the pre-upgrade capture,
    ///    take a fresh handle + fresh `epoch0` inside each arm). `epoch0` can
    ///    then never differ from `epoch`, so nothing ever closes. The old
    ///    `capture < check_a` assertion was satisfied by the re-capture itself,
    ///    because `find` returns the FIRST occurrence anywhere. Killed here by
    ///    anchoring the capture in `ws_handler` and requiring `handle_socket`
    ///    to contain NO capture and NO baseline re-read at all.
    /// 2. Drop the `break` from a checkpoint. The error + Close are still
    ///    written first, so even the `#[ignore]`d integration tests stay green
    ///    while the op runs behind the close frame. Killed here by requiring a
    ///    `break` between each `check_epoch_evicted` and the work it guards.
    ///
    /// Round 2 then measured that round 1's OWN fix let mutant 2 back in: the
    /// reviewer had written it as `{ /* no break */ }`, and `contains("break")`
    /// matched the word inside that comment. Commenting checkpoint (a) out
    /// whole (`// if check_epoch_evicted(…) { break; }`) was green for the same
    /// reason — `find` anchored on a call that no longer ran. Every needle
    /// below is therefore matched against [`srcpin::code_only`], which blanks
    /// comments, so a mutant can no longer leave its own alibi in one.
    ///
    /// Round 3 measured the class all three earlier rounds had left open, and
    /// it is worth naming precisely because it explains the shape of the
    /// needles below. Rounds 1–2 only ever tightened WHERE a checkpoint sits
    /// and WHETHER it breaks — never WHICH ATOMIC it compares. So one line at
    /// the top of `handle_socket`, `let epoch = AtomicU64::new(epoch0);`,
    /// shadowed the passed-in handle (both `&AtomicU64` and `&Arc<AtomicU64>`
    /// coerce at the call sites, so it compiled untouched), left both
    /// checkpoints exactly where the pin demands, and made #955 a total
    /// no-op: `cargo test --lib rooms::` = 53 passed, 0 failed, this pin
    /// among them. Killed here by pinning the ARGUMENT TUPLE itself and by
    /// forbidding the body from naming `AtomicU64` or re-binding `epoch` at
    /// all.
    ///
    /// The `AtomicU64` ban is why this test splits the signature off the body:
    /// `epoch: Arc<AtomicU64>` is a legitimate use in the parameter list, and
    /// the ban applies only to what follows the opening brace.
    ///
    /// Round 3's real lesson, though, is that this pin should not have been
    /// the last line of defence. It is not any more — the loop is now driven
    /// for real in `evicted_conn_loop_closes_1008_and_never_dispatches_the_frame`,
    /// which is EXECUTED in every gate and which that mutant fails outright.
    /// Keep both: the executed test proves the behaviour, this pin proves the
    /// two checkpoints exist where an idle socket and a busy socket
    /// respectively reach them.
    ///
    /// It reads the two functions' own bodies, so the needles in this test's
    /// source cannot satisfy it.
    #[test]
    fn epoch_checkpoints_sit_before_dispatch_and_on_the_keepalive_tick() {
        // Comments blanked FIRST — see the round-2 note above.
        let stripped = srcpin::code_only(include_str!("ws.rs"));
        let src = stripped.as_str();

        // ---- the capture: in `ws_handler`, BEFORE the upgrade ----
        let h_start = src
            .find("pub async fn ws_handler(")
            .expect("ws_handler's signature changed — update this structural pin");
        let h_rest = &src[h_start..];
        let h_end = h_rest
            .find("\n}\n")
            .expect("could not find the end of ws_handler's body");
        let handler = &h_rest[..h_end];

        assert_eq!(
            handler.matches("tenant_epoch_handle(").count(),
            1,
            "ws_handler must capture the tenant eviction baseline EXACTLY once",
        );
        let capture = handler.find("tenant_epoch_handle(").unwrap();
        let upgrade = handler
            .find(".on_upgrade(")
            .expect("ws_handler must still upgrade through .on_upgrade");
        assert!(
            capture < upgrade,
            "the eviction baseline must be captured BEFORE .on_upgrade: the closure runs only \
             after the 101 is written and the task is scheduled, and an evict landing in that \
             window would be adopted as this socket's baseline — permanent immunity to that \
             revocation",
        );

        // ---- the checkpoints: inside `handle_socket` ----
        let start = src
            .find("async fn handle_socket<")
            .expect("handle_socket's signature changed — update this structural pin");
        let rest = &src[start..];
        let end = rest
            .find("\n}\n")
            .expect("could not find the end of handle_socket's body");
        let decl = &rest[..end];

        // Signature and body are scanned separately: `epoch: Arc<AtomicU64>`
        // is legitimate in the parameter list, and forbidden after the brace.
        let open = decl
            .find("\n{\n")
            .expect("handle_socket's body must still open on a line of its own");
        let body = &decl[open..];

        // The mutant that beat rounds 1–3 (`let epoch = AtomicU64::new(epoch0);`
        // shadowing the passed-in handle) is killed by this needle: it pins the
        // WHOLE argument tuple, so the comparison provably runs against the
        // handle the parameter list received, twice — once per checkpoint.
        assert_eq!(
            body.matches("check_epoch_evicted(&mut sink, &epoch, epoch0)")
                .count(),
            2,
            "mutant 3: both checkpoints must compare the PASSED-IN handle against the \
             connect-time epoch0 — `check_epoch_evicted(&mut sink, &epoch, epoch0)`, exactly \
             twice. Pinning only WHERE the calls sit lets a one-line shadow of `epoch` \
             decouple them from the bus with every gate green",
        );

        // Belt and braces for the same class: the body may not name the atomic
        // type at all, nor re-bind `epoch`, so no locally-synthesized counter
        // can be substituted under a matching argument tuple.
        for needle in [
            "AtomicU64",
            "let epoch",
            "let mut epoch",
            "tenant_epoch_handle(",
            "epoch.load(",
            "epoch =",
        ] {
            assert_eq!(
                body.matches(needle).count(),
                0,
                "mutants 1+3: handle_socket's body must not contain `{needle}`. The eviction \
                 baseline is captured ONCE in ws_handler and passed in; anything that takes a \
                 second handle, re-reads epoch0, or synthesizes/rebinds the atomic makes the \
                 comparison vacuous — epoch0 can then never differ from epoch, so no socket is \
                 ever closed",
            );
        }

        // Checkpoint (a): EVERY inbound frame, above the dispatch `match` —
        // not inside the Text arm, so a future op on a Binary frame cannot
        // land outside the checked set.
        let a_arm = body
            .find("maybe_frame = stream.next() => {")
            .expect("branch (a) moved — update this structural pin");
        let dispatch = a_arm
            + body[a_arm..]
                .find("match frame {")
                .expect("branch (a) must still dispatch the frame through `match frame`");
        assert_eq!(
            body[a_arm..dispatch]
                .matches("if check_epoch_evicted(&mut sink, &epoch, epoch0).await { break; }")
                .count(),
            1,
            "checkpoint (a) must be exactly `if check_epoch_evicted(&mut sink, &epoch, epoch0) \
             .await {{ break; }}`, ABOVE `match frame`. Below it (or inside one arm) an evicted \
             socket lands one more op on the way out — one more subscribe, re-creating the \
             channel evict just dropped, or one more publish plus its audit row — and arms the \
             check does not cover are invisible to every other assertion here. Without the \
             `break` the error + Close still go out first, so even the wire assertions pass \
             while the op runs behind them. (If rustfmt ever reflows this statement, re-verify \
             the placement by hand and update the needle — do not relax it.)",
        );

        // Checkpoint (c): the keepalive tick, BEFORE the Ping — this is what
        // bounds an IDLE socket's post-evict life to one keepalive period.
        let ka_arm = body
            .find("_ = ka.tick() => {")
            .expect("the keepalive arm moved — update this structural pin");
        let ping = ka_arm
            + body[ka_arm..]
                .find("Message::Ping(")
                .expect("the keepalive arm must still send a Ping");
        assert_eq!(
            body[ka_arm..ping]
                .matches("if check_epoch_evicted(&mut sink, &epoch, epoch0).await { break; }")
                .count(),
            1,
            "checkpoint (c) must be exactly `if check_epoch_evicted(&mut sink, &epoch, epoch0) \
             .await {{ break; }}`, before the Ping. Without it an evicted IDLE socket lives \
             until the client disconnects, which is unbounded; without the `break` it is told \
             it is evicted, then pinged, then kept",
        );
    }

    /// #955 — drive the REAL conn loop over an in-memory duplex and return
    /// every frame it wrote.
    ///
    /// This exists because `tests/rooms_ws.rs` is entirely `#[ignore]`d
    /// (tokio/2374), so no gate runs a WS integration test and the checkpoint
    /// behaviour had only source-text pins behind it. `handle_socket` is
    /// generic over its sink and stream precisely so this harness can exist.
    ///
    /// Determinism, deliberately: the inbound stream carries ONE frame and is
    /// then closed, so the loop returns on `None` even when nothing evicts it
    /// — no timeout, no sleep, no flake. Keepalive stays at the 30 s default
    /// so branch (c) never fires and cannot muddy the frame list, and the
    /// StreamMap is empty so branch (b) is gated off.
    ///
    /// The frame is `op:ping` **with a `ref`**: it is the only op that
    /// replies without touching a database, and the reply is skipped when
    /// `ref` is absent — so "was the frame dispatched?" is answerable from
    /// the wire alone, which is what makes the negative assertion real
    /// instead of vacuous.
    ///
    /// Division of labour with the structural pin, measured on 2026-08-14
    /// (`cargo test --lib rooms::ws::tests`, one mutant at a time, reverted
    /// after each):
    ///
    /// | mutant | pin | executed |
    /// |---|---|---|
    /// | `let epoch = AtomicU64::new(epoch0);` shadow (round 3) | red | red |
    /// | re-take the handle inside `handle_socket` | red | red |
    /// | checkpoint (a) loses its `break` | red | red |
    /// | checkpoint (a) `{ /* no break */ }` | red | red |
    /// | checkpoint (a) commented out | red | red |
    /// | checkpoint (a) moved BELOW `handle_text_frame` | red | red |
    /// | checkpoint (c) loses its `break` / deleted | red | red |
    /// | checkpoint (a) moved back INSIDE the `Text` arm | red | green |
    ///
    /// The last row is the honest limit of the executed tests and the reason
    /// the pin stays: that mutant does not change what happens to a Text
    /// frame, only which OTHER frames are covered, so only a placement
    /// assertion can see it.
    async fn drive_one_frame(evict: bool) -> Vec<Message> {
        const TENANT: &str = "t_epoch_loop";

        let bus = crate::tenant::rooms::bus::RoomBus::new();
        let epoch = bus.tenant_epoch_handle(TENANT);
        let epoch0 = epoch.load(SeqCst);

        let cfg = RoomsConfig::test_defaults();
        let pc = PublishCtx {
            bus: bus.clone(),
            bucket: cfg.bucket(),
            cfg,
        };

        let (frames_in, stream) =
            futures::channel::mpsc::unbounded::<Result<Message, axum::Error>>();
        frames_in
            .unbounded_send(Ok(Message::Text(Utf8Bytes::from_static(
                r#"{"op":"ping","ref":"r1"}"#,
            ))))
            .unwrap();
        drop(frames_in); // end-of-stream behind the frame

        if evict {
            bus.evict_tenant(TENANT);
        }

        let (sink, out) = futures::channel::mpsc::unbounded::<Message>();
        handle_socket(
            sink,
            stream,
            AuthCtx::Anon,
            pc,
            TENANT.to_string(),
            TenantPublishPolicy::default(),
            epoch,
            epoch0,
        )
        .await;

        out.collect::<Vec<_>>().await
    }

    /// The control arm. Without it, a checkpoint that closed EVERY connection
    /// would satisfy the eviction test below, and #955 would read as green
    /// while realtime was simply broken.
    #[tokio::test]
    async fn live_conn_loop_dispatches_the_frame_and_stays_silent_about_epochs() {
        let out = drive_one_frame(false).await;
        assert_eq!(
            out.len(),
            1,
            "an un-evicted socket must answer the op and emit nothing else: {out:?}"
        );
        let Message::Text(t) = &out[0] else {
            panic!("expected the pong, got {:?}", out[0]);
        };
        let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
        assert_eq!(v["kind"], "pong", "{v}");
        assert_eq!(v["ref"], "r1", "{v}");
    }

    /// #955, EXECUTED: the property the whole change set exists for, proven by
    /// running the real loop rather than by reading its source.
    ///
    /// Measured against the round-3 mutant (`let epoch = AtomicU64::new(epoch0);`
    /// at the top of `handle_socket`, which every source-text pin let through):
    /// this test fails on it.
    #[tokio::test]
    async fn evicted_conn_loop_closes_1008_and_never_dispatches_the_frame() {
        let out = drive_one_frame(true).await;

        assert_eq!(
            out.len(),
            2,
            "an evicted socket must write exactly the typed error and the close — a third \
             frame means the op was dispatched anyway: {out:?}"
        );

        let Message::Text(t) = &out[0] else {
            panic!(
                "expected the CONN_EVICTED error frame first, got {:?}",
                out[0]
            );
        };
        let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
        assert_eq!(v["kind"], "error", "{v}");
        assert_eq!(v["code"], codes::CONN_EVICTED, "{v}");

        match &out[1] {
            Message::Close(Some(cf)) => assert_eq!(
                cf.code,
                axum::extract::ws::close_code::POLICY,
                "must close 1008 Policy Violation, not a normal close"
            ),
            other => panic!("expected Close(1008) after the error, got {other:?}"),
        }

        // The load-bearing negative: the op must NOT have run. A pong here
        // means the checkpoint sat after dispatch — an evicted socket landing
        // one more op on its way out, the exact hole #955 closes.
        assert!(
            !out.iter()
                .any(|m| matches!(m, Message::Text(t) if t.as_str().contains("pong"))),
            "the frame must not have been dispatched: {out:?}"
        );
    }

    /// #955 checkpoint (c), EXECUTED: the IDLE-socket bound.
    ///
    /// This is the arm an operator actually depends on — a revoked holder who
    /// simply stops typing is closed by the keepalive tick, not "whenever
    /// they happen to disconnect" — and it is the arm the frame-driven test
    /// above cannot reach. `keepalive_secs = 1` costs the suite about a
    /// second of real time; the alternative (`tokio::time` paused) would mean
    /// enabling tokio's `test-util` feature repo-wide for one test.
    ///
    /// The outer `timeout` is not belt-and-braces: without it, DELETING
    /// checkpoint (c) — or dropping its `break` — makes this test HANG
    /// forever rather than fail, and a gate that hangs is worse than one that
    /// is red. With it, both mutants fail loudly in 10 s.
    #[tokio::test]
    async fn evicted_idle_conn_loop_closes_on_the_keepalive_tick() {
        const TENANT: &str = "t_epoch_idle";

        let bus = crate::tenant::rooms::bus::RoomBus::new();
        let epoch = bus.tenant_epoch_handle(TENANT);
        let epoch0 = epoch.load(SeqCst);

        let mut cfg = RoomsConfig::test_defaults();
        cfg.keepalive_secs = 1;
        let pc = PublishCtx {
            bus: bus.clone(),
            bucket: cfg.bucket(),
            cfg,
        };

        // Bound for the whole test on purpose: the inbound stream must stay
        // OPEN and silent. Dropping the sender would end the stream and exit
        // the loop through branch (a), proving nothing about the tick.
        let (_frames_in, stream) =
            futures::channel::mpsc::unbounded::<Result<Message, axum::Error>>();
        let (sink, out) = futures::channel::mpsc::unbounded::<Message>();

        bus.evict_tenant(TENANT);

        tokio::time::timeout(
            Duration::from_secs(10),
            handle_socket(
                sink,
                stream,
                AuthCtx::Anon,
                pc,
                TENANT.to_string(),
                TenantPublishPolicy::default(),
                epoch,
                epoch0,
            ),
        )
        .await
        .expect(
            "checkpoint (c) missing or non-breaking: an evicted IDLE socket was still running \
             many keepalive periods later, i.e. its post-evict life is bounded by nothing but \
             the client choosing to disconnect",
        );

        let frames = out.collect::<Vec<_>>().await;
        assert_eq!(
            frames.len(),
            2,
            "the tick must write exactly the typed error and the close: {frames:?}"
        );
        let Message::Text(t) = &frames[0] else {
            panic!("expected CONN_EVICTED first, got {:?}", frames[0]);
        };
        let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
        assert_eq!(v["code"], codes::CONN_EVICTED, "{v}");
        match &frames[1] {
            Message::Close(Some(cf)) => assert_eq!(
                cf.code,
                axum::extract::ws::close_code::POLICY,
                "must close 1008 Policy Violation, not a normal close"
            ),
            other => panic!("expected Close(1008) after the error, got {other:?}"),
        }
        // The keepalive Ping is what the tick does on a LIVE conn; an evicted
        // one must be closed instead, not pinged and kept.
        assert!(
            !frames.iter().any(|m| matches!(m, Message::Ping(_))),
            "an evicted socket must be closed on the tick, not pinged: {frames:?}"
        );
    }
}

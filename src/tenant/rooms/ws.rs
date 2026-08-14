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
//! both to `handle_socket`, which compares on branch (a) before dispatch
//! and on branch (c) every tick. A mismatch sends [`codes::CONN_EVICTED`]
//! and closes 1008.
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
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Path};
use axum::response::Response;
use futures::SinkExt;
use futures::stream::{SplitSink, StreamExt};
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
        .on_upgrade(move |socket| handle_socket(socket, ctx, pc, tenant, policy, epoch, epoch0))
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
async fn handle_socket(
    socket: WebSocket,
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
) {
    let _conn_guard = WsConnGuard::new(); // v1.32 C1 — tracks active WS connections
    let (mut sink, mut stream) = socket.split();

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
                match frame {
                    Message::Text(text) => {
                        // #955 checkpoint (a) — BEFORE dispatch, so it covers
                        // subscribe / unsubscribe / publish / ping uniformly and
                        // an evicted socket cannot land one more op on the way out.
                        if check_epoch_evicted(&mut sink, &epoch, epoch0).await { break; }
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
async fn handle_text_frame(
    text: &str,
    ctx: &AuthCtx,
    pc: &PublishCtx,
    tenant: &str,
    token_hint: &'static str,
    admin_id: Option<i64>,
    policy: &TenantPublishPolicy,
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
    /// It reads the two functions' own bodies, so the needles in this test's
    /// source cannot satisfy it.
    #[test]
    fn epoch_checkpoints_sit_before_dispatch_and_on_the_keepalive_tick() {
        let src = include_str!("ws.rs");

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
            .find("async fn handle_socket(")
            .expect("handle_socket's signature changed — update this structural pin");
        let rest = &src[start..];
        let end = rest
            .find("\n}\n")
            .expect("could not find the end of handle_socket's body");
        let body = &rest[..end];

        assert_eq!(
            body.matches("tenant_epoch_handle(").count(),
            0,
            "mutant 1: handle_socket must NOT take its own epoch handle — the baseline is \
             captured once in ws_handler and passed in. A per-frame capture makes epoch0 \
             always equal epoch, so no socket is ever closed",
        );
        assert_eq!(
            body.matches("epoch.load(").count(),
            0,
            "mutant 1: handle_socket must NOT re-read the baseline off the shared handle — \
             the only load belongs in check_epoch_evicted, which compares against the \
             connect-time epoch0",
        );

        // Checkpoint (a): every inbound Text frame, BEFORE dispatch.
        let text_arm = body
            .find("Message::Text(text) => {")
            .expect("the inbound Text arm moved — update this structural pin");
        let dispatch = text_arm
            + body[text_arm..]
                .find("handle_text_frame(")
                .expect("the Text arm must still dispatch through handle_text_frame");
        let check_a = text_arm
            + body[text_arm..dispatch]
                .find("check_epoch_evicted(")
                .expect(
                    "checkpoint (a) missing: the epoch must be checked BEFORE handle_text_frame, \
                     so an evicted socket cannot land one more subscribe/publish",
                );
        assert!(
            body[check_a..dispatch].contains("break"),
            "mutant 2: checkpoint (a) must BREAK the conn loop. Without the break the error + \
             Close still go out first, so every wire assertion passes, while the op runs \
             behind them — one more subscribe (re-creating the channel evict just dropped) or \
             one more publish plus its audit row",
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
        let check_c = ka_arm
            + body[ka_arm..ping].find("check_epoch_evicted(").expect(
                "checkpoint (c) missing: without it an evicted IDLE socket lives until the \
                 client disconnects, which is unbounded",
            );
        assert!(
            body[check_c..ping].contains("break"),
            "mutant 2: checkpoint (c) must BREAK the conn loop — otherwise the evicted idle \
             socket is told it is evicted, then pinged, then kept",
        );
    }
}

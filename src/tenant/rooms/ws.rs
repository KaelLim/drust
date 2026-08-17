//! v1.31 WebSocket multiplex handler — GET /t/{tenant}/realtime.
//!
//! One WS conn ⇒ N rooms. Per-conn task drives `tokio::select!` over:
//!   (a) upstream `WebSocket::recv()` — demux client op
//!   (b) `StreamMap<String, BroadcastStream<RoomMessage>>` — fan-in
//!   (c) keepalive ticker (`RoomsConfig.keepalive_secs`, default 30 s,
//!       clamped into 1..=300 — see `keepalive_interval`)
//!   (d) #976 — the credential's own expiry, present only for an admin PAT
//!       carrying `expires_at` (`ws_auth::PatDeadline`); fires once, sends
//!       [`codes::CONN_EXPIRED`] and closes 1008
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
//! tenant eviction epoch: the connection's baseline (the tenant's shared
//! epoch handle + its value) is taken BEFORE the upgrade and handed to
//! `handle_socket`, which compares on branch (a) — on EVERY inbound
//! frame, before the `match` that dispatches it — and on branch (c) every
//! tick. A mismatch sends [`codes::CONN_EVICTED`] and closes 1008.
//!
//! #976 — the baseline is now produced one hop earlier, by the
//! `ws_auth::ws_baseline_capture` layer mounted inside `bearer_auth_layer`
//! on `ws_router`; `ws_handler` reads it out of the request extensions and
//! falls back to capturing inline when it is absent. Revocation is one of
//! two ways a socket dies: branch (d) covers the other, a credential that
//! simply runs out of time.
//!
//! Checkpoint (a) sits above the frame `match`, not inside the `Text` arm,
//! deliberately. Only Text carries a privileged effect today, so the narrow
//! placement was not a hole — but it made the covered set an ENUMERATION of
//! arms (Ping / Binary / Pong were unchecked), and the next op carried on a
//! Binary frame would have joined the unchecked side silently. Above the
//! match there is nothing to enumerate: every frame that reaches the server
//! is checked. The structural pin holds that categorical claim up in both
//! directions a refactor could break it — the checkpoint must be the LAST
//! statement before `match frame {` (so it cannot slide into an arm) and
//! nothing above it may branch, `continue` or await (so it cannot be wrapped
//! back into a Text-only check, which was measured green against the
//! placement assertion alone).
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
use crate::tenant::rooms::bus::{RoomBus, RoomMessage};
use crate::tenant::rooms::envelope::{ClientOp, ServerMessage, codes};
use crate::tenant::rooms::policy::{
    PublishGate, TenantPublishPolicy, check_publish_allowed, validate_room_name,
};
use crate::tenant::rooms::rest::{PublishCtx, PublishError, publish_into_bus};
use crate::tenant::rooms::ws_auth::{PatDeadline, WsBaselineMeta};
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

/// #976 — the placeholder period branch (d)'s timer is armed with when this
/// connection has no credential deadline. It is never reached: the branch is
/// guarded off in that case. 30 years sits comfortably inside tokio's timer
/// range, so `sleep_until` neither saturates nor panics.
const FAR_FUTURE: Duration = Duration::from_secs(86_400 * 365 * 30);

/// #955 — this connection's eviction baseline: the tenant's SHARED epoch
/// atomic plus the value it held at connect.
///
/// A named function rather than two inline lines in [`ws_handler`], for the
/// same reason as [`keepalive_interval`]: `ws_handler` cannot be called from a
/// test (a `WebSocketUpgrade` needs a real upgrading request), so anything
/// living only in its body has source-text pins as its ONLY defence — and the
/// T2 review measured two one-line mutants there that left every executed gate
/// green while turning #955 off in production: synthesizing a private
/// `Arc<AtomicU64>` instead of asking the bus (nothing ever closes), and
/// reading the baseline inside the `on_upgrade` closure (an evict landing in
/// the 101-write + task-hand-off window is adopted as the baseline, i.e.
/// permanent immunity to THAT revocation). Both properties are now executed
/// contract, pinned by
/// `connect_baseline_is_the_bus_handle_and_the_live_epoch`; the structural pin
/// is left with the one thing a test cannot reach — that `ws_handler` calls
/// this BEFORE `.on_upgrade`.
fn connect_baseline(bus: &RoomBus, tenant: &str) -> (Arc<AtomicU64>, u64) {
    let epoch = bus.tenant_epoch_handle(tenant);
    let epoch0 = epoch.load(SeqCst);
    (epoch, epoch0)
}

/// GET /t/{tenant}/realtime — WS multiplex upgrade.
pub async fn ws_handler(
    pc: PublishCtx,
    Extension(ctx): Extension<AuthCtx>,
    // v1.32.5 — optional so tests / dev routers that mount without
    // bearer_auth_layer fall through to the safe default (service-only).
    policy: Option<Extension<TenantPublishPolicy>>,
    // #976 — both optional for the same reason, and both fail toward the
    // pre-#976 behaviour when absent: no baseline extension ⇒ capture inline
    // below, no deadline ⇒ branch (d) stays disabled for this connection.
    baseline: Option<Extension<WsBaselineMeta>>,
    pat_deadline: Option<Extension<PatDeadline>>,
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

    // #955/#976 — this connection's eviction baseline, resolved HERE, before
    // the upgrade, never inside the `on_upgrade` closure.
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
    // The window is the bearer-auth DECISION → wherever the pair is actually
    // read, and #976 F1 moves that read out of this handler entirely.
    // `ws_auth::ws_baseline_capture` is mounted INNERMOST on `ws_router`
    // (`src/tenant/mod.rs`), i.e. inside `bearer_auth_layer`, so it runs the
    // statement after auth admitted the request and hands the pair over in a
    // request extension — a per-request server-side slot a client cannot set.
    // What is left of the window is one `next.run` poll hop rather than the
    // whole routing + extractor run, and the fail direction is unchanged:
    // inside it the socket is fail-OPEN for exactly ONE revocation, which it
    // adopts as its baseline and then ignores until some later, unrelated
    // evict.
    //
    // The layer sits on `ws_router` alone — the sub-router that carries only
    // /realtime and the SSE /subscribe route — so no REST, MCP or files
    // request ever runs it. (A previous version of this comment refused the
    // move because taking the pair in `bearer_auth_layer` would tax EVERY
    // tenant request. That cost was never on the table for a per-route layer,
    // and the argument is deleted rather than softened.)
    //
    // The capture may only ever move EARLIER. An older baseline can cause an
    // extra close, never a missed one, so earlier is strictly fail-CLOSED and
    // any refactor that pushes it later — into the closure, into the loop —
    // is a regression regardless of how much tidier it reads. The
    // no-sticky-kill property holds at either end, because a reconnect takes
    // its own fresh baseline
    // (`connect_baseline_is_the_bus_handle_and_the_live_epoch`).
    //
    // WHAT is captured is `connect_baseline`'s executed contract, and the
    // extension arm is the same pair taken one hop earlier; WHERE it is read
    // is all these lines decide, and all the structural pin has to check.
    let (epoch, epoch0) = match baseline {
        Some(Extension(m)) => (m.epoch, m.epoch0),
        None => connect_baseline(&pc.bus, &tenant),
    };

    // #976 F2 — the credential's hard expiry, converted to the monotonic
    // clock the select loop can sleep on. Computed HERE for the same reason
    // as the baseline: `Instant::now()` inside the closure would silently
    // push the deadline out by the whole upgrade window. A deadline already
    // in the past saturates to ZERO and therefore fires on the loop's first
    // poll — the per-request CTE has already filtered such a PAT out, so this
    // arm only ever runs as the fail-closed backstop.
    let deadline: Option<tokio::time::Instant> = pat_deadline.map(|Extension(PatDeadline(exp))| {
        let dur = (exp - chrono::Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        tokio::time::Instant::now() + dur
    });

    ws.max_message_size(cap)
        .max_frame_size(cap)
        .on_upgrade(move |socket| {
            // Splitting HERE rather than inside `handle_socket` is what makes
            // the conn loop generic over its two halves, and therefore
            // drivable by an in-memory duplex in a lib test — see
            // `handle_socket`'s doc for why that mattered enough to change
            // the signature.
            let (sink, stream) = socket.split();
            handle_socket(
                sink, stream, ctx, pc, tenant, policy, epoch, epoch0, deadline,
            )
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
    // #976 — the credential's expiry on the monotonic clock, `None` for every
    // credential family that has no hard one (tenant bearers) or whose expiry
    // slides (user sessions). Resolved in `ws_handler` for the same reason as
    // the baseline: taking `Instant::now()` here would move the deadline by
    // however long the upgrade took.
    deadline: Option<tokio::time::Instant>,
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

    // #976 branch (d)'s timer. `tokio::select!` needs a future it can poll
    // every pass, so the no-deadline case gets a far-future sleep that the
    // `if has_deadline` guard disables — the guard, not the instant, is what
    // makes an unexpiring connection cost nothing.
    //
    // `sleep_until`, never `sleep`: the deadline is a point in time, not a
    // budget. A relative sleep restarted on each pass of the loop lets a
    // client that keeps sending frames postpone its own expiry indefinitely
    // (measured — it is the one mutant
    // `a_busy_socket_expires_on_time_because_the_timer_is_not_re_armed`
    // exists for). Pinning once outside the loop is then just economy, not
    // correctness.
    let has_deadline = deadline.is_some();
    let expiry = tokio::time::sleep_until(
        deadline.unwrap_or_else(|| tokio::time::Instant::now() + FAR_FUTURE),
    );
    tokio::pin!(expiry);

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
            // Branch (d): #976 F2 — the credential's own hard expiry. Fires at
            // most once (the arm breaks), and only for a credential family
            // that HAS a hard expiry, which today is the admin PAT alone.
            // Unlike an evict this is not an authorization event: nothing was
            // revoked, so the frames say CONN_EXPIRED and the client learns
            // that reconnecting needs a NEW token rather than the same one.
            // Both sends are best-effort for the same reason as
            // `check_epoch_evicted`'s — the point is to close.
            _ = &mut expiry, if has_deadline => {
                let _ = send_error(
                    &mut sink,
                    None,
                    codes::CONN_EXPIRED,
                    "credential expired; reconnect with a newly issued token",
                    None,
                )
                .await;
                let _ = sink
                    .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code: axum::extract::ws::close_code::POLICY, // 1008
                        reason: Utf8Bytes::from_static("expired"),
                    })))
                    .await;
                break;
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

    /// #955, EXECUTED — the eviction baseline itself, at the hop that
    /// PRODUCES it.
    ///
    /// Round 3 of the T2 review measured that `ws_handler` — where the handle
    /// and the baseline are actually taken — had zero executed coverage: the
    /// duplex tests below call `handle_socket` directly, so two one-line
    /// mutants in `ws_handler` (synthesize a private `Arc<AtomicU64>` instead
    /// of asking the bus; read the baseline inside the `on_upgrade` closure)
    /// turned #955 into a no-op with `cargo test --lib rooms::` fully green.
    /// The structural pin below is one half of the answer; this is the other:
    /// the two lines are now a named function whose CONTRACT is executed here,
    /// leaving the pin only to prove `ws_handler` calls it before the upgrade.
    ///
    /// Four properties, each a mutant this must kill:
    ///
    /// 1. the handle ALIASES the bus's atomic (`Arc::ptr_eq`) — a private
    ///    `Arc::new(AtomicU64::new(0))` never observes a bump, so no socket
    ///    ever closes;
    /// 2. a bump landing AFTER the capture is visible through it;
    /// 3. a baseline taken after an evict equals the bus's CURRENT epoch —
    ///    both directions: not stale (no immunity) and not a literal `0`
    ///    (which would kill every socket on a tenant that has ever been
    ///    evicted — the fail-CLOSED mutant a source-text pin cannot see);
    /// 4. it is tenant-scoped.
    #[tokio::test]
    async fn connect_baseline_is_the_bus_handle_and_the_live_epoch() {
        use crate::tenant::rooms::bus::RoomBus;
        const T: &str = "t_baseline";
        const OTHER: &str = "t_baseline_other";

        let bus = RoomBus::new();

        // 1 — the handle is the tenant's SHARED atomic, not a private copy.
        let (epoch, epoch0) = connect_baseline(&bus, T);
        assert!(
            Arc::ptr_eq(&epoch, &bus.tenant_epoch_handle(T)),
            "the baseline must alias the bus's own atomic: a locally synthesized one never \
             observes a bump, which makes #955 a total no-op",
        );
        assert_eq!(epoch0, 0, "a tenant never evicted starts at 0");

        // 2 — an evict AFTER the capture is visible through the captured handle.
        bus.evict_tenant(T);
        assert_eq!(
            epoch.load(SeqCst),
            epoch0 + 1,
            "a socket that captured its baseline before the evict must be able to SEE it",
        );

        // 3 — a baseline captured after an evict is the LIVE epoch.
        let (epoch2, epoch2_0) = connect_baseline(&bus, T);
        assert_eq!(
            epoch2_0,
            bus.tenant_epoch_handle(T).load(SeqCst),
            "the returned value must be the bus's current epoch",
        );
        assert_eq!(
            epoch2.load(SeqCst),
            epoch2_0,
            "no sticky kill: a reconnecting client must not start out already evicted",
        );
        assert_eq!(
            epoch2_0, 1,
            "the baseline must be READ, not hardcoded — `let epoch0 = 0;` would close every \
             socket on any tenant that has ever been evicted",
        );

        // 4 — tenant-scoped.
        let (other, other0) = connect_baseline(&bus, OTHER);
        assert_eq!(
            other0, 0,
            "one tenant's evict must not move another's epoch"
        );
        assert!(
            !Arc::ptr_eq(&other, &epoch),
            "each tenant must get its own atomic",
        );
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
    /// Round 4 turned the same lens on the OTHER hop. Rounds 1–3 hardened
    /// `handle_socket` — the consumer — and left the producer, `ws_handler`,
    /// behind a single needle (`tenant_epoch_handle(` appears once before
    /// `.on_upgrade(`) with NO executed coverage at all, because the duplex
    /// tests call `handle_socket` directly and `ws_handler` cannot be called
    /// from a test at all. Two measured one-line mutants there were green
    /// across `cargo test --lib rooms::`:
    ///
    /// 1. `let _unused = pc.bus.tenant_epoch_handle(&tenant);` followed by a
    ///    private `Arc::new(AtomicU64::new(0))` — the needle was satisfied by
    ///    the discarded call, and #955 was off in production.
    /// 2. moving the `epoch0` read INSIDE the `on_upgrade` closure — caught by
    ///    nothing whatsoever, and it re-opens the round-1 HIGH (baseline read
    ///    after the 101 write and the task hand-off, so an evict landing in
    ///    that measured-starvable window becomes the socket's baseline =
    ///    permanent immunity to that revocation). The old pin's own failure
    ///    message claimed to prevent exactly this — a verifier that lied.
    ///
    /// Neither is fixed by a better needle alone, so the two lines became
    /// [`connect_baseline`], whose contract is EXECUTED in
    /// `connect_baseline_is_the_bus_handle_and_the_live_epoch` (including the
    /// fail-CLOSED direction, `let epoch0 = 0;`, which no source-text pin can
    /// see). What is left here is the irreducibly un-executable part: that
    /// `ws_handler` calls it exactly once, before the upgrade, and hands the
    /// pair through untouched.
    ///
    /// Round 4 also measured the class that rounds 1–3 left open on the OTHER
    /// axis of checkpoint (a). Every earlier assertion pinned WHERE the
    /// checkpoint sits relative to the dispatch; none pinned that it runs
    /// UNCONDITIONALLY. So `if matches!(frame, Message::Text(_)) {
    /// <checkpoint> }`, written immediately above `match frame`, was green
    /// (`cargo test --lib rooms::ws` = 15 passed / 0 failed, this pin
    /// included) while quietly restoring the Text-only enumeration the round-2
    /// hoist exists to prevent — and the module doc asserts the categorical
    /// version of that property, so the doc would have been lying. Killed here
    /// by two assertions per checkpoint: (a) must be the LAST statement before
    /// `match frame` with a branch-free, await-free prologue, and (c) must be
    /// the FIRST statement in the keepalive arm.
    ///
    /// #976 (round 5) changed WHAT the `ws_handler` half pins, not why. The
    /// baseline now arrives in a request extension and `connect_baseline` is
    /// the fallback for a router mounted without the capture layer, so the
    /// single-statement needle became a three-part one: the `match` head, the
    /// fallback arm, and — new — the deadline conversion, each asserted to sit
    /// before `.on_upgrade`. The deadline joins for the round-4 reason, one
    /// step removed: `tokio::time::Instant::now()` evaluated inside the
    /// closure would move the expiry out by however long the upgrade took,
    /// which is the same fail-OPEN direction as reading the epoch in there,
    /// and equally invisible to every executed test (they call `handle_socket`
    /// directly and hand it an instant that is already correct).
    ///
    /// It reads the two functions' own bodies, so the needles in this test's
    /// source cannot satisfy it.
    #[test]
    fn epoch_checkpoints_sit_before_dispatch_and_on_the_keepalive_tick() {
        // Comments blanked FIRST — see the round-2 note above.
        let stripped = srcpin::code_only(include_str!("ws.rs"));
        let src = stripped.as_str();

        // ---- the baseline: in `ws_handler`, BEFORE the upgrade ----
        // #976 changed the contract this half pins. There are now TWO ways the
        // pair arrives — the `ws_baseline_capture` extension (production) and
        // the inline `connect_baseline` fallback (a router mounted without the
        // layer) — and BOTH must be resolved before `.on_upgrade`, because the
        // fail-open window this whole apparatus exists to bound ends wherever
        // the read happens, not wherever the extension was written. So the
        // `match` head and its fallback arm are pinned separately, and both
        // against the upgrade.
        const BASELINE: &str = "let (epoch, epoch0) = match baseline {";
        const FALLBACK: &str = "None => connect_baseline(&pc.bus, &tenant),";
        const DEADLINE: &str = "let deadline: Option<tokio::time::Instant> =";
        // The hand-off is past rustfmt's `fn_call_width`, so it is reflowed
        // across lines and the needle has to be the ARGUMENT LIST alone; the
        // call itself is counted separately. Same job either way — tying the
        // resolved pair to the loop that consumes it.
        const HANDOFF_CALL: &str = "handle_socket(";
        const HANDOFF: &str = "sink, stream, ctx, pc, tenant, policy, epoch, epoch0, deadline,";

        let h_start = src
            .find("pub async fn ws_handler(")
            .expect("ws_handler's signature changed — update this structural pin");
        let h_rest = &src[h_start..];
        let h_end = h_rest
            .find("\n}\n")
            .expect("could not find the end of ws_handler's body");
        let handler = &h_rest[..h_end];

        assert_eq!(
            handler.matches(BASELINE).count(),
            1,
            "ws_handler must resolve its eviction baseline EXACTLY once, as `{BASELINE}`. WHAT \
             the fallback arm returns is executed contract \
             (`connect_baseline_is_the_bus_handle_and_the_live_epoch`); this pin exists for the \
             one thing no test can reach — the call site itself, which cannot be exercised \
             because `WebSocketUpgrade` needs a real upgrading request",
        );
        assert_eq!(
            handler.matches(FALLBACK).count(),
            1,
            "the extension arm needs a fallback that is EXACTLY `{FALLBACK}`: a router mounted \
             without `ws_baseline_capture` (dev, tests) must still get today's inline capture. \
             The fail direction of a missing extension is pre-#976 behaviour, never `no baseline \
             at all` — a synthesized handle or a literal 0 would turn #955 off for every such \
             mount",
        );
        assert_eq!(
            handler.matches("connect_baseline(").count(),
            1,
            "exactly ONE baseline per connection: a second call would let the checkpoints \
             compare a handle against some other capture's value",
        );
        let baseline_at = handler.find(BASELINE).unwrap();
        let fallback_at = handler.find(FALLBACK).unwrap();
        let deadline_at = handler
            .find(DEADLINE)
            .expect("ws_handler must convert the PAT deadline as `{DEADLINE}`");
        let upgrade = handler
            .find(".on_upgrade(")
            .expect("ws_handler must still upgrade through .on_upgrade");
        for (what, at) in [
            ("the eviction baseline", baseline_at),
            ("the inline fallback capture", fallback_at),
            ("the deadline conversion", deadline_at),
        ] {
            assert!(
                at < upgrade,
                "{what} must be resolved BEFORE .on_upgrade: the closure runs only after the 101 \
                 is written and the task is scheduled, and this repo has measured that hand-off \
                 being starved. An evict landing in that window would be adopted as this \
                 socket's baseline (permanent immunity to that revocation), and an \
                 `Instant::now()` taken in there would push the credential deadline out by the \
                 whole upgrade",
            );
        }

        // The hand-off. Pinning the whole argument tuple is what ties the
        // resolved pair to the loop that consumes it: `handle_socket`'s own
        // body is already forbidden from taking a second handle, so if what
        // reaches it here is the pair the `match` above produced, the
        // comparison provably runs against the bus.
        assert_eq!(
            handler.matches(HANDOFF_CALL).count(),
            1,
            "ws_handler must start the conn loop exactly once",
        );
        assert_eq!(
            handler.matches(HANDOFF).count(),
            1,
            "ws_handler must hand the resolved pair straight to the conn loop — \
             `{HANDOFF_CALL}` over `{HANDOFF}`. Anything else (a fresh atomic, a literal 0, a \
             re-read, a deadline recomputed in the closure) decouples the loop from what this \
             handler resolved while every other assertion here still passes",
        );
        assert!(
            handler.find(HANDOFF).unwrap() > upgrade,
            "the hand-off belongs inside the on_upgrade closure",
        );

        // Exactly six mentions of `epoch` in the whole (comment-stripped)
        // handler: two in BASELINE's head, two in the extension arm that
        // destructures the meta, two in HANDOFF. Anything else that touches
        // either name — `let epoch0 = 0;` (the fail-CLOSED mutant: every
        // socket on a previously-evicted tenant dies at once), a second
        // binding, an arithmetic tweak — is a mutant, and counting is the only
        // form of this assertion that does not have to enumerate them.
        assert_eq!(
            handler.matches("epoch").count(),
            6,
            "ws_handler must mention `epoch`/`epoch0` in EXACTLY the three pinned statements \
             (2 + 2 + 2). A further mention means something else is producing, rebinding or \
             adjusting this connection's baseline:\n{handler}",
        );
        for needle in ["AtomicU64", "Arc::new(", "tenant_epoch_handle(", ".load("] {
            assert_eq!(
                handler.matches(needle).count(),
                0,
                "ws_handler must not contain `{needle}`: the baseline comes from \
                 `connect_baseline` and nothing else. Synthesizing the atomic here, or \
                 re-reading it, is exactly the mutant that left `cargo test --lib rooms::` \
                 green with #955 disabled in production",
            );
        }

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

        const CHECKPOINT: &str = "if check_epoch_evicted(&mut sink, &epoch, epoch0).await \
                                  { break; }";

        // Checkpoint (a): EVERY inbound frame, above the dispatch `match` —
        // not inside the Text arm, so a future op on a Binary frame cannot
        // land outside the checked set.
        const ARM_A: &str = "maybe_frame = stream.next() => {";
        let a_arm = body
            .find(ARM_A)
            .expect("branch (a) moved — update this structural pin");
        let dispatch = a_arm
            + body[a_arm..]
                .find("match frame {")
                .expect("branch (a) must still dispatch the frame through `match frame`");
        let a_region = &body[a_arm..dispatch];
        assert_eq!(
            a_region.matches(CHECKPOINT).count(),
            1,
            "checkpoint (a) must be exactly `{CHECKPOINT}`, ABOVE `match frame`. Below it (or \
             inside one arm) an evicted socket lands one more op on the way out — one more \
             subscribe, re-creating the channel evict just dropped, or one more publish plus its \
             audit row — and arms the check does not cover are invisible to every other \
             assertion here. Without the `break` the error + Close still go out first, so even \
             the wire assertions pass while the op runs behind them. (If rustfmt ever reflows \
             this statement, re-verify the placement by hand and update the needle — do not \
             relax it.)",
        );

        // Round 4 MEASURED that the count assertion above is satisfied by
        // `if matches!(frame, Message::Text(_)) { <checkpoint> }` written
        // immediately above `match frame`: `cargo test --lib rooms::ws` = 15
        // passed / 0 failed, this pin included. That mutant shrinks the
        // covered set back to Text-only — precisely the ENUMERATION that
        // hoisting the checkpoint out of the `match` exists to prevent, and
        // which this file's module doc asserts categorically ("every frame
        // that reaches the server is checked"). Being ABOVE the dispatch is
        // therefore not enough; the checkpoint must also be UNCONDITIONAL,
        // and the two halves of that are pinned separately below.
        let at = a_region.find(CHECKPOINT).unwrap();
        let trailing = &a_region[at + CHECKPOINT.len()..];
        assert!(
            trailing.trim().is_empty(),
            "checkpoint (a) must be the LAST statement before `match frame` — anything between \
             them means the checkpoint sits inside something (a wrapper's closing brace is \
             exactly what a conditional mutant leaves here). Found:\n{trailing}",
        );
        // …and nothing above it may branch, skip, or await: an `if` wrapping
        // the checkpoint, or an early `continue` that hands one frame kind
        // past it, both leave the checkpoint textually last while some frames
        // never reach it. The ONE statement allowed here is
        // `let frame = match maybe_frame { … };`, which classifies the stream
        // item and cannot skip the checkpoint (its two non-frame arms `break`).
        let prologue = &a_region[..at];
        for (needle, allowed) in [
            ("if ", 0usize),
            ("else", 0),
            ("continue", 0),
            (".await", 0),
            ("match ", 1),
        ] {
            assert_eq!(
                prologue.matches(needle).count(),
                allowed,
                "branch (a)'s prologue must contain exactly {allowed} × `{needle}`: the only \
                 statement allowed above checkpoint (a) is `let frame = match maybe_frame {{ … \
                 }};`. A branch or an early exit there makes the checked set an enumeration \
                 again, with every other assertion in this pin still green. Found:\n{prologue}",
            );
        }

        // Checkpoint (c): the keepalive tick, BEFORE the Ping — this is what
        // bounds an IDLE socket's post-evict life to one keepalive period.
        const ARM_C: &str = "_ = ka.tick() => {";
        let ka_arm = body
            .find(ARM_C)
            .expect("the keepalive arm moved — update this structural pin");
        let ping = ka_arm
            + body[ka_arm..]
                .find("Message::Ping(")
                .expect("the keepalive arm must still send a Ping");
        let c_region = &body[ka_arm..ping];
        assert_eq!(
            c_region.matches(CHECKPOINT).count(),
            1,
            "checkpoint (c) must be exactly `{CHECKPOINT}`, before the Ping. Without it an \
             evicted IDLE socket lives until the client disconnects, which is unbounded; \
             without the `break` it is told it is evicted, then pinged, then kept",
        );
        // Same conditional-wrapper class as (a), mirrored: on the tick side
        // the checkpoint is FIRST rather than last, so what must be empty is
        // everything between the arm's opening brace and the checkpoint.
        let c_prologue = &c_region[ARM_C.len()..c_region.find(CHECKPOINT).unwrap()];
        assert!(
            c_prologue.trim().is_empty(),
            "checkpoint (c) must be the FIRST statement in the keepalive arm — anything before \
             it can wrap or skip it, and an evicted IDLE socket then lives until the client \
             disconnects. Found:\n{c_prologue}",
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
    /// | checkpoint (a) wrapped in `if matches!(frame, Message::Text(_))` | red¹ | green |
    /// | an `if …{ continue; }` slipped above checkpoint (a) | red¹ | green |
    ///
    /// ¹ red only since the round-4 hardening; both were green against the
    /// placement-only pin.
    ///
    /// The last three rows are the honest limit of the executed tests and the
    /// reason the pin stays: those mutants do not change what happens to a
    /// Text frame, only which OTHER frames are covered, so only a source-text
    /// assertion can see them.
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
            None,
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
                None,
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

    /// #976 branch (d) — drive the REAL conn loop with NO inbound traffic and
    /// return what it wrote, or `None` when it was still running after
    /// `budget`.
    ///
    /// The inbound sender is held for the whole call on purpose: dropping it
    /// would end the stream and exit through branch (a), proving nothing about
    /// the timer branches. `None` is a first-class outcome rather than a
    /// failure — the control arm ("a connection with no deadline is never
    /// closed by branch (d)") can ONLY be stated as "it was still running",
    /// and without it a branch that closed EVERY socket would read as green.
    async fn drive_idle(
        deadline: Option<tokio::time::Instant>,
        evict: bool,
        keepalive_secs: u64,
        budget: Duration,
    ) -> Option<Vec<Message>> {
        const TENANT: &str = "t_deadline_idle";

        let bus = crate::tenant::rooms::bus::RoomBus::new();
        let epoch = bus.tenant_epoch_handle(TENANT);
        let epoch0 = epoch.load(SeqCst);

        let mut cfg = RoomsConfig::test_defaults();
        cfg.keepalive_secs = keepalive_secs;
        let pc = PublishCtx {
            bus: bus.clone(),
            bucket: cfg.bucket(),
            cfg,
        };

        let (_frames_in, stream) =
            futures::channel::mpsc::unbounded::<Result<Message, axum::Error>>();
        let (sink, out) = futures::channel::mpsc::unbounded::<Message>();

        if evict {
            bus.evict_tenant(TENANT);
        }

        tokio::time::timeout(
            budget,
            handle_socket(
                sink,
                stream,
                AuthCtx::Anon,
                pc,
                TENANT.to_string(),
                TenantPublishPolicy::default(),
                epoch,
                epoch0,
                deadline,
            ),
        )
        .await
        .ok()?;

        Some(out.collect::<Vec<_>>().await)
    }

    /// Both timer branches close the same way — a typed error frame first,
    /// then 1008 — so the wire assertion is shared rather than written twice
    /// with two chances to drift.
    fn assert_typed_close(frames: &[Message], expected_code: &str) {
        assert_eq!(
            frames.len(),
            2,
            "expected exactly the typed error and the close: {frames:?}"
        );
        let Message::Text(t) = &frames[0] else {
            panic!("expected the typed error frame first, got {:?}", frames[0]);
        };
        let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
        assert_eq!(v["kind"], "error", "{v}");
        assert_eq!(
            v["code"], expected_code,
            "a client distinguishes `your credential ran out` from `you were revoked` by this \
             code alone — reconnecting fixes exactly one of them: {v}",
        );
        match &frames[1] {
            Message::Close(Some(cf)) => assert_eq!(
                cf.code,
                axum::extract::ws::close_code::POLICY,
                "must close 1008 Policy Violation, not a normal close"
            ),
            other => panic!("expected Close(1008) after the error, got {other:?}"),
        }
    }

    /// #976 F2, EXECUTED — an idle socket whose credential expires is closed
    /// by branch (d), not left running until the holder disconnects.
    ///
    /// This is the whole point of F2: a PAT's `expires_at` used to gate new
    /// REQUESTS only, so a socket opened one second before expiry kept
    /// `AuthCtx::Service` for as long as the client cared to hold it.
    ///
    /// The keepalive stays at the 30 s default so branch (c) cannot fire and
    /// take credit for the close, and the socket is never evicted, so the
    /// epoch checkpoints have nothing to report either — the only thing that
    /// can produce these two frames is the deadline.
    #[tokio::test]
    async fn pat_deadline_closes_the_idle_socket_with_conn_expired_1008() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let frames = drive_idle(Some(deadline), false, 30, Duration::from_secs(10))
            .await
            .expect(
                "branch (d) missing or non-breaking: a socket whose credential had expired was \
                 still running long after the deadline, which is exactly the residual #976 F2 \
                 exists to close",
            );
        assert_typed_close(&frames, codes::CONN_EXPIRED);
    }

    /// #976 F2 — an ALREADY-PAST deadline fires on the first poll.
    ///
    /// The per-request CTE already refuses an expired PAT, so this arm should
    /// be unreachable in production; it is pinned because the conversion in
    /// `ws_handler` saturates a negative duration to ZERO, and the plausible
    /// alternative (`unwrap_or(FAR_FUTURE)`, or letting the subtraction
    /// underflow into a huge positive) would turn the backstop into a socket
    /// that never expires at all — fail-OPEN, and silent.
    #[tokio::test]
    async fn already_past_deadline_closes_immediately() {
        let deadline = tokio::time::Instant::now() - Duration::from_secs(1);
        let frames = drive_idle(Some(deadline), false, 30, Duration::from_secs(10))
            .await
            .expect("a deadline in the past must fire on the loop's first poll");
        assert_typed_close(&frames, codes::CONN_EXPIRED);
    }

    /// The control arm for branch (d). Without it, an unguarded timer — or one
    /// armed at `Instant::now()` for every connection — would satisfy the two
    /// tests above while closing every healthy socket on the host.
    #[tokio::test]
    async fn a_connection_with_no_deadline_is_never_closed_by_branch_d() {
        assert!(
            drive_idle(None, false, 30, Duration::from_millis(400))
                .await
                .is_none(),
            "a connection whose credential has no hard expiry (tenant bearer, sliding user \
             session) must outlive branch (d) entirely",
        );
    }

    /// #976 — the two timer branches coexist, and whichever comes FIRST closes
    /// the socket.
    ///
    /// This direction is the one worth pinning: the deadline is far away and
    /// the evict already happened, so an implementation that let branch (d)'s
    /// far-future sleep starve branch (c) — or that returned `CONN_EXPIRED`
    /// for an eviction — is caught. The opposite direction is
    /// `pat_deadline_closes_the_idle_socket_with_conn_expired_1008` above,
    /// which runs with no evict at all.
    #[tokio::test]
    async fn an_evict_still_wins_when_it_lands_before_the_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3600);
        let frames = drive_idle(Some(deadline), true, 1, Duration::from_secs(10))
            .await
            .expect("the keepalive checkpoint must still close an evicted socket");
        assert_typed_close(&frames, codes::CONN_EVICTED);
    }

    /// #976 — the deadline is ABSOLUTE, so a BUSY socket expires on time too.
    ///
    /// Every other branch-(d) test above drives an idle socket, and an idle
    /// socket cannot tell an absolute deadline from a countdown that traffic
    /// restarts. This one feeds a frame every 5 ms for as long as the loop
    /// will take them, so a timer that measures "80 ms since the last pass"
    /// never arrives at all — unlimited life for a dead credential, with
    /// every other test in this file green.
    ///
    /// Measured on 2026-08-17, one mutant at a time, `cargo test --lib
    /// rooms::ws`:
    ///
    /// | mutant | this test |
    /// |---|---|
    /// | `sleep(ttl)` re-created per loop pass | red (times out at 10 s) |
    /// | `sleep_until(deadline)` re-created per loop pass | green |
    ///
    /// The second row is why the doc says ABSOLUTE rather than "pinned
    /// outside the loop": re-creating `sleep_until` with the same instant
    /// costs an allocation and changes nothing, so this test does not — and
    /// should not be described as if it does — pin the timer's placement.
    /// What it pins is that the instant is not recomputed from `now()`.
    #[tokio::test]
    async fn a_busy_socket_expires_on_time_because_the_timer_is_not_re_armed() {
        const TENANT: &str = "t_deadline_busy";

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
        let (sink, out) = futures::channel::mpsc::unbounded::<Message>();

        // Feeds until the conn loop drops its end of the stream, so the
        // re-arming mutant keeps being handed a reason to postpone.
        let feeder = tokio::spawn(async move {
            while frames_in
                .unbounded_send(Ok(Message::Text(Utf8Bytes::from_static(
                    r#"{"op":"ping","ref":"r1"}"#,
                ))))
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let deadline = tokio::time::Instant::now() + Duration::from_millis(80);
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
                Some(deadline),
            ),
        )
        .await
        .expect(
            "a socket under continuous traffic was never closed by its deadline — the expiry \
             timer is being re-armed per pass, so an active client outlives its credential \
             indefinitely",
        );
        feeder.abort();

        let frames = out.collect::<Vec<_>>().await;
        let tail = &frames[frames.len().saturating_sub(2)..];
        assert_typed_close(tail, codes::CONN_EXPIRED);
        assert!(
            frames.len() > 2,
            "the socket was supposed to be BUSY: expected pongs before the close, got {frames:?}",
        );
    }
}

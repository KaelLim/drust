use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use tokio::sync::broadcast;

/// Mirror of [`crate::tenant::events::EventBus`] for ad-hoc broadcast
/// rooms. Per-tenant in-memory channels keyed by `(tenant_id, room)`.
///
/// Nested `DashMap<Arc<str>, DashMap<Arc<str>, _>>` (v1.32.1 D2): the
/// `publish()` hot path looks up via `&str` directly so no `String`
/// alloc happens per event; only first-subscribe on a `(tenant, room)`
/// pair pays the `Arc<str>` clone (amortized across every subsequent
/// subscriber + every publish on that pair).
#[derive(Clone, Default)]
pub struct RoomBus {
    channels: Arc<DashMap<Arc<str>, DashMap<Arc<str>, broadcast::Sender<RoomMessage>>>>,
    /// #955 — per-tenant eviction epoch. `evict_tenant` bumps it BEFORE
    /// dropping channels; WS conns capture the handle + value at connect
    /// and lazily compare per inbound frame + keepalive tick. Entries are
    /// NEVER reclaimed (`sweep_empty` must not touch this map): a
    /// reclaimed and rebuilt entry would hand old sockets a stale `Arc`
    /// that never sees later bumps — pinned by
    /// `sweep_empty_must_not_reclaim_epoch_entries`.
    ///
    /// Cost and bound, stated honestly: an entry is on the order of
    /// **~100 bytes** (an `Arc<str>` key — fat pointer plus its heap
    /// allocation and refcounts — an `Arc<AtomicU64>` with its own
    /// allocation, and the DashMap slot), and the map is monotonic in the
    /// number of DISTINCT tenant ids **seen since process start**,
    /// including ids that have since been deleted — only a restart clears
    /// it. Both `tenant_epoch_handle` AND `evict_tenant` are INSERTING
    /// calls on this key space, so every caller must validate/authorize
    /// the tenant id first: `mgmt::admin_rooms` (v1.31.3 F14) rejects
    /// malformed ids at the door for exactly this reason, and
    /// `tenant_ownership_layer` 404s unknown or soft-deleted ids before
    /// the admin evict handler runs. If tenant churn ever makes the
    /// residue matter, reclaim on tenant HARD-delete — never from the
    /// periodic sweeper. (Precedent: #951 per-tenant webhook semaphore map.)
    epochs: Arc<DashMap<Arc<str>, Arc<AtomicU64>>>,
}

/// Carried by the broadcast channel. `payload` is `Arc`-wrapped so
/// fan-out to N subscribers clones the pointer, not the JSON value.
///
/// `frame_bytes` (v1.32.2 D8): the pre-serialized full
/// `ServerMessage::Message` envelope. Built once by [`publish_into_bus`]
/// (or test helpers) so the WS Message-fanout path just forwards bytes
/// verbatim — no per-subscriber re-serialize, no per-subscriber Value
/// deep-clone. `Bytes` is Arc-backed: `.clone()` is a pointer bump.
/// Lagged error envelopes are still built per-subscriber-per-room so
/// `frame_bytes` is only consulted in the Message branch.
#[derive(Debug, Clone)]
pub struct RoomMessage {
    pub payload: Arc<serde_json::Value>,
    pub ts_ms: i64,
    pub frame_bytes: bytes::Bytes,
}

/// `tokio::sync::broadcast` buffer — slow subscriber lagging > BUFFER
/// messages gets `RecvError::Lagged`. Matches `EventBus` exactly.
const BUFFER: usize = 256;

impl RoomBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Send `msg` to every current subscriber of `(tenant, room)`.
    /// Returns the receiver count at send time (== `delivered_to`).
    /// 0 receivers ⇒ noop. Send errors are mapped to 0 (channel closed).
    pub fn publish(&self, tenant: &str, room: &str, msg: RoomMessage) -> usize {
        if let Some(outer) = self.channels.get(tenant)
            && let Some(tx) = outer.value().get(room)
        {
            return tx.value().send(msg).unwrap_or(0);
        }
        0
    }

    pub fn subscribe(&self, tenant: &str, room: &str) -> broadcast::Receiver<RoomMessage> {
        // v1.31.2 F7 (mirrored at v1.32.0 A4 for EventBus) — hold the
        // shard write lock across subscribe() so sweep_empty's retain
        // can't observe a 0-receiver Sender between insert and Receiver
        // registration. Nested map: both the outer entry guard AND the
        // inner entry guard are held across `.subscribe()` (v1.32.1 D2).
        // DashMap::entry returns a RefMut holding the shard's RwLock
        // write half; both guards drop at end-of-expression. sweep_empty
        // walks the inner map under the same shard lock per shard via
        // .retain, so they serialise correctly.
        let outer_entry = self.channels.entry(Arc::<str>::from(tenant)).or_default();
        let inner_entry = outer_entry
            .value()
            .entry(Arc::<str>::from(room))
            .or_insert_with(|| broadcast::channel(BUFFER).0);
        inner_entry.value().subscribe()
    }

    /// Snapshot of current subscriber count. Used for `ROOM_FULL` gate.
    /// 0 if the channel doesn't exist yet.
    pub fn current_subscriber_count(&self, tenant: &str, room: &str) -> usize {
        self.channels
            .get(tenant)
            .and_then(|outer| {
                outer
                    .value()
                    .get(room)
                    .map(|tx| tx.value().receiver_count())
            })
            .unwrap_or(0)
    }

    /// #955 — shared handle to this tenant's eviction epoch. Captured once
    /// at WS connect; every later check is a bare atomic load, zero map hits.
    pub fn tenant_epoch_handle(&self, tenant: &str) -> Arc<AtomicU64> {
        // Read fast path first. `entry().or_default()` takes the DashMap
        // shard's WRITE lock unconditionally — including the overwhelmingly
        // common case where the entry already exists — so concurrent WS
        // connects for one tenant would serialise on one shard just to clone
        // an `Arc` they only need to read (and would pay an `Arc<str>` key
        // allocation each time). `get` takes the read half instead.
        //
        // Both arms return a clone of the SAME `Arc`, which is the whole
        // contract: `handle_taken_after_evict_reads_current_epoch_no_false_eviction`
        // pins it with `Arc::ptr_eq`, so a fast path that ever handed back a
        // second atomic would fail there.
        if let Some(existing) = self.epochs.get(tenant) {
            return existing.value().clone();
        }
        self.epochs
            .entry(Arc::<str>::from(tenant))
            .or_default()
            .clone()
    }

    /// #955 — bump this tenant's eviction epoch. Private on purpose: the
    /// ONLY caller is [`RoomBus::evict_tenant`], which must call it BEFORE
    /// its teardown (spec §隔離與資安不變量 item 3, pinned by
    /// `evict_tenant_bumps_epoch_before_dropping_channels`). Exposing it
    /// would let a caller close every socket on a tenant without dropping
    /// the channels, which is not a state this design has a meaning for.
    fn bump_epoch(&self, tenant: &str) {
        self.epochs
            .entry(Arc::<str>::from(tenant))
            .or_default()
            .fetch_add(1, SeqCst);
    }

    /// Drop every channel for `tenant`. Existing subscribers get
    /// `RecvError::Closed` on next recv.
    ///
    /// **Called from eight production sites.** Re-derive the list rather than
    /// trusting it — it has drifted three times already: it once named a
    /// `DELETE …/realtime/rooms` route that does not exist; it said "five"
    /// for one commit after #955 T3 added the publish-policy faces; and that
    /// same T3 commit, the one that wrote this warning, left FOUR sibling
    /// docs still cross-referencing the old "5" — `McpRegistry::with_bus`,
    /// `tests/helpers.rs::test_mcp_http`, and two in `tests/rooms_ws.rs`.
    ///
    /// So the rule is now structural rather than diligent: **this list is the
    /// only place allowed to state a count.** Those four siblings were
    /// rewritten to name the tools they care about and link here; a sibling
    /// that needs the number links to this doc instead of copying it, because
    /// a copied count is a count that drifts.
    ///
    /// The recipe that returns exactly these eight and nothing else, verified
    /// 2026-08-14, is `grep -rn 'bus_rooms\.evict_tenant(' src/` — every
    /// production caller reaches this method through a field or parameter so
    /// named, while the in-file tests bind the bus as `bus`. Do NOT grep the
    /// bare method name: [`crate::tenant::events::EventBus`] has an
    /// `evict_tenant` of its own (the SSE side), and two of these sites evict
    /// both buses on adjacent lines.
    ///
    /// - [`crate::tenant::router::TenantAuthState::revoke_user_realtime`],
    ///   which the six #952 REST revoke sites all funnel through (logout,
    ///   logout-all, password change, OAuth account-claim, admin
    ///   revoke-sessions, admin delete-user);
    /// - the two MCP tools `delete_user` / `revoke_user_sessions`;
    /// - the MCP tool `set_publish_policy`
    ///   (`mcp::tools::owner_field::set_publish_policy`) — same
    ///   evicts-only-on-a-real-change rule as its REST twin below;
    /// - token reroll (`mgmt::tokens`);
    /// - tenant soft-delete (`mgmt::tenants::crud`);
    /// - the publish-policy PATCH
    ///   (`mgmt::tenants::crud::patch_publish_policy`) — evicts only when the
    ///   effective `(user, anon)` pair MOVES; a no-op PATCH does not, so an
    ///   admin page re-submitting unchanged checkboxes cannot thunder-herd
    ///   the tenant's subscribers;
    /// - admin `POST /admin/tenants/{id}/realtime/evict-all`
    ///   (`mgmt::admin_rooms::evict_all_rooms_handler`).
    ///
    /// The two publish-policy faces are one station with two doors, and both
    /// must evict: a live WS connection captures its `TenantPublishPolicy`
    /// once at upgrade, so whichever door turns a flag off has to close the
    /// sockets still holding the old one.
    ///
    /// The sibling admin route `POST
    /// /admin/tenants/{id}/realtime/rooms/{room}/evict` calls
    /// [`RoomBus::evict_room`], which by design does NOT bump — per-room
    /// eviction is a data-plane op, not an identity event.
    ///
    /// #955 — also bumps the tenant's eviction epoch, so live WS sockets
    /// close themselves (`CONN_EVICTED` + Close 1008) at their next
    /// inbound frame or keepalive tick.
    ///
    /// **Reconnect cost, measured against the code rather than asserted.**
    /// This turns "drop the channels, the client silently re-subscribes on
    /// its live socket" into "every WS socket on the tenant closes", so every
    /// evict now produces a reconnect herd. The design note originally
    /// claimed a per-token rate limiter "absorbs" it; the limiter is what
    /// REJECTS it. Grounded:
    ///
    /// - `bearer_auth_layer` probes `state.limiter.try_acquire(&hash)`
    ///   (`src/tenant/router.rs`) BEFORE the auth-cache consult — the in-tree
    ///   comment says so explicitly — so an auth-cache hit cannot skip it.
    /// - The bucket is keyed on the token HASH, i.e. every browser client
    ///   sharing one anon token shares ONE bucket, and that same bucket
    ///   carries the token's ordinary REST traffic.
    /// - `RateLimiter` is a sliding window (`src/safety/rate_limit.rs`):
    ///   `DRUST_RATE_LIMIT_PER_TOKEN` (default 60) hits per
    ///   `DRUST_RATE_LIMIT_WINDOW_SECS` (default 10 s) ⇒ **6 reconnects/s per
    ///   token**.
    ///
    /// So, with defaults: **≤ 60 sockets on one token reconnect untouched;
    /// above that the herd drains at ~6/s** (N sockets ⇒ ~N/6 s), the excess
    /// getting 429 + `Retry-After`, and that token's REST calls queue behind
    /// the same budget for the drain. A rejected attempt is NOT pushed into
    /// the window (`try_acquire` returns before `push_back`), so retries do
    /// not extend the throttle — but a client without backoff will still spin
    /// on 429s. An operator expecting more than `DRUST_RATE_LIMIT_PER_TOKEN`
    /// concurrent sockets on a SHARED token should raise that knob or issue
    /// per-user tokens.
    ///
    /// The security direction is unaffected: a throttled reconnect fails
    /// CLOSED (no data), and the eviction's purpose — the revoked holder's
    /// socket is gone — is done by the close itself. The three mitigations
    /// weighed and rejected: jittering the close delays revocation (at the
    /// FRAME checkpoint it would let an evicted socket keep subscribing and
    /// publishing during the jitter — the very hole #955 closes); exempting
    /// the WS upgrade from the bucket removes the DoS gate from the cheapest
    /// surface to open; narrowing the blast radius to one user needs a
    /// per-user room index, explicitly out of scope (spec §不做的事).
    pub fn evict_tenant(&self, tenant: &str) {
        // ORDER LOAD-BEARING (spec §隔離與資安不變量 3) — bump BEFORE the
        // teardown, pinned structurally by
        // `evict_tenant_bumps_epoch_before_dropping_channels` because no
        // behavioural test can see the difference.
        //
        // What the ordering actually buys is narrow, so state it exactly:
        // the window in which a concurrent checkpoint can still read a
        // STALE epoch ends at the bump, i.e. before the channel teardown
        // rather than after it. It does NOT close the re-subscribe race —
        // a socket whose epoch load happened before the bump still
        // proceeds, and its `subscribe()` can land after `channels.remove`,
        // creating a fresh channel that lives until that socket's NEXT
        // checkpoint (≤1 keepalive). That residual is the accepted
        // micro-race, same family as spec §隔離與資安不變量 item 4.
        self.bump_epoch(tenant);
        self.channels.remove(tenant);
    }

    /// Drop one `(tenant, room)` channel. The empty inner DashMap is
    /// left in place — saves churn on re-subscribe, and `sweep_empty`
    /// will reclaim it if it stays empty long enough to matter.
    pub fn evict_room(&self, tenant: &str, room: &str) -> bool {
        if let Some(outer) = self.channels.get(tenant) {
            return outer.value().remove(room).is_some();
        }
        false
    }

    /// Channels currently allocated (tests + admin overview card).
    /// Sums every inner map's len — empty inner maps contribute 0, so
    /// post-evict_room residue is invisible to callers.
    pub fn channel_count(&self) -> usize {
        self.channels.iter().map(|kv| kv.value().len()).sum()
    }

    /// Channels keyed on `tenant` (admin overview per-tenant card).
    pub fn tenant_channel_count(&self, tenant: &str) -> usize {
        self.channels
            .get(tenant)
            .map(|outer| outer.value().len())
            .unwrap_or(0)
    }

    /// Sum of subscriber counts across this tenant's channels.
    pub fn tenant_subscriber_count(&self, tenant: &str) -> usize {
        self.channels
            .get(tenant)
            .map(|outer| {
                outer
                    .value()
                    .iter()
                    .map(|kv| kv.value().receiver_count())
                    .sum::<usize>()
            })
            .unwrap_or(0)
    }

    /// Sweeper helper — retain only channels with live receivers.
    /// Called by the 5-minute sweeper task in `main.rs`. Returns the
    /// number of channels removed. Also reclaims fully-empty outer
    /// entries (tenants with no remaining rooms).
    ///
    /// Reclaims empty CHANNEL entries only — the #955 `epochs` map is
    /// deliberately untouched: a reclaimed-then-rebuilt epoch entry would
    /// leave old sockets holding a stale `Arc` that never sees later bumps.
    pub fn sweep_empty(&self) -> usize {
        let mut removed = 0usize;
        for outer in self.channels.iter() {
            let before = outer.value().len();
            outer.value().retain(|_, tx| tx.receiver_count() > 0);
            removed += before - outer.value().len();
        }
        // Reclaim outer entries whose inner map is now empty so
        // tenant_channel_count etc. don't keep returning the empty husk.
        self.channels.retain(|_, inner| !inner.is_empty());
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn msg(s: &str) -> RoomMessage {
        RoomMessage {
            payload: Arc::new(serde_json::json!({ "body": s })),
            ts_ms: 0,
            // bus unit tests don't exercise the WS Message fanout
            // (which is what consumes frame_bytes); empty is fine.
            frame_bytes: bytes::Bytes::new(),
        }
    }

    #[tokio::test]
    async fn publish_to_empty_room_returns_zero_and_is_not_error() {
        let bus = RoomBus::new();
        let n = bus.publish("t1", "ghost", msg("hi"));
        assert_eq!(n, 0);
        assert_eq!(bus.channel_count(), 0, "publish does not create channel");
    }

    #[tokio::test]
    async fn subscribe_creates_channel_and_receives_subsequent_publish() {
        let bus = RoomBus::new();
        let mut rx = bus.subscribe("t1", "chat");
        assert_eq!(bus.channel_count(), 1);
        let n = bus.publish("t1", "chat", msg("hello"));
        assert_eq!(n, 1);
        let received = rx.recv().await.unwrap();
        assert_eq!(received.payload["body"], "hello");
    }

    #[tokio::test]
    async fn evict_tenant_drops_only_that_tenant() {
        let bus = RoomBus::new();
        let _keep = bus.subscribe("t1", "chat");
        let _drop1 = bus.subscribe("t2", "chat");
        let _drop2 = bus.subscribe("t2", "other");
        assert_eq!(bus.channel_count(), 3);
        bus.evict_tenant("t2");
        assert_eq!(bus.channel_count(), 1);
        assert_eq!(bus.tenant_channel_count("t1"), 1);
        assert_eq!(bus.tenant_channel_count("t2"), 0);
    }

    #[tokio::test]
    async fn evict_room_drops_one_pair_only() {
        let bus = RoomBus::new();
        let _a = bus.subscribe("t1", "a");
        let _b = bus.subscribe("t1", "b");
        assert!(bus.evict_room("t1", "a"));
        assert_eq!(bus.channel_count(), 1);
        // Idempotent: second call no-ops.
        assert!(!bus.evict_room("t1", "a"));
    }

    #[tokio::test]
    async fn cross_tenant_isolation_holds_with_collision_on_room_name() {
        let bus = RoomBus::new();
        let mut rx_a = bus.subscribe("tenant-A", "chat");
        let mut rx_b = bus.subscribe("tenant-B", "chat");
        assert_eq!(bus.publish("tenant-A", "chat", msg("for-A")), 1);
        let got_a = rx_a.recv().await.unwrap();
        assert_eq!(got_a.payload["body"], "for-A");
        // tenant-B's receiver must NOT see the message.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), rx_b.recv())
                .await
                .is_err(),
            "tenant-B saw a cross-tenant publish",
        );
    }

    #[tokio::test]
    async fn current_subscriber_count_reflects_subscribe_and_drop() {
        let bus = RoomBus::new();
        assert_eq!(bus.current_subscriber_count("t1", "r"), 0);
        let rx1 = bus.subscribe("t1", "r");
        assert_eq!(bus.current_subscriber_count("t1", "r"), 1);
        let rx2 = bus.subscribe("t1", "r");
        assert_eq!(bus.current_subscriber_count("t1", "r"), 2);
        drop(rx1);
        assert_eq!(bus.current_subscriber_count("t1", "r"), 1);
        drop(rx2);
        assert_eq!(bus.current_subscriber_count("t1", "r"), 0);
    }

    #[tokio::test]
    async fn sweep_empty_removes_only_zero_receiver_channels() {
        let bus = RoomBus::new();
        let _keep = bus.subscribe("t1", "keep");
        {
            let _drop = bus.subscribe("t1", "drop");
        } // _drop dropped here, channel has 0 receivers
        assert_eq!(bus.channel_count(), 2);
        let removed = bus.sweep_empty();
        assert_eq!(removed, 1);
        assert_eq!(bus.channel_count(), 1);
    }

    /// #955 — a handle captured BEFORE the evict must observe the bump.
    /// This is the whole mechanism: the WS conn holds an `Arc` taken at
    /// connect and only ever does an atomic load on it.
    #[tokio::test]
    async fn evict_tenant_bumps_epoch_visible_through_shared_handle() {
        let bus = RoomBus::new();
        let h = bus.tenant_epoch_handle("t1");
        let e0 = h.load(std::sync::atomic::Ordering::SeqCst);
        bus.evict_tenant("t1");
        assert_eq!(
            h.load(std::sync::atomic::Ordering::SeqCst),
            e0 + 1,
            "handle captured before evict must see the bump"
        );
    }

    /// #955 — a connection opened AFTER an evict takes the CURRENT value
    /// as its baseline, so it is not killed by an eviction that predates
    /// it (no sticky kill) — and it is not immune to the NEXT one either.
    ///
    /// The three legs are deliberate; `assert_eq!(baseline, baseline)`
    /// would pin nothing. Leg 1 catches a `tenant_epoch_handle` that
    /// hands back a fresh 0 instead of the live value. Legs 2/3 catch a
    /// handle-taking that MUTATES (e.g. a plausible-looking "reset the
    /// epoch for a fresh connection"): since `subscribe` is open to anon,
    /// ANY client connecting could otherwise reset the shared atomic and
    /// resurrect every already-revoked socket on that tenant.
    #[tokio::test]
    async fn handle_taken_after_evict_reads_current_epoch_no_false_eviction() {
        let bus = RoomBus::new();
        bus.evict_tenant("t1"); // bump with no prior handle
        let h = bus.tenant_epoch_handle("t1");
        let baseline = h.load(SeqCst);
        // Leg 1 — a NEW connection's baseline is the CURRENT epoch.
        assert_eq!(
            baseline, 1,
            "handle taken after an evict must read the CURRENT epoch, not a fresh 0"
        );
        // Leg 2 — taking a handle is a pure read shared by every caller.
        let h2 = bus.tenant_epoch_handle("t1");
        assert_eq!(
            h.load(SeqCst),
            1,
            "tenant_epoch_handle must never mutate the epoch"
        );
        assert!(
            Arc::ptr_eq(&h, &h2),
            "every handle for a tenant must alias ONE shared atomic"
        );
        // Leg 3 — the post-evict baseline is still live: the next evict moves it.
        bus.evict_tenant("t1");
        assert_eq!(
            h.load(SeqCst),
            2,
            "a handle taken after an evict must still observe later bumps"
        );
        assert_eq!(h2.load(SeqCst), 2, "both handles see the same bump");
    }

    /// #955 regression pin for the load-bearing doc claim on `epochs` and
    /// `sweep_empty`: the sweeper reclaims empty CHANNEL entries ONLY.
    ///
    /// Without this test the claim had zero coverage and adding
    /// `self.epochs.clear()` to `sweep_empty` left the whole suite green.
    /// In production the sweeper runs every 300 s (`main.rs`,
    /// `DRUST_BROADCAST_SWEEPER_INTERVAL_SECS`) but is DISABLED in
    /// `RoomsConfig::test_defaults` (`sweeper_interval_secs: 0`), so no
    /// integration test could ever see it either: every socket older than
    /// one sweep would hold an orphaned `Arc` that never observes a later
    /// bump, and EVERY revoke path (#952's six sites, token reroll,
    /// tenant delete, admin evict) would silently stop closing sockets.
    #[tokio::test]
    async fn sweep_empty_must_not_reclaim_epoch_entries() {
        let bus = RoomBus::new();
        let h = bus.tenant_epoch_handle("t1");
        bus.evict_tenant("t1");
        assert_eq!(h.load(SeqCst), 1);
        // Sweep with nothing to reclaim...
        assert_eq!(bus.sweep_empty(), 0);
        // ...and a sweep that DOES reclaim a dead channel on this tenant.
        {
            let _dead = bus.subscribe("t1", "gone");
        } // 0 receivers
        assert_eq!(bus.sweep_empty(), 1, "the dead channel should be swept");
        bus.evict_tenant("t1");
        assert_eq!(
            h.load(SeqCst),
            2,
            "sweep_empty must not reclaim epoch entries — the old handle would go stale"
        );
    }

    /// #955 (quality review round 3) — the bump-before-teardown ordering
    /// inside `evict_tenant` is a stated invariant (spec §隔離與資安不變量
    /// item 3) that NOTHING pinned: a reviewer swapped the two statements
    /// and both `cargo test --lib rooms::` and `cargo test --test g_rooms`
    /// stayed green, so a future refactor could silently invert it.
    ///
    /// A behavioural test is not available — the difference is a race
    /// window measured in instructions, and any test that tried to observe
    /// it would be a flake generator. So this pins the ordering
    /// STRUCTURALLY, at the only place it is decidable: the source text of
    /// `evict_tenant`'s own body. Same tool as
    /// `handler.rs::tool_count_matches_source_annotations`. It reads the
    /// FUNCTION BODY only, so the needles in this test's own source cannot
    /// satisfy it.
    ///
    /// T2 review round 2 MEASURED that reading raw source was not enough: with
    /// `// self.bump_epoch(tenant);` left in place above the teardown and the
    /// real call moved BELOW it, this test stayed green — `find` returns the
    /// first occurrence, and that was the comment. The invariant was inverted
    /// with every gate passing. Needles are matched against
    /// [`srcpin::code_only`] (comments blanked) for that reason; the same
    /// mutant shape had defeated the sibling pin in `ws.rs` twice.
    #[test]
    fn evict_tenant_bumps_epoch_before_dropping_channels() {
        const FN_HEAD: &str = "pub fn evict_tenant(&self, tenant: &str) {";
        let stripped = crate::tenant::rooms::srcpin::code_only(include_str!("bus.rs"));
        let src = stripped.as_str();
        let start = src
            .find(FN_HEAD)
            .expect("evict_tenant's signature changed — update this structural pin");
        let rest = &src[start..];
        let end = rest
            .find("\n    }\n")
            .expect("could not find the end of evict_tenant's body");
        let body = &rest[..end];

        let bump = body
            .find("self.bump_epoch(tenant);")
            .expect("evict_tenant must bump the epoch via the named bump_epoch helper");
        let teardown = body
            .find("self.channels.remove(tenant);")
            .expect("evict_tenant must still drop the tenant's channels");
        assert!(
            bump < teardown,
            "ORDER LOAD-BEARING (spec §隔離與資安不變量 3): evict_tenant must bump the \
             eviction epoch BEFORE dropping the channels, so the stale-epoch window ends \
             before the teardown rather than after it",
        );
    }

    /// #955 — tenant isolation: one tenant's evict must not move another
    /// tenant's epoch (would close unrelated sockets).
    #[tokio::test]
    async fn epoch_bump_is_tenant_scoped() {
        let bus = RoomBus::new();
        let ha = bus.tenant_epoch_handle("tenant-A");
        let hb = bus.tenant_epoch_handle("tenant-B");
        bus.evict_tenant("tenant-A");
        assert_eq!(ha.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            hb.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "cross-tenant bump leak"
        );
    }

    /// #955 — per-room eviction is a data-plane op (LAGGED recovery
    /// family), not an identity event: it must NOT close sockets.
    #[tokio::test]
    async fn evict_room_does_not_bump_epoch() {
        let bus = RoomBus::new();
        let _rx = bus.subscribe("t1", "a");
        let h = bus.tenant_epoch_handle("t1");
        bus.evict_room("t1", "a");
        assert_eq!(h.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// v1.31.2 F7 regression — subscribe must hold the shard write lock
    /// across the broadcast::Sender::subscribe() call so sweep_empty
    /// can't observe a 0-receiver Sender in the window between insert
    /// and Receiver registration.
    ///
    /// Pre-fix: subscribe called entry().or_insert_with(...).clone() then
    /// tx.subscribe() OUTSIDE the entry lock. sweep_empty.retain reads
    /// receiver_count() under the shard lock; if it ran in that gap,
    /// it removed the entry. The subscriber's Receiver was orphaned —
    /// a subsequent publish allocated a fresh Sender and the orphan
    /// Receiver never delivered.
    ///
    /// Stress test: spawn N subscribers + 1 hot sweeper for 200 ms, then
    /// publish and assert every Receiver delivers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn subscribe_under_concurrent_sweep_does_not_lose_receivers() {
        let bus = std::sync::Arc::new(RoomBus::new());

        let bus_sweep = bus.clone();
        let sweeper = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(200);
            while tokio::time::Instant::now() < deadline {
                bus_sweep.sweep_empty();
                tokio::task::yield_now().await;
            }
        });

        let mut handles = Vec::new();
        for i in 0..50 {
            let bus_sub = bus.clone();
            handles.push(tokio::spawn(async move {
                let room = format!("r{i}");
                let mut rx = bus_sub.subscribe("t1", &room);
                // Yield to let sweep observe the entry.
                tokio::task::yield_now().await;
                // Now publish — receiver should still be registered.
                bus_sub.publish("t1", &room, msg("payload"));
                let got = tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.recv())
                    .await
                    .expect("recv timed out — Receiver was likely orphaned by sweep")
                    .expect("recv error");
                assert_eq!(got.payload["body"], "payload");
            }));
        }

        for h in handles {
            h.await.expect("subscribe task panicked");
        }
        sweeper.await.expect("sweeper task panicked");
    }
}

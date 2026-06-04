use dashmap::DashMap;
use std::sync::Arc;
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
        if let Some(outer) = self.channels.get(tenant) {
            if let Some(tx) = outer.value().get(room) {
                return tx.value().send(msg).unwrap_or(0);
            }
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

    /// Drop every channel for `tenant`. Existing subscribers get
    /// `RecvError::Closed` on next recv. Called from `soft_delete_tenant`
    /// + admin `DELETE …/realtime/rooms`.
    pub fn evict_tenant(&self, tenant: &str) {
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

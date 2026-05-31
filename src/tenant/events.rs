use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Created { record: serde_json::Value },
    Updated { record: serde_json::Value },
    Deleted { id: i64 },
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Event::Created { .. } => "created",
            Event::Updated { .. } => "updated",
            Event::Deleted { .. } => "deleted",
        }
    }
}

/// Nested `DashMap<Arc<str>, DashMap<Arc<str>, _>>` (v1.32.1 D2): the
/// `publish()` hot path is hit on every record CRUD, so we avoid the
/// per-call `(String, String)` allocation. Reads pass `&str` directly;
/// only first-subscribe on a `(tenant, collection)` pair pays the
/// `Arc<str>` clone (amortized across every subsequent subscriber and
/// every publish on that pair).
#[derive(Clone, Default)]
pub struct EventBus {
    channels: Arc<DashMap<Arc<str>, DashMap<Arc<str>, broadcast::Sender<Event>>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&self, tenant: &str, collection: &str, ev: Event) {
        if let Some(outer) = self.channels.get(tenant) {
            if let Some(tx) = outer.value().get(collection) {
                let _ = tx.value().send(ev);
            }
        }
    }

    pub fn subscribe(&self, tenant: &str, collection: &str) -> broadcast::Receiver<Event> {
        // v1.32 A4 — hold the shard write lock across subscribe() so a
        // parallel evict_collection cannot remove the entry between
        // or_insert_with and Receiver registration. Mirror of the v1.31.2
        // F7 fix in rooms/bus.rs. Nested map (v1.32.1 D2): BOTH the outer
        // entry guard AND the inner entry guard are held across the
        // `.subscribe()` call so neither a tenant-level nor a
        // collection-level evict can race the Receiver registration.
        let outer_entry = self.channels.entry(Arc::<str>::from(tenant)).or_default();
        let inner_entry = outer_entry
            .value()
            .entry(Arc::<str>::from(collection))
            .or_insert_with(|| broadcast::channel(256).0);
        inner_entry.value().subscribe()
    }

    /// Drop every broadcast channel for `tenant`. Existing subscribers
    /// receive `Closed` on their next recv. Called from the
    /// soft_delete_tenant path so a deleted tenant doesn't leave channels
    /// hanging in memory until process restart.
    pub fn evict_tenant(&self, tenant: &str) {
        self.channels.remove(tenant);
    }

    /// Drop the broadcast channel for one `(tenant, collection)`. Existing
    /// subscribers receive `Closed` on their next recv. Called from the
    /// realtime-toggle path so disabling broadcast on a collection takes
    /// effect immediately for in-flight SSE connections. The empty inner
    /// DashMap is left in place — saves churn on re-subscribe.
    pub fn evict_collection(&self, tenant: &str, collection: &str) {
        if let Some(outer) = self.channels.get(tenant) {
            outer.value().remove(collection);
        }
    }

    /// How many `(tenant, collection)` channels are currently allocated.
    /// Test/observability hook. Sums every inner map's len — empty inner
    /// maps contribute 0 so post-evict residue is invisible to callers.
    pub fn channel_count(&self) -> usize {
        self.channels.iter().map(|kv| kv.value().len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn evict_collection_drops_only_that_pair() {
        let bus = EventBus::new();
        let mut rx_keep = bus.subscribe("t1", "keep");
        let _rx_drop = bus.subscribe("t1", "drop");
        let _rx_other_tenant = bus.subscribe("t2", "drop");
        assert_eq!(bus.channel_count(), 3);

        bus.evict_collection("t1", "drop");
        assert_eq!(bus.channel_count(), 2);

        // The kept receiver still sees publishes.
        bus.publish("t1", "keep", Event::Deleted { id: 1 });
        let ev = rx_keep.recv().await.unwrap();
        assert!(matches!(ev, Event::Deleted { id: 1 }));
    }

    /// v1.32 A4 regression — subscribe must hold the shard write lock across
    /// broadcast::Sender::subscribe() so evict_collection cannot remove the
    /// entry in the window between or_insert_with and Receiver registration.
    ///
    /// Pre-fix: subscribe cloned the Sender then dropped the entry guard, then
    /// called tx.subscribe() outside the lock. evict_collection's .remove()
    /// could run in that gap, dropping the Sender. The subscriber's Receiver
    /// would be orphaned — a subsequent publish creates a fresh Sender and the
    /// orphaned Receiver never delivers.
    ///
    /// Stress test: spawn N subscribers racing a hot evict_collection loop for
    /// 200 ms, then publish and assert every Receiver delivers (or gets a clean
    /// Closed/Lagged — but never a silent orphan). Mirror of the v1.31.2 F7
    /// test in rooms/bus.rs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn subscribe_under_concurrent_evict_does_not_lose_receivers() {
        use std::sync::Arc;

        let bus = Arc::new(EventBus::new());

        // Hot evict_collection loop for 200 ms.
        let bus_evict = bus.clone();
        let evicter = tokio::spawn(async move {
            let deadline =
                tokio::time::Instant::now() + tokio::time::Duration::from_millis(200);
            while tokio::time::Instant::now() < deadline {
                for i in 0..50_u32 {
                    bus_evict.evict_collection("t1", &format!("coll{i}"));
                }
                tokio::task::yield_now().await;
            }
        });

        let mut handles = Vec::new();
        for i in 0..50_u32 {
            let bus_sub = bus.clone();
            handles.push(tokio::spawn(async move {
                let coll = format!("coll{i}");
                let mut rx = bus_sub.subscribe("t1", &coll);
                // Yield to let the evicter observe the entry.
                tokio::task::yield_now().await;
                // Publish — Receiver must still be registered on the live
                // channel, so it either delivers, or gets RecvError::Closed
                // (evicter removed after subscribe, before publish). It must
                // NOT be a silent orphan (timeout with no message and no error).
                bus_sub.publish("t1", &coll, Event::Deleted { id: i as i64 });
                let result = tokio::time::timeout(
                    tokio::time::Duration::from_millis(500),
                    rx.recv(),
                )
                .await;
                // Either delivered or cleanly closed — never a timeout orphan.
                match result {
                    Ok(Ok(_)) => {}   // delivered
                    Ok(Err(_)) => {}  // RecvError::Closed / Lagged — clean
                    Err(_) => panic!("recv timed out — Receiver was likely orphaned by evict_collection (A4 bug)"),
                }
            }));
        }

        for h in handles {
            h.await.expect("subscribe task panicked");
        }
        evicter.await.expect("evicter task panicked");
    }
}

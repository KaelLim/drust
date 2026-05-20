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

#[derive(Clone, Default)]
pub struct EventBus {
    channels: Arc<DashMap<(String, String), broadcast::Sender<Event>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&self, tenant: &str, collection: &str, ev: Event) {
        let key = (tenant.to_string(), collection.to_string());
        if let Some(tx) = self.channels.get(&key) {
            let _ = tx.send(ev);
        }
    }

    pub fn subscribe(&self, tenant: &str, collection: &str) -> broadcast::Receiver<Event> {
        let key = (tenant.to_string(), collection.to_string());
        let tx = self
            .channels
            .entry(key)
            .or_insert_with(|| broadcast::channel(256).0)
            .clone();
        tx.subscribe()
    }

    /// Drop every broadcast channel for `tenant`. Existing subscribers
    /// receive `Closed` on their next recv. Called from the
    /// soft_delete_tenant path so a deleted tenant doesn't leave channels
    /// hanging in memory until process restart.
    pub fn evict_tenant(&self, tenant: &str) {
        self.channels.retain(|(t, _coll), _| t != tenant);
    }

    /// Drop the broadcast channel for one `(tenant, collection)`. Existing
    /// subscribers receive `Closed` on their next recv. Called from the
    /// realtime-toggle path so disabling broadcast on a collection takes
    /// effect immediately for in-flight SSE connections.
    pub fn evict_collection(&self, tenant: &str, collection: &str) {
        let key = (tenant.to_string(), collection.to_string());
        self.channels.remove(&key);
    }

    /// How many `(tenant, collection)` channels are currently allocated.
    /// Test/observability hook.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
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
}

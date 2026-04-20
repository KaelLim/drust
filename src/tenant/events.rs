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
}

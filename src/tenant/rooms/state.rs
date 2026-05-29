//! v1.31 rooms config: env-driven knobs threaded through `TenantStack`.
//!
//! - `DRUST_BROADCAST_PUBLISH_QPS`         — per-tenant token bucket (default 100)
//! - `DRUST_BROADCAST_PAYLOAD_MAX_BYTES`   — per-message cap (default 65536)
//! - `DRUST_BROADCAST_ROOM_SUBSCRIBER_MAX` — WS subscribe gate (default 1000)
//! - `DRUST_BROADCAST_CLIENT_ROOM_MAX`     — WS per-conn rooms cap (default 100)
//! - `DRUST_BROADCAST_SWEEPER_INTERVAL_SECS` — empty-channel GC (default 300; 0 disables)

use super::policy::PublishBucket;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct RoomsConfig {
    pub publish_qps: i64,
    pub payload_max_bytes: usize,
    pub room_subscriber_max: usize,
    pub client_room_max: usize,
    pub sweeper_interval_secs: u64,
}

impl RoomsConfig {
    pub fn from_env() -> Self {
        fn pos<T: std::str::FromStr>(name: &str, default: T) -> T {
            std::env::var(name)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default)
        }
        Self {
            publish_qps: pos("DRUST_BROADCAST_PUBLISH_QPS", 100i64),
            payload_max_bytes: pos("DRUST_BROADCAST_PAYLOAD_MAX_BYTES", 65_536usize),
            room_subscriber_max: pos("DRUST_BROADCAST_ROOM_SUBSCRIBER_MAX", 1_000usize),
            client_room_max: pos("DRUST_BROADCAST_CLIENT_ROOM_MAX", 100usize),
            sweeper_interval_secs: pos("DRUST_BROADCAST_SWEEPER_INTERVAL_SECS", 300u64),
        }
    }

    /// Permissive defaults for tests — no rate-limit / payload cap surprises.
    #[cfg(any(test, debug_assertions))]
    pub fn test_defaults() -> Self {
        Self {
            publish_qps: 10_000,
            payload_max_bytes: 1_048_576,
            room_subscriber_max: 10_000,
            client_room_max: 1_000,
            sweeper_interval_secs: 0,
        }
    }

    /// Materialize a `PublishBucket` matching this config's QPS.
    pub fn bucket(&self) -> Arc<PublishBucket> {
        Arc::new(PublishBucket::new(self.publish_qps))
    }
}

//! v1.31 rooms config: env-driven knobs threaded through `TenantStack`.
//!
//! - `DRUST_BROADCAST_PUBLISH_QPS`         — per-tenant token bucket (default 100)
//! - `DRUST_BROADCAST_PAYLOAD_MAX_BYTES`   — per-message cap (default 65536)
//! - `DRUST_BROADCAST_ROOM_SUBSCRIBER_MAX` — WS subscribe gate (default 1000)
//! - `DRUST_BROADCAST_CLIENT_ROOM_MAX`     — WS per-conn rooms cap (default 100)
//! - `DRUST_BROADCAST_SWEEPER_INTERVAL_SECS` — empty-channel GC (default 300; 0 disables)
//! - `DRUST_BROADCAST_KEEPALIVE_SECS`       — WS keepalive tick (default 30;
//!   **0 is clamped to 1, NOT "disabled"** — unlike the sweeper knob above it,
//!   keepalive cannot be turned off: it is one of the two #955 epoch
//!   checkpoints, so an evicted IDLE socket would otherwise never close)

use super::policy::PublishBucket;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct RoomsConfig {
    pub publish_qps: i64,
    pub payload_max_bytes: usize,
    pub room_subscriber_max: usize,
    pub client_room_max: usize,
    pub sweeper_interval_secs: u64,
    /// #955 — WS keepalive Ping period. Also the upper bound on how long
    /// an IDLE socket survives a tenant eviction: the keepalive branch is
    /// one of the two epoch checkpoints. **Guaranteed ≥ 1** — `from_env`
    /// clamps 0 up rather than accepting "disable keepalive", because a
    /// disabled tick would strand evicted idle sockets forever (and 0
    /// panics `tokio::time::interval`).
    pub keepalive_secs: u64,
}

impl RoomsConfig {
    pub fn from_env() -> Self {
        // Parse-or-default. Named for what it does: it validates NOTHING
        // (the old name `pos` implied a positivity check that was never
        // there), so any knob with a forbidden value must clamp at its
        // own call site.
        fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
            std::env::var(name)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default)
        }
        Self {
            publish_qps: env_or("DRUST_BROADCAST_PUBLISH_QPS", 100i64),
            payload_max_bytes: env_or("DRUST_BROADCAST_PAYLOAD_MAX_BYTES", 65_536usize),
            room_subscriber_max: env_or("DRUST_BROADCAST_ROOM_SUBSCRIBER_MAX", 1_000usize),
            client_room_max: env_or("DRUST_BROADCAST_CLIENT_ROOM_MAX", 100usize),
            sweeper_interval_secs: env_or("DRUST_BROADCAST_SWEEPER_INTERVAL_SECS", 300u64),
            // #955 — clamp at the SOURCE, not only at the consumer: 0 must
            // mean "as fast as allowed", never "keepalive disabled". See
            // the field doc and `keepalive_zero_is_clamped_to_one_never_disabled`.
            keepalive_secs: env_or("DRUST_BROADCAST_KEEPALIVE_SECS", 30u64).max(1),
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
            // MUST stay 30: a 1 s tick would make every existing WS
            // test's recv loop eat extra Ping frames. The idle-close
            // test overrides this field itself.
            keepalive_secs: 30,
        }
    }

    /// Materialize a `PublishBucket` matching this config's QPS.
    pub fn bucket(&self) -> Arc<PublishBucket> {
        Arc::new(PublishBucket::new(self.publish_qps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `std::env` is process-global. Only `main.rs` and these tests call
    /// `RoomsConfig::from_env`, and nothing else reads
    /// `DRUST_BROADCAST_KEEPALIVE_SECS`, so serialising the env-mutating
    /// tests against each other is sufficient.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn keepalive_from_env(value: Option<&str>) -> u64 {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: env mutation is only sound when no other thread is
        // reading the environment; ENV_LOCK serialises these tests and no
        // other test in this binary touches this variable.
        unsafe {
            match value {
                Some(v) => std::env::set_var("DRUST_BROADCAST_KEEPALIVE_SECS", v),
                None => std::env::remove_var("DRUST_BROADCAST_KEEPALIVE_SECS"),
            }
        }
        let secs = RoomsConfig::from_env().keepalive_secs;
        unsafe { std::env::remove_var("DRUST_BROADCAST_KEEPALIVE_SECS") };
        secs
    }

    /// #955 — the knob one line above this one in the module doc says
    /// "0 disables", so an operator following this module's own
    /// convention WILL try 0 here. It must not be taken literally:
    /// keepalive is one of the two epoch checkpoints, so disabling it
    /// would let an evicted IDLE socket live forever. Unclamped, 0 either
    /// panics `tokio::time::interval` or — with only the consumer-side
    /// `.max(1)` — silently becomes a 1 Hz Ping flood on every live
    /// socket. Clamp at the source; the consumer keeps its `.max(1)` as
    /// belt-and-braces, but it must not be the only guard.
    #[test]
    fn keepalive_zero_is_clamped_to_one_never_disabled() {
        assert_eq!(keepalive_from_env(Some("0")), 1);
    }

    /// The clamp must not eat the default or a legitimate override, and
    /// an unparseable value must fall back to the default, never to 0.
    #[test]
    fn keepalive_default_override_and_garbage() {
        assert_eq!(keepalive_from_env(None), 30);
        assert_eq!(keepalive_from_env(Some("5")), 5);
        assert_eq!(keepalive_from_env(Some("banana")), 30);
    }
}

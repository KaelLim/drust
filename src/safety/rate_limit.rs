use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Token-bucket rate limiter, keyed on caller-supplied opaque strings
/// (typically a SHA-256 hex of the bearer). Per-key state grows lazily
/// on first `try_acquire`; `spawn_cleanup` is the matching pruner that
/// keeps the map from being a memory-DoS vector for fake-bearer floods.
pub struct RateLimiter {
    budget: usize,
    window: Duration,
    /// Hard upper bound on cached entries. Cleanup pass drops oldest
    /// arbitrary entries when exceeded — only fires under sustained
    /// load that survives the window-expiry sweep.
    map_cap: usize,
    buckets: DashMap<String, VecDeque<Instant>>,
}

#[derive(Debug, thiserror::Error)]
#[error("rate limit exceeded: retry after {0:?}")]
pub struct RateLimitedError(pub Duration);

impl RateLimiter {
    /// Default cap of 10_000 entries — covers ~2k tenants × 5 tokens
    /// with 1× headroom for spike traffic.
    pub fn new(budget: u32, window: Duration) -> Self {
        Self::with_cap(budget, window, 10_000)
    }

    pub fn with_cap(budget: u32, window: Duration, map_cap: usize) -> Self {
        Self {
            budget: budget as usize,
            window,
            map_cap,
            buckets: DashMap::new(),
        }
    }

    pub fn try_acquire(&self, key: &str) -> Result<(), RateLimitedError> {
        let now = Instant::now();
        let mut entry = self.buckets.entry(key.to_string()).or_default();
        while let Some(front) = entry.front() {
            if now.duration_since(*front) >= self.window {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() >= self.budget {
            let oldest = *entry.front().expect("len >= budget > 0");
            let retry = self.window.saturating_sub(now.duration_since(oldest));
            return Err(RateLimitedError(retry));
        }
        entry.push_back(now);
        Ok(())
    }

    /// One sweep: drop entries whose newest hit is older than the
    /// window (they'd be popped on next try_acquire anyway), then if
    /// still over `map_cap`, drop arbitrary entries until under cap.
    pub fn cleanup_once(&self) {
        let now = Instant::now();
        self.buckets.retain(|_, q| match q.back() {
            Some(&t) => now.duration_since(t) < self.window,
            None => false,
        });
        let over = self.buckets.len().saturating_sub(self.map_cap);
        if over > 0 {
            let keys_to_drop: Vec<String> = self
                .buckets
                .iter()
                .take(over)
                .map(|e| e.key().clone())
                .collect();
            for k in keys_to_drop {
                self.buckets.remove(&k);
            }
        }
    }

    /// Spawn a background task that calls `cleanup_once` every
    /// `interval`. Returns the JoinHandle so callers can `abort` on
    /// shutdown if they want — the runtime drops it automatically
    /// when the parent task exits, so for drust we just leak it.
    pub fn spawn_cleanup(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            // First tick fires immediately; skip it so we don't hammer
            // an empty map on startup.
            tick.tick().await;
            loop {
                tick.tick().await;
                self.cleanup_once();
            }
        })
    }

    /// How many keys are currently cached. Test/observability hook.
    pub fn cached_count(&self) -> usize {
        self.buckets.len()
    }
}

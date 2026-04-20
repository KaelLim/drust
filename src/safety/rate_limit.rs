use dashmap::DashMap;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    budget: usize,
    window: Duration,
    buckets: DashMap<String, VecDeque<Instant>>,
}

#[derive(Debug, thiserror::Error)]
#[error("rate limit exceeded: retry after {0:?}")]
pub struct RateLimitedError(pub Duration);

impl RateLimiter {
    pub fn new(budget: u32, window: Duration) -> Self {
        Self {
            budget: budget as usize,
            window,
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
}

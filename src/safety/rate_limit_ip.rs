use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Bucket {
    count: u32,
    window_start: Instant,
    last_seen: Instant,
}

pub struct IpRateLimit {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    capacity: u32,
    window: Duration,
    max_entries: usize,
}

impl IpRateLimit {
    pub fn new(capacity: u32, window: Duration, max_entries: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            window,
            max_entries,
        }
    }

    /// Returns true if the request is allowed; false if it exceeds the per-IP budget.
    /// LRU eviction: when the map is full and a new IP arrives, the IP with the oldest
    /// `last_seen` timestamp is dropped to make room, resetting that IP's budget.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();

        if map.len() >= self.max_entries && !map.contains_key(&ip) {
            // LRU eviction: drop the oldest entry by last_seen
            if let Some(oldest) = map.iter().min_by_key(|(_, b)| b.last_seen).map(|(k, _)| *k) {
                map.remove(&oldest);
            }
        }

        let entry = map.entry(ip).or_insert(Bucket {
            count: 0,
            window_start: now,
            last_seen: now,
        });

        if now.duration_since(entry.window_start) >= self.window {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.last_seen = now;

        if entry.count >= self.capacity {
            return false;
        }
        entry.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn under_limit_passes() {
        let rl = IpRateLimit::new(3, Duration::from_secs(60), 100);
        assert!(rl.check(ip("1.1.1.1")));
        assert!(rl.check(ip("1.1.1.1")));
        assert!(rl.check(ip("1.1.1.1")));
    }

    #[test]
    fn over_limit_rejects() {
        let rl = IpRateLimit::new(3, Duration::from_secs(60), 100);
        for _ in 0..3 {
            assert!(rl.check(ip("2.2.2.2")));
        }
        assert!(!rl.check(ip("2.2.2.2")));
    }

    #[test]
    fn buckets_isolated_per_ip() {
        let rl = IpRateLimit::new(1, Duration::from_secs(60), 100);
        assert!(rl.check(ip("3.3.3.3")));
        assert!(!rl.check(ip("3.3.3.3")));
        assert!(rl.check(ip("4.4.4.4")));
    }

    #[test]
    fn window_resets_after_duration() {
        let rl = IpRateLimit::new(1, Duration::from_millis(50), 100);
        assert!(rl.check(ip("5.5.5.5")));
        assert!(!rl.check(ip("5.5.5.5")));
        std::thread::sleep(Duration::from_millis(70));
        assert!(rl.check(ip("5.5.5.5")));
    }

    #[test]
    fn lru_eviction_when_full() {
        let rl = IpRateLimit::new(1, Duration::from_secs(60), 2);
        assert!(rl.check(ip("10.0.0.1")));
        assert!(rl.check(ip("10.0.0.2")));
        assert!(rl.check(ip("10.0.0.3"))); // evicts 10.0.0.1
        // 10.0.0.1 budget reset because it was evicted
        assert!(rl.check(ip("10.0.0.1")));
    }
}

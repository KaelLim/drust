use drust::safety::rate_limit::RateLimiter;
use std::time::Duration;

#[test]
fn allows_up_to_burst_then_denies() {
    let rl = RateLimiter::new(3, Duration::from_secs(1));
    assert!(rl.try_acquire("k").is_ok());
    assert!(rl.try_acquire("k").is_ok());
    assert!(rl.try_acquire("k").is_ok());
    assert!(rl.try_acquire("k").is_err());
}

#[test]
fn window_resets_after_sleep() {
    let rl = RateLimiter::new(2, Duration::from_millis(50));
    assert!(rl.try_acquire("k").is_ok());
    assert!(rl.try_acquire("k").is_ok());
    assert!(rl.try_acquire("k").is_err());
    std::thread::sleep(Duration::from_millis(80));
    assert!(rl.try_acquire("k").is_ok());
}

#[test]
fn independent_keys() {
    let rl = RateLimiter::new(1, Duration::from_secs(1));
    assert!(rl.try_acquire("a").is_ok());
    assert!(rl.try_acquire("b").is_ok());
    assert!(rl.try_acquire("a").is_err());
    assert!(rl.try_acquire("b").is_err());
}

#[test]
fn cleanup_drops_expired_entries() {
    let rl = RateLimiter::new(1, Duration::from_millis(40));
    for i in 0..5 {
        let _ = rl.try_acquire(&format!("k{i}"));
    }
    assert_eq!(rl.cached_count(), 5);
    std::thread::sleep(Duration::from_millis(60));
    rl.cleanup_once();
    assert_eq!(rl.cached_count(), 0, "all entries past their window should be dropped");
}

#[test]
fn hard_cap_caps_map_size_under_attack() {
    // Tiny cap so we can verify the fallback fires. 1s window so entries
    // don't expire during the test (no sleep).
    let rl = RateLimiter::with_cap(1, Duration::from_secs(1), 3);
    for i in 0..10 {
        let _ = rl.try_acquire(&format!("k{i}"));
    }
    assert_eq!(rl.cached_count(), 10, "all 10 keys cached before cleanup");
    rl.cleanup_once();
    assert_eq!(rl.cached_count(), 3, "cleanup must enforce the cap");
}

// Note: spawn_cleanup itself is not tested — Instant::now() is real-time
// and tokio's paused-clock can't drive it forward. The two cleanup_once
// tests above cover the actual eviction logic; spawn_cleanup is plumbing.

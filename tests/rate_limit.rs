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

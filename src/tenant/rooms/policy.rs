//! v1.31 policy gates: room-name validation, per-tenant publish
//! token-bucket QPS, payload-byte cap. All decisions return typed
//! Err so REST and WS can map to HTTP and wire codes respectively.

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Room name validation. See spec §Room name validation.
/// Returns `Err(code)` with codes from `envelope::codes`.
pub fn validate_room_name(name: &str) -> Result<(), &'static str> {
    use super::envelope::codes;
    if name.is_empty() {
        return Err(codes::ROOM_NAME_INVALID);
    }
    if name.starts_with("_system_") {
        return Err(codes::PROTECTED_ROOM);
    }
    if name.len() > 128 {
        return Err(codes::ROOM_NAME_INVALID);
    }
    let mut chars = name.chars();
    let first = chars.next().ok_or(codes::ROOM_NAME_INVALID)?;
    if !first.is_ascii_alphabetic() {
        return Err(codes::ROOM_NAME_INVALID);
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '-')) {
        return Err(codes::ROOM_NAME_INVALID);
    }
    Ok(())
}

/// Per-tenant token bucket. Refill rate = `max_tokens / 1000` tokens
/// per millisecond. Bucket capacity = `max_tokens`. Per-tenant, NOT
/// per-token (a tenant with N service keys shares one bucket).
pub struct PublishBucket {
    inner: Arc<DashMap<String, BucketState>>,
    max_tokens: i64,
}

struct BucketState {
    tokens: AtomicI64,         // scaled by 1_000 so refill is integer-friendly
    last_refill_ms: AtomicU64,
}

impl PublishBucket {
    /// `max_tokens` is the steady-state QPS = bucket capacity.
    /// Default (production): 100. Tests pass 0 to disable.
    pub fn new(max_tokens: i64) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            max_tokens: max_tokens.max(0),
        }
    }

    /// Try to consume 1 token. On success returns `Ok(())`. On
    /// exhaustion returns `Err(Duration)` indicating wait time until
    /// the next token arrives.
    pub fn try_consume(&self, tenant: &str) -> Result<(), Duration> {
        if self.max_tokens == 0 {
            return Ok(()); // disabled
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Scale: tokens stored × 1_000. max_tokens × 1_000 capacity.
        let capacity_scaled = self.max_tokens.saturating_mul(1_000);
        let entry = self
            .inner
            .entry(tenant.to_string())
            .or_insert_with(|| BucketState {
                tokens: AtomicI64::new(capacity_scaled),
                last_refill_ms: AtomicU64::new(now_ms),
            });
        // Refill: scaled tokens per ms = max_tokens (since bucket × 1_000, rate = max × ms).
        let last = entry.last_refill_ms.swap(now_ms, Ordering::AcqRel);
        let elapsed_ms = now_ms.saturating_sub(last) as i64;
        let refill_scaled = elapsed_ms.saturating_mul(self.max_tokens);
        let prev = entry.tokens.load(Ordering::Acquire);
        let after_refill = (prev + refill_scaled).min(capacity_scaled);
        if after_refill < 1_000 {
            // Less than 1 whole token available. Compute wait.
            let deficit = 1_000 - after_refill;
            let wait_ms = (deficit + self.max_tokens - 1) / self.max_tokens; // ceil div
            entry.tokens.store(after_refill, Ordering::Release);
            return Err(Duration::from_millis(wait_ms.max(1) as u64));
        }
        entry.tokens.store(after_refill - 1_000, Ordering::Release);
        Ok(())
    }
}

/// Payload byte cap check. Caller already has the bytes (REST body or
/// WS frame); this is a pure comparison so all three publish paths
/// (WS / REST / MCP) share the same gate.
pub fn check_payload_size(len: usize, max_bytes: usize) -> Result<(), &'static str> {
    use super::envelope::codes;
    if len > max_bytes {
        Err(codes::PAYLOAD_TOO_LARGE)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::rooms::envelope::codes;

    #[test]
    fn valid_room_names_accepted() {
        for n in ["chat", "chat:42", "user.7", "order-pending", "a"] {
            assert_eq!(validate_room_name(n), Ok(()), "rejected: {n}");
        }
    }

    #[test]
    fn protected_prefix_rejected() {
        assert_eq!(
            validate_room_name("_system_chat"),
            Err(codes::PROTECTED_ROOM),
        );
    }

    #[test]
    fn invalid_names_rejected() {
        for n in [
            "",
            "1starts_with_digit",
            "has space",
            "has/slash",
            "has🎉unicode",
            "has\nnewline",
            // 129 chars > 128 cap:
            &"a".repeat(129),
        ] {
            assert_eq!(
                validate_room_name(n),
                Err(codes::ROOM_NAME_INVALID),
                "accepted invalid: {n:?}",
            );
        }
    }

    #[test]
    fn payload_size_check_boundaries() {
        let cap = 100;
        assert_eq!(check_payload_size(0, cap), Ok(()));
        assert_eq!(check_payload_size(cap, cap), Ok(()));
        assert_eq!(
            check_payload_size(cap + 1, cap),
            Err(codes::PAYLOAD_TOO_LARGE)
        );
    }

    #[test]
    fn bucket_disabled_when_max_zero() {
        let b = PublishBucket::new(0);
        for _ in 0..1_000 {
            assert!(b.try_consume("t1").is_ok());
        }
    }

    #[test]
    fn bucket_allows_burst_then_rate_limits() {
        let b = PublishBucket::new(10); // 10 QPS
        // First 10 should succeed (initial bucket).
        for i in 0..10 {
            assert!(b.try_consume("t1").is_ok(), "iter {i}");
        }
        // 11th should be rejected immediately.
        assert!(b.try_consume("t1").is_err());
    }

    #[test]
    fn bucket_isolates_per_tenant() {
        let b = PublishBucket::new(2);
        assert!(b.try_consume("t1").is_ok());
        assert!(b.try_consume("t1").is_ok());
        assert!(b.try_consume("t1").is_err()); // t1 exhausted
        assert!(b.try_consume("t2").is_ok()); // t2 has its own bucket
        assert!(b.try_consume("t2").is_ok());
    }

    #[test]
    fn bucket_refills_over_time() {
        let b = PublishBucket::new(100); // 100 QPS = 1 token/10ms
        // Drain.
        for _ in 0..100 {
            let _ = b.try_consume("t1");
        }
        // Sleep 50ms — should refill ~5 tokens.
        std::thread::sleep(Duration::from_millis(50));
        let mut ok_count = 0;
        for _ in 0..20 {
            if b.try_consume("t1").is_ok() {
                ok_count += 1;
            }
        }
        assert!(
            ok_count >= 3 && ok_count <= 8,
            "refilled {ok_count} tokens after 50ms"
        );
    }
}

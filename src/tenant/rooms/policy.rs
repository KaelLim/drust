//! v1.31 policy gates: room-name validation, per-tenant publish
//! token-bucket QPS, payload-byte cap. All decisions return typed
//! Err so REST and WS can map to HTTP and wire codes respectively.

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::Mutex;
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
    inner: Arc<DashMap<String, Arc<Mutex<BucketState>>>>,
    max_tokens: i64,
}

struct BucketState {
    tokens: i64, // scaled by 1_000 so refill is integer-friendly
    last_refill_ms: u64,
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
        let capacity_scaled = self.max_tokens.saturating_mul(1_000);
        // v1.31.2 F9 — per-tenant Mutex so refill+compute+decrement is
        // one atomic step. Pre-fix the load/compute/store were independent
        // atomics and concurrent callers could both observe >= 1 token
        // and both decrement.
        let lock = self
            .inner
            .entry(tenant.to_string())
            .or_insert_with(|| {
                Arc::new(Mutex::new(BucketState {
                    tokens: capacity_scaled,
                    last_refill_ms: now_ms,
                }))
            })
            .clone();
        let mut g = lock.lock().expect("PublishBucket Mutex poisoned");
        let elapsed_ms = now_ms.saturating_sub(g.last_refill_ms) as i64;
        let refill_scaled = elapsed_ms.saturating_mul(self.max_tokens);
        let after_refill = (g.tokens + refill_scaled).min(capacity_scaled);
        g.last_refill_ms = now_ms;
        if after_refill < 1_000 {
            // Less than 1 whole token available. Compute wait.
            let deficit = 1_000 - after_refill;
            let wait_ms = (deficit + self.max_tokens - 1) / self.max_tokens; // ceil div
            g.tokens = after_refill;
            return Err(Duration::from_millis(wait_ms.max(1) as u64));
        }
        g.tokens = after_refill - 1_000;
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

/// v1.32.5 — per-tenant publish policy. Bound on every request by
/// `bearer_auth_layer` so REST + WS handlers can gate without an
/// extra meta.sqlite round-trip. MCP `broadcast` does NOT consume
/// this — MCP dispatch is already service-only by construction.
///
/// Default for both fields is `false` (matches the column default in
/// `meta.sqlite.tenants`). A fresh install or pre-v1.32.5 deployment
/// upgrade therefore preserves the historical "service-only publish"
/// behavior — flags must be flipped to opt in.
#[derive(Debug, Clone, Copy, Default)]
pub struct TenantPublishPolicy {
    pub allow_user: bool,
    pub allow_anon: bool,
}

/// Outcome of `check_publish_allowed`. Distinct deny variants so REST
/// and WS can emit role-specific error codes without re-pattern-matching
/// on `AuthCtx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishGate {
    Allow,
    DenyUser,
    DenyAnon,
}

/// v1.32.5 — single source of truth for publish authorization.
///
/// - `AuthCtx::Service` → always `Allow` (admin keys / service bearer)
/// - `AuthCtx::User`    → `Allow` iff `policy.allow_user`
/// - `AuthCtx::Anon`    → `Allow` iff `policy.allow_anon`
///
/// MCP `broadcast` does NOT call this — it relies on MCP dispatch being
/// service-only globally (second layer of defense-in-depth).
pub fn check_publish_allowed(
    ctx: &crate::auth::middleware::AuthCtx,
    policy: &TenantPublishPolicy,
) -> PublishGate {
    use crate::auth::middleware::AuthCtx;
    match ctx {
        AuthCtx::Service { .. } => PublishGate::Allow,
        AuthCtx::User { .. } if policy.allow_user => PublishGate::Allow,
        AuthCtx::User { .. } => PublishGate::DenyUser,
        AuthCtx::Anon if policy.allow_anon => PublishGate::Allow,
        AuthCtx::Anon => PublishGate::DenyAnon,
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
    fn check_publish_allowed_matrix() {
        use crate::auth::middleware::AuthCtx;
        let off = TenantPublishPolicy {
            allow_user: false,
            allow_anon: false,
        };
        let user_on = TenantPublishPolicy {
            allow_user: true,
            allow_anon: false,
        };
        let anon_on = TenantPublishPolicy {
            allow_user: false,
            allow_anon: true,
        };
        let both_on = TenantPublishPolicy {
            allow_user: true,
            allow_anon: true,
        };
        let svc = AuthCtx::Service { admin_id: None };
        let usr = AuthCtx::User {
            user_id: "u-1".into(),
            token_hash: "h".into(),
        };
        let anon = AuthCtx::Anon;
        // Service: always Allow.
        for p in [&off, &user_on, &anon_on, &both_on] {
            assert_eq!(check_publish_allowed(&svc, p), PublishGate::Allow);
        }
        // User: gated by allow_user.
        assert_eq!(check_publish_allowed(&usr, &off), PublishGate::DenyUser);
        assert_eq!(check_publish_allowed(&usr, &user_on), PublishGate::Allow);
        assert_eq!(check_publish_allowed(&usr, &anon_on), PublishGate::DenyUser);
        assert_eq!(check_publish_allowed(&usr, &both_on), PublishGate::Allow);
        // Anon: gated by allow_anon.
        assert_eq!(check_publish_allowed(&anon, &off), PublishGate::DenyAnon);
        assert_eq!(
            check_publish_allowed(&anon, &user_on),
            PublishGate::DenyAnon
        );
        assert_eq!(check_publish_allowed(&anon, &anon_on), PublishGate::Allow);
        assert_eq!(check_publish_allowed(&anon, &both_on), PublishGate::Allow);
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

    /// v1.31.2 F9 regression — `try_consume` must be atomic under
    /// per-tenant concurrency. Pre-fix the load + compute + store steps
    /// were independent atomics; two concurrent callers from the same
    /// tenant could both observe tokens >= 1_000 and both decrement,
    /// breaking the documented QPS cap.
    #[test]
    fn bucket_under_concurrent_burst_honors_max_tokens_exactly() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const MAX_TOKENS: i64 = 10;
        const THREADS: usize = 50;

        let b = Arc::new(PublishBucket::new(MAX_TOKENS));
        let barrier = Arc::new(Barrier::new(THREADS));

        let counters: Vec<_> = (0..THREADS)
            .map(|_| {
                let b = b.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    if b.try_consume("t1").is_ok() { 1 } else { 0 }
                })
            })
            .collect();

        let total_ok: usize = counters.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total_ok, MAX_TOKENS as usize,
            "expected exactly {MAX_TOKENS} consumes; got {total_ok} (race?)"
        );
    }
}

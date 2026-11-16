//! In-memory limiters for `/oauth/token`, and the limiter key shapes
//! (`/oauth/revoke` reads no budget). Budgets are hardcoded (no env): failed
//! lookups per client IP, failed checks per code, and refresh exchanges per
//! grant. A request that presents a valid credential never touches the per-IP
//! miss bucket.

use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};
use crate::safety::ip::ClientIp;
use crate::safety::rate_limit::RateLimiter;
use std::sync::Arc;
use std::time::Duration;

// Non-zero: RateLimiter panics at budget 0 (`expect("len >= budget > 0")`).
pub const MISS_IP_BUDGET: u32 = 30;
pub const MISS_IP_WINDOW: Duration = Duration::from_secs(60);
pub const PER_CODE_BUDGET: u32 = 10;
pub const PER_CODE_WINDOW: Duration = Duration::from_secs(300);
pub const PER_GRANT_BUDGET: u32 = 10;
pub const PER_GRANT_WINDOW: Duration = Duration::from_secs(60);
const CLEANUP_EVERY: Duration = Duration::from_secs(60);

pub struct McpOauthLimiters {
    /// Failed credential lookups, keyed by [`client_ip_key`].
    pub miss_ip: Arc<RateLimiter>,
    /// Failed checks on a code that exists, keyed by [`code_key`].
    pub per_code: Arc<RateLimiter>,
    /// Refresh presentations of a known token of the grant, keyed by [`grant_key`];
    /// read by `refresh::rotate` only on the branches it bounds (never on reuse
    /// detection or a losing sibling's branch cut).
    pub per_grant: Arc<RateLimiter>,
}

impl McpOauthLimiters {
    pub fn new() -> Self {
        Self {
            miss_ip: Arc::new(RateLimiter::new(MISS_IP_BUDGET, MISS_IP_WINDOW)),
            per_code: Arc::new(RateLimiter::new(PER_CODE_BUDGET, PER_CODE_WINDOW)),
            per_grant: Arc::new(RateLimiter::new(PER_GRANT_BUDGET, PER_GRANT_WINDOW)),
        }
    }

    /// main.rs only, and only when `McpOauthConfig::enabled()`: a disabled host
    /// mounts no route that could fill these, so it runs no sweeper either.
    /// Reuses `RateLimiter::spawn_cleanup`.
    pub fn spawn_cleanup(&self) {
        for l in [&self.miss_ip, &self.per_code, &self.per_grant] {
            // Named binding: `let _ =` on a JoinHandle reads as a dropped future.
            let _detached = l.clone().spawn_cleanup(CLEANUP_EVERY);
        }
    }
}

impl Default for McpOauthLimiters {
    fn default() -> Self {
        Self::new()
    }
}

/// The ONLY place MA0 turns a caller's address into a limiter key. The address
/// is the `ClientIp` extractor's (`safety::ip`, the one client-IP derivation in
/// the tree, which honours `DRUST_TRUSTED_PROXIES` and the TCP peer), so a
/// handler takes `ClientIp` and never reads a forwarding header itself. A
/// proxy count that is wrong for the deployment collapses every client into
/// one key; valid credentials never read the miss bucket, so only genuine
/// misses would share it.
pub fn client_ip_key(ip: &ClientIp) -> String {
    format!("ip:{}", ip.0)
}

/// Per-code key. Takes the PLAINTEXT code and hashes it here, so no caller can
/// put a plaintext code into a key the limiter keeps in memory for a whole window.
pub fn code_key(code: &str) -> String {
    format!("code:{}", tokens::hash(TokenKind::Code, code))
}

/// Per-grant key.
pub fn grant_key(grant_id: i64) -> String {
    format!("grant:{grant_id}")
}

/// Ceil to whole seconds, at least 1 (a `Retry-After: 0` invites a hot loop).
pub fn retry_after_secs(d: Duration) -> u64 {
    (d.as_secs() + u64::from(d.subsec_nanos() > 0)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{ConnectInfo, FromRequestParts};
    use std::net::SocketAddr;

    fn exhaust(l: &RateLimiter, key: &str, budget: u32) {
        for i in 0..budget {
            assert!(
                l.try_acquire(key).is_ok(),
                "{key}: attempt {} refused",
                i + 1
            );
        }
        assert!(
            l.try_acquire(key).is_err(),
            "{key}: attempt {} allowed",
            budget + 1
        );
        assert!(l.try_acquire("other").is_ok(), "another key is unaffected");
    }

    #[test]
    fn budgets_are_the_plan_numbers() {
        let l = McpOauthLimiters::new();
        exhaust(&l.miss_ip, "ip:203.0.113.7", 30);
        exhaust(&l.per_code, "code:x", 10);
        exhaust(&l.per_grant, "grant:1", 10);
    }

    #[test]
    fn default_equals_new() {
        let l = McpOauthLimiters::default();
        exhaust(&l.miss_ip, "ip:203.0.113.7", 30);
    }

    #[test]
    fn retry_after_rounds_up_to_at_least_one() {
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::from_secs(1)), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(1001)), 2);
        assert_eq!(retry_after_secs(Duration::from_secs(60)), 60);
    }

    /// The key for a request with no forwarding header, through the real
    /// `ClientIp` extractor (the TCP peer from `ConnectInfo`, when there is one).
    async fn key_for(peer: Option<&str>) -> String {
        let mut req = axum::http::Request::new(());
        if let Some(p) = peer {
            req.extensions_mut()
                .insert(ConnectInfo(p.parse::<SocketAddr>().unwrap()));
        }
        let (mut parts, ()) = req.into_parts();
        let ip = <ClientIp as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        client_ip_key(&ip)
    }

    #[tokio::test]
    async fn client_ip_key_shapes() {
        // No connect-info (Router::oneshot): the extractor's loopback default.
        assert_eq!(key_for(None).await, "ip:127.0.0.1");
        assert_eq!(key_for(Some("203.0.113.7:5000")).await, "ip:203.0.113.7");
        assert_eq!(key_for(Some("[2001:db8::1]:5000")).await, "ip:2001:db8::1");
        // A dual-stack bind does not split one client across two keys.
        assert_eq!(
            key_for(Some("[::ffff:203.0.113.7]:5000")).await,
            "ip:203.0.113.7"
        );
    }

    #[tokio::test]
    async fn spawn_cleanup_does_not_panic() {
        McpOauthLimiters::new().spawn_cleanup();
    }

    #[test]
    fn limiter_keys_never_hold_plaintext() {
        let c = tokens::new_token(TokenKind::Code);
        assert_eq!(
            code_key(&c),
            format!("code:{}", tokens::hash(TokenKind::Code, &c))
        );
        assert!(!code_key(&c).contains(&c));
        assert_eq!(grant_key(42), "grant:42");
    }
}

//! v1.35 — process-local invalidate-on-write auth cache for `bearer_auth_layer`.
//!
//! A `DashMap<token_hash, AuthCacheEntry>` consulted on the hot path of
//! `bearer_auth_layer` so the common authenticated request skips the single
//! global `meta` mutex + bearer-auth CTE. Correctness rests on two independent
//! layers (drust/CLAUDE.md "revocation must take effect promptly"):
//!   - Layer 1 — every write path that changes auth state invalidates the
//!     entry synchronously (the eleven hooks in the Finding #3 spec).
//!   - Layer 2 — a per-entry `safety_ttl` (prod 10 s) forces a re-read even
//!     if a future write path forgets its hook: a missed hook degrades from
//!     "forever" to "≤ safety_ttl", never a permanent bypass.
//!
//! Negative / unknown-bearer results are NEVER cached (a brute-force prober
//! must not be able to poison the map or get a timing oracle).
//!
//! Hook 10 (session janitor) intentionally has NO wiring here: the
//! `drust_session_janitor` binary (`src/bin/drust_session_janitor.rs`) runs
//! out-of-process with its own `meta.sqlite` + fresh `TenantRegistry`, so it
//! cannot reach this in-process map. Expired `CachedAuth::User` entries
//! self-reject via their cached `expires_at`, and the safety TTL reaps them —
//! both fully cover the janitor's belt-and-suspenders role.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Cache-local role. The live `crate::tenant::router::TokenRole` is
/// `Copy` and carries no data, so it cannot hold the PAT `admin_id`. This
/// enum mirrors the three `AuthCtx` shapes a `Bearer` hit reconstructs:
/// `Anon` → `AuthCtx::Anon`, `Service` → `AuthCtx::Service { admin_id: None }`,
/// `AdminPat { admin_id }` → `AuthCtx::Service { admin_id: Some(admin_id) }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CachedRole {
    Anon,
    Service,
    AdminPat { admin_id: i64 },
}

/// One resolved identity + the publish-policy/expiry bits needed to
/// reconstruct the request extensions WITHOUT touching `meta.sqlite`.
#[derive(Clone, Debug)]
pub enum CachedAuth {
    /// Service / anon / admin-PAT bearer. The `publish_*` bits are
    /// per-tenant, captured at fill time from `tenants.allow_*_publish`.
    /// `email_snapshot` is the admin-PAT email (`pat_email` CTE column) — `None`
    /// for service/anon — carried so an admin-PAT cache HIT keeps the audit
    /// row's `actor_email_snapshot` identical to the DB path.
    Bearer {
        bound_tenant_id: String,
        role: CachedRole,
        publish_user_allowed: bool,
        publish_anon_allowed: bool,
        email_snapshot: Option<String>,
        /// v1.42 — per-tenant file caps captured at fill time. A hit MUST
        /// reconstruct the SAME `TenantFileCaps` the CTE path produces, never
        /// a default — a stale-empty hit would wrongly DENY a permitted op.
        file_caps: crate::tenant::file_caps::TenantFileCaps,
    },
    /// `drust_user_*` session bearer. `expires_at` is the cached source of
    /// truth → self-check, no `_system_sessions` read on a hit. The
    /// `publish_*` bits MIRROR the `Bearer` variant: a `User` cache hit MUST
    /// reconstruct the SAME `TenantPublishPolicy` the CTE path produces
    /// (`router.rs:359`), NEVER a `false/false` default — hardcoding
    /// false/false would wrongly DENY a permitted user publish.
    User {
        tenant_id: String,
        user_id: String,
        expires_at: chrono::DateTime<chrono::Utc>,
        publish_user_allowed: bool,
        publish_anon_allowed: bool,
        /// v1.42 — see `Bearer::file_caps`.
        file_caps: crate::tenant::file_caps::TenantFileCaps,
    },
}

#[derive(Clone, Debug)]
struct AuthCacheEntry {
    inserted: Instant,
    auth: CachedAuth,
}

/// Process-local auth cache. Cloned by `Arc` into every state that needs to
/// read (the auth layer) or invalidate (the write handlers).
pub struct AuthCache {
    map: DashMap<String, AuthCacheEntry>,
    /// Per-entry validity window. A `Duration` FIELD (NOT a const) so tests
    /// inject e.g. 50 ms; prod sets 10 s in `main.rs`.
    safety_ttl: Duration,
    /// Hard ceiling on live entries. On overflow `insert` clears the map
    /// (clear-and-refill — strict LRU not worth the bookkeeping per spec).
    max_entries: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl AuthCache {
    pub fn new(safety_ttl: Duration, max_entries: usize) -> Self {
        Self {
            map: DashMap::new(),
            safety_ttl,
            max_entries,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn safety_ttl(&self) -> Duration {
        self.safety_ttl
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Look up a token hash. On a present, non-expired entry: increment the
    /// hit counter and return a clone of the cached auth. On absent OR
    /// past-TTL: increment the miss counter, drop any stale entry, return
    /// `None`. The TTL check is the per-entry `inserted.elapsed() < safety_ttl`.
    pub fn get(&self, hash: &str) -> Option<CachedAuth> {
        if let Some(e) = self.map.get(hash)
            && e.inserted.elapsed() < self.safety_ttl
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(e.auth.clone());
        }
        // Absent or stale.
        self.misses.fetch_add(1, Ordering::Relaxed);
        self.map.remove(hash);
        None
    }

    /// Insert a freshly-resolved positive entry. Enforces the max-entries
    /// ceiling by clearing the map on overflow (clear-and-refill).
    pub fn insert(&self, hash: String, auth: CachedAuth) {
        if self.map.len() >= self.max_entries {
            self.map.clear();
        }
        self.map.insert(
            hash,
            AuthCacheEntry {
                inserted: Instant::now(),
                auth,
            },
        );
    }

    /// Hook 5/6 — single known hash.
    pub fn remove(&self, hash: &str) {
        self.map.remove(hash);
    }

    /// Hooks 3/4/11 — tenant-scoped scan-clear: drop every `Bearer` and
    /// `User` entry bound to `tenant_id`.
    pub fn clear_tenant(&self, tenant_id: &str) {
        self.map.retain(|_, e| match &e.auth {
            CachedAuth::Bearer {
                bound_tenant_id, ..
            } => bound_tenant_id != tenant_id,
            CachedAuth::User { tenant_id: t, .. } => t != tenant_id,
        });
    }

    /// Hook 1 — (tenant_id, role)-scoped scan-clear of service/anon `Bearer`
    /// entries. `role` is `CachedRole::Service` or `CachedRole::Anon`.
    pub fn clear_tenant_role(&self, tenant_id: &str, role: &CachedRole) {
        self.map.retain(|_, e| match &e.auth {
            CachedAuth::Bearer {
                bound_tenant_id,
                role: r,
                ..
            } => !(bound_tenant_id == tenant_id && r == role),
            _ => true,
        });
    }

    /// Hook 2 — admin-PAT scan-clear: drop every `Bearer` whose role is
    /// `AdminPat { admin_id }`.
    pub fn clear_admin_pat(&self, admin_id: i64) {
        self.map.retain(|_, e| {
            !matches!(
                &e.auth,
                CachedAuth::Bearer {
                    role: CachedRole::AdminPat { admin_id: a },
                    ..
                } if *a == admin_id
            )
        });
    }

    /// Hooks 7/8/9 — per-user scan-clear: drop every `CachedAuth::User`
    /// with matching `user_id`.
    pub fn clear_user(&self, user_id: &str) {
        self.map
            .retain(|_, e| !matches!(&e.auth, CachedAuth::User { user_id: u, .. } if u == user_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fresh_cache_is_empty_with_prod_ttl() {
        let c = AuthCache::new(Duration::from_secs(10), 200_000);
        assert_eq!(c.len(), 0);
        assert_eq!(c.hits(), 0);
        assert_eq!(c.misses(), 0);
        assert_eq!(c.safety_ttl(), Duration::from_secs(10));
    }

    #[test]
    fn bearer_entry_round_trips() {
        let c = AuthCache::new(Duration::from_secs(10), 200_000);
        c.insert(
            "h1".to_string(),
            CachedAuth::Bearer {
                bound_tenant_id: "t1".to_string(),
                role: CachedRole::AdminPat { admin_id: 7 },
                publish_user_allowed: true,
                publish_anon_allowed: false,
                email_snapshot: Some("admin@x".to_string()),
                file_caps: Default::default(),
            },
        );
        assert_eq!(c.len(), 1);
        match c.get("h1") {
            Some(CachedAuth::Bearer {
                bound_tenant_id,
                role,
                publish_user_allowed,
                ..
            }) => {
                assert_eq!(bound_tenant_id, "t1");
                assert!(matches!(role, CachedRole::AdminPat { admin_id: 7 }));
                assert!(publish_user_allowed);
            }
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    #[test]
    fn entry_expires_after_safety_ttl() {
        let c = AuthCache::new(Duration::from_millis(50), 200_000);
        c.insert(
            "h2".to_string(),
            CachedAuth::Bearer {
                bound_tenant_id: "t1".to_string(),
                role: CachedRole::Service,
                publish_user_allowed: false,
                publish_anon_allowed: false,
                email_snapshot: None,
                file_caps: Default::default(),
            },
        );
        // Fresh: hit.
        assert!(c.get("h2").is_some());
        assert_eq!(c.hits(), 1);
        // After the 50 ms window: miss + entry dropped.
        std::thread::sleep(Duration::from_millis(70));
        assert!(c.get("h2").is_none());
        assert_eq!(c.misses(), 1);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn miss_on_absent_increments_miss_and_does_not_grow() {
        let c = AuthCache::new(Duration::from_secs(10), 200_000);
        assert!(c.get("nope").is_none());
        assert!(c.get("nope").is_none());
        assert_eq!(c.misses(), 2);
        assert_eq!(c.len(), 0);
    }
}

//! Trigger parsing + per-tenant binding cache.
//!
//! `BindingCache` is invalidate-on-write (auth_cache precedent — BOTH layers):
//!
//! - **Layer 1 — enumerated hooks.** Writers (EXHAUSTIVE, all in
//!   functions::routes + mcp::tools::functions + mgmt::functions_admin):
//!   create_function, delete_function, set_active, update_meta. Every code
//!   path that mutates `_system_functions` MUST call `cache.invalidate(tenant)`
//!   after the write commits — v1.35 lesson: enumerate by grepping all
//!   writers before merge.
//! - **Layer 2 — per-entry safety TTL** (default 10 s, injectable in tests;
//!   `src/tenant/auth_cache.rs` pattern). Bounds two failure modes to ≤ TTL
//!   instead of forever: (a) a missed Layer-1 hook, and (b) the load/insert
//!   race — loader misses cache, reads state A, a concurrent writer commits
//!   state B and invalidates (removes nothing), loader inserts stale A.

use crate::storage::pool::SharedTenantPool;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// One entry of `triggers_json`. Two shapes:
///   {"collection":"posts","events":["created","updated"]}
///   {"file_uploaded":true}
///
/// Untagged caveat: an object carrying BOTH Record fields and
/// `"file_uploaded":true` deserializes as `Record` and the flag is silently
/// ignored. Accepted — triggers are validated at write time by our own
/// surfaces, never hand-authored into the DB.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum TriggerSpec {
    Record {
        collection: String,
        events: Vec<String>,
    },
    FileUploaded {
        file_uploaded: bool,
    },
}

/// Validate a triggers_json string. Returns the parsed list or a
/// sentinel-prefixed error.
pub fn parse_triggers(s: &str) -> anyhow::Result<Vec<TriggerSpec>> {
    let list: Vec<TriggerSpec> =
        serde_json::from_str(s).map_err(|e| anyhow::anyhow!("FN_TRIGGERS_INVALID: {e}"))?;
    for t in &list {
        if let TriggerSpec::Record { events, collection } = t {
            if collection.is_empty() {
                anyhow::bail!("FN_TRIGGERS_INVALID: empty collection");
            }
            if events.is_empty() {
                anyhow::bail!(
                    "FN_TRIGGERS_INVALID: empty events (a record trigger that can never match)"
                );
            }
            for ev in events {
                if !matches!(ev.as_str(), "created" | "updated" | "deleted") {
                    anyhow::bail!(
                        "FN_TRIGGERS_INVALID: unknown event {ev:?} (created|updated|deleted)"
                    );
                }
            }
        }
    }
    Ok(list)
}

/// One active function's parsed bindings.
#[derive(Clone, Debug)]
pub struct Binding {
    pub function_name: String,
    pub triggers: Vec<TriggerSpec>,
}

impl Binding {
    pub fn matches_record(&self, collection: &str, event_name: &str) -> bool {
        self.triggers.iter().any(|t| match t {
            TriggerSpec::Record {
                collection: c,
                events,
            } => c == collection && events.iter().any(|e| e == event_name),
            TriggerSpec::FileUploaded { .. } => false,
        })
    }
    pub fn matches_file_uploaded(&self) -> bool {
        self.triggers.iter().any(|t| {
            matches!(
                t,
                TriggerSpec::FileUploaded {
                    file_uploaded: true
                }
            )
        })
    }
}

/// Default per-entry safety TTL (Layer 2) — matches the auth cache's 10 s.
pub const DEFAULT_SAFETY_TTL: Duration = Duration::from_secs(10);

struct CacheEntry {
    inserted: Instant,
    bindings: Arc<Vec<Binding>>,
}

/// Per-tenant cache of ACTIVE bindings, keyed by tenant id. Each entry holds
/// the parsed snapshot plus its insertion time for the Layer-2 TTL check.
pub struct BindingCache {
    map: DashMap<String, CacheEntry>,
    /// Per-entry validity window. A `Duration` FIELD (NOT a const) so tests
    /// can inject e.g. `Duration::ZERO`; prod uses `DEFAULT_SAFETY_TTL`.
    safety_ttl: Duration,
}

impl Default for BindingCache {
    fn default() -> Self {
        Self::new()
    }
}

impl BindingCache {
    pub fn new() -> Self {
        Self::with_safety_ttl(DEFAULT_SAFETY_TTL)
    }

    pub fn with_safety_ttl(safety_ttl: Duration) -> Self {
        Self {
            map: DashMap::new(),
            safety_ttl,
        }
    }

    pub fn invalidate(&self, tenant: &str) {
        self.map.remove(tenant);
    }

    /// Cached read; on miss (entry absent OR past the safety TTL) loads
    /// ACTIVE rows from `_system_functions`. A tenant with zero functions
    /// caches an empty Vec — the hot-path cost for function-less tenants is
    /// one DashMap get.
    pub async fn get_or_load(&self, tenant: &str, pool: &SharedTenantPool) -> Arc<Vec<Binding>> {
        if let Some(e) = self.map.get(tenant)
            && e.inserted.elapsed() < self.safety_ttl
        {
            return e.bindings.clone();
        }
        // Absent or past-TTL: drop any stale entry, then reload.
        self.map.remove(tenant);
        let rows = match crate::functions::schema::list_functions(pool).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(tenant, error = %e, "binding load failed — treating as none");
                return Arc::new(Vec::new());
            }
        };
        let bindings: Vec<Binding> = rows
            .into_iter()
            .filter(|r| r.active)
            .filter_map(|r| match parse_triggers(&r.triggers_json) {
                Ok(triggers) => Some(Binding {
                    function_name: r.name,
                    triggers,
                }),
                Err(e) => {
                    // A bound function silently never firing is this
                    // codebase's textbook silent-misbehavior class — log it.
                    tracing::warn!(
                        tenant,
                        function = %r.name,
                        error = %e,
                        "stored triggers_json unparseable — function will not fire"
                    );
                    None
                }
            })
            .collect();
        let arc = Arc::new(bindings);
        self.map.insert(
            tenant.to_string(),
            CacheEntry {
                inserted: Instant::now(),
                bindings: arc.clone(),
            },
        );
        arc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_both_shapes() {
        let l = parse_triggers(
            r#"[{"collection":"posts","events":["created","deleted"]},{"file_uploaded":true}]"#,
        )
        .expect("parse");
        assert_eq!(l.len(), 2);
        let b = Binding {
            function_name: "f".into(),
            triggers: l,
        };
        assert!(b.matches_record("posts", "created"));
        assert!(b.matches_record("posts", "deleted"));
        assert!(!b.matches_record("posts", "updated"));
        assert!(!b.matches_record("other", "created"));
        assert!(b.matches_file_uploaded());
    }

    #[test]
    fn parse_rejects_unknown_event_and_empty_collection() {
        assert!(parse_triggers(r#"[{"collection":"x","events":["upserted"]}]"#).is_err());
        assert!(parse_triggers(r#"[{"collection":"","events":["created"]}]"#).is_err());
        // A Record trigger with zero events can never match — reject at parse.
        assert!(parse_triggers(r#"[{"collection":"x","events":[]}]"#).is_err());
        assert!(parse_triggers("not json").is_err());
    }

    #[test]
    fn file_uploaded_false_does_not_match() {
        let l = parse_triggers(r#"[{"file_uploaded":false}]"#).expect("parse");
        let b = Binding {
            function_name: "f".into(),
            triggers: l,
        };
        assert!(!b.matches_file_uploaded());
    }

    #[tokio::test]
    async fn cache_invalidate_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let reg = std::sync::Arc::new(crate::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        ));
        let pool = reg.get_or_open("t-b").unwrap();
        let cache = BindingCache::new();
        assert!(cache.get_or_load("t-b", &pool).await.is_empty());

        crate::functions::schema::create_function(
            &pool,
            crate::functions::schema::CreateFunctionParams {
                name: "f1".into(),
                wasm_sha256: "00".repeat(32),
                size_bytes: 1,
                triggers_json: r#"[{"file_uploaded":true}]"#.into(),
                description: String::new(),
            },
            10,
        )
        .await
        .unwrap();

        // stale until invalidated
        assert!(cache.get_or_load("t-b", &pool).await.is_empty());
        cache.invalidate("t-b");
        assert_eq!(cache.get_or_load("t-b", &pool).await.len(), 1);
    }

    /// Layer 2 (safety TTL): with a zero TTL every cached entry is already
    /// past its validity window, so a write whose invalidate hook was missed
    /// (or raced the load/insert) is still picked up on the next read — the
    /// staleness bound is ≤ TTL, never indefinite. Deterministic: no sleeps,
    /// `Duration::ZERO` makes `elapsed() < ttl` false immediately.
    #[tokio::test]
    async fn zero_safety_ttl_bounds_missed_invalidate() {
        let dir = tempfile::tempdir().unwrap();
        let reg = std::sync::Arc::new(crate::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        ));
        let pool = reg.get_or_open("t-ttl").unwrap();
        let cache = BindingCache::with_safety_ttl(std::time::Duration::ZERO);
        assert!(cache.get_or_load("t-ttl", &pool).await.is_empty());

        crate::functions::schema::create_function(
            &pool,
            crate::functions::schema::CreateFunctionParams {
                name: "f1".into(),
                wasm_sha256: "00".repeat(32),
                size_bytes: 1,
                triggers_json: r#"[{"file_uploaded":true}]"#.into(),
                description: String::new(),
            },
            10,
        )
        .await
        .unwrap();

        // Deliberately NO invalidate() — the TTL alone forces the reload.
        assert_eq!(cache.get_or_load("t-ttl", &pool).await.len(), 1);
    }

    /// A stored row whose triggers_json no longer parses (DB corruption,
    /// binary downgrade after a trigger-shape extension) is dropped — with a
    /// warn log — without poisoning the rest of the tenant's bindings.
    /// `schema::create_function` does not validate triggers_json (validation
    /// lives at the routes/MCP layer), which models exactly this state.
    #[tokio::test]
    async fn unparseable_stored_row_dropped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let reg = std::sync::Arc::new(crate::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        ));
        let pool = reg.get_or_open("t-bad").unwrap();
        for (name, triggers) in [("good", r#"[{"file_uploaded":true}]"#), ("bad", "not json")] {
            crate::functions::schema::create_function(
                &pool,
                crate::functions::schema::CreateFunctionParams {
                    name: name.into(),
                    wasm_sha256: "00".repeat(32),
                    size_bytes: 1,
                    triggers_json: triggers.into(),
                    description: String::new(),
                },
                10,
            )
            .await
            .unwrap();
        }
        let b = BindingCache::new().get_or_load("t-bad", &pool).await;
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].function_name, "good");
    }
}

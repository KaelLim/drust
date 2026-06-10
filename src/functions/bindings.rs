//! Trigger parsing + per-tenant binding cache.
//!
//! `BindingCache` is invalidate-on-write (auth_cache precedent). Writers
//! (EXHAUSTIVE, all in functions::routes + mcp::tools::functions +
//! mgmt::functions_admin): create_function, delete_function, set_active,
//! update_meta. Every code path that mutates `_system_functions` MUST call
//! `cache.invalidate(tenant)` after the write commits — v1.35 lesson:
//! enumerate by grepping all writers before merge.

use crate::storage::pool::SharedTenantPool;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// One entry of `triggers_json`. Two shapes:
///   {"collection":"posts","events":["created","updated"]}
///   {"file_uploaded":true}
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
    let list: Vec<TriggerSpec> = serde_json::from_str(s)
        .map_err(|e| anyhow::anyhow!("FN_TRIGGERS_INVALID: {e}"))?;
    for t in &list {
        if let TriggerSpec::Record { events, collection } = t {
            if collection.is_empty() {
                anyhow::bail!("FN_TRIGGERS_INVALID: empty collection");
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
            TriggerSpec::Record { collection: c, events } => {
                c == collection && events.iter().any(|e| e == event_name)
            }
            TriggerSpec::FileUploaded { .. } => false,
        })
    }
    pub fn matches_file_uploaded(&self) -> bool {
        self.triggers
            .iter()
            .any(|t| matches!(t, TriggerSpec::FileUploaded { file_uploaded: true }))
    }
}

/// Per-tenant cache of ACTIVE bindings. `None` entry = not loaded yet.
#[derive(Default)]
pub struct BindingCache {
    map: DashMap<String, Arc<Vec<Binding>>>,
}

impl BindingCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn invalidate(&self, tenant: &str) {
        self.map.remove(tenant);
    }

    /// Cached read; on miss loads ACTIVE rows from `_system_functions`.
    /// A tenant with zero functions caches an empty Vec — the hot-path
    /// cost for function-less tenants is one DashMap get.
    pub async fn get_or_load(
        &self,
        tenant: &str,
        pool: &SharedTenantPool,
    ) -> Arc<Vec<Binding>> {
        if let Some(b) = self.map.get(tenant) {
            return b.clone();
        }
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
            .filter_map(|r| {
                parse_triggers(&r.triggers_json)
                    .ok()
                    .map(|triggers| Binding { function_name: r.name, triggers })
            })
            .collect();
        let arc = Arc::new(bindings);
        self.map.insert(tenant.to_string(), arc.clone());
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
        let b = Binding { function_name: "f".into(), triggers: l };
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
        assert!(parse_triggers("not json").is_err());
    }

    #[test]
    fn file_uploaded_false_does_not_match() {
        let l = parse_triggers(r#"[{"file_uploaded":false}]"#).expect("parse");
        let b = Binding { function_name: "f".into(), triggers: l };
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
}

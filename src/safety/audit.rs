use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Cloneable carrier for handler-supplied audit metadata. Index DDL
/// handlers attach this via `Response.extensions_mut().insert(AuditExtra(...))`,
/// which the audit-emit point in `bearer_auth_layer` reads and merges
/// into the entry via `with_extra`.
#[derive(Clone, Debug)]
pub struct AuditExtra(pub serde_json::Value);

/// Default audit metadata derived from the authentication context, set
/// by `bearer_auth_layer` once per request. Merged BEFORE `AuditExtra`,
/// so handler-supplied keys override these defaults.
#[derive(Clone, Debug)]
pub struct DefaultAuditExtra(pub serde_json::Value);

/// `tenant` / `token_hint` are `"-"` on admin-plane rows (e.g. admin OAuth
/// callback) that aren't tenant-scoped — the admin audit UI filters on
/// presence of the typed `oauth_*` fields, not on these sentinels.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub ts: String,
    pub tenant: String,
    pub token_hint: String,
    pub op: String,
    pub status: String,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    /// `"<invalid>"` when the upstream address fails `validate_email`;
    /// otherwise lowercased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_error_code: Option<String>,
    /// Admin attribution for service-equivalent callers (v1.29+).
    /// Populated by `bearer_auth_layer` when the bearer is a PAT (`drust_pat_*`)
    /// or an OAuth access token (`drust_at_*`). `None` for shared per-tenant
    /// service tokens (no admin identity available). Top-level (NOT inside
    /// `extra`) so SQL queries can `WHERE actor_admin_id = ?`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_admin_id: Option<i64>,
    /// Email snapshot at the moment of audit emission, paired with
    /// `actor_admin_id`. Snapshot rather than FK so historical rows survive
    /// admin row deletion. `None` when `actor_admin_id` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_email_snapshot: Option<String>,
    /// Extra top-level keys for op-specific metadata (index_name, row_count, etc.).
    /// Flattened on serialisation; empty map is skipped.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl AuditEntry {
    pub fn success(tenant: &str, token_hint: &str, op: &str, duration_ms: u64) -> Self {
        Self {
            ts: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            tenant: tenant.to_string(),
            token_hint: token_hint.to_string(),
            op: op.to_string(),
            status: "ok".to_string(),
            duration_ms,
            collection: None,
            sql_hash: None,
            record_id: None,
            error_code: None,
            error_message: None,
            auth_method: None,
            oauth_email: None,
            oauth_error_code: None,
            actor_admin_id: None,
            actor_email_snapshot: None,
            extra: serde_json::Map::new(),
        }
    }
    pub fn failure(
        tenant: &str,
        token_hint: &str,
        op: &str,
        duration_ms: u64,
        code: &str,
        msg: &str,
    ) -> Self {
        Self {
            ts: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            tenant: tenant.to_string(),
            token_hint: token_hint.to_string(),
            op: op.to_string(),
            status: "error".to_string(),
            duration_ms,
            collection: None,
            sql_hash: None,
            record_id: None,
            error_code: Some(code.to_string()),
            error_message: Some(msg.to_string()),
            auth_method: None,
            oauth_email: None,
            oauth_error_code: None,
            actor_admin_id: None,
            actor_email_snapshot: None,
            extra: serde_json::Map::new(),
        }
    }
    pub fn with_collection(mut self, c: &str) -> Self {
        self.collection = Some(c.to_string());
        self
    }
    pub fn with_sql_hash(mut self, h: &str) -> Self {
        self.sql_hash = Some(h.to_string());
        self
    }
    pub fn with_record_id(mut self, id: i64) -> Self {
        self.record_id = Some(id);
        self
    }
    pub fn with_extra(mut self, value: serde_json::Value) -> Self {
        if let serde_json::Value::Object(m) = value {
            self.extra.extend(m);
        }
        self
    }

    /// Serialise the `extra` flatten map to a compact JSON string for display
    /// in the audit UI. Returns `None` when the map is empty so templates can
    /// skip the block entirely.
    pub fn extra_as_json(&self) -> Option<String> {
        if self.extra.is_empty() {
            return None;
        }
        // Use a BTreeMap round-trip to get deterministic key ordering.
        let ordered: std::collections::BTreeMap<&str, &serde_json::Value> =
            self.extra.iter().map(|(k, v)| (k.as_str(), v)).collect();
        serde_json::to_string(&ordered).ok()
    }
}

/// Spec S6: path whitelist gating future body logging. Auth bodies must never be persisted.
pub fn should_log_body(path: &str) -> bool {
    !path.contains("/auth/")
        && !path.contains("/admin/settings/token/reroll")
        && !path.contains("/admin/settings/token") // defense-in-depth: future siblings
}

/// Stateless one-shot dispatch to the global SQLite audit writer.
/// Used by auth flows + the per-request `bearer_auth_layer` audit emit
/// point. `_dir` is retained for caller-site compatibility after
/// v1.25.2 retired the JSONL writer and v1.32.1 retired the
/// `AuditLog` carrier struct entirely — see CHANGELOG.
pub async fn write_entry(_dir: &std::path::Path, entry: &AuditEntry) {
    crate::safety::audit_db::try_send(entry);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_carries_actor_attribution_fields() {
        let mut e = AuditEntry::success("tenant-x", "abcd", "GET /thing", 5);
        e.actor_admin_id = Some(7);
        e.actor_email_snapshot = Some("kael@example.com".into());
        let j: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(j["actor_admin_id"], serde_json::json!(7));
        assert_eq!(j["actor_email_snapshot"], serde_json::json!("kael@example.com"));
    }

    #[test]
    fn audit_entry_omits_actor_fields_when_none() {
        let e = AuditEntry::success("tenant-x", "abcd", "GET /thing", 5);
        let j: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert!(j.get("actor_admin_id").is_none(),  "actor_admin_id should be skipped when None");
        assert!(j.get("actor_email_snapshot").is_none(),  "actor_email_snapshot should be skipped when None");
    }

    /// v1.32.1 — moved from the retired `tests/audit_log.rs` integration
    /// file. `with_extra` must flatten an object value into top-level
    /// JSON keys via `serde(flatten)`.
    #[test]
    fn with_extra_flattens_into_top_level_json() {
        let entry = AuditEntry::success("t1", "drust_abc", "POST /collections/foo/indexes", 42)
            .with_collection("foo")
            .with_extra(serde_json::json!({
                "index_name":   "idx_foo_bar",
                "index_fields": ["bar"],
                "row_count":    18432,
                "force_used":   false,
            }));
        let line = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["index_name"], "idx_foo_bar");
        assert_eq!(v["index_fields"], serde_json::json!(["bar"]));
        assert_eq!(v["row_count"], 18432);
        assert_eq!(v["force_used"], false);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["collection"], "foo");
    }

    /// v1.32.1 — moved from the retired `tests/audit_log.rs`. Non-object
    /// `extra` values are silently dropped (no panic, no leaked key).
    #[test]
    fn with_extra_ignores_non_object_value() {
        let entry = AuditEntry::success("t1", "h", "op", 0)
            .with_extra(serde_json::json!("not an object"));
        let line = serde_json::to_string(&entry).unwrap();
        assert!(!line.contains("not an object"));
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::*;

    #[test]
    fn auth_paths_block_body_logging() {
        assert!(!should_log_body("/t/abc/auth/login"));
        assert!(!should_log_body("/t/abc/auth/register"));
        assert!(!should_log_body("/t/abc/auth/logout"));
    }
    #[test]
    fn non_auth_paths_allow_body_logging() {
        assert!(should_log_body("/t/abc/records/posts"));
        assert!(should_log_body("/t/abc/me"));
        assert!(should_log_body("/t/abc/query"));
    }
    #[test]
    fn pat_reroll_path_blocks_body_logging() {
        assert!(!should_log_body("/drust/admin/settings/token/reroll"));
        assert!(!should_log_body("/admin/settings/token/reroll"));
        // Any future endpoint under /admin/settings/token also blocked.
        assert!(!should_log_body("/admin/settings/token"));
    }
}

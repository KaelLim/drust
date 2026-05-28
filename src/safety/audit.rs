use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

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

/// Audit-log writer. Non-blocking append: callers send entries through
/// an unbounded mpsc to a dedicated writer task that batches file
/// I/O off the request hot path. The previous design serialised every
/// request on a single `Mutex<()>` and lost lines on SIGTERM because
/// the per-request `tokio::spawn` futures were dropped mid-write.
pub struct AuditLog {
    tx: mpsc::UnboundedSender<AuditEntry>,
    log_dir: PathBuf,
}

impl AuditLog {
    /// Directory containing the daily `audit-YYYY-MM-DD.jsonl` files.
    /// Exposed so code paths that don't carry the `Arc<AuditLog>` (e.g.
    /// per-tenant OAuth callback's stateless `write_entry` call) can
    /// resolve the same directory without re-reading env vars.
    pub fn log_dir(&self) -> &std::path::Path {
        &self.log_dir
    }
}

/// Returned by `AuditLog::start`. Holding the handle lets graceful
/// shutdown await the writer's drain after the request server has
/// stopped, so no audit lines are lost on SIGTERM.
pub struct AuditWriterHandle(tokio::task::JoinHandle<()>);

impl AuditWriterHandle {
    /// Wait for the writer task to finish draining. Caller is
    /// responsible for first dropping every `Arc<AuditLog>` clone so
    /// the channel closes; otherwise this awaits forever.
    pub async fn join(self) {
        let _ = self.0.await;
    }
}

impl AuditLog {
    /// Test/lib-internal constructor: spawns the writer and forgets
    /// the handle. The dropped handle does not abort the task; it
    /// keeps writing for as long as the runtime lives.
    pub fn new(dir: PathBuf) -> Self {
        let (audit, _h) = Self::start(dir);
        audit
    }

    /// Production constructor: returns the writer's `JoinHandle` so
    /// `main` can await it on graceful shutdown.
    pub fn start(dir: PathBuf) -> (Self, AuditWriterHandle) {
        let (tx, mut rx) = mpsc::unbounded_channel::<AuditEntry>();
        let dir_for_writer = dir.clone();
        let handle = tokio::spawn(async move {
            let mut current_path: Option<PathBuf> = None;
            let mut current_file: Option<tokio::fs::File> = None;
            while let Some(entry) = rx.recv().await {
                let date = entry.ts.get(..10).unwrap_or(&entry.ts).to_string();
                let path = dir_for_writer.join(format!("audit-{date}.jsonl"));
                if current_path.as_ref() != Some(&path) {
                    if let Some(mut f) = current_file.take() {
                        let _ = f.flush().await;
                    }
                    let _ = tokio::fs::create_dir_all(&dir_for_writer).await;
                    current_file = tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                        .await
                        .ok();
                    current_path = if current_file.is_some() {
                        Some(path)
                    } else {
                        None
                    };
                }
                if let (Some(f), Ok(mut line)) =
                    (current_file.as_mut(), serde_json::to_string(&entry))
                {
                    line.push('\n');
                    if let Err(e) = f.write_all(line.as_bytes()).await {
                        tracing::warn!(error = %e, "audit write_all failed");
                        continue;
                    }
                    if let Err(e) = f.flush().await {
                        tracing::warn!(error = %e, "audit flush failed");
                    }
                }
            }
            // Channel closed — flush + close the open file before exit.
            if let Some(mut f) = current_file.take() {
                let _ = f.flush().await;
            }
        });
        (
            Self {
                tx,
                log_dir: dir,
            },
            AuditWriterHandle(handle),
        )
    }

    /// Enqueue one audit entry. O(1), never blocks. Drops the entry
    /// silently if the writer task has exited (only on shutdown).
    pub fn append(&self, entry: AuditEntry) {
        let _ = self.tx.send(entry);
    }
}

/// Stateless one-shot dispatch to the global SQLite audit writer.
/// Used by auth flows that don't carry the shared `Arc<AuditLog>` —
/// admin + per-tenant OAuth callbacks and admin login / password
/// endpoints. `_dir` is retained for caller-site compatibility after
/// v1.25.2 retired the JSONL writer — see CHANGELOG; v1.25.3+ may
/// drop the parameter.
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

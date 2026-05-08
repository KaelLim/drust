use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

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
}

/// Audit-log writer. Non-blocking append: callers send entries through
/// an unbounded mpsc to a dedicated writer task that batches file
/// I/O off the request hot path. The previous design serialised every
/// request on a single `Mutex<()>` and lost lines on SIGTERM because
/// the per-request `tokio::spawn` futures were dropped mid-write.
pub struct AuditLog {
    tx: mpsc::UnboundedSender<AuditEntry>,
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
        (Self { tx }, AuditWriterHandle(handle))
    }

    /// Enqueue one audit entry. O(1), never blocks. Drops the entry
    /// silently if the writer task has exited (only on shutdown).
    pub fn append(&self, entry: AuditEntry) {
        let _ = self.tx.send(entry);
    }
}

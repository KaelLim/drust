use chrono::Utc;
use serde::Serialize;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Debug, Serialize, Clone)]
pub struct AuditEntry {
    pub ts: String,
    pub tenant: String,
    pub token_hint: String,
    pub op: String,
    pub status: &'static str,
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
}

impl AuditEntry {
    pub fn success(tenant: &str, token_hint: &str, op: &str, duration_ms: u64) -> Self {
        Self {
            ts: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            tenant: tenant.to_string(),
            token_hint: token_hint.to_string(),
            op: op.to_string(),
            status: "ok",
            duration_ms,
            collection: None,
            sql_hash: None,
            record_id: None,
            error_code: None,
            error_message: None,
        }
    }
    pub fn failure(tenant: &str, token_hint: &str, op: &str, duration_ms: u64, code: &str, msg: &str) -> Self {
        Self {
            ts: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            tenant: tenant.to_string(),
            token_hint: token_hint.to_string(),
            op: op.to_string(),
            status: "error",
            duration_ms,
            collection: None,
            sql_hash: None,
            record_id: None,
            error_code: Some(code.to_string()),
            error_message: Some(msg.to_string()),
        }
    }
    pub fn with_collection(mut self, c: &str) -> Self { self.collection = Some(c.to_string()); self }
    pub fn with_sql_hash(mut self, h: &str) -> Self { self.sql_hash = Some(h.to_string()); self }
    pub fn with_record_id(mut self, id: i64) -> Self { self.record_id = Some(id); self }
}

pub struct AuditLog {
    dir: PathBuf,
    write_lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, write_lock: Mutex::new(()) }
    }

    fn file_path_for_today(&self) -> PathBuf {
        let date = Utc::now().format("%Y-%m-%d");
        self.dir.join(format!("audit-{date}.jsonl"))
    }

    pub async fn append(&self, entry: AuditEntry) -> anyhow::Result<()> {
        let _guard = self.write_lock.lock().await;
        tokio::fs::create_dir_all(&self.dir).await?;
        let path = self.file_path_for_today();
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }
}

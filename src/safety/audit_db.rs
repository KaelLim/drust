//! v1.24 — SQLite-backed audit log storage. See spec
//! docs/superpowers/specs/2026-05-23-drust-audit-sqlite-design.md.
//!
//! Lives in src/safety/ alongside the existing JSONL-based audit.rs.
//! Both write paths run in parallel during the v1.24 dual-write window;
//! the JSONL writer is removed in v1.26 once SQLite has proven stable
//! in production.

use anyhow::Context;
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS audit (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  ts               TEXT    NOT NULL,
  tenant           TEXT    NOT NULL DEFAULT '-',
  token_hint       TEXT    NOT NULL DEFAULT '-',
  op               TEXT    NOT NULL,
  status           TEXT    NOT NULL,
  duration_ms      INTEGER NOT NULL DEFAULT 0,
  error_code       TEXT,
  auth_method      TEXT,
  oauth_email      TEXT,
  oauth_error_code TEXT,
  caller_ip        TEXT,
  user_agent       TEXT,
  extra            TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_ts        ON audit(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit(tenant, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_status_ts ON audit(ts DESC) WHERE status = 'error';
";

const PRAGMAS_WRITE: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = OFF;
PRAGMA wal_autocheckpoint = 1000;
";

const PRAGMAS_READ: &str = "
PRAGMA query_only = ON;
PRAGMA busy_timeout = 5000;
";

const CHANNEL_CAPACITY: usize = 1000;
const FLUSH_INTERVAL_MS: u64 = 100;
const FLUSH_BATCH_SIZE: usize = 100;

const INSERT_SQL: &str = "
INSERT INTO audit (ts, tenant, token_hint, op, status, duration_ms,
                   error_code, auth_method, oauth_email, oauth_error_code,
                   caller_ip, user_agent, extra)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";

/// Open the audit DB in read-write mode and apply schema + write PRAGMAs.
/// Idempotent: CREATE TABLE IF NOT EXISTS + index CREATE IF NOT EXISTS.
pub fn open_audit_db_write(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening audit DB at {}", path.display()))?;
    conn.execute_batch(PRAGMAS_WRITE)
        .with_context(|| format!("opening audit DB at {}", path.display()))?;
    conn.execute_batch(SCHEMA_SQL)
        .with_context(|| format!("opening audit DB at {}", path.display()))?;
    Ok(conn)
}

/// Open the audit DB in read-only mode. Caller is responsible for
/// ensuring the file exists (open_audit_db_write was called at least
/// once first).
pub fn open_audit_db_read(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("opening audit DB read-only at {}", path.display()))?;
    conn.execute_batch(PRAGMAS_READ)
        .with_context(|| format!("opening audit DB read-only at {}", path.display()))?;
    Ok(conn)
}

/// v1.24 — extracted-column shape returned by `hoist_indexed_fields`.
/// The writer task uses these as direct column values during INSERT;
/// `remaining_json` (the post-hoist `extra` map serialised) goes into
/// the `extra` column as a JSON blob.
pub struct HoistResult {
    pub caller_ip: Option<String>,
    pub user_agent: Option<String>,
    /// Post-hoist map serialised. `None` when the map is empty after
    /// removing caller_ip + user_agent.
    pub remaining_json: Option<String>,
}

/// Remove `caller_ip` and `user_agent` (if present as strings) from the
/// passed-in `extra` map and return them as separate fields. The
/// remaining map serialises as JSON for the `extra` column. Non-string
/// values for those keys are left in the map (will go into `extra`).
pub fn hoist_indexed_fields(
    mut extra: serde_json::Map<String, serde_json::Value>,
) -> HoistResult {
    let caller_ip = take_string_key(&mut extra, "caller_ip");
    let user_agent = take_string_key(&mut extra, "user_agent");
    let remaining_json = if extra.is_empty() {
        None
    } else {
        serde_json::to_string(&serde_json::Value::Object(extra)).ok()
    };
    HoistResult { caller_ip, user_agent, remaining_json }
}

fn take_string_key(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    // Peek the value: only remove if it's a String. Leave non-String
    // values in the map so they end up in the `extra` blob and the
    // caller can debug.
    if let Some(serde_json::Value::String(_)) = map.get(key) {
        if let Some(serde_json::Value::String(s)) = map.remove(key) {
            return Some(s);
        }
    }
    None
}

/// v1.24 — process-global audit writer handle. Cheap to clone (Arc-backed
/// channel); one instance per drust process, lives forever after startup.
pub struct AuditWriter {
    tx: mpsc::Sender<WriterCmd>,
    pub dropped: Arc<AtomicU64>,
}

/// Commands accepted by the background writer task. `Insert` is the hot
/// path; `RunRetention` is invoked once per day by the retention task
/// (which sends through the same channel to preserve single-owner-of-
/// connection semantics — no Mutex contention between writer and
/// retention).
pub enum WriterCmd {
    Insert(crate::safety::audit::AuditEntry),
    RunRetention { cutoff_ts: String, vacuum: bool },
}

impl AuditWriter {
    /// Spawn the background writer task and return a handle. The task
    /// owns the rw connection for its entire lifetime; commands flow
    /// through the mpsc channel.
    pub fn new(conn: Connection) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_tx = tx.clone();
        tokio::spawn(writer_loop(conn, rx));
        Self { tx: writer_tx, dropped }
    }

    /// Non-blocking dispatch from a request handler. On channel-full,
    /// drops the entry, increments the counter, and logs a warning.
    /// Returns immediately regardless of writer-task state.
    fn try_send_inner(&self, entry: &crate::safety::audit::AuditEntry) {
        match self.tx.try_send(WriterCmd::Insert(entry.clone())) {
            Ok(_) => {}
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("audit write dropped (channel full)");
            }
        }
    }

    /// Used by the retention task. Blocking send is acceptable because
    /// retention runs on its own task, not in a request path.
    pub async fn send_retention(&self, cutoff_ts: String, vacuum: bool) {
        if let Err(e) = self
            .tx
            .send(WriterCmd::RunRetention { cutoff_ts, vacuum })
            .await
        {
            tracing::error!(err=?e, "audit retention command send failed");
        }
    }

    /// Used by the backfill at startup. Same blocking-send semantics as
    /// retention — backfill is not in a request path.
    pub async fn send_backfill(
        &self,
        entry: crate::safety::audit::AuditEntry,
    ) -> Result<(), ()> {
        self.tx
            .send(WriterCmd::Insert(entry))
            .await
            .map_err(|_| ())
    }
}

async fn writer_loop(mut conn: Connection, mut rx: mpsc::Receiver<WriterCmd>) {
    let mut buf: Vec<crate::safety::audit::AuditEntry> =
        Vec::with_capacity(FLUSH_BATCH_SIZE);
    let flush_window = std::time::Duration::from_millis(FLUSH_INTERVAL_MS);
    loop {
        let timeout = tokio::time::sleep(flush_window);
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                maybe_cmd = rx.recv() => {
                    match maybe_cmd {
                        Some(WriterCmd::Insert(e)) => {
                            buf.push(e);
                            if buf.len() >= FLUSH_BATCH_SIZE { break; }
                        }
                        Some(WriterCmd::RunRetention { cutoff_ts, vacuum }) => {
                            // Drain in-flight buf first so the DELETE sees a consistent view.
                            if !buf.is_empty() {
                                flush(&mut conn, &mut buf);
                            }
                            run_retention(&mut conn, &cutoff_ts, vacuum);
                            break;
                        }
                        None => {
                            // channel closed — drain and exit (shutdown path)
                            if !buf.is_empty() {
                                flush(&mut conn, &mut buf);
                            }
                            tracing::info!("audit writer loop: channel closed, exiting");
                            return;
                        }
                    }
                }
                _ = &mut timeout => break,
            }
        }
        if !buf.is_empty() {
            flush(&mut conn, &mut buf);
        }
    }
}

fn flush(conn: &mut Connection, buf: &mut Vec<crate::safety::audit::AuditEntry>) {
    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(err=?e, count=buf.len(), "audit flush: open transaction");
            buf.clear();
            return;
        }
    };
    {
        let mut stmt = match tx.prepare_cached(INSERT_SQL) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(err=?e, "audit flush: prepare");
                buf.clear();
                return;
            }
        };
        for entry in buf.drain(..) {
            let hoist = hoist_indexed_fields(entry.extra);
            let r = stmt.execute(params![
                entry.ts,
                entry.tenant,
                entry.token_hint,
                entry.op,
                entry.status,
                entry.duration_ms,
                entry.error_code,
                entry.auth_method,
                entry.oauth_email,
                entry.oauth_error_code,
                hoist.caller_ip,
                hoist.user_agent,
                hoist.remaining_json,
            ]);
            if let Err(e) = r {
                tracing::error!(err=?e, "audit flush: insert");
                // Continue — one bad row shouldn't bin the batch.
            }
        }
    }
    if let Err(e) = tx.commit() {
        tracing::error!(err=?e, "audit flush: commit");
    }
}

fn run_retention(conn: &mut Connection, cutoff_ts: &str, vacuum: bool) {
    match conn.execute("DELETE FROM audit WHERE ts < ?1", params![cutoff_ts]) {
        Ok(n) => tracing::info!(deleted = n, cutoff = %cutoff_ts, "audit retention"),
        Err(e) => tracing::error!(err=?e, "audit retention DELETE"),
    }
    if vacuum {
        if let Err(e) = conn.execute("VACUUM", []) {
            tracing::error!(err=?e, "audit VACUUM");
        } else {
            tracing::info!("audit VACUUM complete");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_audit.sqlite");
        (dir, path)
    }

    #[test]
    fn open_creates_table_and_indexes() {
        let (_dir, path) = tmp_db();
        let conn = open_audit_db_write(&path).unwrap();
        let idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'index' AND tbl_name = 'audit' \
                 AND name LIKE 'idx_audit_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 3, "expect 3 indexes (ts / tenant_ts / status_ts)");
    }

    #[test]
    fn open_is_idempotent_on_second_call() {
        let (_dir, path) = tmp_db();
        let _c1 = open_audit_db_write(&path).unwrap();
        // Second open should not error on existing table / indexes.
        let _c2 = open_audit_db_write(&path).unwrap();
    }

    #[test]
    fn schema_is_strict_mode() {
        let (_dir, path) = tmp_db();
        let conn = open_audit_db_write(&path).unwrap();
        // STRICT mode enforces declared column type. Note: TEXT affinity
        // still coerces INTEGER/REAL → TEXT silently (per SQLite STRICT
        // rules — see https://www.sqlite.org/stricttables.html), so the
        // proof has to be BLOB into TEXT, which STRICT genuinely rejects
        // with `cannot store BLOB value in TEXT column`.
        let r = conn.execute(
            "INSERT INTO audit (ts, op, status) VALUES (?1, ?2, ?3)",
            params![vec![0u8, 1u8, 2u8], "GET /x", "ok"], // BLOB into ts (TEXT)
        );
        assert!(r.is_err(), "STRICT should reject BLOB into TEXT column");
    }

    #[test]
    fn read_connection_rejects_inserts() {
        let (_dir, path) = tmp_db();
        let _w = open_audit_db_write(&path).unwrap();
        let r = open_audit_db_read(&path).unwrap();
        let res = r.execute(
            "INSERT INTO audit (ts, op, status) VALUES ('2026-05-23T00:00:00Z', 'x', 'ok')",
            [],
        );
        assert!(res.is_err(), "read-only conn must reject writes");
    }

    #[test]
    fn hoist_extracts_caller_ip_and_user_agent_strings() {
        let mut extra = serde_json::Map::new();
        extra.insert("caller_ip".into(), serde_json::json!("203.0.113.5"));
        extra.insert("user_agent".into(), serde_json::json!("curl/8.0"));
        extra.insert("auth_kind".into(), serde_json::json!("admin"));
        let result = hoist_indexed_fields(extra);
        assert_eq!(result.caller_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(result.user_agent.as_deref(), Some("curl/8.0"));
        // remaining holds only auth_kind
        let remaining_json = result.remaining_json.expect("remaining");
        assert!(remaining_json.contains("\"auth_kind\":\"admin\""));
        assert!(!remaining_json.contains("caller_ip"));
        assert!(!remaining_json.contains("user_agent"));
    }

    #[test]
    fn hoist_empty_extra_returns_all_none() {
        let result = hoist_indexed_fields(serde_json::Map::new());
        assert!(result.caller_ip.is_none());
        assert!(result.user_agent.is_none());
        assert!(result.remaining_json.is_none());
    }

    #[test]
    fn hoist_leaves_non_string_caller_ip_in_remaining() {
        let mut extra = serde_json::Map::new();
        // Wrong type — `caller_ip` is a number for some reason.
        extra.insert("caller_ip".into(), serde_json::json!(12345));
        let result = hoist_indexed_fields(extra);
        assert!(result.caller_ip.is_none(), "non-string ignored");
        // The number stays in remaining so the bug is visible in extra.
        let remaining_json = result.remaining_json.expect("remaining");
        assert!(remaining_json.contains("\"caller_ip\":12345"));
    }

    #[test]
    fn hoist_empty_after_extraction_returns_none_for_remaining() {
        let mut extra = serde_json::Map::new();
        extra.insert("caller_ip".into(), serde_json::json!("1.2.3.4"));
        let result = hoist_indexed_fields(extra);
        assert_eq!(result.caller_ip.as_deref(), Some("1.2.3.4"));
        assert!(result.remaining_json.is_none(), "empty map → None, not 'null'");
    }

    fn mk_entry(ts: &str, tenant: &str, op: &str, status: &str, ms: u64) -> crate::safety::audit::AuditEntry {
        let mut e = crate::safety::audit::AuditEntry::success(tenant, "-", op, ms);
        e.ts = ts.to_string();
        if status == "error" {
            e.status = "error".to_string();
        }
        e
    }

    #[tokio::test]
    async fn writer_single_entry_round_trip() {
        let (_dir, path) = tmp_db();
        let conn = open_audit_db_write(&path).unwrap();
        let w = AuditWriter::new(conn);
        let entry = mk_entry("2026-05-23T01:00:00.000Z", "acme", "GET /x", "ok", 12);
        w.send_backfill(entry).await.unwrap();
        // Give the writer 200 ms to flush.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let r = open_audit_db_read(&path).unwrap();
        let count: i64 = r.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
        let (tenant, op, ms): (String, String, i64) = r
            .query_row("SELECT tenant, op, duration_ms FROM audit", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(tenant, "acme");
        assert_eq!(op, "GET /x");
        assert_eq!(ms, 12);
    }

    #[tokio::test]
    async fn writer_batches_100_entries() {
        let (_dir, path) = tmp_db();
        let conn = open_audit_db_write(&path).unwrap();
        let w = AuditWriter::new(conn);
        for i in 0..100 {
            let entry = mk_entry(
                &format!("2026-05-23T01:00:{:02}.000Z", i % 60),
                "acme", "GET /x", "ok", i as u64,
            );
            w.send_backfill(entry).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let r = open_audit_db_read(&path).unwrap();
        let count: i64 = r.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 100);
    }
}

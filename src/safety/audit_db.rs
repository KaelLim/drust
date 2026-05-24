//! v1.24 — SQLite-backed audit log storage. See spec
//! docs/superpowers/specs/2026-05-23-drust-audit-sqlite-design.md.
//!
//! Lives in src/safety/ alongside the existing JSONL-based audit.rs.
//! Both write paths run in parallel during the v1.24 dual-write window;
//! the JSONL writer is removed in v1.26 once SQLite has proven stable
//! in production.

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
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

CREATE TABLE IF NOT EXISTS _meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;
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

    // v1.24.2 one-time migration: if the audit table has rows AND the
    // legacy filesystem marker `audit-backfill.done` exists AND no `_meta`
    // sentinel is present yet, promote the marker to the in-DB sentinel.
    // Without this, a v1.24 node upgrading to v1.24.2 would re-run
    // backfill and produce duplicates (see F2 in the design spec).
    let has_sentinel: bool = conn
        .query_row(
            "SELECT 1 FROM _meta WHERE key = 'backfill_done'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .is_some();
    let has_rows: bool = conn
        .query_row("SELECT 1 FROM audit LIMIT 1", [], |_| Ok(true))
        .optional()?
        .is_some();
    let fs_marker = path
        .parent()
        .map(|p| p.join("audit-backfill.done"))
        .unwrap_or_default();
    if !has_sentinel && has_rows && fs_marker.exists() {
        // INSERT OR IGNORE so a race between concurrent opens never errors.
        conn.execute(
            "INSERT OR IGNORE INTO _meta(key, value) VALUES ('backfill_done', ?1)",
            rusqlite::params![chrono::Utc::now().to_rfc3339()],
        )?;
        tracing::info!("v1.24.2 migration: filesystem backfill marker promoted to _meta sentinel");
    }

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
    SetMeta { key: String, value: String },
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
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // Emit WARN at thresholds to bound systemd-journal spam
                // during sustained backpressure. F3 rationale: a real
                // spike can hit 1000/s and produce one identical WARN
                // per drop, masking real errors in the journal.
                if n == 1 || n % 10_000 == 0 {
                    tracing::warn!(
                        total_dropped = n,
                        "audit: channel full, entry dropped (rate-limited log)"
                    );
                }
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

    /// Persist a single key/value into the audit DB's `_meta` table
    /// via the writer task. Used by the retention task to record
    /// `last_vacuum_ts`. Single-owner-of-connection invariant preserved.
    pub async fn send_set_meta(&self, key: String, value: String) {
        let _ = self.tx.send(WriterCmd::SetMeta { key, value }).await;
    }
}

use std::sync::OnceLock;

static WRITER: OnceLock<AuditWriter> = OnceLock::new();
static DUAL_WRITE: OnceLock<bool> = OnceLock::new();

/// v1.24 — test-only helper. Opens an in-memory audit DB with the same
/// schema as `open_audit_db_write` so tests that construct `MgmtState`
/// can satisfy the `audit_meta_read` field without touching the disk.
/// Gated to test + debug builds; absent from the release binary.
#[cfg(any(test, debug_assertions))]
pub fn open_audit_db_memory() -> anyhow::Result<Connection> {
    let conn = Connection::open_in_memory()
        .with_context(|| "opening in-memory audit DB")?;
    conn.execute_batch(SCHEMA_SQL)
        .with_context(|| "applying schema to in-memory audit DB")?;
    Ok(conn)
}

/// One-time initialisation. Called from `main.rs` after the audit DB is
/// open and the writer task is spawned. Idempotent: second call is a
/// no-op (returns Err from .set, ignored).
pub fn init_globals(writer: AuditWriter, dual_write: bool) {
    let _ = WRITER.set(writer);
    let _ = DUAL_WRITE.set(dual_write);
}

/// Non-blocking dispatch from a request handler. No-op when init_globals
/// has not run yet (test paths, pre-init startup). Caller's JSONL write
/// path is independent and still runs.
pub fn try_send(entry: &crate::safety::audit::AuditEntry) {
    if let Some(w) = WRITER.get() {
        w.try_send_inner(entry);
    }
}

/// True during the v1.24 dual-write window. Default `true` when env is
/// absent or invalid. v1.25 flips the default.
pub fn dual_write_enabled() -> bool {
    *DUAL_WRITE.get().unwrap_or(&true)
}

/// Test-only / future-main-use accessor. Used by Task 7's retention task
/// to send WriterCmd::RunRetention through the same channel. NOT for use
/// from request handlers (those should use `try_send` which is the
/// non-blocking variant).
pub fn writer_for_init_use() -> Option<&'static AuditWriter> {
    WRITER.get()
}

/// Process-lifetime counter: total number of audit entries dropped
/// because the writer channel was full. Resets to 0 on restart.
/// Returns 0 when no writer is initialised (test paths, pre-init).
pub fn dropped_total() -> u64 {
    WRITER
        .get()
        .map(|w| w.dropped.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0)
}

/// Compute the next 03:00 UTC fire time strictly after `now`. If `now`
/// is exactly 03:00:00 UTC, returns the same time tomorrow (no double-fire).
pub fn next_0300_utc(now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    let today_0300 = now
        .date_naive()
        .and_hms_opt(3, 0, 0)
        .expect("3am is valid")
        .and_utc();
    if now < today_0300 {
        today_0300
    } else {
        today_0300 + chrono::Duration::days(1)
    }
}

/// Decide whether the retention pass should also run VACUUM. True when:
/// - `now` is the 1st of the month (always — preserves the original
///   month-boundary intent), OR
/// - no previous vacuum is recorded (fresh process / cold DB), OR
/// - the last recorded vacuum was in a previous month.
///
/// Last clause is what recovers from a restart on day 1 that skipped
/// the day-1 fire — by day-2+ same month, the check still returns true.
pub fn should_vacuum(
    now: chrono::DateTime<chrono::Utc>,
    last_vacuum: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    use chrono::Datelike;
    if now.day() == 1 {
        return true;
    }
    match last_vacuum {
        None => true,
        Some(last) => last.year() != now.year() || last.month() != now.month(),
    }
}

/// Read the `last_vacuum_ts` from the audit `_meta` table. Returns None
/// when the row is absent (cold DB) or unparseable. Uses the audit RO
/// connection — fast, no contention with the writer task.
pub async fn read_last_vacuum_ts(
    conn: &std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let guard = conn.lock().await;
    let s: Option<String> = guard
        .query_row(
            "SELECT value FROM _meta WHERE key = 'last_vacuum_ts'",
            [],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten();
    drop(guard);
    s.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
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
                        Some(WriterCmd::SetMeta { key, value }) => {
                            if let Err(e) = conn.execute(
                                "INSERT OR REPLACE INTO _meta(key, value) VALUES (?1, ?2)",
                                rusqlite::params![key, value],
                            ) {
                                tracing::warn!(error = %e, key = %key, "audit: _meta write failed");
                            }
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

/// v1.24.2 — transactional, synchronous backfill. Replaces v1.24's
/// `backfill_from_jsonl` which used `tokio::spawn` + channel + drain wait
/// + filesystem marker. Now: own RW connection, single BEGIN...COMMIT
/// wrapping every INSERT + the sentinel row.
///
/// Caller MUST invoke via `tokio::task::spawn_blocking`. Holds a write
/// lock on `meta_logs.sqlite` for the duration of the transaction
/// (production-confirmed: ~9s for ~2.58M rows). Run BEFORE the
/// `AuditWriter` is spawned to keep this the only writer.
pub fn backfill_from_jsonl_sync(
    audit_db_path: &Path,
    log_dir: &Path,
) -> anyhow::Result<u64> {
    let mut conn = open_audit_db_write(audit_db_path).with_context(|| {
        format!("opening audit DB for backfill at {}", audit_db_path.display())
    })?;

    // Sentinel check: skip if already done
    let already: Option<String> = conn
        .query_row(
            "SELECT value FROM _meta WHERE key = 'backfill_done'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if already.is_some() {
        tracing::info!("audit backfill: sentinel present, skipping");
        return Ok(0);
    }

    let entries = read_all_jsonl(log_dir);
    let expected = entries.len() as u64;
    tracing::info!(parsed = expected, "audit backfill: parsed JSONL files");

    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(INSERT_SQL)?;
        for e in &entries {
            let h = hoist_indexed_fields(e.extra.clone());
            stmt.execute(rusqlite::params![
                e.ts,
                e.tenant,
                e.token_hint,
                e.op,
                e.status,
                e.duration_ms,
                e.error_code.as_deref(),
                e.auth_method.as_deref(),
                e.oauth_email.as_deref(),
                e.oauth_error_code.as_deref(),
                h.caller_ip,
                h.user_agent,
                h.remaining_json,
            ])?;
        }
        tx.execute(
            "INSERT INTO _meta(key, value) VALUES ('backfill_done', ?1)",
            rusqlite::params![chrono::Utc::now().to_rfc3339()],
        )?;
    }
    tx.commit()?;
    tracing::info!(rows = expected, "audit backfill: committed atomically");
    Ok(expected)
}

/// Walk `log_dir` for `audit-*.jsonl{,.N,.gz}` files and parse each.
/// Order is by filename (date-prefixed names sort lexically = chronologically).
/// Skips files that fail to read; logs a warn per skipped file.
fn read_all_jsonl(log_dir: &std::path::Path) -> Vec<crate::safety::audit::AuditEntry> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(err=?e, "audit backfill: log_dir read failed");
            return out;
        }
    };
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("audit-") && (
                    n.contains(".jsonl") || n.contains(".jsonl.")
                ))
        })
        .collect();
    paths.sort();
    for path in paths {
        let parsed = if path.extension().and_then(|s| s.to_str()) == Some("gz") {
            crate::mgmt::audit::read_gz(&path)
        } else {
            crate::mgmt::audit::read_plain(&path)
        };
        match parsed {
            Ok((entries, errs)) => {
                if errs > 0 {
                    tracing::warn!(file=%path.display(), errs, "audit backfill: parse errors");
                }
                out.extend(entries);
            }
            Err(e) => tracing::warn!(file=%path.display(), err=?e, "audit backfill: read failed"),
        }
    }
    out
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

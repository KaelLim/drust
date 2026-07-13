//! `_system_cron_jobs` + `_system_cron_runs` — lazy DDL (idempotent
//! `CREATE TABLE IF NOT EXISTS` run by every writer fn, so the tables appear
//! on first use with no migration step) + row CRUD. Every fn here takes a
//! bare `&rusqlite::Connection` and runs inside a `pool.with_writer` /
//! `with_reader` closure OWNED BY THE CALLER — this module never touches the
//! pool. Both tables are `_system_`-prefixed ⇒ automatically drop-protected
//! and invisible to `/records/*` / MCP record tools / SSE (storage/schema.rs).
//!
//! Reader-lane fns (`*_reader`) deliberately skip `ensure_tables` and map
//! "no such table" → empty/None (the `get_function` pattern in
//! `src/functions/schema.rs`): a tenant that never used cron must not grow
//! the tables from a read path.

use rusqlite::Connection;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS _system_cron_jobs (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  name             TEXT    NOT NULL UNIQUE,
  schedule         TEXT    NOT NULL,
  target_kind      TEXT    NOT NULL CHECK (target_kind IN ('function','rpc')),
  target_name      TEXT    NOT NULL,
  payload_json     TEXT,
  active           INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT    NOT NULL DEFAULT (datetime('now')),
  last_run_at      TEXT,
  last_status      TEXT,
  last_error       TEXT,
  last_duration_ms INTEGER
) STRICT;
CREATE TABLE IF NOT EXISTS _system_cron_runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id      INTEGER NOT NULL,
  fired_at    TEXT    NOT NULL,
  status      TEXT    NOT NULL,
  error       TEXT,
  duration_ms INTEGER
) STRICT;
CREATE INDEX IF NOT EXISTS idx_syscronruns_job ON _system_cron_runs(job_id, id DESC);
"#;

/// Newest run rows kept per job (trim-on-write in `record_run`).
const RUNS_KEEP_PER_JOB: i64 = 20;

pub fn ensure_tables(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(DDL)
}

#[derive(Clone, Debug)]
pub struct CronJob {
    pub id: i64,
    pub name: String,
    pub schedule: String,
    pub target_kind: String,
    pub target_name: String,
    pub payload_json: Option<String>,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_run_at: Option<String>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub last_duration_ms: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct CronRun {
    pub id: i64,
    pub job_id: i64,
    pub fired_at: String,
    pub status: String,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
}

const JOB_COLS: &str = "id, name, schedule, target_kind, target_name, payload_json, active, \
     created_at, updated_at, last_run_at, last_status, last_error, last_duration_ms";

fn row_to_job(r: &rusqlite::Row<'_>) -> rusqlite::Result<CronJob> {
    Ok(CronJob {
        id: r.get(0)?,
        name: r.get(1)?,
        schedule: r.get(2)?,
        target_kind: r.get(3)?,
        target_name: r.get(4)?,
        payload_json: r.get(5)?,
        active: r.get::<_, i64>(6)? != 0,
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
        last_run_at: r.get(9)?,
        last_status: r.get(10)?,
        last_error: r.get(11)?,
        last_duration_ms: r.get(12)?,
    })
}

fn row_to_run(r: &rusqlite::Row<'_>) -> rusqlite::Result<CronRun> {
    Ok(CronRun {
        id: r.get(0)?,
        job_id: r.get(1)?,
        fired_at: r.get(2)?,
        status: r.get(3)?,
        error: r.get(4)?,
        duration_ms: r.get(5)?,
    })
}

/// "no such table" — the reader-lane tolerance predicate (functions/schema.rs
/// `get_function` shape): the tables are created lazily by the first writer
/// fn, so a read before any cron job ever existed means "no jobs".
fn is_missing_table(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(_, Some(m)) if m.contains("no such table"))
}

/// INSERT + read-back. Caller pre-checks duplicates and the per-tenant cap
/// (ops layer); a UNIQUE violation may still surface here — callers map it.
pub fn create_job(
    c: &Connection,
    name: &str,
    schedule: &str,
    target_kind: &str,
    target_name: &str,
    payload_json: Option<&str>,
    active: bool,
) -> rusqlite::Result<CronJob> {
    ensure_tables(c)?;
    c.execute(
        "INSERT INTO _system_cron_jobs (name, schedule, target_kind, target_name, payload_json, active)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![name, schedule, target_kind, target_name, payload_json, active as i64],
    )?;
    c.query_row(
        &format!("SELECT {JOB_COLS} FROM _system_cron_jobs WHERE name = ?1"),
        rusqlite::params![name],
        row_to_job,
    )
}

/// Writer lane only (runs DDL). Readers use `list_jobs_reader`.
pub fn list_jobs(c: &Connection) -> rusqlite::Result<Vec<CronJob>> {
    ensure_tables(c)?;
    let mut st = c.prepare(&format!(
        "SELECT {JOB_COLS} FROM _system_cron_jobs ORDER BY name"
    ))?;
    st.query_map([], row_to_job)?.collect()
}

/// Reader lane: NO `ensure_tables` — a cron-less tenant must not grow the
/// tables from a read path. Missing table ⇒ no jobs.
pub fn list_jobs_reader(c: &Connection) -> rusqlite::Result<Vec<CronJob>> {
    let mut st = match c.prepare(&format!(
        "SELECT {JOB_COLS} FROM _system_cron_jobs ORDER BY name"
    )) {
        Ok(st) => st,
        Err(e) if is_missing_table(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    st.query_map([], row_to_job)?.collect()
}

/// Reader lane, same missing-table tolerance as `list_jobs_reader`.
pub fn get_job_reader(c: &Connection, name: &str) -> rusqlite::Result<Option<CronJob>> {
    match c.query_row(
        &format!("SELECT {JOB_COLS} FROM _system_cron_jobs WHERE name = ?1"),
        rusqlite::params![name],
        row_to_job,
    ) {
        Ok(j) => Ok(Some(j)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) if is_missing_table(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// One-sided merge (target is immutable by omission — no target params).
/// `payload_json`: outer `None` = untouched, `Some(None)` = clear,
/// `Some(Some(s))` = set. Bumps `updated_at`; returns the updated row, or
/// `None` when no job has that name.
pub fn update_job(
    c: &Connection,
    name: &str,
    schedule: Option<&str>,
    payload_json: Option<Option<&str>>,
    active: Option<bool>,
) -> rusqlite::Result<Option<CronJob>> {
    ensure_tables(c)?;
    let Some(cur) = get_job_reader(c, name)? else {
        return Ok(None);
    };
    let schedule = schedule.unwrap_or(&cur.schedule);
    let payload: Option<&str> = match &payload_json {
        Some(p) => *p,
        None => cur.payload_json.as_deref(),
    };
    let active = active.unwrap_or(cur.active);
    c.execute(
        "UPDATE _system_cron_jobs
         SET schedule = ?2, payload_json = ?3, active = ?4, updated_at = datetime('now')
         WHERE id = ?1",
        rusqlite::params![cur.id, schedule, payload, active as i64],
    )?;
    get_job_reader(c, name)
}

/// Deletes the job AND its runs — same connection, inside the caller's tx.
/// Returns whether a job row existed.
pub fn delete_job(c: &Connection, name: &str) -> rusqlite::Result<bool> {
    ensure_tables(c)?;
    let id: i64 = match c.query_row(
        "SELECT id FROM _system_cron_jobs WHERE name = ?1",
        rusqlite::params![name],
        |r| r.get(0),
    ) {
        Ok(id) => id,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
        Err(e) => return Err(e),
    };
    c.execute(
        "DELETE FROM _system_cron_runs WHERE job_id = ?1",
        rusqlite::params![id],
    )?;
    c.execute(
        "DELETE FROM _system_cron_jobs WHERE id = ?1",
        rusqlite::params![id],
    )?;
    Ok(true)
}

/// Writer lane (create pre-check runs inside the same `with_writer` closure).
pub fn count_jobs(c: &Connection) -> rusqlite::Result<i64> {
    ensure_tables(c)?;
    c.query_row("SELECT COUNT(*) FROM _system_cron_jobs", [], |r| r.get(0))
}

/// INSERT run + prune to the newest 20 for that job + UPDATE the job's
/// `last_*` columns. Three statements, one caller-owned writer closure —
/// scheduler callers wrap this in `with_writer_tx` so all three commit or
/// roll back together. If the job row is gone (deleted while the run was
/// in flight — `_system_cron_runs` has no FK and `delete_job`'s cascade
/// already ran), this is a no-op: writing would re-insert an orphan row
/// invisible to `list_runs_reader`'s JOIN that nothing ever deletes.
pub fn record_run(
    c: &Connection,
    job_id: i64,
    fired_at: &str,
    status: &str,
    error: Option<&str>,
    duration_ms: Option<i64>,
) -> rusqlite::Result<()> {
    ensure_tables(c)?;
    match c.query_row(
        "SELECT 1 FROM _system_cron_jobs WHERE id = ?1",
        rusqlite::params![job_id],
        |_| Ok(()),
    ) {
        Ok(()) => {}
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(()),
        Err(e) => return Err(e),
    }
    c.execute(
        "INSERT INTO _system_cron_runs (job_id, fired_at, status, error, duration_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![job_id, fired_at, status, error, duration_ms],
    )?;
    c.execute(
        "DELETE FROM _system_cron_runs
         WHERE job_id = ?1 AND id NOT IN (
           SELECT id FROM _system_cron_runs WHERE job_id = ?1 ORDER BY id DESC LIMIT ?2
         )",
        rusqlite::params![job_id, RUNS_KEEP_PER_JOB],
    )?;
    c.execute(
        "UPDATE _system_cron_jobs
         SET last_run_at = ?2, last_status = ?3, last_error = ?4, last_duration_ms = ?5,
             updated_at = datetime('now')
         WHERE id = ?1",
        rusqlite::params![job_id, fired_at, status, error, duration_ms],
    )?;
    Ok(())
}

/// Reader lane: newest first, ≤20, missing-table tolerant.
pub fn list_runs_reader(c: &Connection, name: &str) -> rusqlite::Result<Vec<CronRun>> {
    let mut st = match c.prepare(
        "SELECT r.id, r.job_id, r.fired_at, r.status, r.error, r.duration_ms
         FROM _system_cron_runs r
         JOIN _system_cron_jobs j ON j.id = r.job_id
         WHERE j.name = ?1
         ORDER BY r.id DESC
         LIMIT ?2",
    ) {
        Ok(st) => st,
        Err(e) if is_missing_table(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    st.query_map(rusqlite::params![name, RUNS_KEEP_PER_JOB], row_to_run)?
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> rusqlite::Connection {
        rusqlite::Connection::open_in_memory().unwrap()
    }

    #[test]
    fn create_list_roundtrip_and_lazy_tables() {
        let c = conn();
        let j = create_job(
            &c,
            "sync",
            "*/5 * * * *",
            "function",
            "sync_fn",
            Some("{\"k\":1}"),
            true,
        )
        .unwrap();
        assert_eq!(j.name, "sync");
        assert!(j.active);
        let all = list_jobs(&c).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].payload_json.as_deref(), Some("{\"k\":1}"));
    }

    #[test]
    fn reader_fns_tolerate_missing_tables() {
        let c = conn();
        assert!(list_jobs_reader(&c).unwrap().is_empty());
        assert!(get_job_reader(&c, "x").unwrap().is_none());
        assert!(list_runs_reader(&c, "x").unwrap().is_empty());
    }

    #[test]
    fn update_is_one_sided_merge_and_target_immutable_shape() {
        let c = conn();
        create_job(&c, "j", "0 3 * * *", "rpc", "purge", None, true).unwrap();
        let u = update_job(&c, "j", None, None, Some(false))
            .unwrap()
            .unwrap();
        assert_eq!(u.schedule, "0 3 * * *");
        assert!(!u.active);
        let u2 = update_job(&c, "j", Some("0 4 * * *"), Some(Some("{\"a\":2}")), None)
            .unwrap()
            .unwrap();
        assert_eq!(u2.schedule, "0 4 * * *");
        assert_eq!(u2.payload_json.as_deref(), Some("{\"a\":2}"));
        assert!(!u2.active, "active untouched by second patch");
        assert!(
            update_job(&c, "ghost", None, None, Some(true))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn record_run_updates_last_and_prunes_to_20() {
        let c = conn();
        let j = create_job(&c, "j", "* * * * *", "function", "f", None, true).unwrap();
        for i in 0..25 {
            record_run(
                &c,
                j.id,
                &format!("2026-07-13T00:{i:02}Z"),
                "ok",
                None,
                Some(5),
            )
            .unwrap();
        }
        let runs = list_runs_reader(&c, "j").unwrap();
        assert_eq!(runs.len(), 20);
        assert_eq!(runs[0].fired_at, "2026-07-13T00:24Z", "newest first");
        let job = get_job_reader(&c, "j").unwrap().unwrap();
        assert_eq!(job.last_status.as_deref(), Some("ok"));
        assert_eq!(job.last_run_at.as_deref(), Some("2026-07-13T00:24Z"));
    }

    #[test]
    fn delete_job_cascades_runs() {
        let c = conn();
        let j = create_job(&c, "j", "* * * * *", "function", "f", None, true).unwrap();
        record_run(&c, j.id, "2026-07-13T00:00Z", "error", Some("boom"), None).unwrap();
        assert!(delete_job(&c, "j").unwrap());
        assert!(get_job_reader(&c, "j").unwrap().is_none());
        let orphans: i64 = c
            .query_row("SELECT COUNT(*) FROM _system_cron_runs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(orphans, 0);
        assert!(!delete_job(&c, "j").unwrap());
    }

    #[test]
    fn record_run_for_deleted_job_is_noop() {
        let c = conn();
        let j = create_job(&c, "j", "* * * * *", "function", "f", None, true).unwrap();
        assert!(delete_job(&c, "j").unwrap());
        // A run finishing after delete_job must not re-insert an orphan row
        // (no FK on _system_cron_runs; the delete's cascade already ran).
        record_run(&c, j.id, "2026-07-13T00:00Z", "ok", None, Some(5)).unwrap();
        let orphans: i64 = c
            .query_row("SELECT COUNT(*) FROM _system_cron_runs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(orphans, 0, "no orphan run row for a deleted job");
    }

    #[test]
    fn duplicate_name_is_constraint_error() {
        let c = conn();
        create_job(&c, "j", "* * * * *", "function", "f", None, true).unwrap();
        assert!(create_job(&c, "j", "* * * * *", "function", "f", None, true).is_err());
        assert_eq!(count_jobs(&c).unwrap(), 1);
    }

    /// Pins the "record atomically" half of b101bea end-to-end: scheduler
    /// callers wrap `record_run` in `pool.with_writer_tx`, so a failure later
    /// in the same closure must roll back ALL THREE statements — no run row,
    /// no `last_*` update. A regression to plain `with_writer` recording
    /// would leave the partial write visible (each statement auto-commits),
    /// and this test would catch it.
    #[tokio::test]
    async fn record_run_via_with_writer_tx_rolls_back_fully_on_err() {
        let tmp = tempfile::TempDir::new().unwrap();
        let registry = crate::storage::pool::TenantRegistry::new(tmp.path().to_path_buf(), 2);
        let pool = registry.get_or_open("t-cron-store-tx").unwrap();
        let job = pool
            .with_writer(|c| create_job(c, "j", "* * * * *", "function", "f", None, true))
            .await
            .unwrap();
        assert!(job.last_status.is_none(), "fresh job has no last_status");

        let job_id = job.id;
        let res: rusqlite::Result<()> = pool
            .with_writer_tx(move |tx| {
                record_run(tx, job_id, "2026-07-13T00:00Z", "ok", None, Some(1))?;
                Err(rusqlite::Error::QueryReturnedNoRows)
            })
            .await;
        assert!(res.is_err(), "closure error must surface, got {res:?}");

        // Full rollback: neither the run row nor the job's last_* survives.
        let runs = pool
            .with_reader(|c| list_runs_reader(c, "j"))
            .await
            .unwrap();
        assert!(runs.is_empty(), "rolled-back run row must not be visible");
        let job = pool
            .with_reader(|c| get_job_reader(c, "j"))
            .await
            .unwrap()
            .unwrap();
        assert!(
            job.last_status.is_none(),
            "last_status must stay NULL after rollback"
        );
        assert!(
            job.last_run_at.is_none(),
            "last_run_at must stay NULL after rollback"
        );
    }
}

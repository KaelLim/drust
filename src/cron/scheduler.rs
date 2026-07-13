//! Minute-tick cron scheduler: snapshot the in-memory index each UTC minute,
//! `collect_due` against the pure schedule math, and spawn one `run_due_job`
//! per due (tenant, job). `run_due_job` re-asserts the job row at fire time
//! (fail-closed against index staleness), skips overlapping fires of the same
//! job, dispatches to the target (edge function via the synchronous
//! `Executor::run_one` path, or a stored RPC via the existing read/write
//! executors at `Privileged`/service identity), and records the outcome in
//! `_system_cron_runs`.

use crate::cron::CronConfig;
use crate::cron::index::{CronIndex, IndexedJob};
use crate::cron::schedule;
use crate::cron::store;
use crate::functions::caller::CallerCtx;
use crate::functions::executor::{Executor, Invocation, RunStatus};
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use chrono::{DateTime, Timelike, Utc};
use std::sync::Arc;

/// SQL execution caps for RPC targets — same values as the REST handler
/// (`src/rpc/handler.rs` MAX_ROWS / MAX_BYTES) so a cron fire cannot do more
/// than a service REST call could.
const MAX_ROWS: usize = 1_000;
const MAX_BYTES: usize = 1_048_576;

/// Everything a fire needs. Built once in `main.rs`, shared by every spawned
/// `run_due_job` task.
pub struct CronDeps {
    pub registry: Arc<TenantRegistry>,
    pub index: Arc<CronIndex>,
    /// The functions executor — cron uses the synchronous `run_one` path
    /// (same as REST `/invoke`), NOT the event queue, so the outcome is
    /// observable and recordable per run.
    pub executor: Arc<Executor>,
    /// `(tenant, job id)` in-flight markers — the overlap-skip gate.
    pub in_flight: Arc<dashmap::DashMap<(String, i64), ()>>,
    pub cfg: CronConfig,
}

/// Truncate `after` to its minute and advance one minute — the next tick
/// boundary. Pure so the tick math is testable without a clock.
pub fn next_minute(after: DateTime<Utc>) -> DateTime<Utc> {
    after
        .with_second(0)
        .and_then(|t| t.with_nanosecond(0))
        .expect("zero second/nanosecond is always in range")
        + chrono::Duration::minutes(1)
}

/// Filter an index snapshot down to the jobs whose schedule fires at exactly
/// `minute`. Parse errors are silently not-due (`schedule::is_due` fails
/// closed; create-time validation is the loud gate).
pub fn collect_due(
    snapshot: &[(String, Arc<Vec<IndexedJob>>)],
    minute: DateTime<Utc>,
) -> Vec<(String, IndexedJob)> {
    let mut due = Vec::new();
    for (tenant, jobs) in snapshot {
        for job in jobs.iter() {
            if schedule::is_due(&job.schedule, minute) {
                due.push((tenant.clone(), job.clone()));
            }
        }
    }
    due
}

/// Removes the `(tenant, job)` in-flight marker on EVERY exit of
/// `run_due_job` — early returns, dispatch errors, panics unwinding.
struct InFlightGuard {
    map: Arc<dashmap::DashMap<(String, i64), ()>>,
    key: (String, i64),
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

/// Execute one due fire. Order is load-bearing:
/// 1. overlap gate (previous fire of the SAME job still running →
///    `skipped_overlap` run row, no dispatch);
/// 2. fire-time re-assert against the fresh DB row (fail-closed: row gone /
///    inactive / schedule changed → return silently — whoever changed it
///    already reloaded the index);
/// 3. dispatch by `target_kind` at `Privileged`/service identity;
/// 4. record the outcome (+ measured duration) in `_system_cron_runs`.
pub async fn run_due_job(
    deps: Arc<CronDeps>,
    tenant: String,
    job: IndexedJob,
    fired_minute: DateTime<Utc>,
) {
    let fired = fired_minute.format("%Y-%m-%dT%H:%MZ").to_string();
    let pool = match deps.registry.get_or_open(&tenant) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(tenant = %tenant, job = %job.name, err = ?e, "cron: tenant open failed; fire skipped");
            return;
        }
    };

    // ── 1. Overlap gate. The dashmap entry guard is dropped at the end of
    //    the match (before any await) — never held across a suspend point.
    let key = (tenant.clone(), job.id);
    let inserted = match deps.in_flight.entry(key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(_) => false,
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert(());
            true
        }
    };
    if !inserted {
        let job_id = job.id;
        let fired_c = fired.clone();
        if let Err(e) = pool
            .with_writer(move |c| {
                store::record_run(c, job_id, &fired_c, "skipped_overlap", None, None)
            })
            .await
        {
            tracing::warn!(tenant = %tenant, job = %job.name, err = ?e, "cron: failed to record skipped_overlap run");
        }
        return;
    }
    let _guard = InFlightGuard {
        map: deps.in_flight.clone(),
        key,
    };

    // ── 2. Fire-time re-assert (fail-closed net for index staleness).
    let name_for_read = job.name.clone();
    let fresh = match pool
        .with_reader(move |c| store::get_job_reader(c, &name_for_read))
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(tenant = %tenant, job = %job.name, err = ?e, "cron: re-assert read failed; fire skipped");
            return;
        }
    };
    let Some(fresh) = fresh else {
        return; // deleted under us
    };
    if !fresh.active || fresh.schedule != job.schedule {
        return; // disabled or rescheduled under us
    }

    // ── 3. Dispatch.
    let started = std::time::Instant::now();
    let (status, error) = match job.target_kind.as_str() {
        "function" => dispatch_function(&deps, &tenant, &job, &fired).await,
        "rpc" => dispatch_rpc(&pool, &job).await,
        other => ("error", Some(format!("unknown target_kind '{other}'"))),
    };
    let duration_ms = started.elapsed().as_millis() as i64;

    // ── 4. Record the outcome.
    let job_id = job.id;
    let fired_c = fired.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            store::record_run(
                c,
                job_id,
                &fired_c,
                status,
                error.as_deref(),
                Some(duration_ms),
            )
        })
        .await
    {
        tracing::warn!(tenant = %tenant, job = %job.name, err = ?e, "cron: failed to record run outcome");
    }
}

/// Function target: synchronous `Executor::run_one` (the REST `/invoke`
/// path — run_one itself writes the `_system_function_logs` row + audit row).
async fn dispatch_function(
    deps: &CronDeps,
    tenant: &str,
    job: &IndexedJob,
    fired: &str,
) -> (&'static str, Option<String>) {
    let payload_val: serde_json::Value = job
        .payload_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let out = deps
        .executor
        .run_one(Invocation {
            tenant_id: tenant.to_string(),
            function_name: job.target_name.clone(),
            trigger: format!("cron:{}", job.name),
            event_json: serde_json::json!({
                "trigger": "cron",
                "job": job.name,
                "fired_at": fired,
                "payload": payload_val,
            })
            .to_string(),
            caller: CallerCtx::Privileged,
        })
        .await;
    match out.status {
        RunStatus::Ok => ("ok", None),
        _ => ("error", Some(out.result)),
    }
}

/// RPC target: fresh registry lookup (mode/params may have changed since the
/// job was created), then the existing read/write executors at service
/// identity. Record-history capture rides `run_write_rpc` unchanged.
async fn dispatch_rpc(pool: &SharedTenantPool, job: &IndexedJob) -> (&'static str, Option<String>) {
    let target = job.target_name.clone();
    let stored = match pool
        .with_reader(move |c| Ok(crate::rpc::registry::lookup(c, &target)))
        .await
    {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            return (
                "error",
                Some(format!("rpc not found: '{}'", job.target_name)),
            );
        }
        Ok(Err(e)) => return ("error", Some(format!("rpc lookup failed: {e}"))),
        Err(e) => return ("error", Some(format!("rpc lookup failed: {e}"))),
    };
    // Cron runs at Privileged/service identity with NO end-user bound — an
    // RPC declaring :user_id has nothing meaningful to bind (mirrors the
    // anon categorical refusal in rpc/handler.rs). Config-time (ops layer)
    // refuses too; this is the fail-closed runtime net.
    if stored.params.iter().any(|p| p.name == "user_id") {
        return (
            "error",
            Some("rpc declares :user_id — cron has no user identity to bind".into()),
        );
    }
    let payload_map: serde_json::Map<String, serde_json::Value> = job
        .payload_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    let bound = match crate::rpc::params::validate_and_bind(&stored.params, &payload_map) {
        Ok(b) => b,
        Err(e) => return ("error", Some(format!("param binding failed: {e}"))),
    };
    match stored.mode {
        crate::rpc::registry::RpcMode::Read => {
            let sql = stored.sql.clone();
            let res = pool
                .with_reader(move |c| {
                    Ok(crate::query::executor::execute_read_query_with_named(
                        c, &sql, &bound, MAX_ROWS, MAX_BYTES,
                    ))
                })
                .await;
            match res {
                Ok(Ok(_)) => ("ok", None),
                Ok(Err(e)) => ("error", Some(e.to_string())),
                Err(e) => ("error", Some(e.to_string())),
            }
        }
        crate::rpc::registry::RpcMode::Write => {
            if stored.sql.len() > MAX_BYTES {
                return (
                    "error",
                    Some(format!(
                        "query too large: {} bytes (limit {MAX_BYTES})",
                        stored.sql.len()
                    )),
                );
            }
            let res = crate::rpc::exec_write::run_write_rpc(
                pool,
                stored.sql.clone(),
                bound,
                false,
                crate::storage::record_history::AuditActor::from_auth_ctx(
                    &crate::auth::middleware::AuthCtx::Service { admin_id: None },
                ),
                crate::storage::record_history::CaptureLimits::from_env(),
            )
            .await;
            match res {
                Ok(Ok(_)) => ("ok", None),
                Ok(Err(stmt)) => ("error", Some(stmt.to_string())),
                Err(commit) => ("error", Some(commit.0)),
            }
        }
    }
}

/// The minute-tick loop. Caller `tokio::spawn`s this once from `main.rs`.
/// `DRUST_CRON_DISABLED=1` → log once and return (the retention-task
/// disabled pattern in `record_history.rs`).
pub async fn spawn_scheduler(deps: Arc<CronDeps>) {
    if deps.cfg.disabled {
        tracing::info!("cron scheduler disabled (DRUST_CRON_DISABLED=1)");
        return;
    }
    loop {
        let now = Utc::now();
        let minute = next_minute(now);
        tokio::time::sleep(
            (minute - now)
                .to_std()
                .unwrap_or(std::time::Duration::from_secs(1)),
        )
        .await;
        for (tenant, job) in collect_due(&deps.index.snapshot(), minute) {
            tokio::spawn(run_due_job(deps.clone(), tenant, job, minute));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron::index::IndexedJob;
    use chrono::TimeZone;

    fn mk_job(id: i64, name: &str, schedule: &str) -> IndexedJob {
        IndexedJob {
            id,
            name: name.into(),
            schedule: schedule.into(),
            target_kind: "function".into(),
            target_name: "f".into(),
            payload_json: None,
        }
    }

    #[test]
    fn next_minute_truncates_and_advances() {
        let t = chrono::Utc
            .with_ymd_and_hms(2026, 7, 13, 8, 30, 45)
            .unwrap();
        assert_eq!(
            next_minute(t),
            chrono::Utc.with_ymd_and_hms(2026, 7, 13, 8, 31, 0).unwrap()
        );
        let exact = chrono::Utc.with_ymd_and_hms(2026, 7, 13, 8, 30, 0).unwrap();
        assert_eq!(
            next_minute(exact),
            chrono::Utc.with_ymd_and_hms(2026, 7, 13, 8, 31, 0).unwrap()
        );
    }

    #[test]
    fn collect_due_filters_by_schedule() {
        let jobs = vec![(
            "t1".to_string(),
            std::sync::Arc::new(vec![
                mk_job(1, "quarter", "*/15 * * * *"),
                mk_job(2, "daily", "30 3 * * *"),
            ]),
        )];
        let due = collect_due(
            &jobs,
            chrono::Utc.with_ymd_and_hms(2026, 7, 13, 8, 45, 0).unwrap(),
        );
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1.name, "quarter");
    }
}

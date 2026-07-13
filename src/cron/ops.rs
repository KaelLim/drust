//! Transport-agnostic cron job config cores, shared by REST (`cron::routes`),
//! MCP (`mcp::tools::cron`, Task 7) and the admin `⏰ _cron` page (Task 8).
//! Every mutation validates BEFORE touching the writer lane, performs the
//! duplicate/cap pre-checks INSIDE the same `with_writer` closure as the
//! write (the per-tenant writer mutex serializes them — no TOCTOU), and
//! reloads the in-memory schedule index after commit so a created/enabled
//! job starts firing without a restart.

use crate::cron::{CronState, schedule, store};
use crate::storage::pool::SharedTenantPool;
use chrono::Utc;

/// Max `payload_json` size in bytes (spec: ≤ 64 KiB).
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

#[derive(Debug)]
pub enum OpsError {
    InvalidName,
    InvalidSchedule(String),
    TargetNotFound,
    Duplicate,
    JobLimit(i64),
    /// Payload rejected: over 64 KiB OR not a JSON object. Both violations
    /// share this variant (and the `CRON_PAYLOAD_TOO_LARGE` wire code) — the
    /// plan's error-code set is closed, so the response message carries the
    /// distinction.
    PayloadTooLarge,
    RpcUserId,
    NotFound,
    Db(String),
}

/// Serde-serializable mirror of `store::CronJob` + computed `next_fire`
/// (`%Y-%m-%dT%H:%MZ`, `None` when the stored expression no longer parses).
#[derive(Debug, serde::Serialize)]
pub struct CronJobOut {
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
    pub next_fire: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct CronRunOut {
    pub id: i64,
    pub job_id: i64,
    pub fired_at: String,
    pub status: String,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
}

fn job_out(j: store::CronJob) -> CronJobOut {
    let next_fire = schedule::next_fire(&j.schedule, Utc::now());
    CronJobOut {
        id: j.id,
        name: j.name,
        schedule: j.schedule,
        target_kind: j.target_kind,
        target_name: j.target_name,
        payload_json: j.payload_json,
        active: j.active,
        created_at: j.created_at,
        updated_at: j.updated_at,
        last_run_at: j.last_run_at,
        last_status: j.last_status,
        last_error: j.last_error,
        last_duration_ms: j.last_duration_ms,
        next_fire,
    }
}

fn run_out(r: store::CronRun) -> CronRunOut {
    CronRunOut {
        id: r.id,
        job_id: r.job_id,
        fired_at: r.fired_at,
        status: r.status,
        error: r.error,
        duration_ms: r.duration_ms,
    }
}

fn check_schedule(expr: &str) -> Result<(), OpsError> {
    schedule::validate_schedule(expr).map_err(|e| match e {
        schedule::ScheduleError::NotFiveFields => OpsError::InvalidSchedule(
            "schedule must be a 5-field cron expression (minute hour day month weekday, UTC)"
                .to_string(),
        ),
        schedule::ScheduleError::Invalid(msg) => OpsError::InvalidSchedule(msg),
    })
}

fn check_payload(payload_json: Option<&str>) -> Result<(), OpsError> {
    let Some(p) = payload_json else {
        return Ok(());
    };
    if p.len() > MAX_PAYLOAD_BYTES {
        return Err(OpsError::PayloadTooLarge);
    }
    match serde_json::from_str::<serde_json::Value>(p) {
        Ok(serde_json::Value::Object(_)) => Ok(()),
        _ => Err(OpsError::PayloadTooLarge),
    }
}

fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _)
            if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                || err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
    )
}

/// Validate the target exists on THIS tenant and is schedulable. An RPC that
/// declares `:user_id` is refused — cron runs at Privileged/service identity
/// with no end-user bound (the scheduler re-checks at fire time as the
/// fail-closed runtime net).
async fn check_target(
    pool: &SharedTenantPool,
    target_kind: &str,
    target_name: &str,
) -> Result<(), OpsError> {
    match target_kind {
        "function" => match crate::functions::schema::get_function(pool, target_name).await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(OpsError::TargetNotFound),
            Err(e) => Err(OpsError::Db(e.to_string())),
        },
        "rpc" => {
            let tn = target_name.to_string();
            match pool
                .with_reader(move |c| Ok(crate::rpc::registry::lookup(c, &tn)))
                .await
            {
                Ok(Ok(Some(stored))) => {
                    if stored.params.iter().any(|p| p.name == "user_id") {
                        Err(OpsError::RpcUserId)
                    } else {
                        Ok(())
                    }
                }
                Ok(Ok(None)) => Err(OpsError::TargetNotFound),
                Ok(Err(e)) => Err(OpsError::Db(e.to_string())),
                Err(e) => Err(OpsError::Db(e.to_string())),
            }
        }
        // An unknown kind can never name an existing target; same wire code
        // as a missing one (the plan's error-code set has no separate kind
        // code, and the store's CHECK constraint is the fail-closed net).
        _ => Err(OpsError::TargetNotFound),
    }
}

/// Create a job. Validation order (load-bearing, cheapest first): name →
/// schedule → payload → target → duplicate/cap (inside the writer closure,
/// alongside the INSERT).
#[allow(clippy::too_many_arguments)]
pub async fn create_job(
    pool: &SharedTenantPool,
    state: &CronState,
    tenant: &str,
    name: &str,
    schedule_expr: &str,
    target_kind: &str,
    target_name: &str,
    payload_json: Option<&str>,
    active: bool,
) -> Result<CronJobOut, OpsError> {
    // Same [a-z0-9_-]{1,64} identifier rule as function names — the single
    // shared name validator (stored-RPC create has no stricter one).
    if !crate::functions::schema::valid_name(name) {
        return Err(OpsError::InvalidName);
    }
    check_schedule(schedule_expr)?;
    check_payload(payload_json)?;
    check_target(pool, target_kind, target_name).await?;

    let max = state.cfg.max_jobs_per_tenant;
    let (name_c, sched_c, kind_c, tname_c) = (
        name.to_string(),
        schedule_expr.to_string(),
        target_kind.to_string(),
        target_name.to_string(),
    );
    let payload_c = payload_json.map(str::to_string);
    let created = pool
        .with_writer(move |c| {
            if store::get_job_reader(c, &name_c)?.is_some() {
                return Ok(Err(OpsError::Duplicate));
            }
            if store::count_jobs(c)? >= max {
                return Ok(Err(OpsError::JobLimit(max)));
            }
            match store::create_job(
                c,
                &name_c,
                &sched_c,
                &kind_c,
                &tname_c,
                payload_c.as_deref(),
                active,
            ) {
                Ok(j) => Ok(Ok(j)),
                // Pre-check raced nothing (writer mutex), but keep the UNIQUE
                // mapping as defense in depth.
                Err(e) if is_unique_violation(&e) => Ok(Err(OpsError::Duplicate)),
                Err(e) => Err(e),
            }
        })
        .await;
    let job = match created {
        Ok(Ok(j)) => j,
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(OpsError::Db(e.to_string())),
    };
    state.index.reload(tenant, pool).await;
    Ok(job_out(job))
}

/// Reader lane; each job carries a freshly computed `next_fire`.
pub async fn list_jobs(pool: &SharedTenantPool) -> Result<Vec<CronJobOut>, OpsError> {
    pool.with_reader(store::list_jobs_reader)
        .await
        .map(|v| v.into_iter().map(job_out).collect())
        .map_err(|e| OpsError::Db(e.to_string()))
}

pub async fn get_job(pool: &SharedTenantPool, name: &str) -> Result<CronJobOut, OpsError> {
    let n = name.to_string();
    match pool
        .with_reader(move |c| store::get_job_reader(c, &n))
        .await
    {
        Ok(Some(j)) => Ok(job_out(j)),
        Ok(None) => Err(OpsError::NotFound),
        Err(e) => Err(OpsError::Db(e.to_string())),
    }
}

/// One-sided merge; target is immutable (delete + create to retarget).
/// `payload_json`: outer `None` = untouched, `Some(None)` = clear.
pub async fn update_job(
    pool: &SharedTenantPool,
    state: &CronState,
    tenant: &str,
    name: &str,
    schedule_expr: Option<&str>,
    payload_json: Option<Option<&str>>,
    active: Option<bool>,
) -> Result<CronJobOut, OpsError> {
    if let Some(s) = schedule_expr {
        check_schedule(s)?;
    }
    if let Some(Some(p)) = payload_json {
        check_payload(Some(p))?;
    }
    let n = name.to_string();
    let sched_c = schedule_expr.map(str::to_string);
    let payload_c: Option<Option<String>> = payload_json.map(|p| p.map(str::to_string));
    let updated = pool
        .with_writer(move |c| {
            store::update_job(
                c,
                &n,
                sched_c.as_deref(),
                payload_c.as_ref().map(|p| p.as_deref()),
                active,
            )
        })
        .await;
    match updated {
        Ok(Some(j)) => {
            state.index.reload(tenant, pool).await;
            Ok(job_out(j))
        }
        Ok(None) => Err(OpsError::NotFound),
        Err(e) => Err(OpsError::Db(e.to_string())),
    }
}

pub async fn set_active(
    pool: &SharedTenantPool,
    state: &CronState,
    tenant: &str,
    name: &str,
    active: bool,
) -> Result<CronJobOut, OpsError> {
    update_job(pool, state, tenant, name, None, None, Some(active)).await
}

pub async fn delete_job(
    pool: &SharedTenantPool,
    state: &CronState,
    tenant: &str,
    name: &str,
) -> Result<(), OpsError> {
    let n = name.to_string();
    match pool.with_writer(move |c| store::delete_job(c, &n)).await {
        Ok(true) => {
            state.index.reload(tenant, pool).await;
            Ok(())
        }
        Ok(false) => Err(OpsError::NotFound),
        Err(e) => Err(OpsError::Db(e.to_string())),
    }
}

/// Newest-first recent runs (≤20, the store's retention cap). A name with no
/// job (or a tenant that never used cron) yields an empty list.
pub async fn list_runs(pool: &SharedTenantPool, name: &str) -> Result<Vec<CronRunOut>, OpsError> {
    let n = name.to_string();
    pool.with_reader(move |c| store::list_runs_reader(c, &n))
        .await
        .map(|v| v.into_iter().map(run_out).collect())
        .map_err(|e| OpsError::Db(e.to_string()))
}

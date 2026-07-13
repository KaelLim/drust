//! v1.48 — MCP cron tools. Service-only by MCP dispatch (transport rejects
//! anon/user before any tool runs — same posture as `set_audit_enabled`).
//! Thin adapters over the transport-agnostic `crate::cron::ops` cores; the
//! `OpsError` → `"<CODE>: <message>"` mapping carries the SAME wire codes as
//! the REST surface (`crate::cron::routes::map_ops_error`) so `bail_mcp`
//! reproduces them in `ErrorData.data.error_code`.

use crate::cron::ops;
use crate::mcp::server::DrustMcp;
use serde_json::{Value, json};

fn ops_err(e: ops::OpsError) -> anyhow::Error {
    use ops::OpsError::*;
    match e {
        InvalidName => {
            anyhow::anyhow!("CRON_INVALID_NAME: job name must match [a-z0-9_-]{{1,64}}")
        }
        InvalidSchedule(msg) => anyhow::anyhow!("CRON_INVALID_SCHEDULE: {msg}"),
        TargetNotFound => anyhow::anyhow!(
            "CRON_TARGET_NOT_FOUND: target does not exist on this tenant \
             (target_kind must be 'function' or 'rpc')"
        ),
        Duplicate => anyhow::anyhow!("CRON_DUPLICATE: a cron job with this name already exists"),
        JobLimit(max) => {
            anyhow::anyhow!("CRON_JOB_LIMIT: per-tenant cron job limit reached ({max})")
        }
        PayloadTooLarge => anyhow::anyhow!(
            "CRON_PAYLOAD_TOO_LARGE: payload_json must be a JSON object of at most {} bytes",
            ops::MAX_PAYLOAD_BYTES
        ),
        RpcUserId => anyhow::anyhow!(
            "CRON_RPC_USER_ID: rpc declares :user_id — cron has no user identity to bind"
        ),
        NotFound => anyhow::anyhow!("CRON_NOT_FOUND: no such cron job"),
        Db(msg) => anyhow::anyhow!("INTERNAL_ERROR: {msg}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_cron_job(
    s: &DrustMcp,
    name: &str,
    schedule: &str,
    target_kind: &str,
    target_name: &str,
    payload_json: Option<&str>,
    active: bool,
) -> anyhow::Result<Value> {
    let inner = s.inner();
    let job = ops::create_job(
        &inner.pool,
        &inner.cron,
        &inner.tenant_id,
        name,
        schedule,
        target_kind,
        target_name,
        payload_json,
        active,
    )
    .await
    .map_err(ops_err)?;
    Ok(serde_json::to_value(job)?)
}

pub async fn list_cron_jobs(s: &DrustMcp) -> anyhow::Result<Value> {
    let jobs = ops::list_jobs(&s.inner().pool).await.map_err(ops_err)?;
    Ok(json!({ "jobs": jobs }))
}

pub async fn set_cron_job_active(s: &DrustMcp, name: &str, active: bool) -> anyhow::Result<Value> {
    let inner = s.inner();
    let job = ops::set_active(&inner.pool, &inner.cron, &inner.tenant_id, name, active)
        .await
        .map_err(ops_err)?;
    Ok(serde_json::to_value(job)?)
}

pub async fn delete_cron_job(s: &DrustMcp, name: &str) -> anyhow::Result<Value> {
    let inner = s.inner();
    ops::delete_job(&inner.pool, &inner.cron, &inner.tenant_id, name)
        .await
        .map_err(ops_err)?;
    Ok(json!({ "deleted": true, "name": name }))
}

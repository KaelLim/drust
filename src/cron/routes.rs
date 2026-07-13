//! REST surface: /t/<id>/cron[…]. Service-only via the router-level
//! `require_service_layer` (mounted in tenant/mod.rs — the functions
//! config_router pattern), so anon/user bearers get the layer's
//! `403 WRITE_DENIED` before any handler here runs. Handlers are thin
//! adapters over the transport-agnostic `crate::cron::ops` cores.

use crate::cron::{CronState, ops};
use crate::tenant::router::TenantRef;
use axum::Extension;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use std::sync::Arc;

fn map_ops_error(e: ops::OpsError) -> Response {
    use ops::OpsError::*;
    match e {
        InvalidName => crate::error::json_error(
            StatusCode::BAD_REQUEST,
            "CRON_INVALID_NAME",
            "job name must match [a-z0-9_-]{1,64}",
        ),
        InvalidSchedule(msg) => crate::error::json_error(
            StatusCode::BAD_REQUEST,
            "CRON_INVALID_SCHEDULE",
            &format!("invalid cron schedule: {msg}"),
        ),
        TargetNotFound => crate::error::json_error(
            StatusCode::NOT_FOUND,
            "CRON_TARGET_NOT_FOUND",
            "target does not exist on this tenant (target_kind must be 'function' or 'rpc')",
        ),
        Duplicate => crate::error::json_error(
            StatusCode::CONFLICT,
            "CRON_DUPLICATE",
            "a cron job with this name already exists",
        ),
        JobLimit(max) => crate::error::json_error(
            StatusCode::CONFLICT,
            "CRON_JOB_LIMIT",
            &format!("per-tenant cron job limit reached ({max})"),
        ),
        PayloadTooLarge => crate::error::json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "CRON_PAYLOAD_TOO_LARGE",
            &format!(
                "payload_json must be a JSON object of at most {} bytes",
                ops::MAX_PAYLOAD_BYTES
            ),
        ),
        RpcUserId => crate::error::json_error(
            StatusCode::CONFLICT,
            "CRON_RPC_USER_ID",
            "rpc declares :user_id — cron has no user identity to bind",
        ),
        NotFound => {
            crate::error::json_error(StatusCode::NOT_FOUND, "CRON_NOT_FOUND", "no such cron job")
        }
        Db(msg) => {
            crate::error::json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &msg)
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(serde::Deserialize)]
pub struct CreateBody {
    pub name: String,
    pub schedule: String,
    pub target_kind: String,
    pub target_name: String,
    #[serde(default)]
    pub payload_json: Option<String>,
    #[serde(default = "default_true")]
    pub active: bool,
}

/// Distinguish an ABSENT `payload_json` key (untouched) from an explicit
/// `null` (clear): absent → serde default `None`; present → `Some(inner)`.
fn double_option<'de, D>(de: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Option::<String>::deserialize(de).map(Some)
}

#[derive(serde::Deserialize)]
pub struct PatchBody {
    pub schedule: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub payload_json: Option<Option<String>>,
    pub active: Option<bool>,
    // target_kind / target_name deliberately absent: target is immutable —
    // delete + create to retarget.
}

/// POST /t/<id>/cron
pub async fn create(
    State(st): State<Arc<CronState>>,
    Extension(t): Extension<TenantRef>,
    Path(_tenant): Path<String>,
    Json(body): Json<CreateBody>,
) -> Response {
    match ops::create_job(
        &t.pool,
        &st,
        &t.tenant_id,
        &body.name,
        &body.schedule,
        &body.target_kind,
        &body.target_name,
        body.payload_json.as_deref(),
        body.active,
    )
    .await
    {
        Ok(job) => (StatusCode::CREATED, Json(job)).into_response(),
        Err(e) => map_ops_error(e),
    }
}

/// GET /t/<id>/cron
pub async fn list(
    State(_st): State<Arc<CronState>>,
    Extension(t): Extension<TenantRef>,
    Path(_tenant): Path<String>,
) -> Response {
    match ops::list_jobs(&t.pool).await {
        Ok(jobs) => Json(serde_json::json!({ "jobs": jobs })).into_response(),
        Err(e) => map_ops_error(e),
    }
}

/// GET /t/<id>/cron/<name>
pub async fn get_one(
    State(_st): State<Arc<CronState>>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
) -> Response {
    match ops::get_job(&t.pool, &name).await {
        Ok(job) => Json(job).into_response(),
        Err(e) => map_ops_error(e),
    }
}

/// PATCH /t/<id>/cron/<name> — `{schedule?, payload_json?, active?}`.
pub async fn patch(
    State(st): State<Arc<CronState>>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
    Json(body): Json<PatchBody>,
) -> Response {
    match ops::update_job(
        &t.pool,
        &st,
        &t.tenant_id,
        &name,
        body.schedule.as_deref(),
        body.payload_json.as_ref().map(|p| p.as_deref()),
        body.active,
    )
    .await
    {
        Ok(job) => Json(job).into_response(),
        Err(e) => map_ops_error(e),
    }
}

/// DELETE /t/<id>/cron/<name>
pub async fn delete_one(
    State(st): State<Arc<CronState>>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
) -> Response {
    match ops::delete_job(&t.pool, &st, &t.tenant_id, &name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_ops_error(e),
    }
}

/// GET /t/<id>/cron/<name>/runs
pub async fn runs(
    State(_st): State<Arc<CronState>>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
) -> Response {
    match ops::list_runs(&t.pool, &name).await {
        Ok(runs) => Json(serde_json::json!({ "runs": runs })).into_response(),
        Err(e) => map_ops_error(e),
    }
}

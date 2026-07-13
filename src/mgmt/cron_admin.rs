//! v1.48 — admin UI for the `⏰ _cron` virtual sidebar entry.
//! Mirrors the `ƒ _functions` admin page shape (2-pane shell, sidebar
//! driver, Translator/theme/mascot plumbing). All mutations route through
//! the transport-agnostic `crate::cron::ops` cores, so validation, the
//! duplicate/cap pre-checks and the schedule-index reload are byte-identical
//! to what the service-only REST + MCP faces do.
//!
//! Handlers run under `TenantsState` (same family as the functions/webhooks
//! admin pages); the shared `CronState` reaches them through the v1.48
//! `TenantsState.cron` field.

use super::tenants::TenantsState;
use crate::cron::ops::{self, OpsError};
use crate::mgmt::i18n::{LocaleHint, Translator};
use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "cron_admin.html")]
struct TenantCronPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    jobs: Vec<CronJobView>,
    collections: Vec<crate::storage::schema::Collection>,
    /// Always `"_cron"` — sidebar `.on` matching.
    active_coll: String,
    /// Set when a create failed validation; rendered as an inline banner
    /// above the job table (the rpc_admin form-error idiom — no redirect,
    /// the admin sees what to fix).
    error_banner: Option<String>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

/// One row in the jobs table, with its recent runs pre-loaded for the inline
/// `<details>` expander.
struct CronJobView {
    name: String,
    schedule: String,
    /// `"<target_kind>:<target_name>"` — e.g. `function:f1`.
    target: String,
    next_fire: Option<String>,
    active: bool,
    last_status: Option<String>,
    last_run_at: Option<String>,
    runs: Vec<CronRunView>,
}

struct CronRunView {
    fired_at: String,
    status: String,
    error: Option<String>,
    duration_ms: Option<i64>,
}

/// Human-readable banner text for a failed admin mutation — same wire codes
/// and messages as `cron::routes::map_ops_error`, flattened to one line.
fn ops_error_text(e: &OpsError) -> String {
    match e {
        OpsError::InvalidName => {
            "CRON_INVALID_NAME: job name must match [a-z0-9_-]{1,64}".to_string()
        }
        OpsError::InvalidSchedule(msg) => {
            format!("CRON_INVALID_SCHEDULE: invalid cron schedule: {msg}")
        }
        OpsError::TargetNotFound => "CRON_TARGET_NOT_FOUND: target does not exist on this tenant \
             (target_kind must be 'function' or 'rpc')"
            .to_string(),
        OpsError::Duplicate => {
            "CRON_DUPLICATE: a cron job with this name already exists".to_string()
        }
        OpsError::JobLimit(max) => {
            format!("CRON_JOB_LIMIT: per-tenant cron job limit reached ({max})")
        }
        OpsError::PayloadTooLarge => format!(
            "CRON_PAYLOAD_TOO_LARGE: payload must be a JSON object of at most {} bytes",
            ops::MAX_PAYLOAD_BYTES
        ),
        OpsError::RpcUserId => "CRON_RPC_USER_ID: rpc declares :user_id — cron has no user \
             identity to bind"
            .to_string(),
        OpsError::NotFound => "CRON_NOT_FOUND: no such cron job".to_string(),
        OpsError::Db(msg) => format!("INTERNAL_ERROR: {msg}"),
    }
}

/// Fire-and-forget audit row for an admin-initiated cron mutation (the
/// functions_admin pattern — admin-plane routes bypass `bearer_auth_layer`,
/// so the row is emitted explicitly).
fn audit_admin(tenant_id: &str, op: &str, name: &str) {
    crate::safety::audit_db::try_send(&crate::safety::audit::AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        tenant: tenant_id.to_string(),
        token_hint: "admin-ui".to_string(),
        op: op.to_string(),
        status: "ok".to_string(),
        duration_ms: 0,
        collection: Some(name.to_string()),
        sql_hash: None,
        record_id: None,
        error_code: None,
        error_message: None,
        auth_method: None,
        oauth_email: None,
        oauth_error_code: None,
        actor_admin_id: None,
        actor_email_snapshot: None,
        extra: Default::default(),
    });
}

/// Load every job + its recent runs. Swallows DB errors — a fresh tenant
/// that never used cron just renders the empty state (`list_jobs` rides the
/// "no such table"-tolerant reader).
async fn load_job_views(state: &TenantsState, tenant_id: &str) -> Vec<CronJobView> {
    let pool = match state.tenants.get_or_open(tenant_id) {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    let jobs = ops::list_jobs(&pool).await.unwrap_or_default();
    let mut out = Vec::with_capacity(jobs.len());
    for j in jobs {
        let runs = ops::list_runs(&pool, &j.name)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| CronRunView {
                fired_at: r.fired_at,
                status: r.status,
                error: r.error,
                duration_ms: r.duration_ms,
            })
            .collect();
        out.push(CronJobView {
            target: format!("{}:{}", j.target_kind, j.target_name),
            name: j.name,
            schedule: j.schedule,
            next_fire: j.next_fire,
            active: j.active,
            last_status: j.last_status,
            last_run_at: j.last_run_at,
            runs,
        });
    }
    out
}

/// Internal page render shared by the GET path and the create POST's error
/// path (which re-renders with a banner instead of redirecting).
async fn render_page(
    state: &TenantsState,
    tenant_id: String,
    error_banner: Option<String>,
    locale: crate::mgmt::i18n::Locale,
    theme: crate::mgmt::theme::Theme,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
) -> Response {
    let (tenant_name, collections) =
        match super::tenants::common::load_tenant_shell(state, &tenant_id).await {
            Ok(t) => t,
            Err(r) => return r,
        };
    let jobs = load_job_views(state, &tenant_id).await;
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantCronPage {
            version: env!("CARGO_PKG_VERSION"),
            tenant_id,
            tenant_name,
            jobs,
            collections,
            active_coll: "_cron".to_string(),
            error_banner,
            t: Translator::new(locale),
            admin,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// `GET /admin/tenants/{id}/_cron` — render the management page.
pub async fn page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
) -> Response {
    render_page(&state, tenant_id, None, locale, theme, admin).await
}

/// Create form body. `payload` is the raw textarea — blank means no payload.
/// Target is immutable after create (delete + create to retarget), so the
/// form is the only surface carrying `target_kind`/`target_name`.
#[derive(Debug, Deserialize)]
pub struct CronCreateForm {
    pub name: String,
    pub schedule: String,
    pub target_kind: String,
    pub target_name: String,
    #[serde(default)]
    pub payload: String,
}

/// `POST /admin/tenants/{id}/_cron` — validated create through
/// `ops::create_job` (name / schedule / payload / target / duplicate / cap),
/// then 303 back to the page; a validation error re-renders with a banner.
pub async fn create(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
    Form(form): Form<CronCreateForm>,
) -> Response {
    if let Some(r) = super::tenants::common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let payload = {
        let p = form.payload.trim();
        if p.is_empty() { None } else { Some(p) }
    };
    match ops::create_job(
        &pool,
        &state.cron,
        &tenant_id,
        &form.name,
        &form.schedule,
        &form.target_kind,
        &form.target_name,
        payload,
        true,
    )
    .await
    {
        Ok(_) => {
            audit_admin(&tenant_id, "cron.create", &form.name);
            Redirect::to(&crate::base_path::base(&format!(
                "/admin/tenants/{tenant_id}/_cron"
            )))
            .into_response()
        }
        Err(e) => {
            render_page(
                &state,
                tenant_id,
                Some(ops_error_text(&e)),
                locale,
                theme,
                admin,
            )
            .await
        }
    }
}

/// `POST /admin/tenants/{id}/_cron/{name}/toggle` — flip the active flag
/// (index reload rides `ops::set_active`), audit, 303 back. Missing job 404s.
pub async fn toggle(
    State(state): State<TenantsState>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> Response {
    if let Some(r) = super::tenants::common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };
    let current = match ops::get_job(&pool, &name).await {
        Ok(j) => j.active,
        Err(OpsError::NotFound) => {
            return (StatusCode::NOT_FOUND, "no such cron job").into_response();
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, ops_error_text(&e)).into_response();
        }
    };
    if let Err(e) = ops::set_active(&pool, &state.cron, &tenant_id, &name, !current).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, ops_error_text(&e)).into_response();
    }
    audit_admin(&tenant_id, "cron.update", &name);
    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/_cron"
    )))
    .into_response()
}

/// `POST /admin/tenants/{id}/_cron/{name}/delete` — remove the job and its
/// runs (index reload rides `ops::delete_job`), audit, 303 back. Already
/// gone → idempotent, still redirect (the functions_admin delete pattern).
pub async fn delete(
    State(state): State<TenantsState>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> Response {
    if let Some(r) = super::tenants::common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };
    match ops::delete_job(&pool, &state.cron, &tenant_id, &name).await {
        Ok(()) => audit_admin(&tenant_id, "cron.delete", &name),
        Err(OpsError::NotFound) => {} // already gone — idempotent, still redirect
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, ops_error_text(&e)).into_response();
        }
    }
    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/_cron"
    )))
    .into_response()
}

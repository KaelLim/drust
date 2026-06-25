//! v1.36 — admin UI for the `ƒ _functions` virtual sidebar entry.
//! Mirrors the `_webhooks` admin page shape (2-pane shell, sidebar driver,
//! Translator/theme/mascot plumbing). Upload stays REST-only in v1; the page
//! shows the curl snippet with the tenant's service token.
//!
//! Handlers run under `TenantsState` (same family as the webhooks/rpc admin
//! pages). The dispatcher/executor/artifact-root reach the handlers through
//! the three v1.36 `TenantsState` fields.

use super::tenants::TenantsState;
use crate::functions::schema;
use crate::mgmt::i18n::{LocaleHint, Translator};
use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "tenant_functions.html")]
struct TenantFunctionsPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    /// Service bearer token, surfaced in the upload-hint curl snippet so the
    /// admin can paste-and-run. Plaintext is unavailable after creation, so
    /// this is empty unless re-derivable — we show the placeholder otherwise.
    functions: Vec<FunctionView>,
    collections: Vec<crate::storage::schema::Collection>,
    /// Always `"_functions"` — sidebar `.on` matching.
    active_coll: String,
    /// Public base URL, used in the upload-hint curl snippet.
    public_base_url: String,
    /// Set after a synchronous test-invoke; rendered as an inline outcome card.
    invoke_outcome: Option<InvokeOutcome>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

/// One row in the functions table, with its recent log rows pre-loaded for the
/// inline `<details>` expander and a last-run summary chip.
struct FunctionView {
    name: String,
    /// First 12 chars of the sha for a compact identity chip.
    sha_short: String,
    size_bytes: i64,
    active: bool,
    /// Caller-identity invoke ACL (T5): may anon / end-user bearers invoke this
    /// function (capability-gated). Default-deny; config is service-only.
    invoke_anon: bool,
    invoke_user: bool,
    /// Comma-joined trigger summary (e.g. `record.created:posts, file.uploaded`).
    triggers_summary: String,
    /// Status of the most recent invocation (`ok` / `error` / `timeout` / …),
    /// or empty when the function has never run.
    last_status: String,
    last_run_at: String,
    logs: Vec<schema::LogRowOut>,
}

/// Inline render of a test-invoke result.
struct InvokeOutcome {
    function_name: String,
    status: String,
    duration_ms: u64,
    result: String,
    logs: String,
}

/// Compact trigger summary from the stored `triggers_json` array. Best-effort:
/// a malformed blob renders as the raw string so the admin still sees something.
fn triggers_summary(triggers_json: &str) -> String {
    use crate::functions::bindings::TriggerSpec;
    match crate::functions::bindings::parse_triggers(triggers_json) {
        Ok(specs) => specs
            .iter()
            .map(|s| match s {
                TriggerSpec::Record { collection, events } => {
                    format!("record.{}:{collection}", events.join("|"))
                }
                TriggerSpec::FileUploaded { .. } => "file.uploaded".to_string(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        Err(_) => triggers_json.to_string(),
    }
}

/// Load every function row + its 20 most-recent log rows. Swallows DB errors
/// (a fresh tenant with no `_system_functions` table yet just renders empty).
async fn load_function_views(state: &TenantsState, tenant_id: &str) -> Vec<FunctionView> {
    let pool = match state.tenants.get_or_open(tenant_id) {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    let rows = match schema::list_functions(&pool).await {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let logs = schema::list_logs(&pool, &r.name, 20)
            .await
            .unwrap_or_default();
        let (last_status, last_run_at) = logs
            .first()
            .map(|l| (l.status.clone(), l.created_at.clone()))
            .unwrap_or_default();
        out.push(FunctionView {
            sha_short: r.wasm_sha256.chars().take(12).collect(),
            size_bytes: r.size_bytes,
            active: r.active,
            invoke_anon: r.invoke_anon,
            invoke_user: r.invoke_user,
            triggers_summary: triggers_summary(&r.triggers_json),
            last_status,
            last_run_at,
            logs,
            name: r.name,
        });
    }
    out
}

/// Fire-and-forget audit row for an admin-initiated function mutation.
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

/// Internal page render shared by the GET path and the test-invoke POST (which
/// re-renders the page with an outcome card instead of redirecting).
async fn render_page(
    state: &TenantsState,
    tenant_id: String,
    invoke_outcome: Option<InvokeOutcome>,
    locale: crate::mgmt::i18n::Locale,
    theme: crate::mgmt::theme::Theme,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
) -> Response {
    let (tenant_name, collections) =
        match super::tenants::common::load_tenant_shell(state, &tenant_id).await {
            Ok(t) => t,
            Err(r) => return r,
        };
    let functions = load_function_views(state, &tenant_id).await;
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantFunctionsPage {
            version: env!("CARGO_PKG_VERSION"),
            tenant_id,
            tenant_name,
            functions,
            collections,
            active_coll: "_functions".to_string(),
            public_base_url: state.public_base_url.clone(),
            invoke_outcome,
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

/// `GET /admin/tenants/{id}/_functions` — render the management page.
pub async fn page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
) -> Response {
    render_page(&state, tenant_id, None, locale, theme, admin).await
}

/// `POST /admin/tenants/{id}/_functions/{name}/toggle` — flip the active flag,
/// invalidate the trigger-match cache, audit, then 303 back to the list.
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
    // Read current state, then write the inverse. A missing row 404s.
    let current = match schema::get_function(&pool, &name).await {
        Ok(Some(r)) => r.active,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such function").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = schema::set_active(&pool, &name, !current).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    state.functions.bindings.invalidate(&tenant_id);
    audit_admin(&tenant_id, "function.update", &name);
    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/_functions"
    )))
    .into_response()
}

/// Form for the invoke-ACL toggles. Both checkboxes post their full state on
/// submit (the form carries hidden defaults, so an unchecked box clears the
/// flag); a missing field therefore means "off". Config is service-equivalent
/// here — this handler runs under the admin session, the admin-only surface.
#[derive(Debug, Deserialize, Default)]
pub struct InvokeAclForm {
    #[serde(default)]
    pub invoke_anon: bool,
    #[serde(default)]
    pub invoke_user: bool,
}

/// `POST /admin/tenants/{id}/_functions/{name}/invoke-acl` — set the
/// caller-identity invoke ACL flags in one write (grant AND revoke), invalidate
/// the trigger-binding cache, audit, then 303 back to the list. Mirrors the
/// `toggle` / `delete` admin actions; routes through the same
/// `schema::set_invoke_acl` the REST + MCP surfaces use.
pub async fn set_invoke_acl(
    State(state): State<TenantsState>,
    Path((tenant_id, name)): Path<(String, String)>,
    Form(form): Form<InvokeAclForm>,
) -> Response {
    if let Some(r) = super::tenants::common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };
    match schema::set_invoke_acl(&pool, &name, form.invoke_anon, form.invoke_user).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "no such function").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    state.functions.bindings.invalidate(&tenant_id);
    audit_admin(&tenant_id, "function.update", &name);
    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/_functions"
    )))
    .into_response()
}

/// `POST /admin/tenants/{id}/_functions/{name}/delete` — delete + artifact GC
/// via the shared `delete_impl`, audit, then 303 back to the list.
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
    match crate::functions::routes::delete_impl(
        &pool,
        &state.functions,
        &state.fn_data_root,
        &tenant_id,
        &name,
    )
    .await
    {
        Ok(true) => audit_admin(&tenant_id, "function.delete", &name),
        Ok(false) => {} // already gone — idempotent, still redirect to the list
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/_functions"
    )))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct InvokeForm {
    /// Raw JSON event body from the textarea. Parsed leniently — anything that
    /// is not valid JSON is forwarded as a JSON string so the guest still runs.
    pub event: String,
}

/// `POST /admin/tenants/{id}/_functions/{name}/invoke` — synchronous
/// test-invoke (trigger `"manual"`), re-rendering the page with an inline
/// outcome card. The executor records the log row + `function.invoke` audit
/// itself, so no extra audit here.
pub async fn invoke(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path((tenant_id, name)): Path<(String, String)>,
    Form(form): Form<InvokeForm>,
) -> Response {
    if let Some(r) = super::tenants::common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    // 404 before running anything if the function does not exist.
    if let Ok(pool) = state.tenants.get_or_open(&tenant_id) {
        match schema::get_function(&pool, &name).await {
            Ok(Some(_)) => {}
            Ok(None) => return (StatusCode::NOT_FOUND, "no such function").into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
    // Forward the textarea as-is if it parses to JSON, else wrap it as a string
    // so a non-JSON paste still produces a runnable event body.
    let event_json = match serde_json::from_str::<serde_json::Value>(form.event.trim()) {
        Ok(_) => form.event.trim().to_string(),
        Err(_) => serde_json::Value::String(form.event.clone()).to_string(),
    };
    let started = std::time::Instant::now();
    let out = state
        .functions_exec
        .run_one(crate::functions::executor::Invocation {
            tenant_id: tenant_id.clone(),
            function_name: name.clone(),
            trigger: "manual".into(),
            event_json,
            // Admin invoke is service-equivalent → god-mode, unchanged.
            caller: crate::functions::caller::CallerCtx::Privileged,
        })
        .await;
    let outcome = InvokeOutcome {
        function_name: name,
        status: out.status.as_str().to_string(),
        duration_ms: started.elapsed().as_millis() as u64,
        result: out.result,
        logs: out.log_text,
    };
    render_page(&state, tenant_id, Some(outcome), locale, theme, admin).await
}

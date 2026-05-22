//! Admin-UI handlers for the `_rpc` virtual collection page.
//!
//! Service-key admin only — protected by the admin-session layer applied at
//! the route table (see `routes.rs`). Reads `_system_rpc` via
//! `crate::rpc::registry::list` for the index page; deletes via
//! `crate::rpc::registry::delete` and 303-redirects back to the list.

use crate::mgmt::i18n::{Locale, Translator};
use crate::mgmt::tenants::TenantsState;
use crate::rpc::registry;
use crate::storage::schema::{Collection, list_collections};
use crate::storage::tenant_db::open_read;
use askama::Template;
use axum::Extension;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};

#[derive(Template)]
#[template(path = "tenant_rpc.html")]
struct RpcPage {
    tenant_id: String,
    tenant_name: String,
    /// Driver list for `_collection_sidebar.html`. Empty Vec is fine — the
    /// sidebar still renders the virtual rows.
    collections: Vec<Collection>,
    active_coll: String,
    version: &'static str,
    rpcs: Vec<registry::StoredRpc>,
    /// Pagination — current 1-based page number.
    page: u32,
    total_pages: u32,
    total_rpcs: usize,
    /// Count over the FULL list (pre-pagination) of RPCs marked
    /// `anon_callable=true`. Drives the stat-tile row at the top of
    /// the page.
    total_anon_callable: usize,
    prev_url: Option<String>,
    next_url: Option<String>,
    per_page_options: Vec<RpcPerPageOption>,
    t: Translator,
}

struct RpcPerPageOption {
    value: u32,
    selected: bool,
}

const RPC_DEFAULT_PER_PAGE: u32 = 20;
const RPC_PER_PAGE_OPTIONS: &[u32] = &[20, 50, 100, 200];

#[derive(Debug, serde::Deserialize, Default)]
pub struct RpcListQs {
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

/// `GET /admin/tenants/{id}/_rpc` — list stored RPCs for the tenant.
///
/// Renders `tenant_rpc.html`. A failure to open the tenant DB (e.g. fresh
/// tenant pre-write) yields an empty list — the page still renders with
/// the empty-state mascot and "+ new function" CTA.
pub async fn rpc_index(
    State(state): State<TenantsState>,
    Extension(locale): Extension<Locale>,
    Path(tenant_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<RpcListQs>,
) -> Response {
    // Confirm tenant exists in the meta plane. 404 if missing/deleted —
    // matches the early-out shape in `api_keys_page`.
    let conn = state.session.meta.lock().await;
    let tenant_name: Option<String> = conn
        .query_row(
            "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
        .ok();
    drop(conn);
    let tenant_name = match tenant_name {
        Some(n) => n,
        None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };

    // Read RPC rows. A failed open (no data.sqlite yet) → empty list.
    let all_rpcs: Vec<registry::StoredRpc> = open_read(&state.data_dir, &tenant_id)
        .ok()
        .and_then(|c| registry::list(&c).ok())
        .unwrap_or_default();

    // Sidebar collections — same fallback as `api_keys_page`.
    let collections = open_read(&state.data_dir, &tenant_id)
        .ok()
        .and_then(|c| list_collections(&c).ok())
        .unwrap_or_default();

    let per_page = qs
        .per_page
        .filter(|n| RPC_PER_PAGE_OPTIONS.contains(n))
        .unwrap_or(RPC_DEFAULT_PER_PAGE);
    let total_rpcs = all_rpcs.len();
    let total_anon_callable = all_rpcs.iter().filter(|r| r.anon_callable).count();
    let total_pages = if total_rpcs == 0 {
        1
    } else {
        ((total_rpcs as u64).div_ceil(per_page as u64)) as u32
    };
    let page = qs.page.unwrap_or(1).max(1).min(total_pages);
    let start = ((page - 1) as usize) * per_page as usize;
    let end = (start + per_page as usize).min(total_rpcs);
    let rpcs: Vec<registry::StoredRpc> = all_rpcs.into_iter().skip(start).take(end - start).collect();

    let pager_url = |p: u32| -> String {
        if per_page == RPC_DEFAULT_PER_PAGE {
            format!("/drust/admin/tenants/{tenant_id}/_rpc?page={p}")
        } else {
            format!("/drust/admin/tenants/{tenant_id}/_rpc?page={p}&per_page={per_page}")
        }
    };
    let prev_url = (page > 1).then(|| pager_url(page - 1));
    let next_url = (page < total_pages).then(|| pager_url(page + 1));
    let per_page_options: Vec<RpcPerPageOption> = RPC_PER_PAGE_OPTIONS
        .iter()
        .map(|&v| RpcPerPageOption {
            value: v,
            selected: v == per_page,
        })
        .collect();

    Html(
        RpcPage {
            tenant_id,
            tenant_name,
            collections,
            active_coll: "_rpc".to_string(),
            version: env!("CARGO_PKG_VERSION"),
            rpcs,
            page,
            total_pages,
            total_rpcs,
            total_anon_callable,
            prev_url,
            next_url,
            per_page_options,
            t: Translator::new(locale),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

#[derive(Template)]
#[template(path = "tenant_rpc_form.html")]
struct RpcForm {
    tenant_id: String,
    tenant_name: String,
    active_coll: String,
    version: &'static str,
    collections: Vec<Collection>,
    editing: bool,
    /// Existing RPC name (filled when `editing == true`, "" when creating).
    existing_name: String,
    form_name: String,
    form_description: String,
    form_sql: String,
    form_params_json: String,
    form_anon_callable: bool,
    error: Option<String>,
    t: Translator,
}

async fn lookup_tenant_name(state: &TenantsState, tenant_id: &str) -> Option<String> {
    let conn = state.session.meta.lock().await;
    conn.query_row(
        "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tenant_id],
        |r| r.get(0),
    )
    .ok()
}

/// Load the sidebar collections for the tenant; falls back to empty Vec if
/// the data plane isn't readable yet (e.g. brand-new tenant pre-write).
fn load_collections(state: &TenantsState, tenant_id: &str) -> Vec<Collection> {
    open_read(&state.data_dir, tenant_id)
        .ok()
        .and_then(|c| list_collections(&c).ok())
        .unwrap_or_default()
}

/// `GET /admin/tenants/{id}/_rpc/new` — render the empty create form.
pub async fn rpc_new_form(
    State(state): State<TenantsState>,
    Extension(locale): Extension<Locale>,
    Path(tenant_id): Path<String>,
) -> Response {
    let tenant_name = match lookup_tenant_name(&state, &tenant_id).await {
        Some(n) => n,
        None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };
    let collections = load_collections(&state, &tenant_id);
    Html(
        RpcForm {
            tenant_id: tenant_id.clone(),
            tenant_name,
            active_coll: "_rpc".to_string(),
            version: env!("CARGO_PKG_VERSION"),
            collections,
            editing: false,
            existing_name: String::new(),
            form_name: String::new(),
            form_description: String::new(),
            form_sql: String::new(),
            form_params_json: "[]".into(),
            form_anon_callable: false,
            error: None,
            t: Translator::new(locale),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// `GET /admin/tenants/{id}/_rpc/{name}/edit` — render the form pre-filled
/// from the existing row. 404 when the RPC isn't found.
pub async fn rpc_edit_form(
    State(state): State<TenantsState>,
    Extension(locale): Extension<Locale>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> Response {
    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let existing = match registry::lookup(&conn, &name) {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such rpc").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    drop(conn);
    let tenant_name = match lookup_tenant_name(&state, &tenant_id).await {
        Some(n) => n,
        None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };
    let collections = load_collections(&state, &tenant_id);
    let params_json_string =
        serde_json::to_string_pretty(&existing.params).unwrap_or_else(|_| "[]".into());
    Html(
        RpcForm {
            tenant_id: tenant_id.clone(),
            tenant_name,
            active_coll: "_rpc".to_string(),
            version: env!("CARGO_PKG_VERSION"),
            collections,
            editing: true,
            existing_name: existing.name.clone(),
            form_name: existing.name,
            form_description: existing.description.unwrap_or_default(),
            form_sql: existing.sql,
            form_params_json: params_json_string,
            form_anon_callable: existing.anon_callable,
            error: None,
            t: Translator::new(locale),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

#[derive(serde::Deserialize, Clone)]
pub struct RpcFormBody {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub sql: String,
    pub params_json: String,
    /// Checkbox: present (`"1"`) when checked, absent otherwise.
    #[serde(default)]
    pub anon_callable: Option<String>,
}

/// `POST /admin/tenants/{id}/_rpc/new` (create) and
/// `POST /admin/tenants/{id}/_rpc/{name}/save` (edit). Both routes funnel
/// through this handler — create vs. update is decided by whether a row
/// with the submitted name already exists.
pub async fn rpc_save(
    State(state): State<TenantsState>,
    Extension(locale): Extension<Locale>,
    Path(tenant_id): Path<String>,
    axum::Form(form): axum::Form<RpcFormBody>,
) -> Response {
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let tenant_name = lookup_tenant_name(&state, &tenant_id)
        .await
        .unwrap_or_else(|| tenant_id.clone());

    // Pre-validate params_json before taking the writer lock (no DB needed).
    if let Err(e) = crate::rpc::params::parse_params_json(&form.params_json) {
        let name_for_lookup = form.name.clone();
        let exists_now = pool
            .with_reader(move |c| Ok(registry::lookup(c, &name_for_lookup).ok().flatten().is_some()))
            .await
            .unwrap_or(false);
        return render_form_with_error(&state, &tenant_id, &tenant_name, &form, exists_now, e.to_string(), locale);
    }

    // Validate SQL through the read-only authorizer (uses a reader connection
    // so the authorizer is never attached to the writer).
    let sql_for_validate = form.sql.clone();
    let validate_res = pool
        .with_reader(move |c| {
            crate::rpc::prepare::validate_rpc_sql(c, &sql_for_validate)
                .map_err(|e| rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(e.to_string()),
                ))
        })
        .await;
    if let Err(e) = validate_res {
        let name_for_lookup = form.name.clone();
        let exists_now = pool
            .with_reader(move |c| Ok(registry::lookup(c, &name_for_lookup).ok().flatten().is_some()))
            .await
            .unwrap_or(false);
        return render_form_with_error(&state, &tenant_id, &tenant_name, &form, exists_now, e.to_string(), locale);
    }

    // Single writer transaction: lookup existence + create-or-update.
    let form_for_writer = form.clone();
    let writer_res = pool
        .with_writer(move |c| -> rusqlite::Result<bool> {
            let exists_now = registry::lookup(c, &form_for_writer.name)
                .ok()
                .flatten()
                .is_some();
            let anon_callable = form_for_writer.anon_callable.is_some();
            let result = if exists_now {
                registry::update(
                    c,
                    &form_for_writer.name,
                    Some(&form_for_writer.sql),
                    Some(&form_for_writer.params_json),
                    Some(form_for_writer.description.as_deref()),
                    Some(anon_callable),
                )
            } else {
                registry::create(
                    c,
                    &form_for_writer.name,
                    &form_for_writer.sql,
                    &form_for_writer.params_json,
                    form_for_writer.description.as_deref(),
                    anon_callable,
                )
            };
            result.map(|_| exists_now).map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(1),
                Some(e.to_string()),
            ))
        })
        .await;
    if let Err(e) = writer_res {
        let name_for_lookup = form.name.clone();
        let exists_now = pool
            .with_reader(move |c| Ok(registry::lookup(c, &name_for_lookup).ok().flatten().is_some()))
            .await
            .unwrap_or(false);
        return render_form_with_error(&state, &tenant_id, &tenant_name, &form, exists_now, e.to_string(), locale);
    }

    Redirect::to(&format!("/drust/admin/tenants/{tenant_id}/_rpc")).into_response()
}

fn render_form_with_error(
    state: &TenantsState,
    tenant_id: &str,
    tenant_name: &str,
    form: &RpcFormBody,
    editing: bool,
    msg: String,
    locale: Locale,
) -> Response {
    let collections = load_collections(state, tenant_id);
    Html(
        RpcForm {
            tenant_id: tenant_id.to_string(),
            tenant_name: tenant_name.to_string(),
            active_coll: "_rpc".to_string(),
            version: env!("CARGO_PKG_VERSION"),
            collections,
            editing,
            existing_name: form.name.clone(),
            form_name: form.name.clone(),
            form_description: form.description.clone().unwrap_or_default(),
            form_sql: form.sql.clone(),
            form_params_json: form.params_json.clone(),
            form_anon_callable: form.anon_callable.is_some(),
            error: Some(msg),
            t: Translator::new(locale),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// One row in the test page's parameter form. Mirrors `ParamSpec` for
/// rendering; the `value` field carries either the empty string (initial
/// render) or the user-submitted value (re-rendered after a run).
struct RpcTestParam {
    name: String,
    /// Lowercase string of `ParamType` — feeds the input `data-type` attribute.
    ty: String,
    required: bool,
    /// Pretty-printed default JSON, or empty string when no default.
    default_display: String,
    value: String,
}

#[derive(Template)]
#[template(path = "tenant_rpc_test.html")]
struct RpcTestPage {
    tenant_id: String,
    tenant_name: String,
    version: &'static str,
    collections: Vec<Collection>,
    active_coll: String,
    existing_name: String,
    description: Option<String>,
    sql: String,
    anon_callable: bool,
    params: Vec<RpcTestParam>,
    /// Set when the user has just clicked Run. None on the bare GET.
    outcome: Option<RpcTestOutcome>,
    t: Translator,
}

struct RpcTestOutcome {
    duration_ms: u128,
    /// Pretty-printed JSON of the bound params (to confirm coercion).
    bound_json: String,
    /// `Some(...)` on success.
    result: Option<RpcTestResult>,
    /// `Some(...)` on failure (set instead of `result`).
    error: Option<String>,
    /// Rows from `EXPLAIN QUERY PLAN <sql>`. Empty on early failures.
    explain_rows: Vec<String>,
}

struct RpcTestResult {
    column_names: Vec<String>,
    rows: Vec<Vec<String>>,
    row_count: usize,
    truncated: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct RpcTestRunForm {
    /// Each param submitted as `p_<name>=<string>`. We collect dynamically.
    #[serde(flatten)]
    fields: std::collections::BTreeMap<String, String>,
}

/// `GET /admin/tenants/{id}/_rpc/{name}/test` — render the test playground
/// for a stored RPC. 404 when the RPC doesn't exist; 404 when the tenant
/// doesn't exist (matches the existence check shape of other handlers).
pub async fn rpc_test_form(
    State(state): State<TenantsState>,
    Extension(locale): Extension<Locale>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> Response {
    let tenant_name = match lookup_tenant_name(&state, &tenant_id).await {
        Some(n) => n,
        None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };
    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let stored = match registry::lookup(&conn, &name) {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such rpc").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let collections = list_collections(&conn).unwrap_or_default();
    drop(conn);

    Html(
        RpcTestPage {
            tenant_id,
            tenant_name,
            version: env!("CARGO_PKG_VERSION"),
            collections,
            active_coll: "_rpc".to_string(),
            existing_name: stored.name.clone(),
            description: stored.description.clone(),
            sql: stored.sql.clone(),
            anon_callable: stored.anon_callable,
            params: stored
                .params
                .iter()
                .map(|p| RpcTestParam {
                    name: p.name.clone(),
                    ty: param_ty_to_str(p.ty).to_string(),
                    required: p.required,
                    default_display: p
                        .default
                        .as_ref()
                        .map(|d| serde_json::to_string(d).unwrap_or_default())
                        .unwrap_or_default(),
                    value: String::new(),
                })
                .collect(),
            outcome: None,
            t: Translator::new(locale),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

fn param_ty_to_str(t: crate::rpc::params::ParamType) -> &'static str {
    use crate::rpc::params::ParamType::*;
    match t {
        Text => "text",
        Integer => "integer",
        Real => "real",
        Boolean => "boolean",
    }
}

/// Coerce a single form-string into a JSON value typed by the declared
/// param. Empty string → `null` (let `validate_and_bind` apply default
/// or report as missing). Unparseable → string back; `validate_and_bind`
/// will raise `TypeMismatch`.
fn coerce_form_string(ty: crate::rpc::params::ParamType, s: &str) -> serde_json::Value {
    use crate::rpc::params::ParamType::*;
    use serde_json::Value;
    if s.is_empty() {
        return Value::Null;
    }
    match ty {
        Text => Value::String(s.to_string()),
        Integer => s
            .parse::<i64>()
            .map(|n| Value::Number(n.into()))
            .unwrap_or_else(|_| Value::String(s.to_string())),
        Real => s
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(s.to_string())),
        Boolean => match s {
            "1" | "true" | "on" | "yes" => Value::Bool(true),
            "0" | "false" | "off" | "no" => Value::Bool(false),
            _ => Value::String(s.to_string()),
        },
    }
}

/// `POST /admin/tenants/{id}/_rpc/{name}/test/run` — execute the RPC with
/// the submitted form values and re-render the page with the result.
pub async fn rpc_test_run(
    State(state): State<TenantsState>,
    Extension(locale): Extension<Locale>,
    Path((tenant_id, name)): Path<(String, String)>,
    axum::Form(form): axum::Form<RpcTestRunForm>,
) -> Response {
    let tenant_name = match lookup_tenant_name(&state, &tenant_id).await {
        Some(n) => n,
        None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };
    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let stored = match registry::lookup(&conn, &name) {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such rpc").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let collections = list_collections(&conn).unwrap_or_default();

    // Build a JSON body Map by coercing each `p_<name>=<value>` form entry.
    let mut body_map = serde_json::Map::new();
    let mut visible_inputs: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for spec in &stored.params {
        let key = format!("p_{}", spec.name);
        let raw = form.fields.get(&key).cloned().unwrap_or_default();
        visible_inputs.insert(spec.name.clone(), raw.clone());
        let coerced = coerce_form_string(spec.ty, &raw);
        // Skip null entries so missing-required surfaces via validate_and_bind.
        if !coerced.is_null() {
            body_map.insert(spec.name.clone(), coerced);
        }
    }

    // Validate + bind. On failure, surface as outcome.error.
    let bound_result = crate::rpc::params::validate_and_bind(&stored.params, &body_map);
    let bound = match bound_result {
        Ok(b) => b,
        Err(e) => {
            return render_test_outcome(
                tenant_id,
                tenant_name,
                collections,
                &stored,
                visible_inputs,
                Err(e.to_string()),
                Vec::new(),
                0,
                serde_json::to_string_pretty(&body_map).unwrap_or_default(),
                locale,
            );
        }
    };

    let bound_json = serde_json::to_string_pretty(&body_map).unwrap_or_default();

    // EXPLAIN QUERY PLAN — best-effort. Failures here are non-fatal; we
    // still attempt the real query so the user sees whichever signal is
    // more informative.
    let explain_rows = explain_plan(&conn, &stored.sql, &bound).unwrap_or_default();

    // Real execution.
    let started = std::time::Instant::now();
    let exec_result = crate::query::executor::execute_read_query_with_named(
        &conn,
        &stored.sql,
        &bound,
        1_000,
        1_048_576,
    );
    let duration_ms = started.elapsed().as_millis();

    match exec_result {
        Ok(qr) => render_test_outcome(
            tenant_id,
            tenant_name,
            collections,
            &stored,
            visible_inputs,
            Ok(qr),
            explain_rows,
            duration_ms,
            bound_json,
            locale,
        ),
        Err(e) => render_test_outcome(
            tenant_id,
            tenant_name,
            collections,
            &stored,
            visible_inputs,
            Err(e.to_string()),
            explain_rows,
            duration_ms,
            bound_json,
            locale,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn render_test_outcome(
    tenant_id: String,
    tenant_name: String,
    collections: Vec<Collection>,
    stored: &registry::StoredRpc,
    visible_inputs: std::collections::BTreeMap<String, String>,
    exec: Result<crate::query::executor::QueryResult, String>,
    explain_rows: Vec<String>,
    duration_ms: u128,
    bound_json: String,
    locale: Locale,
) -> Response {
    let result = exec.as_ref().ok().map(|qr| RpcTestResult {
        column_names: qr.column_names.clone(),
        rows: qr
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|v| match v {
                        serde_json::Value::Null => "NULL".to_string(),
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect()
            })
            .collect(),
        row_count: qr.rows.len(),
        truncated: qr.truncated,
    });
    let error = exec.err();

    let params: Vec<RpcTestParam> = stored
        .params
        .iter()
        .map(|p| RpcTestParam {
            name: p.name.clone(),
            ty: param_ty_to_str(p.ty).to_string(),
            required: p.required,
            default_display: p
                .default
                .as_ref()
                .map(|d| serde_json::to_string(d).unwrap_or_default())
                .unwrap_or_default(),
            value: visible_inputs.get(&p.name).cloned().unwrap_or_default(),
        })
        .collect();

    Html(
        RpcTestPage {
            tenant_id,
            tenant_name,
            version: env!("CARGO_PKG_VERSION"),
            collections,
            active_coll: "_rpc".to_string(),
            existing_name: stored.name.clone(),
            description: stored.description.clone(),
            sql: stored.sql.clone(),
            anon_callable: stored.anon_callable,
            params,
            outcome: Some(RpcTestOutcome {
                duration_ms,
                bound_json,
                result,
                error,
                explain_rows,
            }),
            t: Translator::new(locale),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Run `EXPLAIN QUERY PLAN <sql>` with the given bound params. Returns
/// the `detail` column from each plan row. Errors are non-fatal and
/// returned as `Err` so the caller can decide whether to surface them.
fn explain_plan(
    conn: &rusqlite::Connection,
    sql: &str,
    bound: &std::collections::BTreeMap<String, crate::rpc::params::BoundValue>,
) -> Result<Vec<String>, rusqlite::Error> {
    let plan_sql = format!("EXPLAIN QUERY PLAN {sql}");
    let mut stmt = conn.prepare(&plan_sql)?;
    // Bind named params. Missing ones are tolerated by SQLite (NULL).
    let bind_pairs: Vec<(String, rusqlite::types::Value)> = bound
        .iter()
        .map(|(k, v)| (format!(":{k}"), v.to_sql()))
        .collect();
    let bind_refs: Vec<(&str, &dyn rusqlite::ToSql)> = bind_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v as &dyn rusqlite::ToSql))
        .collect();
    let rows: Vec<String> = stmt
        .query_map(bind_refs.as_slice(), |r| {
            // SQLite EXPLAIN QUERY PLAN columns: id, parent, notused, detail
            r.get::<_, String>(3)
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

/// `POST /admin/tenants/{id}/_rpc/{name}/delete` — drop a stored RPC.
///
/// Idempotent: a missing row still 303-redirects back to the list (matches
/// the spirit of `delete_file` MCP and avoids angry confirmation modals
/// on double-submits). Any other DB error yields 500.
pub async fn rpc_delete(
    State(state): State<TenantsState>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> Response {
    // Confirm tenant exists.
    let conn = state.session.meta.lock().await;
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    drop(conn);
    if exists == 0 {
        return (StatusCode::NOT_FOUND, "tenant not found").into_response();
    }

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let name_for_writer = name.clone();
    let delete_res: Result<(), String> = pool
        .with_writer(move |c| {
            match registry::delete(c, &name_for_writer) {
                Ok(()) | Err(registry::RegistryError::NotFound(_)) => Ok(()),
                Err(e) => Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(e.to_string()),
                )),
            }
        })
        .await
        .map_err(|e| e.to_string());
    if let Err(msg) = delete_res {
        return (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response();
    }

    Redirect::to(&format!("/drust/admin/tenants/{}/_rpc", tenant_id)).into_response()
}

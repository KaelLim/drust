//! Admin-UI handlers for the `_rpc` virtual collection page.
//!
//! Service-key admin only — protected by the admin-session layer applied at
//! the route table (see `routes.rs`). Reads `_system_rpc` via
//! `crate::rpc::registry::list` for the index page; deletes via
//! `crate::rpc::registry::delete` and 303-redirects back to the list.

use crate::mgmt::tenants::TenantsState;
use crate::rpc::registry;
use crate::storage::schema::{Collection, list_collections};
use crate::storage::tenant_db::{open_read, open_write};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};

#[derive(Template)]
#[template(path = "tenant_rpc.html")]
struct RpcPage {
    tenant_id: String,
    /// Driver list for `_collection_sidebar.html`. Empty Vec is fine — the
    /// sidebar still renders the virtual rows.
    collections: Vec<Collection>,
    active_coll: String,
    version: &'static str,
    rpcs: Vec<registry::StoredRpc>,
}

/// `GET /admin/tenants/{id}/_rpc` — list stored RPCs for the tenant.
///
/// Renders `tenant_rpc.html`. A failure to open the tenant DB (e.g. fresh
/// tenant pre-write) yields an empty list — the page still renders with
/// the empty-state mascot and "+ new function" CTA.
pub async fn rpc_index(
    State(state): State<TenantsState>,
    Path(tenant_id): Path<String>,
) -> Response {
    // Confirm tenant exists in the meta plane. 404 if missing/deleted —
    // matches the early-out shape in `api_keys_page`.
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

    // Read RPC rows. A failed open (no data.sqlite yet) → empty list.
    let rpcs = open_read(&state.data_dir, &tenant_id)
        .ok()
        .and_then(|c| registry::list(&c).ok())
        .unwrap_or_default();

    // Sidebar collections — same fallback as `api_keys_page`.
    let collections = open_read(&state.data_dir, &tenant_id)
        .ok()
        .and_then(|c| list_collections(&c).ok())
        .unwrap_or_default();

    Html(
        RpcPage {
            tenant_id,
            collections,
            active_coll: "_rpc".to_string(),
            version: env!("CARGO_PKG_VERSION"),
            rpcs,
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
    Path(tenant_id): Path<String>,
) -> Response {
    let collections = load_collections(&state, &tenant_id);
    Html(
        RpcForm {
            tenant_id: tenant_id.clone(),
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
    let collections = load_collections(&state, &tenant_id);
    let params_json_string =
        serde_json::to_string_pretty(&existing.params).unwrap_or_else(|_| "[]".into());
    Html(
        RpcForm {
            tenant_id: tenant_id.clone(),
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
    Path(tenant_id): Path<String>,
    axum::Form(form): axum::Form<RpcFormBody>,
) -> Response {
    let writer = match open_write(&state.data_dir, &tenant_id) {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let anon_callable = form.anon_callable.is_some();

    // Validate params_json parses.
    if let Err(e) = crate::rpc::params::parse_params_json(&form.params_json) {
        let exists_now = registry::lookup(&writer, &form.name).ok().flatten().is_some();
        return render_form_with_error(&state, &tenant_id, &form, exists_now, e.to_string());
    }
    // Validate SQL through the read-only authorizer.
    if let Err(e) = crate::rpc::prepare::validate_rpc_sql(&writer, &form.sql) {
        let exists_now = registry::lookup(&writer, &form.name).ok().flatten().is_some();
        return render_form_with_error(&state, &tenant_id, &form, exists_now, e.to_string());
    }

    let exists_now = registry::lookup(&writer, &form.name).ok().flatten().is_some();
    let res = if exists_now {
        registry::update(
            &writer,
            &form.name,
            Some(&form.sql),
            Some(&form.params_json),
            Some(form.description.as_deref()),
            Some(anon_callable),
        )
    } else {
        registry::create(
            &writer,
            &form.name,
            &form.sql,
            &form.params_json,
            form.description.as_deref(),
            anon_callable,
        )
    };
    if let Err(e) = res {
        return render_form_with_error(&state, &tenant_id, &form, exists_now, e.to_string());
    }
    Redirect::to(&format!("/drust/admin/tenants/{tenant_id}/_rpc")).into_response()
}

fn render_form_with_error(
    state: &TenantsState,
    tenant_id: &str,
    form: &RpcFormBody,
    editing: bool,
    msg: String,
) -> Response {
    let collections = load_collections(state, tenant_id);
    Html(
        RpcForm {
            tenant_id: tenant_id.to_string(),
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
        }
        .render()
        .unwrap(),
    )
    .into_response()
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

    let writer = match open_write(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    match registry::delete(&writer, &name) {
        Ok(()) | Err(registry::RegistryError::NotFound(_)) => {}
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    Redirect::to(&format!("/drust/admin/tenants/{}/_rpc", tenant_id)).into_response()
}

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

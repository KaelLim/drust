//! Cross-page helpers shared by the OAuth-providers and Webhooks admin pages.
//! Relocated from `tenants.rs` (group G) by the Finding #4 split.
//! `load_tenant_shell` + `ensure_tenant_exists` are `pub(crate)` — the only
//! deliberate visibility widening in the refactor (was module-private).

use super::TenantsState;
use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use crate::storage::tenant_db::open_read;

/// Internal: resolve tenant name (404 if missing/deleted) and pull the
/// collection list for the sidebar. Mirrors what `_api_keys` does.
pub(crate) async fn load_tenant_shell(
    state: &TenantsState,
    tenant_id: &str,
) -> Result<(String, Vec<crate::storage::schema::Collection>), Response> {
    let tenant_name: Option<String> = {
        let conn = state.session.meta.lock().await;
        conn.query_row(
            "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
        .ok()
    };
    let tenant_name = match tenant_name {
        Some(n) => n,
        None => {
            return Err((StatusCode::NOT_FOUND, "no such tenant").into_response());
        }
    };
    let collections = open_read(&state.data_dir, tenant_id)
        .ok()
        .and_then(|c| crate::storage::schema::list_collections(&c).ok())
        .unwrap_or_default();
    Ok((tenant_name, collections))
}

/// Lightweight existence guard for admin POST handlers (DELETE / upsert):
/// returns `None` if the tenant exists in `meta.tenants` and isn't
/// soft-deleted, or a 404 response otherwise. Used before
/// `state.tenants.get_or_open(...)` so we don't materialise an empty
/// `tenants/<bogus_id>/data.sqlite` for an admin-typed path. Cheaper than
/// `load_tenant_shell` (no collection list).
pub(crate) async fn ensure_tenant_exists(state: &TenantsState, tenant_id: &str) -> Option<Response> {
    let exists: bool = {
        let conn = state.session.meta.lock().await;
        conn.query_row(
            "SELECT 1 FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |_| Ok(()),
        )
        .is_ok()
    };
    if !exists {
        return Some((StatusCode::NOT_FOUND, "no such tenant").into_response());
    }
    None
}

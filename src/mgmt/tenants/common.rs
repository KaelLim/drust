//! Cross-page helpers shared by the OAuth-providers and Webhooks admin pages.
//! Relocated from `tenants.rs` (group G) by the Finding #4 split.
//! `load_tenant_shell` + `ensure_tenant_visible` are `pub(crate)` — the only
//! deliberate visibility widening in the refactor (was module-private).

use super::TenantsState;
use crate::storage::tenant_db::open_read;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

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

/// v1.50 — ownership-aware visibility guard for admin POST handlers
/// (DELETE / upsert), the successor to `ensure_tenant_exists`: returns
/// `None` when the tenant exists in `meta.tenants`, isn't soft-deleted,
/// AND `tenant_authz::tenant_access_for` allows the caller (sees_all =
/// owner OR admin: always; member: only tenants they own). Missing tenant
/// and member-not-owned both return the SAME 404 so a member cannot probe
/// for a foreign tenant's existence. Runs before `state.tenants.get_or_create(...)`
/// so we don't materialise an empty `tenants/<bogus_id>/data.sqlite` for an
/// admin-typed path. Cheaper than `load_tenant_shell` (no collection list).
pub(crate) async fn ensure_tenant_visible(
    state: &TenantsState,
    tenant_id: &str,
    sees_all: bool,
    caller_admin_id: i64,
) -> Option<Response> {
    let owner: Result<Option<i64>, _> = {
        let conn = state.session.meta.lock().await;
        conn.query_row(
            "SELECT owner_admin_id FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
    };
    match owner {
        Err(_) => Some((StatusCode::NOT_FOUND, "no such tenant").into_response()),
        Ok(o) => match crate::mgmt::tenant_authz::tenant_access_for(sees_all, caller_admin_id, o) {
            crate::mgmt::tenant_authz::TenantAccess::Allow => None,
            // 404 (not 403): never leak a foreign tenant's existence to a member.
            crate::mgmt::tenant_authz::TenantAccess::Deny => {
                Some((StatusCode::NOT_FOUND, "no such tenant").into_response())
            }
        },
    }
}

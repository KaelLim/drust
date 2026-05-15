//! Pure async helpers for the per-tenant OAuth-provider admin MCP tools
//! (T14-T16). MCP is service-key-only — anon bearers are blocked at the
//! dispatch layer, so these helpers do not re-check the role.
//!
//! Each function mirrors a handler in `src/tenant/oauth_admin_routes.rs`
//! and returns `anyhow::Result<serde_json::Value>` so it can be wired
//! uniformly from `#[tool]` methods in `handler.rs`.

use crate::storage::pool::SharedTenantPool;
use crate::tenant::oauth_config;
use serde_json::json;

// ─── list ────────────────────────────────────────────────────────────────────

pub async fn list_oauth_providers(
    pool: &SharedTenantPool,
) -> anyhow::Result<serde_json::Value> {
    let rows = pool
        .with_reader(move |c| oauth_config::list(c))
        .await
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    let providers: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|c| {
            json!({
                "provider":              c.provider,
                "client_id":             c.client_id,
                "client_secret":         "●●●●",
                "allowed_redirect_uris": c.allowed_redirect_uris,
                "created_at":            c.created_at,
                "updated_at":            c.updated_at,
            })
        })
        .collect();
    Ok(json!({ "providers": providers }))
}

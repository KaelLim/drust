//! Pure async helpers for the per-tenant OAuth-provider admin MCP tools
//! (T14-T16). MCP is service-key-only — anon bearers are blocked at the
//! dispatch layer, so these helpers do not re-check the role.
//!
//! Each function mirrors a handler in `src/tenant/oauth_admin_routes.rs`
//! and returns `anyhow::Result<serde_json::Value>` so it can be wired
//! uniformly from `#[tool]` methods in `handler.rs`.

use crate::storage::pool::SharedTenantPool;
use crate::tenant::oauth_config::{self, OauthConfigError};
use serde_json::json;

// ─── list ────────────────────────────────────────────────────────────────────

pub async fn list_oauth_providers(pool: &SharedTenantPool) -> anyhow::Result<serde_json::Value> {
    let rows = pool
        .with_reader(oauth_config::list)
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

// ─── set (upsert) ────────────────────────────────────────────────────────────

pub async fn set_oauth_provider(
    pool: &SharedTenantPool,
    provider: String,
    client_id: String,
    client_secret: String,
    allowed_redirect_uris: Vec<String>,
) -> anyhow::Result<serde_json::Value> {
    // Validate up front so we fail fast with the granular error code
    // (INVALID_PROVIDER / INVALID_REDIRECT_URI / EMPTY_REDIRECT_URIS /
    // INVALID_CLIENT_ID / INVALID_CLIENT_SECRET) before touching the writer
    // mutex. The `<CODE>: <message>` shape is what `bail_mcp` surfaces in
    // the tool's text payload — LLMs can branch on the leading code.
    if let Err(e) = oauth_config::validate_upsert(
        &provider,
        &client_id,
        &client_secret,
        &allowed_redirect_uris,
    ) {
        return Err(anyhow::anyhow!("{}: {}", e.error_code(), e));
    }
    let provider2 = provider.clone();
    pool.with_writer(move |c| {
        oauth_config::upsert(
            c,
            &provider2,
            &client_id,
            &client_secret,
            &allowed_redirect_uris,
        )
        .map_err(|e| match e {
            OauthConfigError::Db(re) => re,
            // Validation already ran above; treat any residual validation
            // miss as a generic rusqlite error so the caller maps to a
            // 500-equivalent. Defence in depth.
            other => rusqlite::Error::InvalidParameterName(other.to_string()),
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    Ok(json!({ "ok": true, "provider": provider }))
}

// ─── set redirect uris (update-only) ─────────────────────────────────────────

pub async fn set_redirect_uris(
    pool: &SharedTenantPool,
    provider: String,
    allowed_redirect_uris: Vec<String>,
) -> anyhow::Result<serde_json::Value> {
    if allowed_redirect_uris.is_empty() {
        return Err(anyhow::anyhow!(
            "EMPTY_REDIRECT_URIS: allowed_redirect_uris must be a non-empty array"
        ));
    }
    for u in &allowed_redirect_uris {
        if let Err(e) = oauth_config::validate_redirect_uri(u) {
            return Err(anyhow::anyhow!("{}: {}", e.error_code(), e));
        }
    }
    let provider2 = provider.clone();
    let count = allowed_redirect_uris.len();
    let uris = allowed_redirect_uris;
    let changed = pool
        .with_writer(move |c| {
            oauth_config::update_redirect_uris(c, &provider2, &uris).map_err(|e| match e {
                OauthConfigError::Db(re) => re,
                other => rusqlite::Error::InvalidParameterName(other.to_string()),
            })
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    if !changed {
        return Err(anyhow::anyhow!("NOT_FOUND: provider not configured"));
    }
    Ok(json!({ "ok": true, "provider": provider, "redirect_uris_count": count }))
}

// ─── delete ──────────────────────────────────────────────────────────────────

pub async fn delete_oauth_provider(
    pool: &SharedTenantPool,
    provider: String,
) -> anyhow::Result<serde_json::Value> {
    let provider2 = provider.clone();
    let existed = pool
        .with_writer(move |c| oauth_config::delete(c, &provider2))
        .await
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    if !existed {
        return Err(anyhow::anyhow!("NOT_FOUND: provider not configured"));
    }
    Ok(json!({ "ok": true, "provider": provider, "deleted": true }))
}

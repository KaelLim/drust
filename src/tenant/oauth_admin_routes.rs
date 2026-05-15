//! Service-only admin endpoints for managing this tenant's OAuth provider
//! configs (the `_system_oauth_providers` table).
//!
//! Routes (all service-key-only):
//!   GET    /t/{tenant}/admin/oauth-providers              — list (secrets redacted)
//!   PUT    /t/{tenant}/admin/oauth-providers/{provider}   — upsert
//!   DELETE /t/{tenant}/admin/oauth-providers/{provider}   — delete
//!
//! Auth: service-only. The `bearer_auth_layer` attaches `AuthCtx` as a
//! request extension; we gate on `AuthCtx::Service` here (mirrors
//! `admin_user_routes`). Audit is handled by the bearer middleware — no
//! per-handler audit wiring needed.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

use crate::auth::middleware::AuthCtx;
use crate::tenant::oauth_config::{self, OauthConfigError};
use crate::tenant::router::TenantAuthState;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn err(s: StatusCode, code: &str, msg: &str) -> Response {
    (s, Json(json!({"error_code": code, "message": msg}))).into_response()
}

fn require_service_ctx(ctx: &AuthCtx) -> Option<Response> {
    if !matches!(ctx, AuthCtx::Service) {
        return Some(err(
            StatusCode::FORBIDDEN,
            "SERVICE_ONLY",
            "service token required",
        ));
    }
    None
}

fn get_tid(params: &HashMap<String, String>) -> Result<String, Response> {
    params
        .get("tenant")
        .cloned()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"))
}

#[allow(dead_code)] // Used by PUT/DELETE handlers added in T12/T13.
fn get_provider(params: &HashMap<String, String>) -> Result<String, Response> {
    params
        .get("provider")
        .cloned()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing provider"))
}

// ─── response shape ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct OauthProviderListItem {
    pub provider: String,
    pub client_id: String,
    /// Always the literal `"●●●●"` — real secrets never leave the writer.
    pub client_secret: &'static str,
    pub allowed_redirect_uris: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ─── handlers ────────────────────────────────────────────────────────────────

pub async fn list_oauth_providers_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
) -> Response {
    if let Some(r) = require_service_ctx(&ctx) {
        return r;
    }
    let tid = match get_tid(&params) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let rows = match pool
        .with_reader(move |c| oauth_config::list(c))
        .await
    {
        Ok(v) => v,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB", ""),
    };
    let resp: Vec<OauthProviderListItem> = rows
        .into_iter()
        .map(|c| OauthProviderListItem {
            provider: c.provider,
            client_id: c.client_id,
            client_secret: "●●●●",
            allowed_redirect_uris: c.allowed_redirect_uris,
            created_at: c.created_at,
            updated_at: c.updated_at,
        })
        .collect();
    (StatusCode::OK, Json(json!({ "providers": resp }))).into_response()
}

// ─── request bodies (re-used by PUT in T12) ──────────────────────────────────

#[allow(dead_code)] // Used by PUT handler added in T12.
#[derive(Deserialize)]
pub struct UpsertBody {
    pub client_id: String,
    pub client_secret: String,
    pub allowed_redirect_uris: Vec<String>,
}

#[allow(dead_code)] // Used by PUT/DELETE handlers added in T12/T13.
fn oauth_err_status(e: &OauthConfigError) -> StatusCode {
    match e {
        OauthConfigError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

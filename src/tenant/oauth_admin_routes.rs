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
//! `admin_user_routes`). Audit: the bearer middleware writes the base row
//! (op + status); PUT and DELETE additionally attach `AuditExtra` —
//! `{provider, redirect_uris_count}` on PUT, `{provider}` on DELETE — for
//! forensic correlation, matching the v1.9 admin-user-route precedent.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::tenant::oauth_config::{self, OauthConfigError};
use crate::tenant::router::TenantAuthState;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn require_service_ctx(ctx: &AuthCtx) -> Option<Response> {
    if !matches!(ctx, AuthCtx::Service) {
        return Some(json_error(
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
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"))
}

fn get_provider(params: &HashMap<String, String>) -> Result<String, Response> {
    params
        .get("provider")
        .cloned()
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing provider"))
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
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let rows = match pool
        .with_reader(move |c| oauth_config::list(c))
        .await
    {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB", ""),
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

// ─── request bodies ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpsertBody {
    pub client_id: String,
    pub client_secret: String,
    pub allowed_redirect_uris: Vec<String>,
}

fn oauth_err_status(e: &OauthConfigError) -> StatusCode {
    match e {
        OauthConfigError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

pub async fn put_oauth_provider_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
    Json(body): Json<UpsertBody>,
) -> Response {
    if let Some(r) = require_service_ctx(&ctx) {
        return r;
    }
    let tid = match get_tid(&params) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let provider = match get_provider(&params) {
        Ok(p) => p,
        Err(r) => return r,
    };
    // Validate up front so we return a granular 400 (INVALID_PROVIDER /
    // INVALID_REDIRECT_URI / EMPTY_REDIRECT_URIS / INVALID_CLIENT_ID /
    // INVALID_CLIENT_SECRET) without ever touching the writer mutex.
    if let Err(e) = oauth_config::validate_upsert(
        &provider,
        &body.client_id,
        &body.client_secret,
        &body.allowed_redirect_uris,
    ) {
        return (
            oauth_err_status(&e),
            Json(json!({
                "error_code": e.error_code(),
                "message": e.to_string(),
            })),
        )
            .into_response();
    }
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let provider2 = provider.clone();
    let client_id = body.client_id;
    let client_secret = body.client_secret;
    let uris = body.allowed_redirect_uris;
    // Capture before move into the writer closure — needed for AuditExtra.
    let uris_count = uris.len();
    let res = pool
        .with_writer(move |c| {
            oauth_config::upsert(c, &provider2, &client_id, &client_secret, &uris)
                .map_err(|e| match e {
                    OauthConfigError::Db(re) => re,
                    // Validation already ran above; treat any residual
                    // validation miss as a generic Rusqlite error so the
                    // outer handler can map to 500. (We do not expect to
                    // hit this branch — validate_upsert is called twice
                    // intentionally for defence-in-depth.)
                    _ => rusqlite::Error::InvalidParameterName(e.to_string()),
                })
        })
        .await;
    match res {
        Ok(()) => {
            let mut resp = (
                StatusCode::OK,
                Json(json!({ "ok": true, "provider": &provider })),
            )
                .into_response();
            resp.extensions_mut()
                .insert(crate::safety::audit::AuditExtra(json!({
                    "provider": provider,
                    "redirect_uris_count": uris_count,
                })));
            resp
        }
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB", ""),
    }
}

pub async fn delete_oauth_provider_handler(
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
    let provider = match get_provider(&params) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let provider2 = provider.clone();
    let res = pool
        .with_writer(move |c| oauth_config::delete(c, &provider2))
        .await;
    match res {
        Ok(true) => {
            let mut resp = StatusCode::NO_CONTENT.into_response();
            resp.extensions_mut()
                .insert(crate::safety::audit::AuditExtra(json!({
                    "provider": provider,
                })));
            resp
        }
        Ok(false) => json_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "provider not configured",
        ),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB", ""),
    }
}

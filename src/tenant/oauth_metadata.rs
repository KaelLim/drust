//! Per-tenant RFC 9728 Protected Resource Metadata.
//!
//! Each tenant's MCP endpoint (`/t/<tenant>/mcp`) is its own protected
//! resource per RFC 9728 / RFC 8707.  This handler serves the metadata at
//! `/t/<tenant>/.well-known/oauth-protected-resource` with `resource`
//! populated to the actual per-tenant URL — required so MCP SDKs that
//! strictly compare `resource` against the URL they tried to access do
//! not reject the document.
//!
//! The root-level `/.well-known/oauth-protected-resource` (Task 16) is
//! retained as a generic discovery hint; the MCP gate's
//! `WWW-Authenticate: resource_metadata=...` points at this per-tenant
//! endpoint instead so spec-compliant clients land on the right URL.
//!
//! Public — no bearer auth required.  v1.29.1.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Json, Response};

use crate::tenant::router::TenantAuthState;

pub async fn protected_resource_for_tenant(
    State(s): State<TenantAuthState>,
    Path(tenant): Path<String>,
) -> Response {
    let base = s.public_url.trim_end_matches('/');
    Json(serde_json::json!({
        "resource": format!("{base}/drust/t/{tenant}/mcp"),
        "authorization_servers": [format!("{base}/drust")],
        "scopes_supported": ["drust"],
        "bearer_methods_supported": ["header"],
    }))
    .into_response()
}

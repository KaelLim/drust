//! Axum handler that forwards `/t/:tenant/mcp` traffic to the
//! corresponding tenant's rmcp Streamable HTTP service.
//!
//! Runs AFTER `bearer_auth_layer`, so `TenantRef` is in request
//! extensions and the token has already been validated, rate-limited,
//! and audited.

use crate::mcp::http_registry::McpHttpRegistry;
use crate::tenant::router::{TenantRef, TokenRole};
use axum::Extension;
use axum::body::Body;
use axum::extract::Path;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use tower::ServiceExt;

fn json_err(status: StatusCode, code: &str, msg: &str) -> Response {
    let body = serde_json::json!({ "error_code": code, "message": msg });
    let mut r = axum::Json(body).into_response();
    *r.status_mut() = status;
    r
}

pub async fn dispatch(
    registry: Arc<McpHttpRegistry>,
    Extension(tenant_ref): Extension<TenantRef>,
    Path(params): Path<std::collections::HashMap<String, String>>,
    req: Request<Body>,
) -> Response {
    // MCP is service-only. An anon key is for read-only REST consumers;
    // exposing MCP over anon would widen the attack surface without a
    // clear use case.
    if tenant_ref.role == TokenRole::Anon {
        return json_err(
            StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            "MCP requires a service key; anon keys cannot open an MCP session",
        );
    }

    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return json_err(StatusCode::BAD_REQUEST, "INTERNAL", "missing tenant param"),
    };

    let svc = match registry.get_or_create(&tenant_id).await {
        Ok(s) => s,
        Err(e) => {
            return json_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                &format!("mcp service init failed: {e}"),
            );
        }
    };

    // Clone the inner service (3 Arc clones per rmcp's Clone impl) so
    // we have an owned `&mut` target for `oneshot`.
    let owned = (*svc).clone();
    match owned.oneshot(req).await {
        Ok(resp) => resp.into_response(),
        Err(_infallible) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "mcp transport error",
        ),
    }
}

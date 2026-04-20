use crate::auth::bearer::{hash_token, token_hint};
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct TenantAuthState {
    pub meta: Arc<Mutex<Connection>>,
    pub registry: Arc<TenantRegistry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenRole {
    Anon,
    Service,
}

impl TokenRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anon => "anon",
            Self::Service => "service",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "anon" => Some(Self::Anon),
            "service" => Some(Self::Service),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct TenantRef {
    pub tenant_id: String,
    pub token_hint: String,
    pub pool: SharedTenantPool,
    pub role: TokenRole,
}

pub async fn bearer_auth_layer(
    State(state): State<TenantAuthState>,
    Path(params): Path<std::collections::HashMap<String, String>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return (StatusCode::BAD_REQUEST, "missing tenant in path").into_response(),
    };
    let bearer = match extract_bearer(&req) {
        Some(t) => t,
        None => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHENTICATED",
                "missing bearer",
            );
        }
    };
    let hash = hash_token(&bearer);
    // Verify: (token active) AND (tenant active). Fetch role alongside.
    let conn = state.meta.lock().await;
    let ok: Option<(String, String)> = conn
        .query_row(
            "SELECT t.tenant_id, t.role FROM tokens t
             JOIN tenants n ON n.id = t.tenant_id
             WHERE t.token_hash = ?1 AND t.revoked_at IS NULL AND n.deleted_at IS NULL",
            rusqlite::params![hash],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok();
    drop(conn);
    let (bound_tenant, role_str) = match ok {
        Some(row) => row,
        None => return json_error(StatusCode::UNAUTHORIZED, "UNAUTHENTICATED", "invalid token"),
    };
    if bound_tenant != tenant_id {
        return json_error(
            StatusCode::NOT_FOUND,
            "TENANT_NOT_FOUND",
            "tenant not accessible",
        );
    }
    let role = match TokenRole::parse(&role_str) {
        Some(r) => r,
        None => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHENTICATED",
                "token has invalid role",
            );
        }
    };
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "TENANT_NOT_FOUND",
                "tenant data missing",
            );
        }
    };
    req.extensions_mut().insert(TenantRef {
        tenant_id: tenant_id.clone(),
        token_hint: token_hint(&bearer),
        pool,
        role,
    });
    next.run(req).await
}

/// Guard used by write-path handlers. Returns `Err(response)` if the
/// current bearer is an anon key, ready to short-circuit the handler.
pub fn require_service(t: &TenantRef) -> Result<(), Response> {
    if t.role == TokenRole::Anon {
        let body = axum::Json(serde_json::json!({
            "error_code": "WRITE_DENIED",
            "message": "anon key cannot write; use a service key"
        }));
        let mut r = body.into_response();
        *r.status_mut() = StatusCode::FORBIDDEN;
        return Err(r);
    }
    Ok(())
}

fn extract_bearer<B>(req: &Request<B>) -> Option<String> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.to_string())
}

fn json_error(status: StatusCode, code: &str, msg: &str) -> Response {
    let body = serde_json::json!({ "error_code": code, "message": msg });
    let mut r = axum::Json(body).into_response();
    *r.status_mut() = status;
    r
}

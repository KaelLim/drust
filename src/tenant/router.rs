use crate::auth::bearer::{hash_token, token_hint};
use crate::safety::audit::{AuditEntry, AuditLog};
use crate::safety::rate_limit::RateLimiter;
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rusqlite::Connection;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct TenantAuthState {
    pub meta: Arc<Mutex<Connection>>,
    pub registry: Arc<TenantRegistry>,
    pub limiter: Arc<RateLimiter>,
    pub audit: Arc<AuditLog>,
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
    let start = Instant::now();
    let method_for_audit = req.method().clone();
    let path_for_audit = req.uri().path().to_string();
    let tenant_for_audit = params.get("tenant").cloned().unwrap_or_default();
    let hint_for_audit = extract_bearer(&req)
        .map(|b| token_hint(&b))
        .unwrap_or_else(|| "-".to_string());
    let audit_sink = state.audit.clone();

    let resp = async move {
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
        // Per-token rate limit. Keyed on the SHA-256 hash so rerolled tokens
        // get their own bucket. Runs before the DB lookup so an abusive
        // client cannot keep us churning on meta.sqlite.
        if let Err(e) = state.limiter.try_acquire(&hash) {
            let secs = e.0.as_secs().max(1);
            let body = serde_json::json!({
                "error_code": "RATE_LIMITED",
                "message": format!("rate limit exceeded; retry after {secs}s"),
            });
            let mut r = axum::Json(body).into_response();
            *r.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            r.headers_mut().insert(
                header::RETRY_AFTER,
                axum::http::HeaderValue::from_str(&secs.to_string()).unwrap(),
            );
            return r;
        }
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
            None => {
                return json_error(StatusCode::UNAUTHORIZED, "UNAUTHENTICATED", "invalid token");
            }
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
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;
    let op_path = path_for_audit
        .strip_prefix(&format!("/t/{tenant_for_audit}"))
        .unwrap_or(&path_for_audit);
    let op = format!("{method_for_audit} {op_path}");
    let status = resp.status();
    let entry = if status.is_success() || status.is_redirection() {
        AuditEntry::success(&tenant_for_audit, &hint_for_audit, &op, duration_ms)
    } else {
        AuditEntry::failure(
            &tenant_for_audit,
            &hint_for_audit,
            &op,
            duration_ms,
            &format!("HTTP_{}", status.as_u16()),
            "",
        )
    };
    tokio::spawn(async move {
        if let Err(e) = audit_sink.append(entry).await {
            tracing::warn!(error = %e, "audit append failed");
        }
    });
    resp
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

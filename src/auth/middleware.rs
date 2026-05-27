use crate::auth::session::validate_session;
use crate::error::json_error;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AdminSessionState {
    pub meta: Arc<Mutex<Connection>>,
}

/// Tri-state authentication context attached to every request after `bearer_auth_layer`.
#[derive(Clone, Debug)]
pub enum AuthCtx {
    Anon,
    /// Service-equivalent caller. `admin_id` is `Some` for per-admin tokens
    /// (PAT or OAuth) and `None` for the shared per-tenant `service` token.
    /// All three sources have identical authorization power; `admin_id` is
    /// purely for audit attribution.
    Service { admin_id: Option<i64> },
    User { user_id: String, token_hash: String },
}

impl AuthCtx {
    pub fn kind(&self) -> &'static str {
        match self {
            AuthCtx::Anon => "anon",
            AuthCtx::Service { .. } => "service",
            AuthCtx::User { .. } => "user",
        }
    }
    pub fn user_id(&self) -> Option<&str> {
        match self {
            AuthCtx::User { user_id, .. } => Some(user_id),
            _ => None,
        }
    }
    /// New helper for v1.29 attribution paths.
    pub fn admin_id(&self) -> Option<i64> {
        match self {
            AuthCtx::Service { admin_id } => *admin_id,
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdminId(pub i64);

pub const SESSION_COOKIE: &str = "drust_session";

pub async fn admin_session_layer(
    State(state): State<AdminSessionState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let cookie_val = extract_cookie(&req, SESSION_COOKIE);
    let admin_id = match cookie_val {
        Some(v) => {
            let conn = state.meta.lock().await;
            validate_session(&conn, &v).ok().flatten()
        }
        None => None,
    };
    match admin_id {
        Some(id) => {
            req.extensions_mut().insert(AdminId(id));
            next.run(req).await
        }
        None => {
            let mut r = Response::new(axum::body::Body::empty());
            *r.status_mut() = StatusCode::SEE_OTHER;
            r.headers_mut()
                .insert(header::LOCATION, "/drust/login".parse().unwrap());
            r
        }
    }
}

fn extract_cookie<B>(req: &Request<B>, name: &str) -> Option<String> {
    let raw = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=')
            && k == name
        {
            return Some(v.to_string());
        }
    }
    None
}

pub fn build_session_cookie(token: &str, ttl_secs: u64) -> String {
    format!(
        "{}={}; Path=/drust; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        SESSION_COOKIE, token, ttl_secs
    )
}

pub fn clear_session_cookie() -> String {
    format!(
        "{}=; Path=/drust; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        SESSION_COOKIE
    )
}

impl IntoResponse for AdminId {
    fn into_response(self) -> Response {
        Response::new(axum::body::Body::from(self.0.to_string()))
    }
}

/// Path-extracted tenant id, gated by a service-role bearer check.
///
/// Use as a handler parameter when the route shape is
/// `/t/{tenant}/admin/...` AND the handler is service-key-only.
/// Combines the two-line preamble (service-role check + path
/// extraction) into one extractor.
///
/// Rejection responses:
/// - 500 AUTH_CTX_MISSING — bearer_auth_layer ordering bug; should
///   never fire in production (the layer is mounted before any handler).
/// - 403 SERVICE_ONLY — bearer token is anon or user, not service.
/// - 400 BAD_REQUEST — `{tenant}` path parameter missing.
pub struct ServiceTid(pub String);

impl<S: Send + Sync> FromRequestParts<S> for ServiceTid {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // 1. AuthCtx must already be in extensions (bearer_auth_layer runs
        //    before every handler). If absent, that's an internal bug.
        let ctx = parts.extensions.get::<AuthCtx>().ok_or_else(|| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_CTX_MISSING",
                "AuthCtx not populated; bearer_auth_layer order bug",
            )
        })?;

        // 2. Service role only.
        if !matches!(ctx, AuthCtx::Service { .. }) {
            return Err(json_error(
                StatusCode::FORBIDDEN,
                "SERVICE_ONLY",
                "service token required",
            ));
        }

        // 3. Extract `tenant` from path params via the inner Path extractor.
        let Path(params): Path<HashMap<String, String>> =
            Path::from_request_parts(parts, state).await.map_err(|_| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "missing or malformed path params",
                )
            })?;
        let tid = params.get("tenant").cloned().ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "missing tenant in path",
            )
        })?;

        Ok(ServiceTid(tid))
    }
}

#[cfg(test)]
mod ctx_tests {
    use super::*;

    #[test]
    fn auth_ctx_kind_strings() {
        assert_eq!(AuthCtx::Anon.kind(), "anon");
        assert_eq!(AuthCtx::Service { admin_id: None }.kind(), "service");
        assert_eq!(AuthCtx::User { user_id: "u".into(), token_hash: "h".into() }.kind(), "user");
    }

    #[test]
    fn auth_ctx_user_id_extracts_only_for_user_variant() {
        assert_eq!(AuthCtx::Anon.user_id(), None);
        assert_eq!(AuthCtx::Service { admin_id: None }.user_id(), None);
        assert_eq!(
            AuthCtx::User { user_id: "u-42".into(), token_hash: "h".into() }.user_id(),
            Some("u-42"),
        );
    }

    #[test]
    fn admin_id_returned_only_for_service_with_some() {
        assert_eq!(AuthCtx::Service { admin_id: None }.admin_id(), None);
        assert_eq!(AuthCtx::Service { admin_id: Some(7) }.admin_id(), Some(7));
        assert_eq!(AuthCtx::Anon.admin_id(), None);
        assert_eq!(AuthCtx::User { user_id: "u".into(), token_hash: "h".into() }.admin_id(), None);
    }

    /// Admin session cookie MUST be SameSite=Lax, not Strict — Strict
    /// breaks the OAuth callback redirect chain (Google → drust → drust
    /// is treated as cross-site-initiated, so Strict cookies set on the
    /// callback aren't sent on the followup GET to /drust/admin/tenants
    /// and the user bounces back to /drust/login despite the session
    /// being created in the DB.
    #[test]
    fn session_cookie_is_samesite_lax() {
        let set = build_session_cookie("tok", 60);
        assert!(set.contains("SameSite=Lax"), "got: {set}");
        assert!(!set.contains("SameSite=Strict"), "got: {set}");
        let clear = clear_session_cookie();
        assert!(clear.contains("SameSite=Lax"), "got: {clear}");
    }
}

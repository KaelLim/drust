use crate::auth::session::validate_session;
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rusqlite::Connection;
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
    Service,
    User { user_id: String, token_hash: String },
}

impl AuthCtx {
    pub fn kind(&self) -> &'static str {
        match self {
            AuthCtx::Anon => "anon",
            AuthCtx::Service => "service",
            AuthCtx::User { .. } => "user",
        }
    }
    pub fn user_id(&self) -> Option<&str> {
        match self {
            AuthCtx::User { user_id, .. } => Some(user_id),
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

#[cfg(test)]
mod ctx_tests {
    use super::*;

    #[test]
    fn auth_ctx_kind_strings() {
        assert_eq!(AuthCtx::Anon.kind(), "anon");
        assert_eq!(AuthCtx::Service.kind(), "service");
        assert_eq!(AuthCtx::User { user_id: "u".into(), token_hash: "h".into() }.kind(), "user");
    }

    #[test]
    fn auth_ctx_user_id_extracts_only_for_user_variant() {
        assert_eq!(AuthCtx::Anon.user_id(), None);
        assert_eq!(AuthCtx::Service.user_id(), None);
        assert_eq!(
            AuthCtx::User { user_id: "u-42".into(), token_hash: "h".into() }.user_id(),
            Some("u-42"),
        );
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

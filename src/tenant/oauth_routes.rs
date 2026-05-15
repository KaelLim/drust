//! Per-tenant OAuth start + callback handlers. End users of a tenant's
//! application sign in via Google/GitHub and receive a `drust_user_*`
//! bearer token (the v1.9 user-session shape). Token delivery is via
//! URL fragment to the frontend's redirect_uri (Supabase/Auth0 pattern).

use crate::oauth::{
    github::GitHubAdapter,
    google::GoogleAdapter,
    provider::OauthProvider,
    state as oauth_state,
};
use crate::tenant::oauth_config;
use crate::tenant::router::TenantAuthState;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use std::collections::HashMap;

pub(crate) const STATE_COOKIE: &str = "drust_t_oauth_state";
pub(crate) const PKCE_COOKIE: &str = "drust_t_oauth_pkce";
pub(crate) const REDIRECT_URI_COOKIE: &str = "drust_t_oauth_redirect_uri";
pub(crate) const COOKIE_TTL_SECS: i64 = 300;

/// Build the cookie attribute suffix (no `key=value` prefix). Path =
/// `/drust/t/<tid>/oauth/` is REQUIRED because Caddy strips `/drust`
/// before forwarding to axum — browsers must see the full prefix to
/// send the cookie back on the callback. See memory
/// `project_drust_caddy_prefix_paths`.
pub(crate) fn cookie_attrs(tid: &str, secure: bool) -> String {
    let scheme_attrs = if secure { "Secure; " } else { "" };
    format!(
        "Path=/drust/t/{tid}/oauth/; HttpOnly; {scheme_attrs}SameSite=Lax; Max-Age={ttl}",
        tid = tid,
        scheme_attrs = scheme_attrs,
        ttl = COOKIE_TTL_SECS,
    )
}

pub(crate) fn set_cookie(name: &str, value: &str, tid: &str, secure: bool) -> String {
    format!("{name}={value}; {attrs}", attrs = cookie_attrs(tid, secure))
}

#[allow(dead_code)]
pub(crate) fn clear_cookie(name: &str, tid: &str) -> String {
    format!("{name}=; Path=/drust/t/{tid}/oauth/; Max-Age=0; HttpOnly; SameSite=Lax")
}

pub(crate) fn secure_from_headers(h: &axum::http::HeaderMap) -> bool {
    h.get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
}

/// Build an adapter from a stored config row. Returns `None` on an
/// unrecognised provider name. The upsert path validates the provider
/// name, but a stale row from a future drust release (or hand-edited
/// SQL) could carry an unknown value — returning None instead of
/// panicking keeps the request handler honest.
pub(crate) fn build_adapter(
    cfg: &oauth_config::OauthProviderConfig,
) -> Option<Box<dyn OauthProvider>> {
    match cfg.provider.as_str() {
        "google" => Some(Box::new(GoogleAdapter::production(
            cfg.client_id.clone(),
            cfg.client_secret.clone(),
        ))),
        "github" => Some(Box::new(GitHubAdapter::production(
            cfg.client_id.clone(),
            cfg.client_secret.clone(),
        ))),
        _ => None,
    }
}

pub(crate) fn plain_text(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

#[derive(serde::Deserialize)]
pub(crate) struct StartQuery {
    pub(crate) redirect_uri: String,
}

pub(crate) async fn oauth_start(
    Path(params): Path<HashMap<String, String>>,
    State(state): State<TenantAuthState>,
    Query(q): Query<StartQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let tid = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return plain_text(StatusCode::BAD_REQUEST, "missing tenant"),
    };
    let provider_name = match params.get("provider") {
        Some(p) => p.clone(),
        None => return plain_text(StatusCode::BAD_REQUEST, "missing provider"),
    };

    // Look up provider config from the tenant DB.
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return plain_text(StatusCode::NOT_FOUND, "tenant not found"),
    };

    let provider_name_for_lookup = provider_name.clone();
    let cfg_opt = pool
        .with_reader(move |c| oauth_config::get(c, &provider_name_for_lookup))
        .await;
    let cfg = match cfg_opt {
        Ok(Some(c)) => c,
        Ok(None) => return plain_text(StatusCode::BAD_REQUEST, "oauth_misconfigured"),
        Err(_) => return plain_text(StatusCode::INTERNAL_SERVER_ERROR, "db error"),
    };

    // Validate redirect_uri against allowlist (exact match).
    if !cfg.allowed_redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return plain_text(StatusCode::BAD_REQUEST, "oauth_invalid_redirect");
    }

    let csrf_state = oauth_state::issue_state();
    let (pkce_verifier, pkce_challenge) = oauth_state::issue_pkce();

    let public_url = std::env::var("DRUST_PUBLIC_URL").unwrap_or_default();
    if public_url.is_empty() {
        return plain_text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DRUST_PUBLIC_URL not set",
        );
    }
    let drust_callback =
        format!("{public_url}/drust/t/{tid}/oauth/{provider_name}/callback");

    let adapter = match build_adapter(&cfg) {
        Some(a) => a,
        None => return plain_text(StatusCode::BAD_REQUEST, "oauth_misconfigured"),
    };
    let auth_url = adapter.authorize_url(&csrf_state, &pkce_challenge, &drust_callback);

    let secure = secure_from_headers(&headers);
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, auth_url)
        .header(
            header::SET_COOKIE,
            set_cookie(STATE_COOKIE, &csrf_state, &tid, secure),
        )
        .header(
            header::SET_COOKIE,
            set_cookie(PKCE_COOKIE, &pkce_verifier, &tid, secure),
        )
        .header(
            header::SET_COOKIE,
            set_cookie(REDIRECT_URI_COOKIE, &q.redirect_uri, &tid, secure),
        )
        .body(axum::body::Body::empty())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_attrs_includes_drust_t_prefix() {
        let s = cookie_attrs("tid-1", true);
        assert!(s.contains("Path=/drust/t/tid-1/oauth/"), "{s}");
        assert!(s.contains("Secure"), "{s}");
        assert!(s.contains("HttpOnly"), "{s}");
        assert!(s.contains("SameSite=Lax"), "{s}");
        assert!(s.contains("Max-Age=300"), "{s}");
    }

    #[test]
    fn cookie_attrs_skips_secure_in_dev() {
        let s = cookie_attrs("tid-1", false);
        assert!(!s.contains("Secure"), "{s}");
        // But path/HttpOnly/SameSite still present
        assert!(s.contains("Path=/drust/t/tid-1/oauth/"), "{s}");
        assert!(s.contains("HttpOnly"), "{s}");
    }

    #[test]
    fn secure_from_headers_https() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(secure_from_headers(&h));
    }

    #[test]
    fn secure_from_headers_http_no() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!secure_from_headers(&h));
    }

    #[test]
    fn secure_from_headers_missing_defaults_false() {
        let h = axum::http::HeaderMap::new();
        assert!(!secure_from_headers(&h));
    }
}

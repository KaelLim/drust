//! Admin-specific OAuth glue. Calls into src/oauth/ (provider-agnostic
//! library) and turns a VerifiedUser into an admin session.

use crate::mgmt::routes::MgmtState;
use crate::oauth::state as oauth_state;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;

pub(crate) fn secure_from_headers(h: &HeaderMap) -> bool {
    h.get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
}

fn redirect_login_error(err: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, format!("/drust/login?oauth_error={err}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

pub async fn oauth_start(
    Path(provider): Path<String>,
    State(s): State<MgmtState>,
    headers: HeaderMap,
) -> Response {
    let Some(p) = s.oauth_registry.get(&provider) else {
        return redirect_login_error("oauth_misconfigured");
    };
    if s.public_url.is_empty() {
        return redirect_login_error("oauth_misconfigured");
    }

    let state = oauth_state::issue_state();
    let (verifier, challenge) = oauth_state::issue_pkce();
    let redirect_uri = format!("{}/drust/admin/oauth/{}/callback", s.public_url, provider);
    let auth_url = p.authorize_url(&state, &challenge, &redirect_uri);

    let secure = secure_from_headers(&headers);
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, auth_url)
        .header(
            header::SET_COOKIE,
            oauth_state::state_cookie(&state, secure).to_string(),
        )
        .header(
            header::SET_COOKIE,
            oauth_state::pkce_cookie(&verifier, secure).to_string(),
        )
        .body(axum::body::Body::empty())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn secure_from_xff_https_yes() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(secure_from_headers(&h));
    }

    #[test]
    fn secure_from_xff_http_no() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!secure_from_headers(&h));
    }

    #[test]
    fn secure_no_xff_defaults_false() {
        let h = HeaderMap::new();
        assert!(!secure_from_headers(&h));
    }
}

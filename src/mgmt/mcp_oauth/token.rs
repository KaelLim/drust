//! `POST /oauth/token` (MA0-PLAN §3.8.4). This unit ships the request
//! validation and grant-type dispatch only: both supported grants answer
//! `unsupported_grant_type` until the code exchange (MA0-7) and refresh
//! rotation (MA0-8) land. No meta lock, no DB, no rate-limit budget here yet.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::mgmt::mcp_oauth::oauth_error_layer::{ClientAuthScheme, OAuthError};
use crate::mgmt::mcp_oauth::params::{self, Params};
use crate::mgmt::routes::MgmtState;

/// Body cap for `/oauth/token` and `/oauth/revoke` (`DefaultBodyLimit`, and
/// `parse_pairs`' own limit).
pub const OAUTH_BODY_LIMIT: usize = 16 * 1024;

/// Defined parameters whose repetition is `invalid_request` (OAuth 2.1 §3.2.4
/// "repeats a parameter"; `resource` may not repeat here either). Unknown
/// parameters are ignored even when repeated.
const TOKEN_PARAMS: &[&str] = &[
    "grant_type",
    "code",
    "code_verifier",
    "redirect_uri",
    "client_id",
    "resource",
    "refresh_token",
    "scope",
];

/// Steps 3-5 of MA0-PLAN §3.8.4, shared with revoke. Steps 1-2 (POST only,
/// 16 KiB) happen in the router before the handler runs. The credential only
/// ever comes from the form body: no cookie, no query string is read.
pub(crate) fn preflight(
    headers: &HeaderMap,
    body: &[u8],
    defined: &[&str],
) -> Result<Params, OAuthError> {
    if !is_form_urlencoded(headers) {
        return Err(OAuthError::InvalidRequest);
    }
    // drust supports only token_endpoint_auth_method "none" (public client).
    if let Some(v) = headers.get(header::AUTHORIZATION) {
        return Err(OAuthError::InvalidClientHeader {
            scheme: scheme_of(v),
        });
    }
    let p = params::parse_pairs(body, OAUTH_BODY_LIMIT).map_err(|_| OAuthError::InvalidRequest)?;
    if defined.iter().any(|k| p.is_duplicated(k)) {
        return Err(OAuthError::InvalidRequest);
    }
    Ok(p)
}

/// The media-type essence (before any `;` parameter, trimmed), ASCII
/// case-insensitive.
fn is_form_urlencoded(h: &HeaderMap) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|essence| {
            essence
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// First token of the header, ASCII case-insensitive: `bearer` => Bearer,
/// anything else (Basic, unrecognised, non-UTF-8) => Basic.
fn scheme_of(v: &HeaderValue) -> ClientAuthScheme {
    let first = v
        .as_bytes()
        .split(|b| *b == b' ')
        .find(|t| !t.is_empty())
        .unwrap_or_default();
    if first.eq_ignore_ascii_case(b"bearer") {
        ClientAuthScheme::Bearer
    } else {
        ClientAuthScheme::Basic
    }
}

pub async fn token(State(_s): State<MgmtState>, headers: HeaderMap, body: Bytes) -> Response {
    let p = match preflight(&headers, &body, TOKEN_PARAMS) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match p.get("grant_type") {
        None => OAuthError::InvalidRequest.into_response(),
        // MA0-7 replaces this arm with the code exchange, MA0-8 with refresh
        // rotation. Until then the AS is incomplete — reachable only under an
        // explicit DRUST_MCP=on.
        Some("authorization_code") | Some("refresh_token") => {
            OAuthError::UnsupportedGrantType.into_response()
        }
        Some(_) => OAuthError::UnsupportedGrantType.into_response(),
    }
}

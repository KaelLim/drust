//! RFC 8414 (Authorization Server Metadata) + RFC 9728 (Protected Resource Metadata).

use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};

use crate::mgmt::routes::MgmtState;

/// `GET /.well-known/oauth-protected-resource`
///
/// RFC 9728 §3 — returns JSON metadata describing this protected resource
/// (the drust MCP endpoints) and which authorization server issues tokens
/// for it. MCP clients use this to discover the AS metadata endpoint and
/// then the token + authorization endpoints.
pub async fn protected_resource(State(s): State<MgmtState>) -> Response {
    let base = s.public_base_url.trim_end_matches('/');
    Json(serde_json::json!({
        "resource": format!("{base}/drust/t/{{tenant}}/mcp"),
        "authorization_servers": [format!("{base}/drust")],
        "scopes_supported": ["drust"],
        "bearer_methods_supported": ["header"],
    }))
    .into_response()
}

/// `GET /.well-known/oauth-authorization-server`
///
/// RFC 8414 §3 — returns JSON metadata for this OAuth 2.1 authorization
/// server. MCP clients auto-discover the endpoints they need
/// (authorize, token, register) from this document without out-of-band
/// configuration.
pub async fn authorization_server(State(s): State<MgmtState>) -> Response {
    let base = s.public_base_url.trim_end_matches('/');
    Json(serde_json::json!({
        "issuer": format!("{base}/drust"),
        "authorization_endpoint": format!("{base}/drust/oauth/authorize"),
        "token_endpoint":         format!("{base}/drust/oauth/token"),
        "registration_endpoint":  format!("{base}/drust/oauth/register"),
        "scopes_supported":       ["drust"],
        "response_types_supported": ["code"],
        "grant_types_supported":  ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "ui_locales_supported":   ["en", "zh-TW"],
    }))
    .into_response()
}

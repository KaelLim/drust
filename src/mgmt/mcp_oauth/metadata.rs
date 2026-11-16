//! RFC 8414 authorization-server metadata (MA0-PLAN §3.7, §3.8.1).

use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::routes::MgmtState;

/// The final shape. Pure: no lock, no I/O, no request header read, nothing
/// fallible — so the endpoint cannot 5xx, and a shared cache honouring
/// `max-age=300` can never be poisoned through `Host`. Every URL comes from
/// `cfg` (invariant 15). No `registration_endpoint`: clients are pinned.
pub fn metadata_json(cfg: &McpOauthConfig) -> serde_json::Value {
    serde_json::json!({
        "issuer": cfg.issuer(),
        "authorization_endpoint": cfg.endpoint_url("/oauth/authorize"),
        "token_endpoint": cfg.endpoint_url("/oauth/token"),
        "revocation_endpoint": cfg.endpoint_url("/oauth/revoke"),
        "revocation_endpoint_auth_methods_supported": ["none"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
        "scopes_supported": ["mcp", "offline_access"],
    })
}

/// `GET /.well-known/oauth-authorization-server`. Deliberately NOT under
/// `oauth_error_layer`: it only ever answers 200, and its cache header must not
/// become `no-store`.
pub async fn metadata(State(s): State<MgmtState>) -> Response {
    let mut resp = axum::Json(metadata_json(&s.mcp_oauth)).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lib tests never call base_path::set, so base_path() is the default "/drust".
    fn cfg() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }

    #[test]
    fn metadata_has_exactly_the_final_keys_in_order() {
        let m = metadata_json(&cfg());
        let keys: Vec<&str> = m.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "revocation_endpoint",
                "revocation_endpoint_auth_methods_supported",
                "response_types_supported",
                "response_modes_supported",
                "grant_types_supported",
                "code_challenge_methods_supported",
                "token_endpoint_auth_methods_supported",
                "client_id_metadata_document_supported",
                "authorization_response_iss_parameter_supported",
                "scopes_supported",
            ]
        );
    }

    #[test]
    fn metadata_values() {
        let m = metadata_json(&cfg());
        let issuer = "https://drust.test/drust";
        assert_eq!(m["issuer"], issuer);
        assert_eq!(
            m["authorization_endpoint"],
            format!("{issuer}/oauth/authorize")
        );
        assert_eq!(m["token_endpoint"], format!("{issuer}/oauth/token"));
        assert_eq!(m["revocation_endpoint"], format!("{issuer}/oauth/revoke"));
        let none = serde_json::json!(["none"]);
        assert_eq!(m["revocation_endpoint_auth_methods_supported"], none);
        assert_eq!(m["token_endpoint_auth_methods_supported"], none);
        assert_eq!(m["response_types_supported"], serde_json::json!(["code"]));
        assert_eq!(m["response_modes_supported"], serde_json::json!(["query"]));
        assert_eq!(
            m["grant_types_supported"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            m["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(m["client_id_metadata_document_supported"], true);
        assert_eq!(m["authorization_response_iss_parameter_supported"], true);
        assert_eq!(
            m["scopes_supported"],
            serde_json::json!(["mcp", "offline_access"])
        );
        assert!(m.get("registration_endpoint").is_none());
    }
}

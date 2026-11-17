//! RFC 9728 protected resource metadata for the account-level MCP endpoint.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::mgmt::mcp_oauth::config::McpOauthConfig;

/// The document for the `/mcp` resource. Pure: no lock, no I/O, no request
/// header read, so a shared cache honouring `max-age=300` can never be
/// poisoned through `Host`. Every URL comes from `cfg` (invariant 15); the
/// authorization server is byte-identical to the AS metadata `issuer`.
/// `offline_access` is not listed: every token response says `"scope":"mcp"`.
pub(crate) fn prm_json(cfg: &McpOauthConfig) -> serde_json::Value {
    serde_json::json!({
        "resource": cfg.resource_url(),
        "authorization_servers": [cfg.issuer()],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
        "resource_name": "drust (MCP)",
    })
}

/// `GET /.well-known/oauth-protected-resource/mcp`. It only ever answers 200,
/// so it sits under no error layer, and its cache header must not become
/// `no-store`.
pub(crate) async fn prm_handler(State(cfg): State<Arc<McpOauthConfig>>) -> Response {
    let mut resp = axum::Json(prm_json(&cfg)).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::config::McpOauthConfig;
    use crate::mgmt::mcp_oauth::metadata::metadata_json;
    use axum::http::{StatusCode, header};
    use std::sync::Arc;

    // Lib tests never call base_path::set, so base_path() is the default "/drust".
    fn cfg() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }

    #[test]
    fn prm_has_exactly_the_five_keys_in_order() {
        let p = prm_json(&cfg());
        let keys: Vec<&str> = p.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "resource",
                "authorization_servers",
                "scopes_supported",
                "bearer_methods_supported",
                "resource_name"
            ]
        );
    }

    #[test]
    fn prm_values_match_the_config_and_the_as_metadata() {
        let c = cfg();
        let p = prm_json(&c);
        assert_eq!(p["resource"], "https://drust.test/drust/mcp");
        assert_eq!(p["resource"], c.resource_url());
        assert!(c.is_our_resource(p["resource"].as_str().unwrap()));
        assert_eq!(
            p["authorization_servers"],
            serde_json::json!(["https://drust.test/drust"])
        );
        assert_eq!(
            serde_json::to_string(&p["authorization_servers"][0]).unwrap(),
            serde_json::to_string(&metadata_json(&c)["issuer"]).unwrap(),
            "PRM authorization server and AS issuer must be byte-identical",
        );
        assert_eq!(p["scopes_supported"], serde_json::json!(["mcp"]));
        assert!(!p.to_string().contains("offline_access"));
        assert_eq!(p["bearer_methods_supported"], serde_json::json!(["header"]));
        assert_eq!(p["resource_name"], "drust (MCP)");
        assert_eq!(
            c.prm_url(),
            "https://drust.test/drust/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[tokio::test]
    async fn prm_handler_is_cacheable_json() {
        let c = Arc::new(cfg());
        let resp = prm_handler(axum::extract::State(c.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "public, max-age=300");
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, prm_json(&c));
    }
}

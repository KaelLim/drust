//! MCP OAuth authorization server. Routes are mounted only when
//! `config::McpOauthConfig::enabled()`; with DRUST_MCP unset every HTTP response is
//! byte-identical to a build without this module. Tables:
//! `db::migrations::SQL_CREATE_MCP_OAUTH_IF_NOT_EXISTS`. Release notes: CHANGELOG.md.
pub mod authorize;
pub mod clients;
pub mod config;
pub mod consent;
pub mod envelope;
pub mod metadata;
pub mod oauth_error_layer;
pub mod params;
pub mod pkce;
pub mod redirect;
pub mod revoke;
pub mod rl;
pub mod store;
pub mod sweep;
pub mod token;
pub mod tokens;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn;
use axum::routing::{get, post};

use crate::mgmt::routes::MgmtState;

/// Unauthenticated OAuth AS routes, already `with_state`. Mounted by
/// `MgmtState::with_data_dir` ONLY when `McpOauthConfig::enabled()`.
///
/// `route_layer`, never `layer`: `Router::layer` also wraps this router's
/// default 404 fallback, and `merge` keeps the merged-in side's default
/// fallback, so `layer` would turn unmatched admin-plane paths into OAuth JSON
/// the moment the merge order changes. `route_layer` wraps each route including
/// its own 405 — exactly these two endpoints. The metadata route sits outside
/// the error layer on purpose: it only answers 200 and is cacheable. So does
/// `GET /oauth/authorize`: before redirect validation its answer is an HTML
/// page, after it a 303, and neither may be rewritten to JSON.
pub fn public_routes(state: &MgmtState) -> Router {
    let oauth_api = Router::new()
        .route("/oauth/token", post(token::token))
        .route("/oauth/revoke", post(revoke::revoke))
        .route_layer(DefaultBodyLimit::max(token::OAUTH_BODY_LIMIT))
        // Added last = outermost: it also sees the body limit's 413.
        .route_layer(from_fn(oauth_error_layer::oauth_error_layer));
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::metadata),
        )
        .route("/oauth/authorize", get(authorize::authorize))
        .merge(oauth_api)
        .with_state(state.clone())
}

/// Consent routes (MA0-6), already `with_state`. `MgmtState::with_data_dir`
/// merges them into `protected` ONLY when `McpOauthConfig::enabled()`, so they
/// sit under `admin_session_layer` (`AdminId` + `AuthMethod`), the profile and
/// inner theme layers, and inside `frame_guard_layers`.
pub fn session_routes(state: &MgmtState) -> Router {
    Router::new()
        .route("/oauth/consent", get(consent::consent_page))
        .route("/oauth/consent/approve", post(consent::consent_approve))
        .route("/oauth/consent/deny", post(consent::consent_deny))
        .with_state(state.clone())
}

/// en and zh-TW must carry the same keys under every MCP OAuth prefix (build.rs
/// only checks en). The two later prefixes are empty until MA0-9 and are
/// checked automatically from then on.
#[cfg(test)]
mod i18n_parity {
    use std::collections::BTreeMap;

    const PREFIXES: &[&str] = &["mcp_oauth.", "settings.mcp_grants.", "admin_team.mcp."];

    fn flatten(prefix: &str, v: &toml::Value, out: &mut BTreeMap<String, String>) {
        match v {
            toml::Value::Table(t) => {
                for (k, child) in t {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    flatten(&key, child, out);
                }
            }
            toml::Value::String(s) => {
                out.insert(prefix.to_string(), s.clone());
            }
            other => {
                out.insert(prefix.to_string(), other.to_string());
            }
        }
    }

    fn keys(src: &str) -> BTreeMap<String, String> {
        let v: toml::Value = toml::from_str(src).expect("locale bundle parses");
        let mut out = BTreeMap::new();
        flatten("", &v, &mut out);
        out
    }

    #[test]
    fn mcp_oauth_locale_sections_have_identical_keys() {
        let en = keys(include_str!("../../../locales/en.toml"));
        let zh = keys(include_str!("../../../locales/zh-TW.toml"));
        for p in PREFIXES {
            let e: Vec<_> = en.keys().filter(|k| k.starts_with(p)).collect();
            let z: Vec<_> = zh.keys().filter(|k| k.starts_with(p)).collect();
            assert_eq!(e, z, "en and zh-TW disagree under `{p}`");
        }
        // Anti-vacuous: MA0-5 ships the error page section.
        assert!(en.keys().any(|k| k.starts_with("mcp_oauth.error.")));
        // No empty translation.
        for (k, v) in zh
            .iter()
            .filter(|(k, _)| PREFIXES.iter().any(|p| k.starts_with(p)))
        {
            assert!(!v.trim().is_empty(), "zh-TW `{k}` is empty");
        }
    }
}

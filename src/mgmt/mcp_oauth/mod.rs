//! MCP OAuth authorization server. Routes are mounted only when
//! `config::McpOauthConfig::enabled()`; with DRUST_MCP unset every HTTP response is
//! byte-identical to a build without this module. Tables:
//! `db::migrations::SQL_CREATE_MCP_OAUTH_IF_NOT_EXISTS`. Release notes: CHANGELOG.md.
pub mod clients;
pub mod config;
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
/// the error layer on purpose: it only answers 200 and is cacheable.
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
        .merge(oauth_api)
        .with_state(state.clone())
}

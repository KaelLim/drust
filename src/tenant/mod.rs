pub mod admin_user_routes;
pub mod auth_routes;
pub mod collections;
pub mod events;
pub mod mcp_dispatch;
pub mod oauth_config;
pub mod owner_field;
pub mod query_endpoint;
pub mod records;
pub mod router;
pub mod sse;
pub mod vector_search;

use crate::mcp::http_registry::McpHttpRegistry;
use crate::mgmt::tenant_files::TenantFilesState;
use axum::Router;
use axum::http::{HeaderValue, Method, header};
use axum::routing::{any, delete, get, post};
use auth_routes::{
    login_handler, logout_all_handler, logout_handler, me_get_handler, me_patch_handler,
    me_password_handler, register_handler,
};
use events::EventBus;
use router::TenantAuthState;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};

#[derive(Clone)]
pub struct TenantStack {
    pub auth: TenantAuthState,
    pub bus: EventBus,
    pub mcp: Arc<McpHttpRegistry>,
    pub files: Option<TenantFilesState>,
    /// Allow-list for cross-origin browser fetch on tenant routes (parsed
    /// from `DRUST_CORS_ORIGINS`). Empty Vec ⇒ no CORS layer, browsers
    /// keep blocking — same as before this feature shipped.
    pub cors_origins: Vec<String>,
}

/// One entry from `DRUST_CORS_ORIGINS`. Either an exact origin
/// (`https://app.example.com`) or a single-wildcard pattern where `*`
/// stands in for one variable section (`https://*.example.com`,
/// `http://localhost:*`). Multi-`*` patterns are rejected at parse time.
fn origin_matches(pattern: &str, origin: &str) -> bool {
    match pattern.find('*') {
        None => origin == pattern,
        Some(star) => {
            let prefix = &pattern[..star];
            let suffix = &pattern[star + 1..];
            if suffix.contains('*') {
                return false;
            }
            // Length strictly greater so `*` consumes at least one char —
            // `*.tzuchi.org` must NOT match the bare `tzuchi.org`, only its
            // subdomains.
            origin.len() > prefix.len() + suffix.len()
                && origin.starts_with(prefix)
                && origin.ends_with(suffix)
        }
    }
}

/// Build the CORS layer applied OUTSIDE `bearer_auth_layer` so that
/// `OPTIONS` preflight requests short-circuit before auth (preflight
/// doesn't carry the bearer token by spec — `fetch` deliberately omits it).
/// Returns `None` when the allow-list is empty so callers can skip wiring
/// the layer entirely.
///
/// Supports two pattern shapes:
///   - exact: `https://app.example.com`
///   - single wildcard: `https://*.example.com`, `http://localhost:*`
fn build_cors_layer(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let patterns: Vec<String> = origins
        .iter()
        .filter(|s| !s.is_empty() && !s.matches('*').nth(1).is_some()) // <= 1 wildcard
        .cloned()
        .collect();
    if patterns.is_empty() {
        tracing::warn!(
            origins = ?origins,
            "DRUST_CORS_ORIGINS contained only invalid entries — CORS disabled"
        );
        return None;
    }
    tracing::info!(
        origins = ?patterns,
        "CORS enabled for tenant routes"
    );
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(
                move |origin: &HeaderValue, _: &axum::http::request::Parts| {
                    let Ok(s) = origin.to_str() else {
                        return false;
                    };
                    patterns.iter().any(|p| origin_matches(p, s))
                },
            ))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
                Method::HEAD,
            ])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
            .max_age(Duration::from_secs(600)),
    )
}

#[cfg(test)]
mod cors_tests {
    use super::origin_matches;

    #[test]
    fn exact_match() {
        assert!(origin_matches(
            "https://app.tzuchi.org",
            "https://app.tzuchi.org"
        ));
        assert!(!origin_matches(
            "https://app.tzuchi.org",
            "https://app.tzuchi.org.tw"
        ));
    }

    #[test]
    fn subdomain_wildcard() {
        let p = "https://*.tzuchi.org";
        assert!(origin_matches(p, "https://app.tzuchi.org"));
        assert!(origin_matches(p, "https://academic-events.tzuchi.org"));
        assert!(origin_matches(p, "https://a.b.tzuchi.org"));
        // Bare domain must NOT match — wildcard requires content.
        assert!(!origin_matches(p, "https://tzuchi.org"));
        // Suffix-injection attempt (different TLD).
        assert!(!origin_matches(p, "https://tzuchi.org.attacker.com"));
        // Hyphen-confusion (no leading dot).
        assert!(!origin_matches(p, "https://anything-tzuchi.org"));
        // Different scheme.
        assert!(!origin_matches(p, "http://app.tzuchi.org"));
    }

    #[test]
    fn localhost_port_wildcard() {
        let p = "http://localhost:*";
        assert!(origin_matches(p, "http://localhost:5173"));
        assert!(origin_matches(p, "http://localhost:8080"));
        // Empty after `:` rejected (wildcard requires content).
        assert!(!origin_matches(p, "http://localhost:"));
    }
}

pub fn build_tenant_router(state: TenantStack) -> Router {
    let auth_state = state.auth.clone();
    let bus = state.bus.clone();
    let mcp = state.mcp.clone();
    let cors = build_cors_layer(&state.cors_origins);

    let core = Router::new()
        .route("/t/{tenant}/collections", get(collections::list_handler))
        .route(
            "/t/{tenant}/collections/{coll}",
            get(collections::describe_handler),
        )
        .route(
            "/t/{tenant}/collections/{coll}/owner-field",
            axum::routing::post(owner_field::set_owner_field_handler)
                .delete(owner_field::clear_owner_field_handler),
        )
        .route(
            "/t/{tenant}/collections/{coll}/indexes",
            post(collections::create_index_handler),
        )
        .route(
            "/t/{tenant}/collections/{coll}/indexes/{name}",
            delete(collections::drop_index_handler),
        )
        .route(
            "/t/{tenant}/collections/{coll}/search",
            post(vector_search::search_handler),
        )
        .route(
            "/t/{tenant}/records/{coll}",
            get(records::list_handler).post({
                let b = bus.clone();
                move |ext, ctx, p, body| records::create_handler(ext, ctx, p, body, b.clone())
            }),
        )
        .route(
            "/t/{tenant}/records/{coll}/{id}",
            get(records::get_handler)
                .patch({
                    let b = bus.clone();
                    move |ext, ctx, p, body| records::update_handler(ext, ctx, p, body, b.clone())
                })
                .delete({
                    let b = bus.clone();
                    move |ext, ctx, p| records::delete_handler(ext, ctx, p, b.clone())
                }),
        )
        .route(
            "/t/{tenant}/records/{coll}/subscribe",
            get({
                let b = bus.clone();
                move |ext, path| sse::subscribe_handler(b.clone(), ext, path)
            }),
        )
        .route("/t/{tenant}/query", post(query_endpoint::query_handler))
        .route(
            "/t/{tenant}/query/explain",
            post(query_endpoint::explain_handler),
        )
        .route("/t/{tenant}/auth/logout", post(logout_handler))
        .route("/t/{tenant}/auth/logout-all", post(logout_all_handler))
        .route(
            "/t/{tenant}/me",
            axum::routing::get(me_get_handler).patch(me_patch_handler),
        )
        .route("/t/{tenant}/me/password", post(me_password_handler))
        .route(
            "/t/{tenant}/rpc/{name}",
            post(crate::rpc::handler::call_rpc),
        )
        // ── Admin user-management (service-only) ──────────────────────────
        .route(
            "/t/{tenant}/admin/users",
            post(admin_user_routes::create_user_handler)
                .get(admin_user_routes::list_users_handler),
        )
        .route(
            "/t/{tenant}/admin/users/{uid}",
            get(admin_user_routes::get_user_handler)
                .patch(admin_user_routes::update_user_handler)
                .delete(admin_user_routes::delete_user_handler),
        )
        .route(
            "/t/{tenant}/admin/users/{uid}/revoke-sessions",
            post(admin_user_routes::revoke_sessions_handler),
        )
        .route(
            "/t/{tenant}/mcp",
            any({
                let mcp = mcp.clone();
                move |ext, path, req| mcp_dispatch::dispatch(mcp.clone(), ext, path, req)
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            router::bearer_auth_layer,
        ))
        .with_state(auth_state.clone());

    // File-bytes proxy routes — only wired when Garage storage is configured.
    // These also sit behind bearer_auth_layer (applied here on the sub-router
    // so TenantAuthState is available to the middleware while TenantFilesState
    // is available to the handler).
    let files_router = if let Some(files_state) = state.files {
        let max_upload_bytes = files_state.max_upload_bytes;
        Router::new()
            .route(
                "/t/{tenant}/files",
                post(crate::mgmt::tenant_files::upload)
                    .layer(axum::extract::DefaultBodyLimit::max(max_upload_bytes))
                    .get(crate::mgmt::tenant_files::list),
            )
            .route(
                "/t/{tenant}/files/{key}",
                get(crate::mgmt::tenant_files::get_one)
                    .delete(crate::mgmt::tenant_files::delete_one),
            )
            .route(
                "/t/{tenant}/files/{key}/bytes",
                get(crate::mgmt::tenant_files::stream_bytes),
            )
            .route(
                "/t/{tenant}/files/{key}/sign",
                post(crate::mgmt::tenant_files::sign_url),
            )
            .layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                router::bearer_auth_layer,
            ))
            .with_state(files_state)
    } else {
        Router::new()
    };

    // Auth routes: no bearer token required (register/login are public entry points).
    // State is TenantAuthState (for meta db + registry + rate limiters), but
    // these routes are NOT wrapped in bearer_auth_layer.
    let auth_router = Router::new()
        .route("/t/{tenant}/auth/register", post(register_handler))
        .route("/t/{tenant}/auth/login", post(login_handler))
        .with_state(auth_state);

    let merged = core.merge(files_router).merge(auth_router);
    // CORS layer goes OUTSIDE bearer_auth_layer (= applied last) so OPTIONS
    // preflight is intercepted by tower_http before reaching auth, returning
    // 200 + ACA* headers without seeing the bearer token. Real GET/POST/etc.
    // still pass through bearer_auth normally; the layer just appends the
    // ACAO header on the way back out.
    if let Some(cors) = cors {
        merged.layer(cors)
    } else {
        merged
    }
}

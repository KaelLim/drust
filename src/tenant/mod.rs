pub mod admin_user_routes;
pub mod auth_routes;
pub mod collections;
pub mod events;
pub mod webhook_dispatcher;
pub mod webhook_resolver;
pub use webhook_dispatcher::WebhookDispatcher;
pub mod mcp_dispatch;
pub mod oauth_admin_routes;
pub mod oauth_config;
pub mod oauth_routes;
pub mod owner_field;
pub mod query_endpoint;
pub mod realtime_routes;
pub mod records;
pub mod records_list;
pub mod rooms;
pub mod router;
pub mod sse;
pub mod uploads;
pub mod vector_search;
pub mod webhook_routes;

use crate::mcp::http_registry::McpHttpRegistry;
use crate::mgmt::tenant_files::TenantFilesState;
use auth_routes::{
    login_handler, logout_all_handler, logout_handler, me_get_handler, me_password_handler,
    me_patch_handler, register_handler,
};
use axum::Router;
use axum::http::{HeaderValue, Method, header, header::HeaderName};
use axum::routing::{any, delete, get, post, put};
use events::EventBus;
use router::TenantAuthState;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};

#[derive(Clone)]
pub struct TenantStack {
    pub auth: TenantAuthState,
    pub bus: EventBus,
    /// v1.31 broadcast rooms bus — ad-hoc per-room WS multiplex channels.
    /// `soft_delete_tenant` evicts both `bus` and `bus_rooms`.
    pub bus_rooms: rooms::RoomBus,
    /// v1.31 per-tenant publish QPS bucket. Shared `Arc` so the same
    /// bucket state lives across REST / WS / MCP publish callers.
    pub bucket: Arc<rooms::PublishBucket>,
    /// v1.31 broadcast rooms config (payload cap, subscriber caps).
    /// Cloneable; tests use `RoomsConfig::test_defaults()`.
    pub rooms_cfg: rooms::RoomsConfig,
    pub mcp: Arc<McpHttpRegistry>,
    pub files: Option<TenantFilesState>,
    pub webhooks: Arc<WebhookDispatcher>,
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
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                HeaderName::from_static("tus-resumable"),
                HeaderName::from_static("upload-length"),
                HeaderName::from_static("upload-offset"),
                HeaderName::from_static("upload-metadata"),
            ])
            // v1.29.7 C3 — RFC 8594 deprecation headers must be visible to
            // cross-origin browser SPAs. Without this, `response.headers
            // .get('deprecation')` returns null even though the bytes arrive,
            // defeating the discovery audience H5-1 phase 1 was designed for.
            // v1.33 — extend for tus response headers so browser tus clients
            // can read Upload-Offset, Location, etc. from cross-origin responses.
            .expose_headers([
                axum::http::header::HeaderName::from_static("deprecation"),
                axum::http::header::HeaderName::from_static("sunset"),
                axum::http::header::HeaderName::from_static("link"),
                HeaderName::from_static("tus-resumable"),
                HeaderName::from_static("tus-version"),
                HeaderName::from_static("tus-extension"),
                HeaderName::from_static("tus-max-size"),
                HeaderName::from_static("upload-offset"),
                HeaderName::from_static("upload-length"),
                HeaderName::from_static("upload-expires"),
                HeaderName::from_static("location"),
            ])
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

    /// v1.29.7 C3 — Cross-origin browser SPAs must be able to read the
    /// new RFC 8594 deprecation headers (`Deprecation`, `Sunset`, `Link`).
    /// Without `Access-Control-Expose-Headers`, the browser hides them
    /// from `response.headers.get(...)` even though the bytes arrive.
    #[tokio::test]
    async fn cors_exposes_deprecation_headers() {
        // build_cors_layer is private; the test invokes it directly. We
        // can't introspect CorsLayer internals, so instead we mount the
        // layer on a stub axum Router and assert the actual response
        // carries `Access-Control-Expose-Headers` listing all three.
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode, header};
        use axum::{Router, routing::get};
        use tower::ServiceExt;

        let origins = vec!["https://app.tzuchi.org".to_string()];
        let cors = super::build_cors_layer(&origins).expect("cors layer");
        let app: Router = Router::new()
            .route("/echo", get(|| async { "ok" }))
            .layer(cors);

        // Real GET (not preflight). Access-Control-Expose-Headers is set
        // on the actual response, not just preflight.
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/echo")
                    .header(header::ORIGIN, "https://app.tzuchi.org")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let exposed = resp
            .headers()
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        for hdr in ["deprecation", "sunset", "link"] {
            assert!(
                exposed.to_ascii_lowercase().contains(hdr),
                "Access-Control-Expose-Headers must list `{hdr}` (got: `{exposed}`)"
            );
        }
    }

    /// v1.33.2 — the CORS layer short-circuits OPTIONS preflight before it can
    /// reach `uploads::options`, so the tus capability headers must be re-added
    /// by `inject_tus_capabilities` mounted OUTSIDE cors. A live HTTP probe found
    /// the original handler dead; this pins the full layer stack so it can't
    /// regress. Mirrors `build_tenant_router`'s `merged.layer(cors).layer(tus)`.
    #[tokio::test]
    async fn tus_capabilities_survive_cors_preflight() {
        use axum::body::Body;
        use axum::http::{Method, Request, header};
        use axum::{Router, routing::post};
        use tower::ServiceExt;

        let cors =
            super::build_cors_layer(&["https://app.tzuchi.org".to_string()]).expect("cors layer");
        let app: Router = Router::new()
            .route("/t/x/uploads", post(|| async { "ok" }))
            .route("/t/x/collections", post(|| async { "ok" }))
            .layer(cors)
            .layer(axum::middleware::from_fn_with_state(
                2_147_483_648usize,
                super::inject_tus_capabilities,
            ));

        // Browser preflight to the creation endpoint → CORS answers, then the
        // tus layer re-attaches capabilities.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/t/x/uploads")
                    .header(header::ORIGIN, "https://app.tzuchi.org")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let h = resp.headers();
        assert_eq!(h.get("tus-version").unwrap(), "1.0.0");
        assert_eq!(h.get("tus-resumable").unwrap(), "1.0.0");
        assert!(
            h.get("tus-extension")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("creation"),
            "tus-extension must advertise creation"
        );
        assert_eq!(h.get("tus-max-size").unwrap(), "2147483648");

        // Scoping: a non-/uploads OPTIONS must NOT carry tus headers.
        let resp2 = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/t/x/collections")
                    .header(header::ORIGIN, "https://app.tzuchi.org")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp2.headers().get("tus-version").is_none(),
            "tus headers must be scoped to /uploads only"
        );
    }
}

/// v1.33.2 — re-attach tus capability headers (`Tus-Version` / `Tus-Extension`
/// / `Tus-Max-Size`) onto `OPTIONS /t/<id>/uploads`.
///
/// The `.options(uploads::options)` handler is unreachable over HTTP: the CORS
/// layer is mounted OUTSIDE bearer_auth (so preflight short-circuits before auth
/// — see `build_tenant_router`) and answers every OPTIONS before it reaches the
/// router, returning a bare CORS 200 without the tus headers. A unit test that
/// calls the handler directly can't see this; only a live HTTP probe does.
///
/// This layer is mounted OUTSIDE the CORS layer, so on the response path it runs
/// last and re-attaches the static capabilities onto the CORS-generated preflight
/// response. Scoped to OPTIONS on paths ending `/uploads` (the creation endpoint;
/// `/uploads/{token}` PATCH preflights are left untouched). Capability discovery
/// is unauthenticated by tus convention and the advertised value is a public
/// config constant, matching the unauthenticated CORS preflight it rides on.
async fn inject_tus_capabilities(
    axum::extract::State(max_size): axum::extract::State<usize>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_caps =
        req.method() == axum::http::Method::OPTIONS && req.uri().path().ends_with("/uploads");
    let mut resp = next.run(req).await;
    if is_caps {
        use axum::http::HeaderValue;
        let h = resp.headers_mut();
        h.insert(
            "tus-resumable",
            HeaderValue::from_static(uploads::TUS_VERSION),
        );
        h.insert(
            "tus-version",
            HeaderValue::from_static(uploads::TUS_VERSION),
        );
        h.insert(
            "tus-extension",
            HeaderValue::from_static(uploads::TUS_EXTENSION),
        );
        if let Ok(v) = HeaderValue::from_str(&max_size.to_string()) {
            h.insert("tus-max-size", v);
        }
    }
    resp
}

pub fn build_tenant_router(state: TenantStack) -> Router {
    let auth_state = state.auth.clone();
    let bus = state.bus.clone();
    let webhooks = state.webhooks.clone();
    let mcp = state.mcp.clone();
    let cors = build_cors_layer(&state.cors_origins);
    // Captured before `state.files` is moved into files_router below; feeds the
    // tus capability layer (Tus-Max-Size) that re-attaches headers onto the
    // CORS-shadowed OPTIONS /uploads response. None when Garage is unconfigured
    // (files_router empty), so the layer is simply not mounted.
    let tus_max_size: Option<usize> = state.files.as_ref().map(|f| f.large_upload_max_bytes);

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
            "/t/{tenant}/collections/{coll}/list",
            post(records_list::post_list),
        )
        .route(
            "/t/{tenant}/collections/{coll}/list/explain",
            post(records_list::post_list_explain),
        )
        .route(
            "/t/{tenant}/collections/{coll}/realtime",
            put({
                let b = bus.clone();
                move |ext, path, body| {
                    realtime_routes::put_realtime_handler(ext, path, body, b.clone())
                }
            }),
        )
        .route(
            "/t/{tenant}/collections/{coll}/description",
            put(collections::put_collection_description_handler),
        )
        .route(
            "/t/{tenant}/collections/{coll}/fields/{field}/description",
            put(collections::put_field_description_handler),
        )
        .route(
            "/t/{tenant}/collections/{coll}/indexes/{index_name}/description",
            put(collections::put_index_description_handler),
        )
        .route(
            "/t/{tenant}/schema/overview",
            get(collections::get_schema_overview_handler),
        )
        .route(
            "/t/{tenant}/openapi.json",
            get(crate::codegen::handlers::openapi_handler),
        )
        .route(
            "/t/{tenant}/types.ts",
            get(crate::codegen::handlers::types_handler),
        )
        .route(
            "/t/{tenant}/zod.ts",
            get(crate::codegen::handlers::zod_handler),
        )
        .route(
            "/t/{tenant}/records/{coll}",
            get(records::list_handler).post({
                let b = bus.clone();
                let wh = webhooks.clone();
                move |ext, ctx, p, body| {
                    records::create_handler(ext, ctx, p, body, b.clone(), wh.clone())
                }
            }),
        )
        .route(
            "/t/{tenant}/records/{coll}/{id}",
            get(records::get_handler)
                .patch({
                    let b = bus.clone();
                    let wh = webhooks.clone();
                    move |ext, ctx, p, body| {
                        records::update_handler(ext, ctx, p, body, b.clone(), wh.clone())
                    }
                })
                .delete({
                    let b = bus.clone();
                    let wh = webhooks.clone();
                    move |ext, ctx, p, q| {
                        records::delete_handler(ext, ctx, p, q, b.clone(), wh.clone())
                    }
                }),
        )
        // /t/{tenant}/records/{coll}/subscribe lives on `ws_router` below,
        // NOT on `core` — its outer layer must be `ws_query_token_adapter`
        // (running BEFORE bearer_auth_layer) so browsers can pass the bearer
        // via `?token=`. Keeping it on `core` would put bearer_auth_layer
        // outermost, which rejects the request with 401 before the adapter
        // can rewrite the query into an Authorization header.
        .route(
            "/t/{tenant}/rooms/{room}",
            post({
                let pc = rooms::PublishCtx {
                    bus: state.bus_rooms.clone(),
                    bucket: state.bucket.clone(),
                    cfg: state.rooms_cfg.clone(),
                };
                move |ctx, policy, path, json| {
                    rooms::rest::publish_handler(pc.clone(), ctx, policy, path, json)
                }
            })
            .layer(axum::extract::DefaultBodyLimit::max(128 * 1024)),
        )
        // /t/{tenant}/realtime lives on `ws_router` below — see the SSE
        // subscribe note above for the layer-order rationale.
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
            post(admin_user_routes::create_user_handler).get(admin_user_routes::list_users_handler),
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
        // ── Admin OAuth provider config (service-only) ────────────────────
        .route(
            "/t/{tenant}/admin/oauth-providers",
            get(oauth_admin_routes::list_oauth_providers_handler),
        )
        .route(
            "/t/{tenant}/admin/oauth-providers/{provider}",
            put(oauth_admin_routes::put_oauth_provider_handler)
                .delete(oauth_admin_routes::delete_oauth_provider_handler),
        )
        // ── Admin webhook subscriptions (service-only) ────────────────────
        .route(
            "/t/{tenant}/admin/webhooks",
            post(webhook_routes::create_handler).get(webhook_routes::list_handler),
        )
        .route(
            "/t/{tenant}/admin/webhooks/{id}",
            get(webhook_routes::get_handler)
                .patch(webhook_routes::patch_handler)
                .delete(webhook_routes::delete_handler),
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
        let chunk_max = files_state.large_upload_chunk_max_bytes;
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
                    .delete(crate::mgmt::tenant_files::delete_one)
                    .patch(crate::mgmt::tenant_files::set_visibility),
            )
            .route(
                "/t/{tenant}/files/{key}/bytes",
                get(crate::mgmt::tenant_files::stream_bytes),
            )
            .route(
                "/t/{tenant}/files/{key}/sign",
                post(crate::mgmt::tenant_files::sign_url),
            )
            .route(
                "/t/{tenant}/uploads",
                post(crate::tenant::uploads::create)
                    .get(crate::tenant::uploads::list_sessions)
                    .options(crate::tenant::uploads::options),
            )
            .route(
                "/t/{tenant}/uploads/{token}",
                axum::routing::patch(crate::tenant::uploads::patch)
                    .head(crate::tenant::uploads::head)
                    .delete(crate::tenant::uploads::terminate)
                    .layer(axum::extract::DefaultBodyLimit::max(chunk_max)),
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
        .route(
            "/t/{tenant}/oauth/{provider}/start",
            get(oauth_routes::oauth_start),
        )
        .route(
            "/t/{tenant}/oauth/{provider}/callback",
            get(oauth_routes::oauth_callback),
        )
        .with_state(auth_state.clone());

    // v1.31.7 — WebSocket / SSE sub-router. These two routes accept the
    // bearer via `?token=` (browsers' native WebSocket / EventSource APIs
    // can't set custom headers), so the `ws_query_token_adapter` MUST run
    // BEFORE `bearer_auth_layer` to rewrite the query into an Authorization
    // header. axum applies router-level `.layer(...)` outermost (= runs
    // first); per-route `.layer(...)` is INNER (= runs after the outer
    // router layer). Putting both on `core` reversed the desired order and
    // every WS upgrade with `?token=` got rejected as `UNAUTHENTICATED`.
    // The fix: isolate these two routes in their own sub-router, applying
    // `bearer_auth_layer` INNER + `ws_query_token_adapter` OUTER, then
    // merge.
    let ws_router = Router::new()
        .route(
            "/t/{tenant}/records/{coll}/subscribe",
            get({
                let b = bus.clone();
                move |ext, ctx, path| sse::subscribe_handler(b.clone(), ext, ctx, path)
            }),
        )
        .route(
            "/t/{tenant}/realtime",
            get({
                let pc = rooms::PublishCtx {
                    bus: state.bus_rooms.clone(),
                    bucket: state.bucket.clone(),
                    cfg: state.rooms_cfg.clone(),
                };
                move |ctx, policy, path, ws| {
                    rooms::ws::ws_handler(pc.clone(), ctx, policy, path, ws)
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            router::bearer_auth_layer,
        ))
        .layer(axum::middleware::from_fn(
            rooms::ws_auth::ws_query_token_adapter,
        ))
        .with_state(auth_state);

    let merged = core.merge(files_router).merge(auth_router).merge(ws_router);
    // CORS layer goes OUTSIDE bearer_auth_layer (= applied last) so OPTIONS
    // preflight is intercepted by tower_http before reaching auth, returning
    // 200 + ACA* headers without seeing the bearer token. Real GET/POST/etc.
    // still pass through bearer_auth normally; the layer just appends the
    // ACAO header on the way back out.
    let merged = if let Some(cors) = cors {
        merged.layer(cors)
    } else {
        merged
    };
    // Mounted OUTSIDE the CORS layer (applied after it = outermost) so it post-
    // processes the CORS-short-circuited OPTIONS /uploads preflight and re-adds
    // the tus capability headers the shadowed `uploads::options` handler can't.
    if let Some(max_size) = tus_max_size {
        merged.layer(axum::middleware::from_fn_with_state(
            max_size,
            inject_tus_capabilities,
        ))
    } else {
        merged
    }
}

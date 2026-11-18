//! The account-level MCP router: `/mcp` and its protected-resource metadata.
//!
//! `/mcp` is rmcp's stateless Streamable HTTP service for
//! [`AccountMcp`](crate::mcp::account::AccountMcp) behind three route layers,
//! outermost first: the entry gate (`route_layer::mcp_route_layer`: switch,
//! Host, Origin, declared body size), the OAuth bearer layer
//! (`rs_layer::mcp_oauth_auth_layer`) and the body buffer
//! (`route_layer::mcp_body_buffer`), so an unauthenticated body is never read.
//!
//! Two things together keep the admin router's fallback untouched, and with it
//! every unmatched path byte-identical: the gates are `route_layer`s, never
//! `layer`s (`Router::layer` also wraps the fallback), and the metadata route
//! is merged last (`merge` keeps the merged-in side's default fallback, so a
//! gated fallback is replaced by the metadata router's plain one). A `.layer`
//! on the router this returns would gate every unmatched admin path.
//!
//! `MgmtState::with_data_dir` always merges this router; disabled, it holds
//! only `/mcp`, which answers H1. The metadata route sits outside the three
//! gates on purpose: it reads no Host, no header and no database, like the
//! authorization-server metadata.
//!
//! No rmcp handler lives here and nothing here holds a request context
//! (`no_mcp_handler_lives_under_mcp_oauth`): the push scan over `src/mcp`
//! cannot see this directory.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum::middleware::{from_fn, from_fn_with_state};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::mcp::account::{AccountMcp, UploadLimits};
use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::mcp_oauth::prm::prm_handler;
use crate::mgmt::mcp_oauth::route_layer::{mcp_body_buffer, mcp_route_layer};
use crate::mgmt::mcp_oauth::rs_layer::{RsState, mcp_oauth_auth_layer};
use crate::mgmt::routes::MgmtState;

/// The account-level MCP endpoint, the path `McpOauthConfig::resource_url`
/// names.
pub(crate) const MCP_PATH: &str = "/mcp";

/// Its protected-resource metadata, the path `McpOauthConfig::prm_url` names.
pub(crate) const PRM_PATH: &str = "/.well-known/oauth-protected-resource/mcp";

/// rmcp's transport settings for `/mcp`: stateless (no session, no GET
/// stream), SSE responses with rmcp's default keep-alive, and the same host
/// list the entry gate checks. Origin is left to the entry gate alone.
pub(crate) fn account_http_config(cfg: &McpOauthConfig) -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_allowed_hosts(cfg.allowed_hosts())
}

/// The large-upload limits the account-level server issues uploads under.
pub(crate) fn upload_limits(state: &MgmtState) -> UploadLimits {
    UploadLimits {
        storage_configured: state.garage.is_some(),
        max_bytes: state.large_upload_max_bytes,
        chunk_max_bytes: state.large_upload_chunk_max_bytes,
        session_ttl_secs: state.large_upload_session_ttl_secs,
    }
}

/// `/mcp` behind its three gates, plus the metadata route. See the module
/// doc for why the order and the layer kind matter.
pub fn account_routes(state: &MgmtState) -> Router {
    let cfg = state.mcp_oauth.clone();
    if !cfg.enabled() {
        // Disabled: no rmcp service and no metadata route. The entry gate's
        // first check answers H1 on every method, before any Host check.
        return Router::new()
            .route(
                MCP_PATH,
                axum::routing::any(|| async { StatusCode::NOT_FOUND }),
            )
            .route_layer(from_fn_with_state(cfg, mcp_route_layer));
    }
    let mcp = AccountMcp::new(
        state.mcp.registry().clone(),
        state.meta.clone(),
        cfg.clone(),
        upload_limits(state),
        state.log_dir.clone(),
    );
    let svc = StreamableHttpService::new(
        move || Ok(mcp.clone()),
        Arc::new(NeverSessionManager::default()),
        account_http_config(&cfg),
    );
    let rs = RsState {
        meta: state.meta.clone(),
        cfg: cfg.clone(),
        rl: state.mcp_oauth_rl.clone(),
    };
    // route_layer, never layer, and the metadata route merged last: a
    // layered fallback would become the merged admin router's fallback and
    // gate every unmatched path.
    // Added innermost first: body buffer, then auth, then the entry gate.
    Router::new()
        .route_service(MCP_PATH, svc)
        .route_layer(from_fn(mcp_body_buffer))
        .route_layer(from_fn_with_state(rs, mcp_oauth_auth_layer))
        .route_layer(from_fn_with_state(cfg.clone(), mcp_route_layer))
        .merge(
            Router::new()
                .route(PRM_PATH, axum::routing::get(prm_handler))
                .with_state(cfg),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::route_layer::MCP_BODY_LIMIT;
    use crate::mgmt::mcp_oauth::rs_layer::challenge;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    const H4: &[u8] =
        br#"{"message":"request body too large for /mcp","error_code":"MCP_BODY_TOO_LARGE"}"#;

    fn enabled_state(tmp: &tempfile::TempDir) -> MgmtState {
        let data = tmp.path().to_path_buf();
        let conn = crate::storage::meta::open_meta(&data.join("meta.sqlite")).unwrap();
        crate::db::migrations::run_migrations(&conn, &data).unwrap();
        let tenants = Arc::new(crate::storage::pool::TenantRegistry::new(data.clone(), 2));
        let mcp = Arc::new(crate::mcp::http_registry::McpHttpRegistry::new(Arc::new(
            crate::mcp::server::McpRegistry::new(tenants.clone()),
        )));
        let mut s = MgmtState::test_default(
            Arc::new(Mutex::new(conn)),
            data,
            tenants,
            mcp,
            crate::tenant::events::EventBus::new(),
            crate::tenant::rooms::RoomBus::new(),
        );
        s.mcp_oauth = Arc::new(McpOauthConfig::for_tests("https://drust.test"));
        s
    }

    /// One owner and one live grant on the state's meta; returns the access token.
    async fn seeded_access(s: &MgmtState) -> String {
        let m = s.meta.lock().await;
        m.execute(
            "INSERT INTO admins (username, password_hash, email, role) \
             VALUES ('owner', '$oauth-only$', 'owner@example.test', 'owner')",
            [],
        )
        .unwrap();
        crate::mgmt::mcp_oauth::store::seed_access_for_tests(&m, m.last_insert_rowid())
            .unwrap()
            .access
    } // guard dropped here, before any request runs

    /// A chunked body that records whether it was ever polled.
    fn watched_chunked(total: usize, polled: Arc<AtomicBool>) -> Body {
        use futures::StreamExt;
        let chunk = 1 << 20;
        let parts: Vec<Result<bytes::Bytes, std::io::Error>> = (0..total.div_ceil(chunk))
            .map(|i| Ok(bytes::Bytes::from(vec![b'x'; chunk.min(total - i * chunk)])))
            .collect();
        Body::from_stream(
            futures::stream::iter(parts).inspect(move |_| polled.store(true, Ordering::SeqCst)),
        )
    }

    /// POST /mcp with Host 127.0.0.1 and the given extra headers.
    fn post_mcp(headers: &[(&str, &str)], body: Body) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header("host", "127.0.0.1")
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(body).unwrap()
    }

    /// A body-less request with the given headers.
    fn bare(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    type Snap = (StatusCode, Vec<(String, String)>, Vec<u8>);

    /// status + every header sorted by name + body: the byte-identity comparison.
    async fn snap(app: &Router, method: &str, uri: &str, headers: &[(&str, &str)]) -> Snap {
        let r = app
            .clone()
            .oneshot(bare(method, uri, headers))
            .await
            .unwrap();
        let status = r.status();
        let mut hs: Vec<(String, String)> = r
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        hs.sort_by(|a, b| a.0.cmp(&b.0));
        let body = axum::body::to_bytes(r.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec();
        (status, hs, body)
    }

    #[test]
    fn http_config_is_stateless_and_uses_the_one_host_list() {
        let cfg = McpOauthConfig::for_tests("https://drust.test");
        let c = account_http_config(&cfg);
        assert!(!c.stateful_mode);
        assert_eq!(c.allowed_hosts, cfg.allowed_hosts());
        assert!(c.allowed_hosts.iter().any(|h| h == "drust.test"));
        assert!(
            c.allowed_origins.is_empty(),
            "Origin is checked once, in mcp_route_layer"
        );
        assert!(
            !c.json_response,
            "SSE keeps long tool calls alive behind proxies"
        );
        assert_eq!(c.sse_keep_alive, Some(std::time::Duration::from_secs(15)));
    }

    #[test]
    fn mounted_paths_are_the_paths_the_urls_name() {
        let cfg = McpOauthConfig::for_tests("https://drust.test");
        assert!(cfg.resource_url().ends_with(MCP_PATH));
        assert!(cfg.prm_url().ends_with(PRM_PATH));
    }

    /// The bare-metal proxy snippet: both root discovery rules rewrite to the
    /// paths this crate mounts, keep the default Host, and write one
    /// directive per line (Caddyfile has no `;` separator).
    #[test]
    fn caddy_snippet_forwards_both_root_discovery_paths() {
        let lines: Vec<&str> = include_str!("../../../deploy/Caddyfile")
            .lines()
            .map(|l| l.split('#').next().unwrap_or_default().trim())
            .filter(|l| !l.is_empty())
            .collect();
        let as_path = "/.well-known/oauth-authorization-server";
        assert!(
            include_str!("mod.rs").contains(&format!("\"{as_path}\"")),
            "the AS metadata route moved; update this pin and deploy/Caddyfile"
        );
        for (public, target) in [
            (format!("{as_path}/drust"), as_path.to_string()),
            (
                format!("/.well-known/oauth-protected-resource/drust{MCP_PATH}"),
                PRM_PATH.to_string(),
            ),
        ] {
            let head = format!("handle {public} {{");
            let at = lines
                .iter()
                .position(|l| *l == head)
                .unwrap_or_else(|| panic!("deploy/Caddyfile: no `{head}` block"));
            let rewrite = format!("rewrite * {target}");
            assert_eq!(
                lines.get(at + 1).copied(),
                Some(rewrite.as_str()),
                "{public}"
            );
            assert_eq!(
                lines.get(at + 2).copied(),
                Some("reverse_proxy 127.0.0.1:47826 {"),
                "{public}"
            );
            assert_eq!(
                lines.get(at + 3).copied(),
                Some("header_up Host \"127.0.0.1:47826\""),
                "{public}"
            );
        }
        let joined: Vec<&&str> = lines.iter().filter(|l| l.contains(';')).collect();
        assert!(
            joined.is_empty(),
            "deploy/Caddyfile: one directive per line: {joined:?}"
        );
    }

    // A runtime only because MgmtState::test_default starts the function
    // executor.
    #[tokio::test]
    async fn upload_limits_mirror_the_state() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = enabled_state(&tmp);
        s.large_upload_max_bytes = 101;
        s.large_upload_chunk_max_bytes = 13;
        s.large_upload_session_ttl_secs = 17;
        s.garage = None;
        assert_eq!(
            upload_limits(&s),
            UploadLimits {
                storage_configured: false,
                max_bytes: 101,
                chunk_max_bytes: 13,
                session_ttl_secs: 17
            }
        );
        s.garage = Some(Arc::new(crate::storage::garage::GarageClient::from_store(
            Arc::new(object_store::memory::InMemory::new()),
            "private",
        )));
        assert!(upload_limits(&s).storage_configured);
    }

    #[tokio::test]
    async fn unmatched_paths_keep_the_default_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let s = enabled_state(&tmp);
        let base = || Router::new().route("/x", axum::routing::get(|| async { "x" }));
        let with = base().merge(account_routes(&s));
        let junk = [("authorization", "Bearer junk"), ("host", "evil.example")];
        for (m, uri) in [
            ("GET", "/no-such-path"),
            ("POST", "/mcp/"),
            ("GET", "/mcp/x"),
            ("GET", "/.well-known/oauth-protected-resource/mcp/"),
            ("GET", "/.well-known/oauth-protected-resource"),
        ] {
            assert_eq!(
                snap(&with, m, uri, &junk).await,
                snap(&base(), m, uri, &junk).await,
                "{m} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn every_method_meets_the_gates_before_rmcp() {
        let tmp = tempfile::tempdir().unwrap();
        let s = enabled_state(&tmp);
        let app = account_routes(&s);
        for m in ["POST", "GET", "DELETE", "OPTIONS"] {
            let r = app
                .clone()
                .oneshot(bare(m, MCP_PATH, &[("host", "127.0.0.1")]))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{m}");
            assert_eq!(
                r.headers()["www-authenticate"],
                challenge(&s.mcp_oauth, false),
                "{m}"
            );
            assert!(
                r.headers().get("allow").is_none(),
                "{m}: rmcp must not have answered"
            );
        }
        let r = app
            .clone()
            .oneshot(bare(
                "POST",
                MCP_PATH,
                &[("host", "evil.example"), ("authorization", "Bearer junk")],
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST);
    }

    #[tokio::test]
    async fn unauthenticated_bodies_are_never_read() {
        let tmp = tempfile::tempdir().unwrap();
        let s = enabled_state(&tmp);
        let app = account_routes(&s);
        let unknown = format!(
            "Bearer {}",
            crate::mgmt::mcp_oauth::tokens::new_token(
                crate::mgmt::mcp_oauth::tokens::TokenKind::Access
            )
        );
        for auth in [None, Some("Bearer junk".to_string()), Some(unknown)] {
            let polled = Arc::new(AtomicBool::new(false));
            let hs: Vec<(&str, &str)> = auth
                .as_deref()
                .map(|a| vec![("authorization", a)])
                .unwrap_or_default();
            let r = app
                .clone()
                .oneshot(post_mcp(
                    &hs,
                    watched_chunked(MCP_BODY_LIMIT + 1, polled.clone()),
                ))
                .await
                .unwrap();
            assert_eq!(
                r.status(),
                StatusCode::UNAUTHORIZED,
                "auth present: {}",
                auth.is_some()
            );
            assert!(
                !polled.load(Ordering::SeqCst),
                "body was read before authentication"
            );
        }
    }

    #[tokio::test]
    async fn oversized_chunked_body_after_auth_is_h4_not_500() {
        let tmp = tempfile::tempdir().unwrap();
        let s = enabled_state(&tmp);
        let auth = format!("Bearer {}", seeded_access(&s).await);
        let polled = Arc::new(AtomicBool::new(false));
        let r = account_routes(&s)
            .oneshot(post_mcp(
                &[("authorization", &auth)],
                watched_chunked(MCP_BODY_LIMIT + 1, polled.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert_eq!(
            axum::body::to_bytes(r.into_body(), 1 << 20)
                .await
                .unwrap()
                .as_ref(),
            H4
        );
        assert!(
            polled.load(Ordering::SeqCst),
            "the buffer is mounted and read the body"
        );
    }

    #[tokio::test]
    async fn content_length_over_limit_is_413_before_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let s = enabled_state(&tmp);
        let len = (MCP_BODY_LIMIT + 1).to_string();
        let r = account_routes(&s)
            .oneshot(post_mcp(&[("content-length", &len)], Body::empty()))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(r.headers().get("www-authenticate").is_none());
        assert_eq!(
            axum::body::to_bytes(r.into_body(), 1 << 20)
                .await
                .unwrap()
                .as_ref(),
            H4
        );
    }

    #[tokio::test]
    async fn prm_is_served_outside_the_gates() {
        let tmp = tempfile::tempdir().unwrap();
        let s = enabled_state(&tmp);
        let r = account_routes(&s)
            .oneshot(bare("GET", PRM_PATH, &[("host", "evil.example")]))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()["cache-control"], "public, max-age=300");
        let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, crate::mgmt::mcp_oauth::prm::prm_json(&s.mcp_oauth));
    }
}

//! Bearer layer for the account-level MCP endpoint: accepts MCP OAuth access tokens only.
//!
//! One lookup per request, through `store::find_grant_by_access`, the only
//! authorization-strength lookup. Every refused token is 401 `invalid_token`,
//! never 429, and no per-IP budget is read: the hourly sweep deletes an
//! expired access row, so an idle client's expired token cannot be told from
//! one never issued, and Claude Code refreshes only on a 401. A budget charged
//! after the lookup would save no work either (the same reasoning as
//! `/oauth/revoke`). A valid token spends its grant's budget first and only
//! then touches `last_used_at`, on the same `meta` guard, which is released
//! before the inner service runs. Refusals write no audit row; their logs are
//! sampled, because unauthenticated traffic can trigger them.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use rusqlite::Connection;
use tokio::sync::Mutex;

use crate::mgmt::mcp_oauth::authorize::WarnSampler;
use crate::mgmt::mcp_oauth::caller::McpCaller;
use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::mcp_oauth::envelope;
use crate::mgmt::mcp_oauth::rl::{self, McpOauthLimiters};
use crate::mgmt::mcp_oauth::route_layer::mcp_error;
use crate::mgmt::mcp_oauth::store;
use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};
use crate::safety::rate_limit::RateLimitedError;

/// What the bearer layer needs: the `meta` connection, the OAuth config (for
/// the challenge URL) and the resource-server budgets.
#[derive(Clone)]
pub(crate) struct RsState {
    pub meta: Arc<Mutex<Connection>>,
    pub cfg: Arc<McpOauthConfig>,
    pub rl: Arc<McpOauthLimiters>,
}

const OAUTH_REQUIRED: (&str, &str) = (
    "OAuth required: in Claude Code run /mcp, then Authenticate",
    "MCP_OAUTH_REQUIRED",
);
const OAUTH_ONLY: (&str, &str) = (
    "OAuth only: remove Authorization header from this server's config, then /mcp -> Authenticate",
    "MCP_OAUTH_REQUIRED",
);
const INTERNAL: (&str, &str) = ("internal error", "INTERNAL");
const RATE_LIMITED: (&str, &str) = ("too many requests; retry later", "RATE_LIMITED");

static RS_REFUSAL_WARN: WarnSampler = WarnSampler::new();
static RS_LOOKUP_ERROR_LOG: WarnSampler = WarnSampler::new();
static RS_TOUCH_WARN: WarnSampler = WarnSampler::new();

/// The `WWW-Authenticate` value of a 401: the protected-resource metadata URL
/// and the scope, plus `error="invalid_token"` when a bearer was presented
/// and refused.
pub(crate) fn challenge(cfg: &McpOauthConfig, invalid_token: bool) -> HeaderValue {
    let mut v = format!(
        "Bearer resource_metadata=\"{}\", scope=\"mcp\"",
        cfg.prm_url()
    );
    if invalid_token {
        v.push_str(", error=\"invalid_token\"");
    }
    HeaderValue::from_str(&v).unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

fn refuse(status: StatusCode, (message, code): (&str, &str)) -> Response {
    mcp_error(status, message, code)
}

fn unauthorized(cfg: &McpOauthConfig, c: (&str, &str), invalid_token: bool) -> Response {
    let mut resp = refuse(StatusCode::UNAUTHORIZED, c);
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge(cfg, invalid_token));
    resp
}

/// `reason` is one of `"shape"`, `"no_grant"`, `"grant_budget"`; nothing
/// else from the request is logged.
fn log_refusal(reason: &'static str, grant_id: Option<i64>) {
    // A clock before the epoch never suppresses.
    match envelope::now_unix().map_or(Some(0), |n| RS_REFUSAL_WARN.sample(n)) {
        Some(suppressed) => tracing::warn!(reason, grant_id, suppressed, "mcp: bearer refused"),
        None => tracing::debug!(reason, grant_id, "mcp: bearer refused"),
    }
}

/// The outcome of the one locked block. Carries no token.
enum Lookup {
    Valid(McpCaller),
    GrantBudget(Duration, i64),
    NoGrant,
    Error(rusqlite::Error),
}

/// Admits only a live MCP OAuth access token, on every method: no usable
/// Bearer credential is 401 without `error`, any other credential shape or a
/// token the lookup refuses is 401 `invalid_token` (a foreign shape before the
/// `meta` lock), a lookup error is 500 and a spent grant budget is 429, the
/// last two without a challenge. Only the FIRST `Authorization` value is
/// read. On success the request carries the [`McpCaller`] and no
/// `Authorization` (any value), `Cookie` or `Proxy-Authorization` header: the
/// inner service reads none of them.
pub(crate) async fn mcp_oauth_auth_layer(
    State(st): State<RsState>,
    mut req: Request,
    next: Next,
) -> Response {
    let raw = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let token = match raw.and_then(|raw| raw.split_once(' ')) {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("Bearer") && !rest.trim().is_empty() =>
        {
            rest.trim().to_owned()
        }
        _ => {
            // Every connection's first request looks like this: not sampled.
            tracing::debug!("mcp: no bearer credential");
            return unauthorized(&st.cfg, OAUTH_REQUIRED, false);
        }
    };
    if !tokens::looks_like(TokenKind::Access, &token) {
        log_refusal("shape", None);
        return unauthorized(&st.cfg, OAUTH_ONLY, true);
    }

    let lookup = {
        let conn = st.meta.lock().await;
        match store::find_grant_by_access(&conn, &token) {
            Err(e) => Lookup::Error(e),
            Ok(None) => Lookup::NoGrant,
            Ok(Some(g)) => match st.rl.rs_grant.try_acquire(&rl::grant_key(g.grant_id())) {
                Err(RateLimitedError(d)) => Lookup::GrantBudget(d, g.grant_id()),
                Ok(()) => {
                    // Display only; a failure never blocks a valid token.
                    if let Err(e) = store::touch_grant_last_used(&conn, &g) {
                        match envelope::now_unix().map_or(Some(0), |n| RS_TOUCH_WARN.sample(n)) {
                            Some(suppressed) => tracing::warn!(
                                error = %crate::error::sqlite_error_without_sql(&e),
                                grant_id = g.grant_id(),
                                suppressed,
                                "mcp: last_used_at update failed"
                            ),
                            None => tracing::debug!(
                                error = %crate::error::sqlite_error_without_sql(&e),
                                grant_id = g.grant_id(),
                                "mcp: last_used_at update failed"
                            ),
                        }
                    }
                    Lookup::Valid(McpCaller::from_access(&g))
                }
            },
        }
    };

    match lookup {
        Lookup::Error(e) => {
            match envelope::now_unix().map_or(Some(0), |n| RS_LOOKUP_ERROR_LOG.sample(n)) {
                Some(suppressed) => tracing::error!(
                    error = %crate::error::sqlite_error_without_sql(&e),
                    suppressed,
                    "mcp: bearer lookup failed"
                ),
                None => tracing::debug!(
                    error = %crate::error::sqlite_error_without_sql(&e),
                    "mcp: bearer lookup failed"
                ),
            }
            refuse(StatusCode::INTERNAL_SERVER_ERROR, INTERNAL)
        }
        Lookup::NoGrant => {
            log_refusal("no_grant", None);
            unauthorized(&st.cfg, OAUTH_ONLY, true)
        }
        Lookup::GrantBudget(d, gid) => {
            log_refusal("grant_budget", Some(gid));
            let mut resp = refuse(StatusCode::TOO_MANY_REQUESTS, RATE_LIMITED);
            resp.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(rl::retry_after_secs(d)),
            );
            resp
        }
        Lookup::Valid(caller) => {
            let h = req.headers_mut();
            h.remove(header::AUTHORIZATION);
            h.remove(header::COOKIE);
            h.remove(header::PROXY_AUTHORIZATION);
            req.extensions_mut().insert(caller);
            next.run(req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::caller::McpCaller;
    use crate::mgmt::mcp_oauth::config::McpOauthConfig;
    use crate::mgmt::mcp_oauth::rl::{self, McpOauthLimiters};
    use crate::mgmt::mcp_oauth::route_layer::{MCP_BODY_LIMIT, mcp_body_buffer, mcp_route_layer};
    use crate::mgmt::mcp_oauth::store;
    use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
    use axum::middleware::{from_fn, from_fn_with_state};
    use axum::response::IntoResponse;
    use axum::routing::any;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    const H5: &[u8] = br#"{"message":"OAuth required: in Claude Code run /mcp, then Authenticate","error_code":"MCP_OAUTH_REQUIRED"}"#;
    const H6: &[u8] = br#"{"message":"OAuth only: remove Authorization header from this server's config, then /mcp -> Authenticate","error_code":"MCP_OAUTH_REQUIRED"}"#;
    const H7: &[u8] = br#"{"message":"internal error","error_code":"INTERNAL"}"#;
    const H8: &[u8] =
        br#"{"message":"too many requests; retry later","error_code":"RATE_LIMITED"}"#;
    const H4: &[u8] =
        br#"{"message":"request body too large for /mcp","error_code":"MCP_BODY_TOO_LARGE"}"#;
    const PRM: &str = "https://drust.test/drust/.well-known/oauth-protected-resource/mcp";
    const HOST: &str = "127.0.0.1:47826";

    struct Fx {
        _dir: tempfile::TempDir,
        st: RsState,
        access: String,
        grant_id: i64,
        admin_id: i64,
    }

    /// A real meta.sqlite (open_meta creates the MCP OAuth tables and turns
    /// foreign keys on), one admin, one live grant with an access token,
    /// fresh limiters.
    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::storage::meta::open_meta(&dir.path().join("meta.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES ('root', '$oauth-only$')",
            [],
        )
        .unwrap();
        let admin_id = conn.last_insert_rowid();
        let s = store::seed_access_for_tests(&conn, admin_id).unwrap();
        let st = RsState {
            meta: Arc::new(Mutex::new(conn)),
            cfg: Arc::new(McpOauthConfig::for_tests("https://drust.test")),
            rl: Arc::new(McpOauthLimiters::new()),
        };
        Fx {
            _dir: dir,
            st,
            access: s.access,
            grant_id: s.grant_id,
            admin_id,
        }
    }

    /// The full entry stack in mounting order; `/mcp` reports what the inner
    /// service would see.
    fn app(st: &RsState) -> Router {
        let meta = st.meta.clone();
        Router::new()
            .route(
                "/mcp",
                any(move |req: axum::extract::Request| {
                    let meta = meta.clone();
                    async move {
                        let caller = req.extensions().get::<McpCaller>().cloned();
                        let h = req.headers();
                        let authorization = h.contains_key(header::AUTHORIZATION);
                        let cookie = h.contains_key(header::COOKIE);
                        let proxy_authorization = h.contains_key(header::PROXY_AUTHORIZATION);
                        let meta_free = meta.try_lock().is_ok();
                        let n = axum::body::to_bytes(req.into_body(), usize::MAX)
                            .await
                            .unwrap()
                            .len();
                        axum::Json(serde_json::json!({
                            "admin_id": caller.as_ref().map(|c| c.admin_id()),
                            "grant_id": caller.as_ref().map(|c| c.grant_id()),
                            "authorization": authorization, "cookie": cookie,
                            "proxy_authorization": proxy_authorization,
                            "meta_free": meta_free, "len": n,
                        }))
                        .into_response()
                    }
                }),
            )
            .layer(from_fn(mcp_body_buffer))
            .layer(from_fn_with_state(st.clone(), mcp_oauth_auth_layer))
            .layer(from_fn_with_state(st.cfg.clone(), mcp_route_layer))
    }

    fn req(method: Method, auth: Option<&[u8]>, body: Body) -> Request<Body> {
        let mut b = Request::builder()
            .method(method)
            .uri("/mcp")
            .header(header::HOST, HOST);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, HeaderValue::from_bytes(a).unwrap());
        }
        b.body(body).unwrap()
    }

    fn bearer(t: &str) -> Vec<u8> {
        format!("Bearer {t}").into_bytes()
    }

    async fn send(app: &Router, r: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let resp = tokio::time::timeout(Duration::from_secs(5), app.clone().oneshot(r))
            .await
            .expect("request hung")
            .unwrap();
        let (s, h) = (resp.status(), resp.headers().clone());
        (
            s,
            h,
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
    }

    fn assert_h(
        got: &(StatusCode, HeaderMap, Vec<u8>),
        status: StatusCode,
        body: &[u8],
        www: Option<&str>,
    ) {
        assert_eq!(got.0, status, "{}", String::from_utf8_lossy(&got.2));
        assert_eq!(got.2, body);
        assert_eq!(got.1[header::CONTENT_TYPE], "application/json");
        assert_eq!(got.1[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            got.1
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap()),
            www
        );
    }

    fn h5_www() -> String {
        format!("Bearer resource_metadata=\"{PRM}\", scope=\"mcp\"")
    }
    fn h6_www() -> String {
        format!("Bearer resource_metadata=\"{PRM}\", scope=\"mcp\", error=\"invalid_token\"")
    }

    fn json(got: &(StatusCode, HeaderMap, Vec<u8>)) -> serde_json::Value {
        serde_json::from_slice(&got.2).unwrap()
    }

    /// `n` access-shaped tokens that were never issued, from one address:
    /// every one is 401 invalid_token. 61 exceeds a 60-per-minute bucket, so a
    /// per-IP budget on this path would show up as a 429.
    async fn flood_unknown(app: &Router, n: usize) {
        for i in 0..n {
            let t = tokens::new_token(TokenKind::Access);
            let got = send(
                app,
                req(Method::POST, Some(bearer(&t).as_slice()), Body::empty()),
            )
            .await;
            assert_eq!(got.0, StatusCode::UNAUTHORIZED, "unknown token #{i}");
            assert_h(&got, StatusCode::UNAUTHORIZED, H6, Some(h6_www().as_str()));
        }
    }

    #[test]
    fn challenge_values() {
        let cfg = McpOauthConfig::for_tests("https://drust.test");
        assert_eq!(cfg.prm_url(), PRM);
        assert_eq!(challenge(&cfg, false), h5_www().as_str());
        assert_eq!(challenge(&cfg, true), h6_www().as_str());
    }

    #[tokio::test]
    async fn h5_no_or_non_bearer_authorization() {
        let f = fx();
        let app = app(&f.st);
        for auth in [
            None,
            Some(&b"Basic dXNlcjpwYXNz"[..]),
            Some(&b"Bearer"[..]),
            Some(&b"Bearer "[..]),
            Some(&b"Bearer    "[..]),
            Some(&b"\xff\xfe"[..]),
            Some(&b"Token abc"[..]),
        ] {
            let got = send(&app, req(Method::POST, auth, Body::empty())).await;
            assert_h(&got, StatusCode::UNAUTHORIZED, H5, Some(h5_www().as_str()));
        }
    }

    #[tokio::test]
    async fn non_post_methods_without_auth_get_h5() {
        let f = fx();
        let app = app(&f.st);
        for m in [Method::GET, Method::DELETE, Method::OPTIONS] {
            let got = send(&app, req(m, None, Body::empty())).await;
            assert_h(&got, StatusCode::UNAUTHORIZED, H5, Some(h5_www().as_str()));
        }
    }

    /// Other credential families are refused on shape alone: the test holds
    /// the meta lock for the whole loop, so any lookup would hang (5 s timeout).
    #[tokio::test]
    async fn h6_foreign_shapes_never_take_the_meta_lock() {
        let f = fx();
        let app = app(&f.st);
        let _held = f.st.meta.lock().await; // held until the test ends
        let foreign = [
            crate::auth::bearer::generate_token(),
            crate::auth::admin_token::generate_token(),
            format!("drust_pat_cli_{}", "a".repeat(43)),
            format!("drust_user_{}", "a".repeat(43)),
            tokens::new_token(TokenKind::Refresh),
            tokens::new_token(TokenKind::UploadTicket),
            tokens::new_token(TokenKind::Code),
            "drust_mcpat_short".to_string(),
            format!("{}x", f.access),
        ];
        for t in &foreign {
            let got = send(
                &app,
                req(Method::POST, Some(bearer(t).as_slice()), Body::empty()),
            )
            .await;
            assert_h(&got, StatusCode::UNAUTHORIZED, H6, Some(h6_www().as_str()));
        }
    }

    #[tokio::test]
    async fn unknown_access_tokens_are_never_rate_limited() {
        let f = fx();
        let app = app(&f.st);
        flood_unknown(&app, 61).await;
    }

    #[tokio::test]
    async fn valid_token_passes_after_a_flood_of_unknown_tokens() {
        let f = fx();
        let app = app(&f.st);
        flood_unknown(&app, 61).await;
        let got = send(
            &app,
            req(
                Method::POST,
                Some(bearer(&f.access).as_slice()),
                Body::empty(),
            ),
        )
        .await;
        assert_eq!(got.0, StatusCode::OK);
        assert_eq!(json(&got)["grant_id"], f.grant_id);
    }

    /// Every refused access token gets 401 invalid_token (the answer that makes
    /// Claude Code refresh), also after the hourly sweep removed an expired
    /// row and after a flood of unknown tokens from the same address — the
    /// shape an idle client wakes up to. (label, UPDATE, access rows swept)
    #[tokio::test]
    async fn dead_tokens_get_401_after_the_sweep_and_a_flood() {
        const DEAD: [(&str, &str, usize); 5] = [
            (
                "expired access",
                "UPDATE _mcp_oauth_access SET expires_at = datetime('now', '-1 second')",
                1,
            ),
            (
                "revoked access",
                "UPDATE _mcp_oauth_access SET revoked_at = datetime('now')",
                0,
            ),
            (
                "revoked grant",
                "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now')",
                0,
            ),
            (
                "idle deadline passed",
                "UPDATE _mcp_oauth_grants SET idle_expires_at = datetime('now', '-1 second')",
                0,
            ),
            (
                "absolute deadline passed",
                "UPDATE _mcp_oauth_grants SET absolute_expires_at = datetime('now', '-1 second')",
                0,
            ),
        ];
        for (label, sql, swept) in DEAD {
            let f = fx();
            f.st.meta.lock().await.execute(sql, []).unwrap();
            let counts = crate::mgmt::mcp_oauth::sweep::sweep_mcp_oauth(&f.st.meta).await;
            assert_eq!(
                counts.access, swept,
                "{label}: access rows the sweep removed"
            );
            let app = app(&f.st);
            flood_unknown(&app, 61).await;
            for _ in 0..3 {
                let got = send(
                    &app,
                    req(
                        Method::POST,
                        Some(bearer(&f.access).as_slice()),
                        Body::empty(),
                    ),
                )
                .await;
                assert_h(&got, StatusCode::UNAUTHORIZED, H6, Some(h6_www().as_str()));
            }
        }
    }

    /// Rowid-recycle layer 3 (created_at mismatch) and a removed admin (the FK
    /// cascade deletes the grant and its access rows) both answer 401.
    #[tokio::test]
    async fn token_of_a_recycled_or_removed_admin_gets_401() {
        for sql in [
            "UPDATE admins SET created_at = datetime('now', '+1 day')",
            "DELETE FROM admins",
        ] {
            let f = fx();
            f.st.meta.lock().await.execute(sql, []).unwrap();
            let app = app(&f.st);
            let got = send(
                &app,
                req(
                    Method::POST,
                    Some(bearer(&f.access).as_slice()),
                    Body::empty(),
                ),
            )
            .await;
            assert_h(&got, StatusCode::UNAUTHORIZED, H6, Some(h6_www().as_str()));
        }
    }

    #[tokio::test]
    async fn h8_grant_budget_spent_touches_nothing() {
        let f = fx();
        f.st.meta
            .lock()
            .await
            .execute(
                "UPDATE _mcp_oauth_grants SET last_used_at = datetime('now', '-1 hour')",
                [],
            )
            .unwrap();
        let app = app(&f.st);
        while f
            .st
            .rl
            .rs_grant
            .try_acquire(&rl::grant_key(f.grant_id))
            .is_ok()
        {}
        let got = send(
            &app,
            req(
                Method::POST,
                Some(bearer(&f.access).as_slice()),
                Body::empty(),
            ),
        )
        .await;
        assert_h(&got, StatusCode::TOO_MANY_REQUESTS, H8, None);
        let ra: u64 = got.1[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&ra), "Retry-After {ra}");
        let stale: bool = f
            .st
            .meta
            .lock()
            .await
            .query_row(
                "SELECT last_used_at <= datetime('now', '-3599 seconds') FROM _mcp_oauth_grants WHERE id = ?1",
                [f.grant_id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stale, "a refused request must not touch last_used_at");
    }

    #[tokio::test]
    async fn grant_budget_is_per_grant() {
        let f = fx();
        let other = store::seed_access_for_tests(&*f.st.meta.lock().await, f.admin_id).unwrap();
        let app = app(&f.st);
        while f
            .st
            .rl
            .rs_grant
            .try_acquire(&rl::grant_key(f.grant_id))
            .is_ok()
        {}
        let a = send(
            &app,
            req(
                Method::POST,
                Some(bearer(&f.access).as_slice()),
                Body::empty(),
            ),
        )
        .await;
        assert_eq!(a.0, StatusCode::TOO_MANY_REQUESTS);
        let b = send(
            &app,
            req(
                Method::POST,
                Some(bearer(&other.access).as_slice()),
                Body::empty(),
            ),
        )
        .await;
        assert_eq!(b.0, StatusCode::OK);
        assert_eq!(json(&b)["grant_id"], other.grant_id);
    }

    #[tokio::test]
    async fn h7_lookup_error_has_no_challenge() {
        let f = fx();
        f.st.meta
            .lock()
            .await
            .execute_batch("DROP TABLE _mcp_oauth_access")
            .unwrap();
        let app = app(&f.st);
        let got = send(
            &app,
            req(
                Method::POST,
                Some(bearer(&f.access).as_slice()),
                Body::empty(),
            ),
        )
        .await;
        assert_h(&got, StatusCode::INTERNAL_SERVER_ERROR, H7, None);
    }

    #[tokio::test]
    async fn valid_token_inserts_the_caller_strips_authorization_and_frees_meta() {
        let f = fx();
        let app = app(&f.st);
        let got = send(
            &app,
            req(
                Method::POST,
                Some(bearer(&f.access).as_slice()),
                Body::from("{}"),
            ),
        )
        .await;
        assert_eq!(got.0, StatusCode::OK);
        let v = json(&got);
        assert_eq!(v["admin_id"], f.admin_id);
        assert_eq!(v["grant_id"], f.grant_id);
        assert_eq!(v["authorization"], false);
        assert_eq!(
            v["meta_free"], true,
            "meta guard still held inside next.run"
        );
        assert_eq!(v["len"], 2);
    }

    /// A second Authorization (an old config's service key), a same-origin
    /// browser's Cookie and a Proxy-Authorization never reach the inner service.
    #[tokio::test]
    async fn valid_token_strips_every_credential_header() {
        let f = fx();
        let app = app(&f.st);
        let mut r = req(
            Method::POST,
            Some(bearer(&f.access).as_slice()),
            Body::empty(),
        );
        let service_key = bearer(&crate::auth::bearer::generate_token());
        let h = r.headers_mut();
        h.append(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(&service_key).unwrap(),
        );
        h.insert(header::COOKIE, HeaderValue::from_static("a=b"));
        h.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic eDp5"),
        );
        let got = send(&app, r).await;
        assert_eq!(got.0, StatusCode::OK);
        let v = json(&got);
        for k in ["authorization", "cookie", "proxy_authorization"] {
            assert_eq!(v[k], false, "{k} reached the inner service");
        }
    }

    /// Only the first Authorization value is authenticated.
    #[tokio::test]
    async fn first_authorization_value_decides() {
        let f = fx();
        let app = app(&f.st);
        let service_key = bearer(&crate::auth::bearer::generate_token());
        let mut r = req(Method::POST, Some(service_key.as_slice()), Body::empty());
        r.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(&bearer(&f.access)).unwrap(),
        );
        let got = send(&app, r).await;
        assert_h(&got, StatusCode::UNAUTHORIZED, H6, Some(h6_www().as_str()));
    }

    #[tokio::test]
    async fn bearer_scheme_is_case_insensitive_and_trimmed() {
        let f = fx();
        let app = app(&f.st);
        for auth in [
            format!("bearer {}", f.access),
            format!("BEARER {}", f.access),
            format!("Bearer   {}  ", f.access),
        ] {
            let got = send(
                &app,
                req(Method::POST, Some(auth.as_bytes()), Body::empty()),
            )
            .await;
            assert_eq!(got.0, StatusCode::OK, "{auth:?}");
        }
    }

    #[tokio::test]
    async fn valid_token_touches_last_used_at() {
        let f = fx();
        f.st.meta
            .lock()
            .await
            .execute(
                "UPDATE _mcp_oauth_grants SET last_used_at = datetime('now', '-1 hour')",
                [],
            )
            .unwrap();
        let app = app(&f.st);
        assert_eq!(
            send(
                &app,
                req(
                    Method::POST,
                    Some(bearer(&f.access).as_slice()),
                    Body::empty()
                )
            )
            .await
            .0,
            StatusCode::OK
        );
        let fresh: bool = f
            .st
            .meta
            .lock()
            .await
            .query_row(
                "SELECT last_used_at > datetime('now', '-60 seconds') FROM _mcp_oauth_grants WHERE id = ?1",
                [f.grant_id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(fresh);
    }

    #[tokio::test]
    async fn touch_failure_does_not_block_a_valid_token() {
        let f = fx();
        f.st.meta
            .lock()
            .await
            .execute_batch(
                "UPDATE _mcp_oauth_grants SET last_used_at = datetime('now', '-1 hour');
                 CREATE TRIGGER block_touch BEFORE UPDATE OF last_used_at ON _mcp_oauth_grants
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
            )
            .unwrap();
        let app = app(&f.st);
        let got = send(
            &app,
            req(
                Method::POST,
                Some(bearer(&f.access).as_slice()),
                Body::empty(),
            ),
        )
        .await;
        assert_eq!(got.0, StatusCode::OK);
        assert_eq!(json(&got)["grant_id"], f.grant_id);
    }

    /// The Content-Length pre-check sits outside the bearer layer: an
    /// unauthenticated oversize request is 413, not 401.
    #[tokio::test]
    async fn content_length_over_limit_without_auth_is_h4_not_h5() {
        let f = fx();
        let app = app(&f.st);
        let mut r = req(Method::POST, None, Body::empty());
        r.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("16777217"));
        let got = send(&app, r).await;
        assert_h(&got, StatusCode::PAYLOAD_TOO_LARGE, H4, None);
    }

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

    #[tokio::test]
    async fn chunked_body_is_never_read_before_authentication() {
        let f = fx();
        let app = app(&f.st);
        for auth in [None, Some(bearer(&tokens::new_token(TokenKind::Access)))] {
            let polled = Arc::new(AtomicBool::new(false));
            let body = watched_chunked(MCP_BODY_LIMIT + 1, polled.clone());
            let got = send(&app, req(Method::POST, auth.as_deref(), body)).await;
            assert_eq!(got.0, StatusCode::UNAUTHORIZED);
            assert!(
                !polled.load(Ordering::SeqCst),
                "body was read before authentication"
            );
        }
    }

    #[tokio::test]
    async fn chunked_body_over_limit_after_authentication_is_h4_not_500() {
        let f = fx();
        let app = app(&f.st);
        let polled = Arc::new(AtomicBool::new(false));
        let body = watched_chunked(MCP_BODY_LIMIT + 1, polled.clone());
        let got = send(
            &app,
            req(Method::POST, Some(bearer(&f.access).as_slice()), body),
        )
        .await;
        assert_h(&got, StatusCode::PAYLOAD_TOO_LARGE, H4, None);
        assert!(polled.load(Ordering::SeqCst));
    }

    /// One meta acquisition and one lookup per request, no background task
    /// (the throttled touch runs on the lookup's own guard), and no per-IP
    /// bucket on this path.
    #[test]
    fn rs_layer_takes_the_meta_lock_exactly_once() {
        use crate::tenant::rooms::srcpin::{code_only, production_half};
        let stripped = code_only(include_str!("rs_layer.rs"));
        let prod = production_half(&stripped);
        assert_eq!(
            prod.matches(concat!(".lo", "ck()")).count(),
            1,
            "meta lock sites"
        );
        assert!(!prod.contains(concat!("spa", "wn(")), "no background task");
        assert!(prod.contains("find_grant_by_access"), "anti-vacuous");
        assert!(prod.contains("touch_grant_last_used"), "anti-vacuous");
        assert!(
            !prod.contains("access_hash_known"),
            "one lookup per request"
        );
        assert!(
            !prod.contains("rs_miss_ip"),
            "the account endpoint reads no per-IP bucket"
        );
        assert!(!prod.contains("AuditEntry"), "refusals write no audit row");
    }

    /// The bearer is read from the first Authorization value once, and every
    /// credential header is removed before the inner service runs.
    #[test]
    fn rs_layer_reads_authorization_once_and_strips_credentials() {
        use crate::tenant::rooms::srcpin::{code_only, production_half};
        let stripped = code_only(include_str!("rs_layer.rs"));
        let prod = production_half(&stripped);
        assert_eq!(
            prod.matches("header::AUTHORIZATION").count(),
            2,
            "one read, one remove"
        );
        assert!(prod.contains(".get(header::AUTHORIZATION)"));
        for h in [
            "header::AUTHORIZATION",
            "header::COOKIE",
            "header::PROXY_AUTHORIZATION",
        ] {
            assert!(
                prod.contains(&format!(".remove({h})")),
                "{h} is not removed"
            );
        }
    }
}

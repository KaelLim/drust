//! v1.31 query-string-to-header bearer adapter for WS upgrade.
//!
//! Browsers' native WebSocket API cannot set custom headers, so drust
//! accepts the bearer in `?token=<value>`. This middleware rewrites
//! it into `Authorization: Bearer <value>` BEFORE `bearer_auth_layer`
//! runs, then strips the param from the URI so it doesn't reach
//! `tracing` spans / Caddy access logs.
//!
//! Precedence: explicit `Authorization` header wins over `?token=`.
//! Both absent → request passes through unauth; bearer_auth rejects 401.
//! Token with chars `HeaderValue::from_str` rejects (CR/LF/NUL) → silently
//! dropped, falls through to unauth.
//!
//! #976 also puts the two request extensions the realtime faces consume here:
//! [`WsBaselineMeta`] (produced by [`ws_baseline_capture`], mounted INSIDE
//! `bearer_auth_layer` on `ws_router` only) and [`PatDeadline`] (produced by
//! the two admin-PAT resolution arms of `bearer_auth_layer` itself). Both are
//! server-side per-request state — a client cannot set a request extension.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Uri, header};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// #976 F1 — this connection's eviction baseline, captured immediately after
/// bearer auth admitted the request instead of inside the WS handler. The
/// window between the auth DECISION and the capture is what a revocation can
/// fall into and be adopted AS this socket's baseline (fail-OPEN for that one
/// eviction), so the capture may only ever move EARLIER: an older baseline can
/// only over-close. Absence is the fallback contract — the consumer captures
/// inline, i.e. exactly today's behavior.
#[derive(Clone)]
pub struct WsBaselineMeta {
    pub epoch: Arc<AtomicU64>,
    pub epoch0: u64,
}

/// #976 F2 — the authenticated credential's own hard expiry, so a realtime
/// connection cannot outlive it. Inserted ONLY when the bearer resolved to an
/// admin PAT carrying `expires_at`: a user session is SLIDING (snapshotting
/// its expiry would drop a session that is still being renewed) and a tenant
/// bearer never expires. The determination follows the credential FAMILY, not
/// the role.
#[derive(Clone, Copy)]
pub struct PatDeadline(pub chrono::DateTime<chrono::Utc>);

impl PatDeadline {
    /// The expiry on the monotonic clock a `select!` loop can sleep on.
    ///
    /// One conversion shared by both realtime faces (ws.rs branch (d),
    /// sse.rs `take_until`) so its fail direction is decided — and unit-tested
    /// — in exactly one place: a deadline already in the PAST saturates to
    /// `Instant::now()` and fires on the first poll. The plausible wrong
    /// alternatives (`unwrap_or` a far-future duration, or letting the
    /// subtraction underflow) would turn the backstop into a socket that
    /// never expires — fail-OPEN, and silent, because the per-request CTE
    /// already filters expired PATs so nothing in production would notice.
    pub fn instant(&self) -> tokio::time::Instant {
        let dur = (self.0 - chrono::Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        tokio::time::Instant::now() + dur
    }
}

/// #976 F1 — runs INNER of `bearer_auth_layer`, on `ws_router` ONLY, so it is
/// strictly after auth admitted the request: `TenantRef` present ⇒ the tenant
/// id is validated, which is what the `epochs` INSERTING-keyspace rule in
/// bus.rs requires of every `tenant_epoch_handle` caller. Missing `TenantRef`
/// ⇒ insert nothing; the consumer's inline fallback covers it.
///
/// The `RoomBus` reached through `state.bus_rooms` MUST be the same instance
/// as the one `ws_handler`'s `PublishCtx.bus` wraps (in production both clone
/// one `TenantsState.bus_rooms`): a handle taken off a DIFFERENT bus would
/// track a different `epochs` map and never see this tenant's bumps.
pub async fn ws_baseline_capture(
    State(state): State<crate::tenant::router::TenantAuthState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if let Some(tid) = req
        .extensions()
        .get::<crate::tenant::router::TenantRef>()
        .map(|t| t.tenant_id.clone())
    {
        let epoch = state.bus_rooms.tenant_epoch_handle(&tid);
        let epoch0 = epoch.load(Ordering::SeqCst);
        req.extensions_mut()
            .insert(WsBaselineMeta { epoch, epoch0 });
    }
    next.run(req).await
}

pub async fn ws_query_token_adapter(mut req: Request<Body>, next: Next) -> Response {
    let already_has_header = req.headers().contains_key(header::AUTHORIZATION);
    let token = req.uri().query().and_then(extract_token_param);

    if let Some(tok) = token {
        if !already_has_header && let Ok(v) = HeaderValue::from_str(&format!("Bearer {tok}")) {
            req.headers_mut().insert(header::AUTHORIZATION, v);
        }
        // HeaderValue::from_str fails on CR/LF/NUL → drop silently.
        // Strip token= from URI regardless of header precedence so
        // downstream tracing / access logs don't capture it.
        if let Some(new_uri) = strip_query_param(req.uri(), "token") {
            *req.uri_mut() = new_uri;
        }
    }
    next.run(req).await
}

/// Extract `token=…` value from a raw query string. URL-decoded.
fn extract_token_param(query: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some(("token", v)) = pair.split_once('=') {
            return Some(urlencoding::decode(v).ok()?.into_owned());
        }
    }
    None
}

/// Return a new `Uri` with `<key>=…` removed from the query string.
fn strip_query_param(uri: &Uri, key: &str) -> Option<Uri> {
    let q = uri.query()?;
    let kept: Vec<&str> = q
        .split('&')
        .filter(|pair| {
            let name = pair.split_once('=').map(|(n, _)| n).unwrap_or(pair);
            name != key
        })
        .collect();
    let mut parts = uri.clone().into_parts();
    let path = uri.path();
    let pq = if kept.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", kept.join("&"))
    };
    parts.path_and_query = pq.parse().ok();
    Uri::from_parts(parts).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use std::time::Duration;
    use tower::ServiceExt;

    /// Probe: returns the inbound Authorization value (or "none").
    async fn probe_auth(headers: axum::http::HeaderMap) -> String {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none")
            .to_string()
    }

    /// Probe: returns the downstream URI as-seen-by-handler.
    async fn probe_uri(req: Request<Body>) -> String {
        req.uri().to_string()
    }

    fn auth_app() -> Router {
        Router::new()
            .route("/probe", get(probe_auth))
            .layer(axum::middleware::from_fn(ws_query_token_adapter))
    }

    fn uri_app() -> Router {
        Router::new()
            .route("/probe", get(probe_uri))
            .layer(axum::middleware::from_fn(ws_query_token_adapter))
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let b = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        String::from_utf8_lossy(&b).into_owned()
    }

    #[tokio::test]
    async fn query_token_rewritten_to_authorization_header() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/probe?token=drust_service_x")
            .body(Body::empty())
            .unwrap();
        let r = auth_app().oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_string(r).await, "Bearer drust_service_x");
    }

    #[tokio::test]
    async fn header_wins_when_both_present() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/probe?token=drust_anon_q")
            .header("authorization", "Bearer drust_service_h")
            .body(Body::empty())
            .unwrap();
        let r = auth_app().oneshot(req).await.unwrap();
        assert_eq!(body_string(r).await, "Bearer drust_service_h");
    }

    #[tokio::test]
    async fn no_token_no_header_passes_through_unauth() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .body(Body::empty())
            .unwrap();
        let r = auth_app().oneshot(req).await.unwrap();
        assert_eq!(body_string(r).await, "none");
    }

    #[tokio::test]
    async fn token_param_stripped_from_uri_for_downstream() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/probe?token=drust_anon_x&keep=1")
            .body(Body::empty())
            .unwrap();
        let r = uri_app().oneshot(req).await.unwrap();
        let uri = body_string(r).await;
        assert!(!uri.contains("token="), "uri still contains token: {uri}");
        assert!(uri.contains("keep=1"), "kept params dropped: {uri}");
    }

    #[tokio::test]
    async fn token_only_param_strips_to_no_query() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/probe?token=drust_x")
            .body(Body::empty())
            .unwrap();
        let r = uri_app().oneshot(req).await.unwrap();
        let uri = body_string(r).await;
        assert!(!uri.contains('?'), "trailing ? not stripped: {uri}");
    }

    #[tokio::test]
    async fn malformed_token_chars_safely_dropped() {
        // Newline in token → HeaderValue::from_str fails → adapter drops.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/probe?token=bad%0Avalue") // %0A = newline
            .body(Body::empty())
            .unwrap();
        let r = auth_app().oneshot(req).await.unwrap();
        assert_eq!(body_string(r).await, "none");
    }

    /// v1.31.7 regression: the WS sub-router puts `ws_query_token_adapter`
    /// OUTER and the bearer-auth check INNER, so `?token=` is rewritten
    /// into `Authorization` BEFORE auth runs. v1.31.2's F4 fix originally
    /// regressed this by moving the adapter from a router-level outer
    /// layer to a per-route INNER layer — combined with the production
    /// `bearer_auth_layer` being applied at router-level OUTER, every WS
    /// `?token=` upgrade got rejected as `UNAUTHENTICATED` because the
    /// adapter never ran. axum layer ordering: `Router::layer(L)` runs
    /// L OUTSIDE everything in the router (= first); per-route
    /// `MethodRouter::layer(L)` runs L INSIDE the route's call stack
    /// (= AFTER any outer router layer). This test pins both shapes so
    /// the bug class can't silently regress.
    #[tokio::test]
    async fn ws_subrouter_layer_order_lets_query_token_reach_auth() {
        // Synthetic auth check: 401 when no Authorization header.
        async fn fake_auth(
            req: Request<Body>,
            next: axum::middleware::Next,
        ) -> axum::response::Response {
            if req
                .headers()
                .contains_key(axum::http::header::AUTHORIZATION)
            {
                next.run(req).await
            } else {
                (StatusCode::UNAUTHORIZED, "missing bearer").into_response()
            }
        }
        use axum::response::IntoResponse;

        // POST-FIX shape: adapter OUTER + auth INNER on a sub-router.
        // Mirrors the v1.31.7 `ws_router` build in src/tenant/mod.rs.
        let good: Router = Router::new()
            .route("/ws", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(fake_auth))
            .layer(axum::middleware::from_fn(ws_query_token_adapter));
        let resp = good
            .oneshot(
                Request::builder()
                    .uri("/ws?token=svc_xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "post-fix sub-router: ?token= must reach auth as Authorization"
        );

        // PRE-FIX shape (the buggy v1.31.5/6 production shape): per-route
        // adapter INNER + router-level auth OUTER. Auth runs first, sees
        // no Authorization, rejects 401; adapter never gets to rewrite.
        let bad: Router = Router::new()
            .route(
                "/ws",
                get(|| async { "ok" }).layer(axum::middleware::from_fn(ws_query_token_adapter)),
            )
            .layer(axum::middleware::from_fn(fake_auth));
        let resp = bad
            .oneshot(
                Request::builder()
                    .uri("/ws?token=svc_xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "pre-fix shape MUST 401 — confirms the layer-order bug \
             is what we think it is, and that the post-fix shape above \
             is the actual fix, not a coincidence"
        );
    }

    /// #976 — `PatDeadline::instant`'s fail direction, both arms. The ws.rs
    /// duplex tests drive `handle_socket` with a ready-made `Instant` and so
    /// never execute this conversion; these two are what actually pin it.
    #[tokio::test]
    async fn deadline_instant_saturates_a_past_expiry_to_now() {
        let past = PatDeadline(chrono::Utc::now() - chrono::Duration::hours(1));
        assert!(
            past.instant() <= tokio::time::Instant::now(),
            "a PAST expiry must convert to an already-elapsed instant \
             (fires on first poll), never to a future one"
        );
    }

    #[tokio::test]
    async fn deadline_instant_lands_a_future_expiry_at_the_right_offset() {
        let dl = PatDeadline(chrono::Utc::now() + chrono::Duration::seconds(600)).instant();
        let offset = dl - tokio::time::Instant::now();
        assert!(
            offset > Duration::from_secs(590) && offset <= Duration::from_secs(600),
            "a future expiry must land ~its real offset out, got {offset:?}"
        );
    }

    /// #976 — pin the PRODUCTION ws_router layer order in src/tenant/mod.rs.
    ///
    /// The behavioural tests above and in `tests/rooms_ws_capture.rs` build
    /// routers that MIRROR the production order; none reads it. Moving the
    /// `ws_baseline_capture` layer after `bearer_auth_layer` in mod.rs
    /// (= outside auth) would silently disable the capture in production —
    /// fallback behavior, every suite green. Needles run over comment-stripped
    /// source (`srcpin::code_only`) so a commented-out layer line cannot
    /// satisfy the order.
    #[test]
    fn production_ws_router_applies_capture_inside_auth() {
        let src = crate::tenant::rooms::srcpin::code_only(include_str!("../mod.rs"));
        let start = src
            .find("let ws_router")
            .expect("src/tenant/mod.rs must build a `ws_router`");
        let end = src[start..]
            .find(".with_state")
            .map(|i| start + i)
            .expect("ws_router block must end in .with_state");
        let block = &src[start..end];
        let capture = block
            .find("ws_baseline_capture")
            .expect("ws_router must mount ws_baseline_capture");
        let bearer = block
            .find("bearer_auth_layer")
            .expect("ws_router must mount bearer_auth_layer");
        let adapter = block
            .find("ws_query_token_adapter")
            .expect("ws_router must mount ws_query_token_adapter");
        assert!(
            capture < bearer && bearer < adapter,
            "ws_router layer order regressed: capture must be added FIRST \
             (innermost, runs after auth), bearer second, adapter last \
             (outermost) — got offsets capture={capture} bearer={bearer} \
             adapter={adapter}"
        );
    }

    /// v1.31.2 F4 regression: `?token=svc_xxx` on a non-WS / non-SSE route
    /// MUST NOT have its bearer rewritten into the Authorization header.
    /// The adapter was previously layered on the entire per-tenant `core`
    /// router; the fix narrows it to just /realtime + /subscribe.
    #[tokio::test]
    async fn non_ws_route_does_not_get_query_token_rewritten() {
        use axum::routing::post;

        // Router shape mirrors the post-fix `core` shape: adapter mounted
        // ONLY on /ws; a sibling /records route has no layer.
        let app: Router = Router::new().route("/records", post(probe_auth)).route(
            "/ws",
            get(probe_auth).layer(axum::middleware::from_fn(super::ws_query_token_adapter)),
        );

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/records?token=svc_secret_xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "none",
            "POST /records?token=… must NOT see Authorization populated"
        );

        // /ws should still rewrite (adapter is mounted there).
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ws?token=svc_secret_xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "Bearer svc_secret_xyz",
            "GET /ws?token=… must rewrite"
        );
    }
}

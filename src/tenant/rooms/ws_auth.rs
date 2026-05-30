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

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, Uri};
use axum::middleware::Next;
use axum::response::Response;

pub async fn ws_query_token_adapter(mut req: Request<Body>, next: Next) -> Response {
    let already_has_header = req.headers().contains_key(header::AUTHORIZATION);
    let token = req.uri().query().and_then(extract_token_param);

    if let Some(tok) = token {
        if !already_has_header {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {tok}")) {
                req.headers_mut().insert(header::AUTHORIZATION, v);
            }
            // HeaderValue::from_str fails on CR/LF/NUL → drop silently.
        }
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
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
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
        let b = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
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

    /// v1.31.2 F4 regression: `?token=svc_xxx` on a non-WS / non-SSE route
    /// MUST NOT have its bearer rewritten into the Authorization header.
    /// The adapter was previously layered on the entire per-tenant `core`
    /// router; the fix narrows it to just /realtime + /subscribe.
    #[tokio::test]
    async fn non_ws_route_does_not_get_query_token_rewritten() {
        use axum::routing::post;

        // Router shape mirrors the post-fix `core` shape: adapter mounted
        // ONLY on /ws; a sibling /records route has no layer.
        let app: Router = Router::new()
            .route("/records", post(probe_auth))
            .route(
                "/ws",
                get(probe_auth).layer(axum::middleware::from_fn(
                    super::ws_query_token_adapter,
                )),
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

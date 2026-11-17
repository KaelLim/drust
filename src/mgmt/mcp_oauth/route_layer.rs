//! Entry gates for the account-level MCP endpoint: on/off switch, Host, Origin, body limit, SSE buffering header.
//!
//! The production code here writes no log line at all: Host and Origin are
//! caller-controlled strings (pinned by `entry_gates_write_no_log_lines`).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::mgmt::mcp_oauth::config::McpOauthConfig;

/// The largest request body the account-level MCP endpoint reads.
pub(crate) const MCP_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// The refusal shape of the account-level MCP endpoint: a message-first JSON
/// body (`{"message":…,"error_code":…}`, not `json_error`'s code-first one),
/// `Content-Type: application/json` and `Cache-Control: no-store`.
pub(crate) fn mcp_error(status: StatusCode, message: &str, error_code: &str) -> Response {
    let body = serde_json::json!({ "message": message, "error_code": error_code }).to_string();
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The Host check's answer. A missing or malformed Host is `Rejected` (421),
/// never left to rmcp's plain-text 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostVerdict {
    Allowed,
    Rejected,
}

/// rmcp's `normalize_host`: brackets trimmed, ASCII lowercase.
fn normalize(host: &str) -> String {
    host.trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase()
}

/// Whether the request's Host (or, without one, the URI authority) names an
/// entry of `allowed`. The matching rule is rmcp's own (`parse_host_header`,
/// `parse_allowed_authority`, `host_is_allowed` in its streamable HTTP tower
/// service): host compared lowercase without brackets, an entry without a
/// port accepts any port. Three points are stricter than rmcp, so whatever
/// this admits rmcp admits too and an authenticated request never meets
/// rmcp's own Host refusal:
/// - an empty list rejects everything (rmcp admits everything);
/// - an authority carrying userinfo (`x@host`) is rejected (`http` parses it
///   and reads the host after the `@`);
/// - a port segment that is not a valid u16 (`host:99999`, `host:`) is
///   rejected (`http` reads it as "no port").
pub(crate) fn host_verdict(allowed: &[String], headers: &HeaderMap, uri: &Uri) -> HostVerdict {
    if allowed.is_empty() {
        return HostVerdict::Rejected;
    }
    let s = match headers.get(header::HOST) {
        Some(v) => match v.to_str() {
            Ok(s) => s,
            Err(_) => return HostVerdict::Rejected,
        },
        None => match uri.authority() {
            Some(a) => a.as_str(),
            None => return HostVerdict::Rejected,
        },
    };
    if s.contains('@') {
        return HostVerdict::Rejected;
    }
    let Ok(authority) = Authority::try_from(s) else {
        return HostVerdict::Rejected;
    };
    // Without userinfo, `host()` is a prefix of `as_str()` (brackets kept).
    let rest = &authority.as_str()[authority.host().len()..];
    let port = authority.port_u16();
    if !rest.is_empty() && port.is_none() {
        return HostVerdict::Rejected;
    }
    let host = normalize(authority.host());
    let admitted = allowed.iter().any(|e| {
        let e = e.trim();
        if e.is_empty() {
            return false;
        }
        let (h, p) = match Authority::try_from(e) {
            Ok(a) => (normalize(a.host()), a.port_u16()),
            Err(_) => (normalize(e), None),
        };
        h == host && p.is_none_or(|p| Some(p) == port)
    });
    if admitted {
        HostVerdict::Allowed
    } else {
        HostVerdict::Rejected
    }
}

const DISABLED: (&str, &str) = (
    "MCP is disabled on this server; ask the operator (see boot log)",
    "MCP_DISABLED",
);
const HOST_NOT_ALLOWED: (&str, &str) = (
    "proxy must send Host: 127.0.0.1:47826 or the public host",
    "MCP_HOST_NOT_ALLOWED",
);
const ORIGIN_NOT_ALLOWED: (&str, &str) = (
    "browser Origin not allowed; MCP clients send no Origin header",
    "MCP_ORIGIN_NOT_ALLOWED",
);
const BODY_TOO_LARGE: (&str, &str) = ("request body too large for /mcp", "MCP_BODY_TOO_LARGE");

fn refuse(status: StatusCode, (message, code): (&str, &str)) -> Response {
    mcp_error(status, message, code)
}

/// The outermost gate of the account-level MCP endpoint, on every method, in
/// this order: 404 while MCP is disabled (checked first: a disabled config has
/// no public host to compare against), 421 for a Host outside
/// `allowed_hosts()`, 403 when ANY `Origin` value is not UTF-8 or not
/// `origin_allowed` (no Origin passes: MCP clients send none), 413 for a
/// `Content-Length` over [`MCP_BODY_LIMIT`] (an unparseable one is left to
/// [`mcp_body_buffer`]). An event-stream response gets
/// `X-Accel-Buffering: no` so a buffering proxy does not hold it back.
pub(crate) async fn mcp_route_layer(
    State(cfg): State<Arc<McpOauthConfig>>,
    req: Request,
    next: Next,
) -> Response {
    if !cfg.enabled() {
        return refuse(StatusCode::NOT_FOUND, DISABLED);
    }
    if host_verdict(&cfg.allowed_hosts(), req.headers(), req.uri()) == HostVerdict::Rejected {
        return refuse(StatusCode::MISDIRECTED_REQUEST, HOST_NOT_ALLOWED);
    }
    let foreign_origin = req
        .headers()
        .get_all(header::ORIGIN)
        .iter()
        .any(|v| v.to_str().map_or(true, |s| !cfg.origin_allowed(s)));
    if foreign_origin {
        return refuse(StatusCode::FORBIDDEN, ORIGIN_NOT_ALLOWED);
    }
    let declared_too_large = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| n > MCP_BODY_LIMIT as u64);
    if declared_too_large {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, BODY_TOO_LARGE);
    }
    let mut resp = next.run(req).await;
    let event_stream = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            let essence = ct.split(';').next().unwrap_or("").trim();
            essence.eq_ignore_ascii_case("text/event-stream")
        });
    if event_stream {
        resp.headers_mut().insert(
            HeaderName::from_static("x-accel-buffering"),
            HeaderValue::from_static("no"),
        );
    }
    resp
}

/// Buffers the whole body, at most [`MCP_BODY_LIMIT`] bytes, before the MCP
/// service sees it; a larger (chunked) body answers 413. Mounted INSIDE the
/// bearer layer, so an unauthenticated request is never read, and outside
/// rmcp, which would otherwise answer an oversize body with a plain-text 500.
/// Headers are left untouched.
pub(crate) async fn mcp_body_buffer(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    match axum::body::to_bytes(body, MCP_BODY_LIMIT).await {
        Ok(bytes) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        // Over the limit is the only failure a client can still read an answer
        // to; a connection that broke mid-body sees none.
        Err(_) => refuse(StatusCode::PAYLOAD_TOO_LARGE, BODY_TOO_LARGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::config::McpOauthConfig;
    use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header};
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    };
    use std::sync::Arc;

    fn allowed() -> Vec<String> {
        McpOauthConfig::for_tests("https://drust.test").allowed_hosts()
    }

    fn headers_with_host(host: Option<&[u8]>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(b) = host {
            h.insert(header::HOST, HeaderValue::from_bytes(b).unwrap());
        }
        h
    }

    /// (Host header bytes, request URI, expected verdict). `allowed()` is
    /// ["localhost", "127.0.0.1", "::1", "drust.test"].
    const HOSTS: &[(Option<&[u8]>, &str, HostVerdict)] = &[
        (Some(b"127.0.0.1:47826"), "/mcp", HostVerdict::Allowed),
        (Some(b"127.0.0.1"), "/mcp", HostVerdict::Allowed),
        (Some(b"localhost"), "/mcp", HostVerdict::Allowed),
        (Some(b"LOCALHOST:8080"), "/mcp", HostVerdict::Allowed),
        (Some(b"[::1]:47826"), "/mcp", HostVerdict::Allowed),
        (Some(b"[::1]"), "/mcp", HostVerdict::Allowed),
        (Some(b"drust.test"), "/mcp", HostVerdict::Allowed),
        (Some(b"drust.test:443"), "/mcp", HostVerdict::Allowed),
        (Some(b"Drust.Test:8443"), "/mcp", HostVerdict::Allowed),
        (None, "http://127.0.0.1:47826/mcp", HostVerdict::Allowed),
        (Some(b"evil.example"), "/mcp", HostVerdict::Rejected),
        (
            Some(b"drust.test.evil.example"),
            "/mcp",
            HostVerdict::Rejected,
        ),
        (Some(b"evil.drust.test"), "/mcp", HostVerdict::Rejected),
        (Some(b"drust.test."), "/mcp", HostVerdict::Rejected),
        (Some(b"x@127.0.0.1"), "/mcp", HostVerdict::Rejected),
        (Some(b"127.0.0.1:99999"), "/mcp", HostVerdict::Rejected),
        (Some(b"127.0.0.1:"), "/mcp", HostVerdict::Rejected),
        (Some(b"127.1"), "/mcp", HostVerdict::Rejected),
        (Some(b"0x7f.0.0.1"), "/mcp", HostVerdict::Rejected),
        (Some(b"[::ffff:127.0.0.1]"), "/mcp", HostVerdict::Rejected),
        (Some(b"[::1%25lo]:1"), "/mcp", HostVerdict::Rejected),
        (Some(b"localhost%00"), "/mcp", HostVerdict::Rejected),
        (Some(b"local\thost"), "/mcp", HostVerdict::Rejected),
        (Some(b""), "/mcp", HostVerdict::Rejected),
        (Some(b"bad host"), "/mcp", HostVerdict::Rejected),
        (Some(b"[::1"), "/mcp", HostVerdict::Rejected),
        (Some(b"\xffhost"), "/mcp", HostVerdict::Rejected),
        (None, "/mcp", HostVerdict::Rejected),
        (None, "http://x@127.0.0.1/mcp", HostVerdict::Rejected),
    ];

    #[test]
    fn host_verdict_table() {
        let a = allowed();
        for (host, uri, want) in HOSTS {
            let got = host_verdict(&a, &headers_with_host(*host), &uri.parse::<Uri>().unwrap());
            assert_eq!(
                got,
                *want,
                "Host {:?} uri {uri}",
                host.map(String::from_utf8_lossy)
            );
        }
    }

    #[test]
    fn host_verdict_rejects_everything_with_an_empty_list() {
        let h = headers_with_host(Some(b"127.0.0.1:47826"));
        assert_eq!(
            host_verdict(&[], &h, &"/mcp".parse().unwrap()),
            HostVerdict::Rejected
        );
    }

    #[derive(Clone)]
    struct Probe;
    impl rmcp::ServerHandler for Probe {}

    /// The same cases go through a real stateless rmcp service configured with
    /// the same list. GET is used because stateless rmcp answers 405 for it only
    /// AFTER its Host check passed: 400/403 mean "refused".
    #[tokio::test]
    async fn host_verdict_never_allows_what_rmcp_refuses() {
        let a = allowed();
        let svc = StreamableHttpService::new(
            || Ok(Probe),
            Arc::new(NeverSessionManager::default()),
            StreamableHttpServerConfig::default()
                .with_stateful_mode(false)
                .with_allowed_hosts(a.clone()),
        );
        let mut allowed_cases = 0;
        for (host, uri, _) in HOSTS {
            let mut b = Request::builder().method(Method::GET).uri(*uri);
            if let Some(bytes) = host {
                b = b.header(header::HOST, HeaderValue::from_bytes(bytes).unwrap());
            }
            let req = b.body(axum::body::Body::empty()).unwrap();
            let drust = host_verdict(&a, req.headers(), req.uri());
            let status = svc.handle(req).await.status();
            if drust == HostVerdict::Allowed {
                allowed_cases += 1;
                assert_eq!(
                    status,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "rmcp refused {host:?} {uri}"
                );
            }
            if status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST {
                assert_eq!(drust, HostVerdict::Rejected, "drust allowed {host:?} {uri}");
            }
        }
        assert!(
            allowed_cases >= 10,
            "only {allowed_cases} allowed cases exercised"
        );
    }

    #[tokio::test]
    async fn mcp_error_body_is_message_first_and_not_cacheable() {
        let resp = mcp_error(StatusCode::IM_A_TEAPOT, "m \"q\" -> x", "SOME_CODE");
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            br#"{"message":"m \"q\" -> x","error_code":"SOME_CODE"}"#
        );
    }

    #[test]
    fn body_limit_is_sixteen_mebibytes() {
        assert_eq!(MCP_BODY_LIMIT, 16_777_216);
    }

    use axum::Router;
    use axum::body::Body;
    use axum::middleware::{from_fn, from_fn_with_state};
    use axum::response::IntoResponse;
    use axum::routing::any;

    const H1: &[u8] = br#"{"message":"MCP is disabled on this server; ask the operator (see boot log)","error_code":"MCP_DISABLED"}"#;
    const H2: &[u8] = br#"{"message":"proxy must send Host: 127.0.0.1:47826 or the public host","error_code":"MCP_HOST_NOT_ALLOWED"}"#;
    const H3: &[u8] = br#"{"message":"browser Origin not allowed; MCP clients send no Origin header","error_code":"MCP_ORIGIN_NOT_ALLOWED"}"#;
    const H4: &[u8] =
        br#"{"message":"request body too large for /mcp","error_code":"MCP_BODY_TOO_LARGE"}"#;

    /// `/mcp` echoes the received body length; `/sse` answers an event stream.
    /// Layer order = the order the account router uses, minus the bearer layer.
    fn gate_app(cfg: McpOauthConfig) -> Router {
        Router::new()
            .route(
                "/mcp",
                any(|req: Request<Body>| async move {
                    let n = axum::body::to_bytes(req.into_body(), usize::MAX)
                        .await
                        .unwrap()
                        .len();
                    axum::Json(serde_json::json!({ "len": n })).into_response()
                }),
            )
            .route(
                "/sse",
                any(|| async {
                    ([(header::CONTENT_TYPE, "text/event-stream")], "data: x\n\n").into_response()
                }),
            )
            .route(
                "/sse2",
                any(|| async {
                    (
                        [(header::CONTENT_TYPE, "Text/Event-Stream; charset=utf-8")],
                        "data: x\n\n",
                    )
                        .into_response()
                }),
            )
            .layer(from_fn(mcp_body_buffer))
            .layer(from_fn_with_state(Arc::new(cfg), mcp_route_layer))
    }

    fn on() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }

    fn req(
        method: Method,
        path: &str,
        host: &str,
        extra: &[(&str, &[u8])],
        body: Body,
    ) -> Request<Body> {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, host);
        for (k, v) in extra {
            b = b.header(*k, HeaderValue::from_bytes(v).unwrap());
        }
        b.body(body).unwrap()
    }

    async fn send(app: &Router, r: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        use tower::ServiceExt;
        let resp = app.clone().oneshot(r).await.unwrap();
        let (s, h) = (resp.status(), resp.headers().clone());
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (s, h, b)
    }

    fn assert_refusal(got: &(StatusCode, HeaderMap, Vec<u8>), status: StatusCode, body: &[u8]) {
        assert_eq!(got.0, status);
        assert_eq!(got.2, body, "{}", String::from_utf8_lossy(&got.2));
        assert_eq!(got.1[header::CONTENT_TYPE], "application/json");
        assert_eq!(got.1[header::CACHE_CONTROL], "no-store");
        assert!(got.1.get(header::WWW_AUTHENTICATE).is_none());
    }

    const METHODS: [Method; 5] = [
        Method::POST,
        Method::GET,
        Method::DELETE,
        Method::OPTIONS,
        Method::PUT,
    ];

    fn chunked(total: usize) -> Body {
        let chunk = 1 << 20;
        let parts: Vec<Result<bytes::Bytes, std::io::Error>> = (0..total.div_ceil(chunk))
            .map(|i| Ok(bytes::Bytes::from(vec![b'x'; chunk.min(total - i * chunk)])))
            .collect();
        Body::from_stream(futures::stream::iter(parts))
    }

    #[tokio::test]
    async fn disabled_answers_h1_on_every_method() {
        let app = gate_app(McpOauthConfig::disabled());
        for m in METHODS {
            // A bad Host does not matter while disabled: the switch is checked first.
            for host in ["127.0.0.1:47826", "evil.example"] {
                let got = send(&app, req(m.clone(), "/mcp", host, &[], Body::empty())).await;
                assert_refusal(&got, StatusCode::NOT_FOUND, H1);
            }
        }
    }

    #[tokio::test]
    async fn bad_host_answers_h2_on_every_method() {
        let app = gate_app(on());
        for m in METHODS {
            let got = send(
                &app,
                req(m.clone(), "/mcp", "evil.example", &[], Body::empty()),
            )
            .await;
            assert_refusal(&got, StatusCode::MISDIRECTED_REQUEST, H2);
        }
        let got = send(
            &app,
            req(Method::POST, "/mcp", "drust.test", &[], Body::empty()),
        )
        .await;
        assert_eq!(got.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn foreign_origin_answers_h3() {
        let app = gate_app(on());
        let got = send(
            &app,
            req(
                Method::POST,
                "/mcp",
                "127.0.0.1:47826",
                &[("origin", &b"https://evil.example"[..])],
                Body::empty(),
            ),
        )
        .await;
        assert_refusal(&got, StatusCode::FORBIDDEN, H3);
    }

    #[tokio::test]
    async fn missing_or_allowed_origin_passes() {
        let app = gate_app(on());
        for origin in [
            None,
            Some(&b"https://drust.test"[..]),
            Some(&b"http://localhost:5173"[..]),
            Some(&b"http://127.0.0.1:9"[..]),
            Some(&b"http://[::1]:3000"[..]),
        ] {
            let extra: Vec<(&str, &[u8])> = origin.map(|o| ("origin", o)).into_iter().collect();
            let got = send(
                &app,
                req(
                    Method::POST,
                    "/mcp",
                    "127.0.0.1:47826",
                    &extra,
                    Body::empty(),
                ),
            )
            .await;
            assert_eq!(got.0, StatusCode::OK, "origin {origin:?}");
        }
    }

    #[tokio::test]
    async fn null_non_utf8_or_mixed_origins_answer_h3() {
        let app = gate_app(on());
        for bad in [&b"null"[..], &b"\xffx"[..]] {
            let got = send(
                &app,
                req(
                    Method::POST,
                    "/mcp",
                    "127.0.0.1:47826",
                    &[("origin", bad)],
                    Body::empty(),
                ),
            )
            .await;
            assert_refusal(&got, StatusCode::FORBIDDEN, H3);
        }
        let got = send(
            &app,
            req(
                Method::POST,
                "/mcp",
                "127.0.0.1:47826",
                &[
                    ("origin", &b"https://drust.test"[..]),
                    ("origin", &b"https://evil.example"[..]),
                ],
                Body::empty(),
            ),
        )
        .await;
        assert_refusal(&got, StatusCode::FORBIDDEN, H3);
    }

    #[tokio::test]
    async fn content_length_over_limit_answers_h4_before_anything_reads_the_body() {
        let app = gate_app(on());
        let got = send(
            &app,
            req(
                Method::POST,
                "/mcp",
                "127.0.0.1:47826",
                &[("content-length", &b"16777217"[..])],
                Body::empty(),
            ),
        )
        .await;
        assert_refusal(&got, StatusCode::PAYLOAD_TOO_LARGE, H4);
    }

    #[tokio::test]
    async fn content_length_at_limit_or_unparseable_is_left_to_the_buffer() {
        let app = gate_app(on());
        for cl in [&b"16777216"[..], &b"abc"[..]] {
            let got = send(
                &app,
                req(
                    Method::POST,
                    "/mcp",
                    "127.0.0.1:47826",
                    &[("content-length", cl)],
                    Body::empty(),
                ),
            )
            .await;
            assert_eq!(
                got.0,
                StatusCode::OK,
                "content-length {:?}",
                String::from_utf8_lossy(cl)
            );
        }
    }

    #[tokio::test]
    async fn gates_apply_in_order() {
        // switch > Host > Origin > Content-Length
        let all_bad: &[(&str, &[u8])] = &[
            ("origin", &b"https://evil.example"[..]),
            ("content-length", &b"99999999"[..]),
        ];
        let d = send(
            &gate_app(McpOauthConfig::disabled()),
            req(Method::POST, "/mcp", "evil.example", all_bad, Body::empty()),
        )
        .await;
        assert_refusal(&d, StatusCode::NOT_FOUND, H1);
        let app = gate_app(on());
        let h = send(
            &app,
            req(Method::POST, "/mcp", "evil.example", all_bad, Body::empty()),
        )
        .await;
        assert_refusal(&h, StatusCode::MISDIRECTED_REQUEST, H2);
        let o = send(
            &app,
            req(
                Method::POST,
                "/mcp",
                "127.0.0.1:47826",
                all_bad,
                Body::empty(),
            ),
        )
        .await;
        assert_refusal(&o, StatusCode::FORBIDDEN, H3);
    }

    #[tokio::test]
    async fn sse_responses_get_x_accel_buffering_and_json_does_not() {
        let app = gate_app(on());
        for path in ["/sse", "/sse2"] {
            let got = send(
                &app,
                req(Method::POST, path, "127.0.0.1:47826", &[], Body::empty()),
            )
            .await;
            assert_eq!(got.1["x-accel-buffering"], "no", "{path}");
        }
        let got = send(
            &app,
            req(Method::POST, "/mcp", "127.0.0.1:47826", &[], Body::empty()),
        )
        .await;
        assert!(got.1.get("x-accel-buffering").is_none());
    }

    #[tokio::test]
    async fn chunked_body_over_limit_answers_h4_from_the_buffer() {
        let app = gate_app(on());
        let got = send(
            &app,
            req(
                Method::POST,
                "/mcp",
                "127.0.0.1:47826",
                &[],
                chunked(MCP_BODY_LIMIT + 1),
            ),
        )
        .await;
        assert_refusal(&got, StatusCode::PAYLOAD_TOO_LARGE, H4);
    }

    #[tokio::test]
    async fn chunked_body_at_limit_reaches_the_handler_whole() {
        let app = gate_app(on());
        let got = send(
            &app,
            req(
                Method::POST,
                "/mcp",
                "127.0.0.1:47826",
                &[],
                chunked(MCP_BODY_LIMIT),
            ),
        )
        .await;
        assert_eq!(got.0, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&got.2).unwrap();
        assert_eq!(v["len"], MCP_BODY_LIMIT);
    }
}

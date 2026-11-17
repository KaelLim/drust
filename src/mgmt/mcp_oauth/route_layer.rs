//! Entry gates for the account-level MCP endpoint: on/off switch, Host, Origin, body limit, SSE buffering header.
//!
//! The production code here writes no log line at all: Host and Origin are
//! caller-controlled strings (pinned by `entry_gates_write_no_log_lines`).

use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

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
}

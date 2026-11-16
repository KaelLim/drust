//! OAuth JSON errors for `/oauth/token` and `/oauth/revoke` (MA0-PLAN §3.6).
//!
//! `OAuthError` is the only way these two routes emit an error as-is: its
//! response carries the module-private `OAuthErrorMark`, and `oauth_error_layer`
//! rewrites every other non-2xx — axum's 405, the body-limit 413, extractor
//! rejections, and any JSON error that did not come from `OAuthError` — so an
//! internal error string can never reach the unauthenticated caller.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The scheme of the `Authorization` header a client sent, so the 401's
/// `WWW-Authenticate` matches it (OAuth 2.1 §3.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthScheme {
    Basic,
    Bearer,
}

/// Stamped on every response built by `OAuthError::into_response`. Private to
/// this module, so nothing else can mint it: "already an OAuth error" is decided
/// by construction, never by sniffing Content-Type. It lives only in the
/// in-process `http::Response` extensions and never reaches the wire.
#[derive(Clone, Copy)]
struct OAuthErrorMark;

#[derive(Debug)]
pub enum OAuthError {
    InvalidRequest,
    /// No `Authorization` header was sent: 400.
    InvalidClient,
    /// The client sent an `Authorization` header (drust supports only `none`):
    /// 401 with a matching-scheme `WWW-Authenticate`.
    InvalidClientHeader {
        scheme: ClientAuthScheme,
    },
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    InvalidTarget,
    TemporarilyUnavailable {
        retry_after_secs: u64,
    },
    ServerError,
}

impl OAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient | Self::InvalidClientHeader { .. } => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::TemporarilyUnavailable { .. } => "temporarily_unavailable",
            Self::ServerError => "server_error",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidClientHeader { .. } => StatusCode::UNAUTHORIZED,
            Self::TemporarilyUnavailable { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        // error_description deliberately omitted: protocol strings never go
        // through i18n and never carry caller input, SQL or internal error text.
        let mut resp = (
            self.status(),
            axum::Json(serde_json::json!({ "error": self.code() })),
        )
            .into_response();
        resp.extensions_mut().insert(OAuthErrorMark);
        let h = resp.headers_mut();
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        match self {
            Self::TemporarilyUnavailable { retry_after_secs } => {
                h.insert(
                    header::RETRY_AFTER,
                    HeaderValue::from(retry_after_secs.max(1)),
                );
            }
            Self::InvalidClientHeader { scheme } => {
                h.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(match scheme {
                        ClientAuthScheme::Basic => r#"Basic realm="drust-oauth""#,
                        ClientAuthScheme::Bearer => r#"Bearer realm="drust-oauth""#,
                    }),
                );
            }
            _ => {}
        }
        resp
    }
}

/// Outermost on `/oauth/token` and `/oauth/revoke` (mounted with `route_layer`,
/// see `mod.rs`). Every non-2xx that `OAuthError` did not build becomes OAuth
/// JSON; every response gets `Cache-Control: no-store`.
pub async fn oauth_error_layer(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    let st = resp.status();
    let marked = resp.extensions().get::<OAuthErrorMark>().is_some();
    let mut resp = if st.is_success() || (marked && !st.is_redirection()) {
        resp
    } else {
        rewrite(resp)
    };
    // `insert` replaces any value a handler set: these responses are never cacheable.
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The original body and every original header (`Location` included) are
/// dropped; only `Retry-After` is carried over, into a fresh `OAuthError`.
fn rewrite(orig: Response) -> Response {
    let st = orig.status();
    let (status, err) = match st.as_u16() {
        429 => (
            st,
            OAuthError::TemporarilyUnavailable {
                retry_after_secs: retry_after(orig.headers()).unwrap_or(1),
            },
        ),
        // 400/404/405/413/415/422 and any other 4xx keep their status.
        400..=499 => (st, OAuthError::InvalidRequest),
        // 5xx, and 3xx / 1xx, which these paths must never emit.
        _ => {
            tracing::error!(
                status = %st,
                "oauth endpoint produced a non-OAuth response; rewritten to server_error"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, OAuthError::ServerError)
        }
    };
    let mut out = err.into_response();
    *out.status_mut() = status;
    // No `Allow` copy: on a 405 the layer never sees one. axum's top-level route
    // future adds `Allow` AFTER this layer returns, and only when absent;
    // `rewrites_405_and_allow_still_arrives` pins the end result.
    out
}

fn retry_after(h: &HeaderMap) -> Option<u64> {
    h.get(header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::middleware::from_fn;
    use axum::routing::post;
    use tower::ServiceExt;

    fn all_variants() -> Vec<OAuthError> {
        vec![
            OAuthError::InvalidRequest,
            OAuthError::InvalidClient,
            OAuthError::InvalidClientHeader {
                scheme: ClientAuthScheme::Basic,
            },
            OAuthError::InvalidClientHeader {
                scheme: ClientAuthScheme::Bearer,
            },
            OAuthError::InvalidGrant,
            OAuthError::UnauthorizedClient,
            OAuthError::UnsupportedGrantType,
            OAuthError::InvalidScope,
            OAuthError::InvalidTarget,
            OAuthError::TemporarilyUnavailable {
                retry_after_secs: 7,
            },
            OAuthError::ServerError,
        ]
    }

    async fn body_bytes(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    fn header(resp: &Response, name: header::HeaderName) -> Option<&str> {
        resp.headers().get(name).map(|v| v.to_str().unwrap())
    }

    async fn assert_shape(resp: Response, status: StatusCode, code: &str, ctx: &str) -> HeaderMap {
        assert_eq!(resp.status(), status, "{ctx}: status");
        assert_eq!(
            header(&resp, header::CONTENT_TYPE),
            Some("application/json"),
            "{ctx}: content-type"
        );
        assert_eq!(
            header(&resp, header::CACHE_CONTROL),
            Some("no-store"),
            "{ctx}: cache-control"
        );
        assert!(
            resp.headers().get(header::LOCATION).is_none(),
            "{ctx}: location"
        );
        let headers = resp.headers().clone();
        let body = body_bytes(resp).await;
        assert_eq!(
            body,
            format!(r#"{{"error":"{code}"}}"#).into_bytes(),
            "{ctx}: body"
        );
        headers
    }

    #[tokio::test]
    async fn every_variant_has_its_status_and_code() {
        let table: Vec<(OAuthError, u16, &str, Option<&str>)> = vec![
            (OAuthError::InvalidRequest, 400, "invalid_request", None),
            (OAuthError::InvalidClient, 400, "invalid_client", None),
            (
                OAuthError::InvalidClientHeader {
                    scheme: ClientAuthScheme::Basic,
                },
                401,
                "invalid_client",
                Some(r#"Basic realm="drust-oauth""#),
            ),
            (
                OAuthError::InvalidClientHeader {
                    scheme: ClientAuthScheme::Bearer,
                },
                401,
                "invalid_client",
                Some(r#"Bearer realm="drust-oauth""#),
            ),
            (OAuthError::InvalidGrant, 400, "invalid_grant", None),
            (
                OAuthError::UnauthorizedClient,
                400,
                "unauthorized_client",
                None,
            ),
            (
                OAuthError::UnsupportedGrantType,
                400,
                "unsupported_grant_type",
                None,
            ),
            (OAuthError::InvalidScope, 400, "invalid_scope", None),
            (OAuthError::InvalidTarget, 400, "invalid_target", None),
            (
                OAuthError::TemporarilyUnavailable {
                    retry_after_secs: 7,
                },
                429,
                "temporarily_unavailable",
                None,
            ),
            (OAuthError::ServerError, 500, "server_error", None),
        ];
        for (err, status, code, www) in table {
            let ctx = format!("{err:?}");
            let is_429 = matches!(err, OAuthError::TemporarilyUnavailable { .. });
            let h = assert_shape(
                err.into_response(),
                StatusCode::from_u16(status).unwrap(),
                code,
                &ctx,
            )
            .await;
            assert_eq!(
                h.get(header::WWW_AUTHENTICATE).map(|v| v.to_str().unwrap()),
                www,
                "{ctx}: www-authenticate"
            );
            if is_429 {
                assert_eq!(h.get(header::RETRY_AFTER).unwrap(), "7", "{ctx}");
            } else {
                assert!(h.get(header::RETRY_AFTER).is_none(), "{ctx}: retry-after");
            }
        }
    }

    #[test]
    fn retry_after_is_at_least_one() {
        let resp = OAuthError::TemporarilyUnavailable {
            retry_after_secs: 0,
        }
        .into_response();
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }

    #[test]
    fn every_code_is_in_the_oauth_charset() {
        // OAuth 2.1 §3.2.4: %x20-21 / %x23-5B / %x5D-7E.
        for err in all_variants() {
            for b in err.code().bytes() {
                assert!(
                    matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E),
                    "{err:?}: byte {b:#x}"
                );
            }
        }
    }

    #[test]
    fn every_variant_carries_the_mark() {
        for err in all_variants() {
            let ctx = format!("{err:?}");
            let resp = err.into_response();
            assert!(resp.extensions().get::<OAuthErrorMark>().is_some(), "{ctx}");
        }
    }

    // ─── the layer, driven through a router exactly as mod.rs mounts it ───

    async fn through_layer<H, T>(handler: H, method: &str) -> Response
    where
        H: axum::handler::Handler<T, ()>,
        T: 'static,
    {
        let app = Router::new()
            .route("/x", post(handler))
            .route_layer(from_fn(oauth_error_layer));
        app.oneshot(
            Request::builder()
                .method(method)
                .uri("/x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn rewrites_plain_text_client_errors_keeping_the_status() {
        for st in [400u16, 403, 404, 408, 413, 415, 422, 401, 411] {
            let status = StatusCode::from_u16(st).unwrap();
            let resp = through_layer(move || async move { (status, "x") }, "POST").await;
            assert_shape(resp, status, "invalid_request", &format!("{st}")).await;
        }
    }

    /// A 401 that `OAuthError` did not build (say, from an auth layer added
    /// later) keeps its status but becomes `invalid_request`, and every one of
    /// its headers is dropped, `WWW-Authenticate` included: only
    /// `InvalidClientHeader` ever answers `invalid_client` with a challenge.
    #[tokio::test]
    async fn an_unmarked_401_becomes_invalid_request_without_its_challenge() {
        let resp = through_layer(
            || async {
                (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, r#"Basic realm="elsewhere""#)],
                    "no",
                )
            },
            "POST",
        )
        .await;
        let h = assert_shape(
            resp,
            StatusCode::UNAUTHORIZED,
            "invalid_request",
            "unmarked 401",
        )
        .await;
        assert!(
            h.get(header::WWW_AUTHENTICATE).is_none(),
            "challenge dropped"
        );
    }

    #[tokio::test]
    async fn rewrites_server_errors_to_500() {
        for (st, body) in [(500u16, "boom"), (502, ""), (503, "")] {
            let status = StatusCode::from_u16(st).unwrap();
            let resp = through_layer(move || async move { (status, body) }, "POST").await;
            assert_shape(
                resp,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("{st}"),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn rewrites_a_redirect_and_drops_location() {
        let resp = through_layer(
            || async {
                (
                    StatusCode::SEE_OTHER,
                    [(header::LOCATION, "https://x.invalid/")],
                )
            },
            "POST",
        )
        .await;
        assert_shape(
            resp,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "303",
        )
        .await;
    }

    #[tokio::test]
    async fn keeps_retry_after_on_429() {
        let resp = through_layer(
            || async {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, "7")],
                    "slow",
                )
            },
            "POST",
        )
        .await;
        let h = assert_shape(
            resp,
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "429",
        )
        .await;
        assert_eq!(h.get(header::RETRY_AFTER).unwrap(), "7");
    }

    #[tokio::test]
    async fn rewrites_405_and_allow_still_arrives() {
        let resp = through_layer(|| async { StatusCode::OK }, "GET").await;
        // The JSON body proves route_layer wrapped the MethodRouter's own 405.
        // `Allow` is added by axum's top-level route future OUTSIDE the layer;
        // if a future axum hands it to the inner fallback, `rewrite` drops it and
        // this assertion goes red — copy it there then.
        let h = assert_shape(
            resp,
            StatusCode::METHOD_NOT_ALLOWED,
            "invalid_request",
            "405",
        )
        .await;
        assert_eq!(h.get(header::ALLOW).unwrap(), "POST");
    }

    #[tokio::test]
    async fn passes_oauth_json_through() {
        let resp = through_layer(|| async { OAuthError::InvalidGrant }, "POST").await;
        assert_shape(
            resp,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "invalid_grant",
        )
        .await;
    }

    #[tokio::test]
    async fn rewrites_unmarked_json_errors() {
        let resp = through_layer(
            || async {
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(
                        serde_json::json!({"error_code": "X", "message": "internal detail"}),
                    ),
                )
            },
            "POST",
        )
        .await;
        assert_shape(
            resp,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "error_code json",
        )
        .await;

        // Looks like OAuth, but was not built by OAuthError: no mark, rewritten.
        let resp = through_layer(
            || async {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({"error": "invalid_grant"})),
                )
            },
            "POST",
        )
        .await;
        assert_shape(
            resp,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "hand-written oauth json",
        )
        .await;
    }

    #[tokio::test]
    async fn adds_no_store_to_success() {
        let resp = through_layer(|| async { (StatusCode::OK, "") }, "POST").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, header::CACHE_CONTROL), Some("no-store"));
        assert!(body_bytes(resp).await.is_empty());
    }

    #[tokio::test]
    async fn overrides_a_cacheable_success() {
        let resp = through_layer(
            || async {
                (
                    StatusCode::OK,
                    [(header::CACHE_CONTROL, "public, max-age=60")],
                    "",
                )
            },
            "POST",
        )
        .await;
        let values: Vec<_> = resp
            .headers()
            .get_all(header::CACHE_CONTROL)
            .iter()
            .collect();
        assert_eq!(values, vec!["no-store"]);
    }
}

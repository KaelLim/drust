//! v1.58 P1-11 — deny framing of the admin plane.
//!
//! `/admin/*` and `/login` carry one-click destructive actions, so a
//! cross-origin iframe plus an overlay is enough to steal a reroll or a delete.
//! Two headers because they cover different browser generations, and because
//! `X-Frame-Options` still wins in some engines that ignore CSP3 for framing.
//!
//! Deliberately NOT applied to:
//!   * the tenant data plane — it is an API for third-party frontends;
//!   * `/public/*` — that never reaches drust (Caddy proxies straight to
//!     Garage), and a tenant embedding its own SVG in an iframe is legitimate.
//!
//! The CSP header is set `if_not_present` so it cannot clobber the sandbox CSP
//! that `storage::files::insert_content_type_headers` puts on
//! `/admin/files/{key}/bytes` and the signed-bytes routes. Losing that sandbox
//! would reopen the same-origin stored-XSS hole (`SANDBOX_CSP`), which is a far
//! worse trade than a byte response missing `frame-ancestors` — and those
//! responses still get `X-Frame-Options: DENY`, which is set unconditionally
//! because denying a frame around a byte response is correct too.

use axum::http::{HeaderName, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

/// Wrap `r` so every response it produces refuses to be framed.
///
/// Applied to the mgmt router as a whole (see `routes.rs`), never to the
/// merged app in `main.rs` — that would catch the tenant data plane too.
pub fn frame_guard_layers<S>(r: axum::Router<S>) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    r.layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("frame-ancestors 'none'"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    ))
}

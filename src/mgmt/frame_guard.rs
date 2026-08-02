//! v1.58 P1-11 — deny framing of the admin plane.
//!
//! `/admin/*` and `/login` carry one-click destructive actions, so a
//! cross-origin iframe plus an overlay is enough to steal a reroll or a delete.
//! Two headers because they cover different browser generations, and because
//! `X-Frame-Options` still wins in some engines that ignore CSP3 for framing.
//!
//! Deliberately NOT applied to:
//!   * the tenant data plane — it is an API for third-party frontends;
//!   * `/s/t/{tenant}/{key}` — the tenant half of the signed-bytes pair. A
//!     tenant mints those URLs for its own assets via `POST
//!     /t/{id}/files/{key}/sign` and may legitimately put one in an `<iframe>`
//!     or `<object>`, which `X-Frame-Options: DENY` would break. Guarding it
//!     would also buy nothing: a byte response carries no same-origin admin
//!     action to hijack, and a markup one is already pinned to an opaque
//!     origin with scripts and forms off by `SANDBOX_CSP`. The admin half,
//!     `/s/admin/{key}`, stays inside the guard — same inert-bytes argument,
//!     but it is admin-owned and has no cross-origin embedder to break;
//!   * `/public/*` — that never reaches drust (Caddy proxies straight to
//!     Garage), and a tenant embedding its own SVG in an iframe is legitimate.
//!
//! The CSP header is set `if_not_present` so it cannot clobber the sandbox CSP
//! that `storage::files::insert_content_type_headers` puts on
//! `/admin/files/{key}/bytes` and `/s/admin/{key}`. Losing that sandbox
//! would reopen the same-origin stored-XSS hole (`SANDBOX_CSP`), which is a far
//! worse trade than a byte response missing `frame-ancestors` — and those
//! responses still get `X-Frame-Options: DENY`, which is set unconditionally
//! because denying a frame around a byte response is correct too.

use axum::http::{HeaderName, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

/// Wrap `r` so every response it produces refuses to be framed.
///
/// Applied to the admin-plane sub-routers in `routes.rs`, never to the merged
/// app in `main.rs` — that would catch the tenant data plane too. The exclusion
/// list above is enforced by where the call site puts the `.merge`, so a new
/// sub-router is guarded by default and opting one out is a visible edit.
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

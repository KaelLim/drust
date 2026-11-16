//! `GET /oauth/authorize` (MA0-PLAN §3.8.3, §3.6).
//!
//! Writes nothing, takes no lock, is not rate-limited and writes no audit row:
//! the whole cost is parameter checks, one HMAC and one `Set-Cookie`.
//!
//! Error split: before the client and its `redirect_uri` are validated, every
//! failure is an HTML error page (400, no `Location`, no `Set-Cookie`) — an
//! unvalidated redirect must never be followed. After that, every failure is a
//! 303 back to the validated `redirect_uri` with `error`, an ASCII
//! `error_description`, `state` (only when sent) and `iss`. Mounted OUTSIDE
//! `oauth_error_layer`, which would rewrite both shapes into OAuth JSON.
//!
//! `prompt` is always ignored (drust is not an OpenID provider; consent is
//! shown every time), and so is every unknown parameter (OAuth 2.1 MUST).
//!
//! Log hygiene: only the page reason, `client_id`, `pinned_on` and the
//! `display_received` form of a rejected redirect are logged — never the
//! state, the PKCE challenge, the resource, the raw query or an envelope.

use askama::Template;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::mgmt::i18n::{Locale, LocaleHint, Translator};
use crate::mgmt::mcp_oauth::clients::{KnownClient, find_client};
use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::mcp_oauth::envelope::{self, AuthzRequest};
use crate::mgmt::mcp_oauth::params;
use crate::mgmt::mcp_oauth::pkce::challenge_well_formed;
use crate::mgmt::mcp_oauth::redirect::{
    RedirectReject, RedirectTarget, append_query, redirect_uri_allowed,
};
use crate::mgmt::routes::MgmtState;
use crate::mgmt::theme::{Theme, ThemeHint};

/// The whole query string, checked before parsing.
pub const MAX_QUERY_BYTES: usize = 4096;

/// The `error` values authorize (and MA0-6's consent deny) send back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthzErrorCode {
    InvalidRequest,
    UnsupportedResponseType,
    InvalidScope,
    InvalidTarget,
    AccessDenied,
    ServerError,
}

impl AuthzErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
        }
    }
}

// `error_description` values: English, OAuth 2.1 §3.2.4 charset
// (%x20-21 / %x23-5B / %x5D-7E), never i18n, never caller input.
const D_DUPLICATE: &str = "a parameter was sent more than once";
const D_RESPONSE_TYPE_MISSING: &str = "response_type is required";
const D_RESPONSE_TYPE: &str = "only response_type=code is supported";
const D_PKCE_METHOD: &str = "code_challenge_method must be S256";
const D_PKCE_CHALLENGE: &str = "code_challenge must be 43 base64url characters";
const D_SCOPE: &str = "scope may contain only mcp and offline_access";
const D_RESOURCE: &str = "resource must be this server's MCP endpoint, sent at most once";
const D_STATE: &str = "state must not exceed 512 bytes";
const D_SERVER: &str = "the request could not be sealed";
#[cfg(test)]
const ALL_DESCRIPTIONS: &[&str] = &[
    D_DUPLICATE,
    D_RESPONSE_TYPE_MISSING,
    D_RESPONSE_TYPE,
    D_PKCE_METHOD,
    D_PKCE_CHALLENGE,
    D_SCOPE,
    D_RESOURCE,
    D_STATE,
    D_SERVER,
];

/// `target_raw` MUST be a `RedirectTarget.raw` (or the `redirect_uri` of a
/// MAC-verified envelope that was re-validated). Pair order: `error`,
/// `error_description`?, `state`?, `iss`.
pub fn error_redirect_location(
    cfg: &McpOauthConfig,
    target_raw: &str,
    code: AuthzErrorCode,
    description: Option<&'static str>,
    state: Option<&str>,
) -> String {
    let iss = cfg.issuer();
    let mut pairs: Vec<(&str, &str)> = vec![("error", code.as_str())];
    if let Some(d) = description {
        pairs.push(("error_description", d));
    }
    if let Some(s) = state {
        pairs.push(("state", s));
    }
    pairs.push(("iss", &iss));
    append_query(target_raw, &pairs)
}

/// `base("/oauth/consent") + "?req=" + wire`, form-urlencoded (a base64url
/// wire passes unchanged).
pub fn consent_location(wire: &str) -> String {
    let enc: String = url::form_urlencoded::byte_serialize(wire.as_bytes()).collect();
    format!("{}?req={enc}", crate::base_path::base("/oauth/consent"))
}

/// Which error page. MA0-6 adds variants (and their `code()` strings and
/// template branches); it never renames these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    RequestInvalid,
    ClientUnknown,
    RedirectRejected,
    // MA0-6 consent (`consent.rs` maps its `Fail` onto these).
    ConsentNoRequest,
    ConsentMalformed,
    ConsentBadMac,
    ConsentExpired,
    ConsentMismatch,
    ConsentClientChanged,
    ConsentCsrf,
    ConsentAdminMissing,
    ConsentInternal,
}

impl ErrorKind {
    /// The template matches on this string, and renders it as the banner's
    /// `data-kind` attribute (tests key on that, not on translated copy).
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::RequestInvalid => "request_invalid",
            Self::ClientUnknown => "client_unknown",
            Self::RedirectRejected => "redirect_rejected",
            Self::ConsentNoRequest => "consent_no_request",
            Self::ConsentMalformed => "consent_malformed",
            Self::ConsentBadMac => "consent_bad_mac",
            Self::ConsentExpired => "consent_expired",
            Self::ConsentMismatch => "consent_mismatch",
            Self::ConsentClientChanged => "consent_client_changed",
            Self::ConsentCsrf => "consent_csrf",
            Self::ConsentAdminMissing => "consent_admin_missing",
            Self::ConsentInternal => "consent_internal",
        }
    }
}

pub(crate) struct ErrorPageModel {
    pub kind: ErrorKind,
    /// Already passed through `display_received`.
    pub received_redirect: Option<String>,
    pub pinned: Option<&'static KnownClient>,
    /// `None` on authorize's pages; consent sets it to a loopback return link
    /// (`error=access_denied`) when the envelope is MAC-valid and re-validates.
    pub back_href: Option<String>,
}

#[derive(Template)]
#[template(path = "mcp_oauth_error.html")]
struct McpOauthErrorPage {
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    kind: &'static str,
    received_redirect: Option<String>,
    pinned: Option<&'static KnownClient>,
    back_href: Option<String>,
}

/// The standalone, script-free error page. `no-store` and `no-referrer`
/// always; a render failure is a bare 500, never a panic.
pub(crate) fn error_page(
    locale: Locale,
    theme: Theme,
    status: StatusCode,
    model: ErrorPageModel,
) -> Response {
    let page = McpOauthErrorPage {
        t: Translator::new(locale),
        palette_resolved: crate::mgmt::theme::palette_for(theme),
        kind: model.kind.code(),
        received_redirect: model.received_redirect,
        pinned: model.pinned,
        back_href: model.back_href,
    };
    match page.render() {
        Ok(html) => (
            status,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            html,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "mcp_oauth: error page failed to render");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CACHE_CONTROL, "no-store")],
                "internal error",
            )
                .into_response()
        }
    }
}

/// Why an error page was shown (logged by the handler).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageReason {
    QueryTooLong,
    ClientMissing,
    ClientDuplicated,
    ClientUnknown,
    RedirectMissing,
    RedirectDuplicated,
    Redirect(RedirectReject),
}

pub(crate) enum Decision {
    Page {
        kind: ErrorKind,
        reason: PageReason,
        received_redirect: Option<String>,
        pinned: Option<&'static KnownClient>,
    },
    Back {
        target: RedirectTarget,
        code: AuthzErrorCode,
        description: &'static str,
        state: Option<String>,
    },
    Proceed(AuthzRequest),
}

/// MA0-PLAN §3.8.3 steps 1-9. Pure: no log, no clock, no I/O.
pub(crate) fn evaluate(cfg: &McpOauthConfig, raw_query: Option<&str>) -> Decision {
    let page = |kind, reason, received_redirect, pinned| Decision::Page {
        kind,
        reason,
        received_redirect,
        pinned,
    };
    // 1. The whole query, parsed once (form decoding happens only here).
    let Ok(p) = params::parse_pairs(raw_query.unwrap_or("").as_bytes(), MAX_QUERY_BYTES) else {
        return page(
            ErrorKind::RequestInvalid,
            PageReason::QueryTooLong,
            None,
            None,
        );
    };
    // 2. client_id. An unknown one is never echoed.
    if p.is_duplicated("client_id") {
        return page(
            ErrorKind::RequestInvalid,
            PageReason::ClientDuplicated,
            None,
            None,
        );
    }
    let Some(client_id) = p.get("client_id") else {
        return page(
            ErrorKind::RequestInvalid,
            PageReason::ClientMissing,
            None,
            None,
        );
    };
    let Some(client) = find_client(client_id) else {
        return page(
            ErrorKind::ClientUnknown,
            PageReason::ClientUnknown,
            None,
            None,
        );
    };
    // 3. redirect_uri, on the decoded raw string.
    if p.is_duplicated("redirect_uri") {
        return page(
            ErrorKind::RequestInvalid,
            PageReason::RedirectDuplicated,
            None,
            Some(client),
        );
    }
    let Some(redirect_uri) = p.get("redirect_uri") else {
        return page(
            ErrorKind::RequestInvalid,
            PageReason::RedirectMissing,
            None,
            Some(client),
        );
    };
    let target = match redirect_uri_allowed(client, redirect_uri) {
        Ok(t) => t,
        Err(why) => {
            return page(
                ErrorKind::RedirectRejected,
                PageReason::Redirect(why),
                Some(display_received(redirect_uri)),
                Some(client),
            );
        }
    };
    // Every later error goes back to `target`, echoing the first state value
    // verbatim, unless it is over `MAX_STATE`: that one is never echoed (a
    // 4 KiB query would otherwise put up to 4 KiB of caller text in Location).
    match after_redirect(cfg, &p, client, &target) {
        Ok(req) => Decision::Proceed(req),
        Err((code, description)) => Decision::Back {
            target,
            code,
            description,
            state: p
                .get("state")
                .filter(|s| s.len() <= envelope::MAX_STATE)
                .map(str::to_owned),
        },
    }
}

/// Steps 4-10: everything after the redirect is trusted.
fn after_redirect(
    cfg: &McpOauthConfig,
    p: &params::Params,
    client: &'static KnownClient,
    target: &RedirectTarget,
) -> Result<AuthzRequest, (AuthzErrorCode, &'static str)> {
    use AuthzErrorCode::*;
    // 4. response_type: missing or repeated is malformed; a value other than
    // `code` is an unsupported method (OAuth 2.1 §4.1.2.1).
    if p.is_duplicated("response_type") {
        return Err((InvalidRequest, D_DUPLICATE));
    }
    match p.get("response_type") {
        None => return Err((InvalidRequest, D_RESPONSE_TYPE_MISSING)),
        Some("code") => {}
        Some(_) => return Err((UnsupportedResponseType, D_RESPONSE_TYPE)),
    }
    // 5. PKCE: S256 only, byte for byte (absent means `plain`, refused too).
    if p.is_duplicated("code_challenge") || p.is_duplicated("code_challenge_method") {
        return Err((InvalidRequest, D_DUPLICATE));
    }
    if p.get("code_challenge_method") != Some("S256") {
        return Err((InvalidRequest, D_PKCE_METHOD));
    }
    let code_challenge = match p.get("code_challenge") {
        Some(c) if challenge_well_formed(c) => c.to_owned(),
        _ => return Err((InvalidRequest, D_PKCE_CHALLENGE)),
    };
    // 6. scope: absent means `mcp`; every token must be known. The grant's
    // scope is always `mcp`, so scope never enters the envelope.
    if p.is_duplicated("scope") {
        return Err((InvalidRequest, D_DUPLICATE));
    }
    if let Some(scope) = p.get("scope")
        && !scope_items_ok(scope)
    {
        return Err((InvalidScope, D_SCOPE));
    }
    // 7. resource: optional (RFC 8707 default); exactly one, ours, or refused.
    let resource = match p.get_all("resource").as_slice() {
        [] => None,
        [r] if r.len() <= envelope::MAX_RESOURCE && cfg.is_our_resource(r) => Some((*r).to_owned()),
        _ => return Err((InvalidTarget, D_RESOURCE)),
    };
    // 8. state.
    if p.is_duplicated("state") {
        return Err((InvalidRequest, D_DUPLICATE));
    }
    let state = p.get("state").map(str::to_owned);
    if state
        .as_ref()
        .is_some_and(|s| s.len() > envelope::MAX_STATE)
    {
        return Err((InvalidRequest, D_STATE));
    }
    // 9. `prompt` and unknown parameters are never read.
    Ok(AuthzRequest {
        client_id: client.client_id.to_owned(),
        redirect_uri: target.raw.clone(),
        state,
        code_challenge,
        resource,
    })
}

/// The scope-item rule: split on `' '`, skip empty items, every item `mcp` or
/// `offline_access` (case-sensitive). Authorize (step 6) and the refresh grant
/// (`token.rs`) both call this, so one scope string never gets two verdicts.
/// What an ABSENT scope means stays with each caller (authorize: `mcp`;
/// refresh: not sent).
pub(crate) fn scope_items_ok(scope: &str) -> bool {
    scope
        .split(' ')
        .filter(|t| !t.is_empty())
        .all(|t| t == "mcp" || t == "offline_access")
}

/// How often a rejected redirect from the pinned client may log at `warn`.
const REDIRECT_WARN_EVERY_SECS: u64 = 60;

/// Rate-samples the "redirect_uri not pinned" warn: the caller is
/// unauthenticated, so a flood must not push journald's per-service limit into
/// dropping real warnings. Process-wide; the rest go to `debug`.
pub(crate) struct WarnSampler {
    /// Unix second of the last warn; 0 = never.
    last: AtomicU64,
    suppressed: AtomicU64,
}

impl WarnSampler {
    pub(crate) const fn new() -> Self {
        Self {
            last: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some(n)`: warn now, `n` = how many were suppressed since the last warn.
    /// `None`: log at `debug` (counted as suppressed). At most one `Some` per
    /// `REDIRECT_WARN_EVERY_SECS` of `now`.
    pub(crate) fn sample(&self, now: u64) -> Option<u64> {
        let last = self.last.load(Ordering::Relaxed);
        let due = last == 0 || now >= last.saturating_add(REDIRECT_WARN_EVERY_SECS);
        if due
            && self
                .last
                .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

static REDIRECT_WARN: WarnSampler = WarnSampler::new();

/// `GET /oauth/authorize`. Reads the OAuth config only: no database handle,
/// no lock, no write.
pub async fn authorize(
    State(s): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    RawQuery(q): RawQuery,
) -> Response {
    let cfg = &*s.mcp_oauth;
    match evaluate(cfg, q.as_deref()) {
        Decision::Page {
            kind,
            reason,
            received_redirect,
            pinned,
        } => {
            match (reason, pinned) {
                (PageReason::Redirect(why), Some(c)) => {
                    // A clock before the epoch never suppresses.
                    let sampled = envelope::now_unix().map_or(Some(0), |n| REDIRECT_WARN.sample(n));
                    match sampled {
                        Some(suppressed) => tracing::warn!(
                            received = received_redirect.as_deref().unwrap_or(""),
                            client_id = c.client_id,
                            pinned_on = c.pinned_on,
                            reason = ?why,
                            suppressed,
                            "mcp_oauth: redirect_uri not pinned"
                        ),
                        None => tracing::debug!(
                            received = received_redirect.as_deref().unwrap_or(""),
                            client_id = c.client_id,
                            pinned_on = c.pinned_on,
                            reason = ?why,
                            "mcp_oauth: redirect_uri not pinned"
                        ),
                    }
                }
                _ => tracing::debug!(reason = ?reason, "mcp_oauth: authorize error page"),
            }
            error_page(
                locale,
                theme,
                StatusCode::BAD_REQUEST,
                ErrorPageModel {
                    kind,
                    received_redirect,
                    pinned,
                    back_href: None,
                },
            )
        }
        Decision::Back {
            target,
            code,
            description,
            state,
        } => see_other(
            error_redirect_location(cfg, &target.raw, code, Some(description), state.as_deref()),
            None,
        ),
        Decision::Proceed(req) => proceed(cfg, &req, envelope::now_unix()),
    }
}

/// The success half, split out so the clock-failure branch is unit-testable:
/// `now == None` (clock before the epoch) or a seal error -> 303
/// `server_error` back to `req.redirect_uri`, no cookie.
pub(crate) fn proceed(cfg: &McpOauthConfig, req: &AuthzRequest, now: Option<u64>) -> Response {
    let back_server_error = || {
        see_other(
            error_redirect_location(
                cfg,
                &req.redirect_uri,
                AuthzErrorCode::ServerError,
                Some(D_SERVER),
                req.state.as_deref(),
            ),
            None,
        )
    };
    let Some(now) = now else {
        return back_server_error();
    };
    match envelope::seal(cfg, req, now) {
        Ok(wire) => see_other(
            consent_location(&wire),
            Some(envelope::resume_cookie(&wire)),
        ),
        Err(_) => back_server_error(),
    }
}

/// 303 + `Cache-Control: no-store` + `Referrer-Policy: no-referrer`
/// (+ `Set-Cookie`). Built by hand: axum's `Redirect::to` panics on an invalid
/// header value; here an impossible failure becomes a bare 500 with no
/// `Location`.
fn see_other(location: String, set_cookie: Option<String>) -> Response {
    let bare_500 = || {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response()
    };
    let Ok(loc) = HeaderValue::from_str(&location) else {
        return bare_500();
    };
    let mut resp = StatusCode::SEE_OTHER.into_response();
    let h = resp.headers_mut();
    h.insert(header::LOCATION, loc);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Some(c) = set_cookie {
        let Ok(v) = HeaderValue::from_str(&c) else {
            return bare_500();
        };
        h.insert(header::SET_COOKIE, v);
    }
    resp
}

/// For the page and the log only: cut at the first '?' or '#', map everything
/// outside U+0020..=U+007E to U+FFFD (no bidi overrides, no newlines in the
/// log), keep at most 96 chars and append "..." when cut. The longest legal
/// value is 31 bytes and anything past 64 is already `TooLong`.
fn display_received(raw: &str) -> String {
    const MAX_CHARS: usize = 96;
    let head = match raw.find(['?', '#']) {
        Some(i) => &raw[..i],
        None => raw,
    };
    let mut out = String::new();
    for (n, c) in head.chars().enumerate() {
        if n == MAX_CHARS {
            out.push_str("...");
            break;
        }
        out.push(if (' '..='~').contains(&c) {
            c
        } else {
            '\u{FFFD}'
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CC: &str = "https://claude.ai/oauth/claude-code-client-metadata";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const REDIRECT: &str = "http://localhost:54321/callback";
    const RESOURCE: &str = "https://drust.test/drust/mcp";
    const ISS_ENC: &str = "https%3A%2F%2Fdrust.test%2Fdrust";

    fn cfg() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }

    type Pairs = Vec<(String, String)>;

    /// The SDK's request shape (extas/auth.ts order).
    fn sdk() -> Pairs {
        [
            ("response_type", "code"),
            ("client_id", CC),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("redirect_uri", REDIRECT),
            ("state", "st"),
            ("scope", "mcp offline_access"),
            ("prompt", "consent"),
            ("resource", RESOURCE),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn set(mut p: Pairs, k: &str, v: &str) -> Pairs {
        p.retain(|(key, _)| key != k);
        p.push((k.into(), v.into()));
        p
    }

    fn del(mut p: Pairs, k: &str) -> Pairs {
        p.retain(|(key, _)| key != k);
        p
    }

    fn add(mut p: Pairs, k: &str, v: &str) -> Pairs {
        p.push((k.into(), v.into()));
        p
    }

    fn q(p: &Pairs) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(p)
            .finish()
    }

    fn eval(p: &Pairs) -> Decision {
        evaluate(&cfg(), Some(&q(p)))
    }

    fn page_reason(d: &Decision) -> Option<(ErrorKind, PageReason)> {
        match d {
            Decision::Page { kind, reason, .. } => Some((*kind, *reason)),
            _ => None,
        }
    }

    fn back(d: &Decision) -> Option<(AuthzErrorCode, &'static str, Option<String>)> {
        match d {
            Decision::Back {
                code,
                description,
                state,
                ..
            } => Some((*code, *description, state.clone())),
            _ => None,
        }
    }

    fn proceeded(d: &Decision) -> Option<AuthzRequest> {
        match d {
            Decision::Proceed(r) => Some(r.clone()),
            _ => None,
        }
    }

    fn header_str(r: &Response, h: header::HeaderName) -> Option<&str> {
        r.headers().get(h).and_then(|v| v.to_str().ok())
    }

    fn query_param(url: &str, key: &str) -> Option<String> {
        let (_, qs) = url.split_once('?')?;
        url::form_urlencoded::parse(qs.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    /// The one scope-item rule, shared by authorize step 6 and the refresh
    /// grant (MA0-8): space-separated, empty items skipped, each `mcp` or
    /// `offline_access`, case-sensitive.
    #[test]
    fn scope_items_ok_table() {
        for ok in [
            "",
            "mcp",
            "offline_access",
            "mcp offline_access",
            "mcp  offline_access",
        ] {
            assert!(scope_items_ok(ok), "{ok:?} must pass");
        }
        for bad in ["admin", "mcp admin", "MCP"] {
            assert!(!scope_items_ok(bad), "{bad:?} must fail");
        }
    }

    #[test]
    fn page_before_redirect_validation() {
        use PageReason::*;
        let long_query = format!("a={}", "x".repeat(MAX_QUERY_BYTES - 1));
        assert_eq!(long_query.len(), MAX_QUERY_BYTES + 1);
        assert_eq!(
            page_reason(&evaluate(&cfg(), Some(&long_query))),
            Some((ErrorKind::RequestInvalid, QueryTooLong))
        );
        let cases: Vec<(&str, Pairs, ErrorKind, PageReason)> = vec![
            (
                "missing client_id",
                del(sdk(), "client_id"),
                ErrorKind::RequestInvalid,
                ClientMissing,
            ),
            (
                "duplicated client_id",
                add(sdk(), "client_id", "https://other.example/cimd"),
                ErrorKind::RequestInvalid,
                ClientDuplicated,
            ),
            (
                "unknown client_id",
                set(sdk(), "client_id", "https://evil.example/cimd"),
                ErrorKind::ClientUnknown,
                ClientUnknown,
            ),
            (
                "client_id 257 bytes",
                set(sdk(), "client_id", &"c".repeat(257)),
                ErrorKind::ClientUnknown,
                ClientUnknown,
            ),
            (
                "missing redirect_uri",
                del(sdk(), "redirect_uri"),
                ErrorKind::RequestInvalid,
                RedirectMissing,
            ),
            (
                "duplicated redirect_uri",
                add(sdk(), "redirect_uri", REDIRECT),
                ErrorKind::RequestInvalid,
                RedirectDuplicated,
            ),
            (
                "rejected redirect_uri",
                set(sdk(), "redirect_uri", "https://localhost:1/callback"),
                ErrorKind::RedirectRejected,
                Redirect(RedirectReject::NotLoopbackForm),
            ),
            (
                "unpinned path",
                set(sdk(), "redirect_uri", "http://localhost:1/callback/"),
                ErrorKind::RedirectRejected,
                Redirect(RedirectReject::NotPinned),
            ),
        ];
        for (what, p, kind, reason) in cases {
            let d = eval(&p);
            assert_eq!(page_reason(&d), Some((kind, reason)), "{what}");
            let Decision::Page {
                received_redirect,
                pinned,
                ..
            } = d
            else {
                unreachable!()
            };
            match reason {
                ClientMissing | ClientDuplicated | ClientUnknown => {
                    assert_eq!(received_redirect, None, "{what}: never echoed");
                    assert!(pinned.is_none(), "{what}");
                }
                RedirectMissing | RedirectDuplicated => {
                    assert_eq!(received_redirect, None, "{what}");
                    assert_eq!(pinned.map(|c| c.client_id), Some(CC), "{what}");
                }
                Redirect(_) => {
                    assert!(received_redirect.is_some(), "{what}");
                    assert_eq!(pinned.map(|c| c.client_id), Some(CC), "{what}");
                }
                QueryTooLong => unreachable!(),
            }
        }
        // No query at all.
        assert_eq!(
            page_reason(&evaluate(&cfg(), None)),
            Some((ErrorKind::RequestInvalid, ClientMissing))
        );
    }

    #[test]
    fn duplicate_identical_values_still_duplicate() {
        assert_eq!(
            page_reason(&eval(&add(sdk(), "client_id", CC))),
            Some((ErrorKind::RequestInvalid, PageReason::ClientDuplicated))
        );
    }

    #[test]
    fn back_after_redirect_validation() {
        use AuthzErrorCode::*;
        let r513 = format!("{RESOURCE}{}", "x".repeat(513 - RESOURCE.len()));
        let cases: Vec<(&str, Pairs, AuthzErrorCode, &str)> = vec![
            (
                "missing response_type",
                del(sdk(), "response_type"),
                InvalidRequest,
                D_RESPONSE_TYPE_MISSING,
            ),
            (
                "duplicated response_type",
                add(sdk(), "response_type", "code"),
                InvalidRequest,
                D_DUPLICATE,
            ),
            (
                "response_type=token",
                set(sdk(), "response_type", "token"),
                UnsupportedResponseType,
                D_RESPONSE_TYPE,
            ),
            (
                "missing method",
                del(sdk(), "code_challenge_method"),
                InvalidRequest,
                D_PKCE_METHOD,
            ),
            (
                "plain",
                set(sdk(), "code_challenge_method", "plain"),
                InvalidRequest,
                D_PKCE_METHOD,
            ),
            (
                "s256",
                set(sdk(), "code_challenge_method", "s256"),
                InvalidRequest,
                D_PKCE_METHOD,
            ),
            (
                "missing challenge",
                del(sdk(), "code_challenge"),
                InvalidRequest,
                D_PKCE_CHALLENGE,
            ),
            (
                "42-char challenge",
                set(sdk(), "code_challenge", &CHALLENGE[..42]),
                InvalidRequest,
                D_PKCE_CHALLENGE,
            ),
            (
                "challenge with +",
                set(sdk(), "code_challenge", &format!("{}+", &CHALLENGE[..42])),
                InvalidRequest,
                D_PKCE_CHALLENGE,
            ),
            (
                "duplicated challenge",
                add(sdk(), "code_challenge", CHALLENGE),
                InvalidRequest,
                D_DUPLICATE,
            ),
            (
                "scope=admin",
                set(sdk(), "scope", "admin"),
                InvalidScope,
                D_SCOPE,
            ),
            (
                "scope=mcp admin",
                set(sdk(), "scope", "mcp admin"),
                InvalidScope,
                D_SCOPE,
            ),
            (
                "duplicated scope",
                add(sdk(), "scope", "mcp"),
                InvalidRequest,
                D_DUPLICATE,
            ),
            (
                "resource #f",
                set(sdk(), "resource", &format!("{RESOURCE}#f")),
                InvalidTarget,
                D_RESOURCE,
            ),
            (
                "resource ?x",
                set(sdk(), "resource", &format!("{RESOURCE}?x")),
                InvalidTarget,
                D_RESOURCE,
            ),
            (
                "resource trailing /",
                set(sdk(), "resource", &format!("{RESOURCE}/")),
                InvalidTarget,
                D_RESOURCE,
            ),
            (
                "resource other host",
                set(sdk(), "resource", "https://evil.test/drust/mcp"),
                InvalidTarget,
                D_RESOURCE,
            ),
            (
                "resource /drust/MCP",
                set(sdk(), "resource", "https://drust.test/drust/MCP"),
                InvalidTarget,
                D_RESOURCE,
            ),
            (
                "two correct resources",
                add(sdk(), "resource", RESOURCE),
                InvalidTarget,
                D_RESOURCE,
            ),
            (
                "resource 513 bytes, not ours",
                set(sdk(), "resource", &r513),
                InvalidTarget,
                D_RESOURCE,
            ),
            (
                "state 513 bytes",
                set(sdk(), "state", &"s".repeat(513)),
                InvalidRequest,
                D_STATE,
            ),
            (
                "duplicated state",
                add(sdk(), "state", "st2"),
                InvalidRequest,
                D_DUPLICATE,
            ),
        ];
        for (what, p, code, desc) in cases {
            let d = eval(&p);
            let got = back(&d);
            assert!(got.is_some(), "{what}: not a redirect-back");
            let (c, dsc, _) = got.unwrap();
            assert_eq!((c, dsc), (code, desc), "{what}");
            let Decision::Back { target, .. } = d else {
                unreachable!()
            };
            assert_eq!(target.raw, REDIRECT, "{what}");
        }
    }

    /// An origin whose own `/mcp` resource is exactly `len` bytes: a host of
    /// 63-byte labels. Only such a config makes a resource over `MAX_RESOURCE`
    /// pass `is_our_resource`, so only it shows the length guard at work.
    pub(crate) fn origin_with_resource_len(len: usize) -> String {
        let path = crate::base_path::base("/mcp");
        let mut left = len - "https://".len() - path.len();
        let mut labels = Vec::new();
        while left > 0 {
            let n = left.min(63);
            // Never leave a 1-byte remainder that only a dot could fill.
            let n = if left > 63 && left - n == 1 { 62 } else { n };
            labels.push("a".repeat(n));
            left -= n;
            left = left.saturating_sub(1); // the dot before the next label
        }
        format!("https://{}", labels.join("."))
    }

    #[test]
    fn an_own_resource_over_the_limit_is_refused_by_the_length_guard() {
        let origin = origin_with_resource_len(envelope::MAX_RESOURCE + 1);
        let c = McpOauthConfig::for_tests(&origin);
        let r513 = c.resource_url();
        assert_eq!(r513.len(), envelope::MAX_RESOURCE + 1);
        assert!(
            c.is_our_resource(&r513),
            "only the length guard can refuse it"
        );
        let p = set(sdk(), "resource", &r513);
        match evaluate(&c, Some(&q(&p))) {
            Decision::Back {
                code, description, ..
            } => assert_eq!(
                (code, description),
                (AuthzErrorCode::InvalidTarget, D_RESOURCE)
            ),
            _ => panic!("a 513-byte resource must go back with invalid_target"),
        }
        // At the limit it proceeds.
        let c = McpOauthConfig::for_tests(&origin_with_resource_len(envelope::MAX_RESOURCE));
        let p = set(sdk(), "resource", &c.resource_url());
        assert!(matches!(evaluate(&c, Some(&q(&p))), Decision::Proceed(_)));
    }

    #[test]
    fn redirect_warn_is_sampled_once_a_minute() {
        let w = WarnSampler::new();
        assert_eq!(w.sample(1000), Some(0), "the first one warns");
        assert_eq!(w.sample(1000), None);
        assert_eq!(w.sample(1059), None, "59 s later: still debug");
        assert_eq!(w.sample(1060), Some(2), "60 s later: warns, carrying 2");
        assert_eq!(w.sample(1061), None);
        assert_eq!(
            w.sample(5000),
            Some(1),
            "the count restarts after each warn"
        );
        assert_eq!(
            w.sample(4990),
            None,
            "a clock step back does not warn early"
        );
    }

    #[test]
    fn back_echoes_first_state_verbatim() {
        let weird = "a b&c=d é";
        let p = set(set(sdk(), "state", weird), "response_type", "token");
        assert_eq!(back(&eval(&p)).and_then(|b| b.2), Some(weird.to_string()));
        // Duplicated: the FIRST value comes back.
        let p = add(set(sdk(), "state", "first"), "state", "second");
        assert_eq!(back(&eval(&p)).and_then(|b| b.2), Some("first".to_string()));
        // Over-long: refused, and never echoed, whatever the error.
        let long = "s".repeat(envelope::MAX_STATE + 1);
        let p = set(sdk(), "state", &long);
        let b = back(&eval(&p));
        assert_eq!(b.as_ref().map(|b| b.1), Some(D_STATE));
        assert_eq!(
            b.and_then(|b| b.2),
            None,
            "an over-long state is not echoed"
        );
        let p = set(set(sdk(), "state", &long), "response_type", "token");
        assert_eq!(back(&eval(&p)).and_then(|b| b.2), None);
        // Exactly at the limit: echoed.
        let at = "s".repeat(envelope::MAX_STATE);
        let p = set(set(sdk(), "state", &at), "response_type", "token");
        assert_eq!(back(&eval(&p)).and_then(|b| b.2), Some(at));
        // Absent: None.
        let p = set(del(sdk(), "state"), "response_type", "token");
        let b = back(&eval(&p));
        assert!(b.is_some());
        assert_eq!(b.and_then(|b| b.2), None);
    }

    #[test]
    fn scope_plus_and_percent20_both_proceed() {
        let base = q(&del(sdk(), "scope"));
        for raw_scope in ["mcp+offline_access", "mcp%20offline_access"] {
            let query = format!("{base}&scope={raw_scope}");
            assert!(
                proceeded(&evaluate(&cfg(), Some(&query))).is_some(),
                "{raw_scope}"
            );
        }
        let query = format!("{base}&scope=mcp%2Badmin");
        assert_eq!(
            back(&evaluate(&cfg(), Some(&query))).map(|b| b.0),
            Some(AuthzErrorCode::InvalidScope)
        );
    }

    fn sample_req() -> AuthzRequest {
        AuthzRequest {
            client_id: CC.into(),
            redirect_uri: REDIRECT.into(),
            state: Some("st".into()),
            code_challenge: CHALLENGE.into(),
            resource: Some(RESOURCE.into()),
        }
    }

    #[test]
    fn clock_failure_goes_back_with_server_error() {
        let req = sample_req();
        let r = proceed(&cfg(), &req, None);
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        let loc = header_str(&r, header::LOCATION).unwrap_or_default();
        assert!(loc.starts_with(&format!("{REDIRECT}?")), "{loc}");
        assert_eq!(query_param(loc, "error").as_deref(), Some("server_error"));
        assert_eq!(
            query_param(loc, "iss").as_deref(),
            Some("https://drust.test/drust")
        );
        assert_eq!(query_param(loc, "state").as_deref(), Some("st"));
        assert!(r.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(header_str(&r, header::CACHE_CONTROL), Some("no-store"));

        let r = proceed(&cfg(), &req, Some(1_800_000_000));
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        let loc = header_str(&r, header::LOCATION).unwrap_or_default();
        assert!(loc.starts_with("/drust/oauth/consent?req="), "{loc}");
        let cookie = header_str(&r, header::SET_COOKIE).unwrap_or_default();
        assert!(cookie.starts_with("drust_mcp_oauth_resume="), "{cookie}");
    }

    #[test]
    fn proceed_shapes() {
        let full = sample_req();
        let no_resource = AuthzRequest {
            resource: None,
            ..sample_req()
        };
        let odd_resource = "HTTPS://DRUST.TEST:443/drust/mcp";
        let cases: Vec<(&str, Pairs, AuthzRequest)> = vec![
            ("sdk", sdk(), full.clone()),
            ("no resource", del(sdk(), "resource"), no_resource.clone()),
            (
                "empty resource",
                set(sdk(), "resource", ""),
                no_resource.clone(),
            ),
            (
                "non-canonical resource kept raw",
                set(sdk(), "resource", odd_resource),
                AuthzRequest {
                    resource: Some(odd_resource.into()),
                    ..sample_req()
                },
            ),
            ("no scope", del(sdk(), "scope"), full.clone()),
            (
                "scope=offline_access",
                set(sdk(), "scope", "offline_access"),
                full.clone(),
            ),
            ("prompt=none", set(sdk(), "prompt", "none"), full.clone()),
            ("foo=bar", add(sdk(), "foo", "bar"), full.clone()),
            (
                "repeated unknown",
                add(add(sdk(), "foo", "1"), "foo", "2"),
                full.clone(),
            ),
            (
                "no state",
                del(sdk(), "state"),
                AuthzRequest {
                    state: None,
                    ..sample_req()
                },
            ),
            (
                "127.0.0.1",
                set(sdk(), "redirect_uri", "http://127.0.0.1/callback"),
                AuthzRequest {
                    redirect_uri: "http://127.0.0.1/callback".into(),
                    ..sample_req()
                },
            ),
            (
                "explicit :80 kept verbatim",
                set(sdk(), "redirect_uri", "http://localhost:80/callback"),
                AuthzRequest {
                    redirect_uri: "http://localhost:80/callback".into(),
                    ..sample_req()
                },
            ),
        ];
        for (what, p, want) in cases {
            assert_eq!(proceeded(&eval(&p)), Some(want), "{what}");
        }
    }

    #[test]
    fn descriptions_are_oauth_ascii() {
        assert_eq!(ALL_DESCRIPTIONS.len(), 9);
        for d in ALL_DESCRIPTIONS {
            assert!(!d.is_empty());
            assert!(
                d.bytes()
                    .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)),
                "{d:?}"
            );
        }
    }

    #[test]
    fn error_redirect_location_order_and_iss() {
        let loc = error_redirect_location(
            &cfg(),
            "http://localhost:1/callback",
            AuthzErrorCode::InvalidRequest,
            Some(D_DUPLICATE),
            Some("s"),
        );
        assert_eq!(
            loc,
            format!(
                "http://localhost:1/callback?error=invalid_request&error_description=a+parameter+was+sent+more+than+once&state=s&iss={ISS_ENC}"
            )
        );
        let loc = error_redirect_location(
            &cfg(),
            "http://localhost:1/callback",
            AuthzErrorCode::AccessDenied,
            None,
            None,
        );
        assert_eq!(
            loc,
            format!("http://localhost:1/callback?error=access_denied&iss={ISS_ENC}")
        );
        assert!(!loc.contains("state="));
    }

    #[test]
    fn error_codes_are_the_oauth_strings() {
        use AuthzErrorCode::*;
        let all = [
            (InvalidRequest, "invalid_request"),
            (UnsupportedResponseType, "unsupported_response_type"),
            (InvalidScope, "invalid_scope"),
            (InvalidTarget, "invalid_target"),
            (AccessDenied, "access_denied"),
            (ServerError, "server_error"),
        ];
        for (c, s) in all {
            assert_eq!(c.as_str(), s);
        }
    }

    #[test]
    fn display_received_sanitizes() {
        assert_eq!(
            display_received("http://localhost:1/callback?x=1#f"),
            "http://localhost:1/callback"
        );
        assert_eq!(display_received("http://a/b#f?x"), "http://a/b");
        assert_eq!(
            display_received("http://x/\n\u{202E}y"),
            "http://x/\u{FFFD}\u{FFFD}y"
        );
        let s96 = "a".repeat(96);
        assert_eq!(display_received(&s96), s96);
        let s97 = "a".repeat(97);
        assert_eq!(display_received(&s97), format!("{s96}..."));
        // Counted in chars, not bytes.
        let wide = "é".repeat(97);
        assert_eq!(
            display_received(&wide),
            format!("{}...", "\u{FFFD}".repeat(96))
        );
    }

    #[test]
    fn consent_location_prefixes_the_base() {
        assert_eq!(consent_location("abc_-"), "/drust/oauth/consent?req=abc_-");
    }

    #[test]
    fn error_kind_codes_match_the_template() {
        assert_eq!(ErrorKind::RequestInvalid.code(), "request_invalid");
        assert_eq!(ErrorKind::ClientUnknown.code(), "client_unknown");
        assert_eq!(ErrorKind::RedirectRejected.code(), "redirect_rejected");
        assert_eq!(ErrorKind::ConsentNoRequest.code(), "consent_no_request");
        assert_eq!(ErrorKind::ConsentMalformed.code(), "consent_malformed");
        assert_eq!(ErrorKind::ConsentBadMac.code(), "consent_bad_mac");
        assert_eq!(ErrorKind::ConsentExpired.code(), "consent_expired");
        assert_eq!(ErrorKind::ConsentMismatch.code(), "consent_mismatch");
        assert_eq!(
            ErrorKind::ConsentClientChanged.code(),
            "consent_client_changed"
        );
        assert_eq!(ErrorKind::ConsentCsrf.code(), "consent_csrf");
        assert_eq!(
            ErrorKind::ConsentAdminMissing.code(),
            "consent_admin_missing"
        );
        assert_eq!(ErrorKind::ConsentInternal.code(), "consent_internal");
    }

    /// Every kind renders its own `data-kind` and, for the consent kinds, its
    /// own copy — a branch added after `{% when _ %}` would never match.
    #[test]
    fn every_error_kind_renders_its_data_kind_and_copy() {
        use crate::mgmt::i18n::Locale;
        use crate::mgmt::theme::Theme;
        let kinds = [
            (
                ErrorKind::RequestInvalid,
                "mcp_oauth.error.request_invalid_body",
            ),
            (
                ErrorKind::ClientUnknown,
                "mcp_oauth.error.client_unknown_body",
            ),
            (
                ErrorKind::RedirectRejected,
                "mcp_oauth.error.redirect_rejected_body",
            ),
            (
                ErrorKind::ConsentNoRequest,
                "mcp_oauth.consent_error.no_request",
            ),
            (
                ErrorKind::ConsentMalformed,
                "mcp_oauth.consent_error.malformed",
            ),
            (ErrorKind::ConsentBadMac, "mcp_oauth.consent_error.invalid"),
            (ErrorKind::ConsentExpired, "mcp_oauth.consent_error.expired"),
            (
                ErrorKind::ConsentMismatch,
                "mcp_oauth.consent_error.mismatch",
            ),
            (
                ErrorKind::ConsentClientChanged,
                "mcp_oauth.consent_error.client_changed",
            ),
            (ErrorKind::ConsentCsrf, "mcp_oauth.consent_error.csrf"),
            (
                ErrorKind::ConsentAdminMissing,
                "mcp_oauth.consent_error.admin_missing",
            ),
            (
                ErrorKind::ConsentInternal,
                "mcp_oauth.consent_error.internal",
            ),
        ];
        let t = Translator::new(Locale::En);
        for (kind, body_key) in kinds {
            let page = McpOauthErrorPage {
                t: Translator::new(Locale::En),
                palette_resolved: crate::mgmt::theme::palette_for(Theme::System),
                kind: kind.code(),
                received_redirect: None,
                pinned: None,
                back_href: None,
            };
            let html = page.render().unwrap();
            assert!(
                html.contains(&format!("data-kind=\"{}\"", kind.code())),
                "{kind:?}"
            );
            let copy = t.s(body_key);
            assert!(!copy.is_empty() && copy != body_key, "{body_key}");
            assert!(
                html.contains(copy.as_ref()),
                "{kind:?}: {body_key} not rendered"
            );
        }
    }
}

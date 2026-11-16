//! MA0-6 — browser consent for the MCP OAuth AS (`GET /oauth/consent`,
//! `POST /oauth/consent/approve`, `POST /oauth/consent/deny`).
//!
//! Rides `protected` (inside `admin_session_layer`), but accepts ONLY the
//! cookie arm: an admin PAT must never become a 90-day grant (design §4.4
//! step 9), so `AuthMethod::Pat` and a missing `AuthMethod` both get 403 JSON
//! `MCP_CONSENT_COOKIE_REQUIRED` before anything else is read.
//!
//! Browser binding = the resume cookie (set only by `/oauth/authorize`) must be
//! present and byte-equal to the `req` being shown or approved, plus a
//! double-submit CSRF token HMAC-bound to `admin_id` and SHA-256(`req`). The
//! envelope is re-validated on every step: `open` (MAC, expiry), then the
//! pinned client and `redirect_uri_allowed` — the SAME predicate authorize
//! uses. Everything the page shows about the client and the return address is
//! taken from that opened envelope and the pinned client list, never from the
//! query or a header.
//!
//! Cookies are cleared only when the request proves the cookie belongs to this
//! `req` AND the flow cannot finish with it (approve/deny success, or an
//! envelope that no longer opens or re-validates). A mismatch or a form-level
//! error clears nothing: the cookies most likely belong to another, newer tab.
//!
//! Not rate-limited: the caller is a signed-in admin (MA0-PLAN §4). Log and
//! audit hygiene: the plaintext authorization code and the redirect it rides
//! never reach `tracing` or an audit row (pinned by a source test).

use askama::Template;
use axum::Extension;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;

use crate::auth::middleware::{AdminId, AuthMethod};
use crate::mgmt::i18n::{Locale, LocaleHint, Translator};
use crate::mgmt::mcp_oauth::authorize::{
    AuthzErrorCode, ErrorKind, ErrorPageModel, error_page, error_redirect_location,
};
use crate::mgmt::mcp_oauth::clients::{self, KnownClient};
use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::mcp_oauth::envelope::{self, AuthzRequest, EnvelopeError};
use crate::mgmt::mcp_oauth::redirect::{self, RedirectTarget};
use crate::mgmt::mcp_oauth::{params, store};
use crate::mgmt::routes::MgmtState;
use crate::mgmt::theme::{Theme, ThemeHint};

pub const CSRF_COOKIE: &str = "drust_mcp_oauth_csrf";
const CSRF_DOMAIN: &[u8] = b"drust-mcp-csrf-v1\0";
const CSRF_MAX_AGE_SECS: u64 = 600;
/// Envelope (~2 KB base64 at the MA0-5 field limits) + csrf (43) + keys.
const FORM_MAX: usize = 8 * 1024;

// ─── CSRF ────────────────────────────────────────────────────────────────────

/// `HMAC-SHA256(csrf_key, "drust-mcp-csrf-v1\0" || admin_id (i64 LE) || ":" ||
/// SHA-256(req))`, base64url without padding. Returns "" if the MAC cannot be
/// keyed (cannot happen for HMAC); "" then fails `check_csrf`, never panics.
pub fn csrf_for(cfg: &McpOauthConfig, admin_id: i64, req_wire: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(cfg.csrf_key()) else {
        return String::new();
    };
    mac.update(CSRF_DOMAIN);
    mac.update(&admin_id.to_le_bytes());
    mac.update(b":");
    mac.update(&Sha256::digest(req_wire.as_bytes()));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// All three required, each compared in constant time: the form value is
/// non-empty, the cookie equals the form value (double submit), and the form
/// value equals the token expected for THIS admin and THIS `req`.
pub fn check_csrf(
    cfg: &McpOauthConfig,
    headers: &HeaderMap,
    admin_id: i64,
    req_wire: &str,
    form_csrf: &str,
) -> bool {
    use subtle::ConstantTimeEq;
    let cookie = read_cookie(headers, CSRF_COOKIE).unwrap_or_default();
    let expected = csrf_for(cfg, admin_id, req_wire);
    let double_submit: bool = cookie.as_bytes().ct_eq(form_csrf.as_bytes()).into();
    let bound: bool = form_csrf.as_bytes().ct_eq(expected.as_bytes()).into();
    !form_csrf.is_empty() && !expected.is_empty() && double_submit && bound
}

/// Same attributes as the resume cookie (`HttpOnly; SameSite=Lax`,
/// `Path=cookie_path("")`, `Secure` unless `DRUST_DEV_NO_SECURE_COOKIES`) plus
/// `Max-Age=600`. `HttpOnly` is fine: the server, not script, writes the token
/// into the form.
pub fn build_csrf_cookie(csrf: &str) -> String {
    csrf_cookie_line(csrf, CSRF_MAX_AGE_SECS)
}

/// Same name, Path and attributes, empty value, `Max-Age=0`.
pub fn clear_csrf_cookie() -> String {
    csrf_cookie_line("", 0)
}

fn csrf_cookie_line(value: &str, max_age: u64) -> String {
    let cpath = crate::base_path::cookie_path("");
    let base =
        format!("{CSRF_COOKIE}={value}; Path={cpath}; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if std::env::var("DRUST_DEV_NO_SECURE_COOKIES").is_ok() {
        base
    } else {
        format!("{base}; Secure")
    }
}

/// Every `Cookie` header (HTTP/2 may split them); the first exact-name match
/// wins — the same reading as `envelope::read_resume_cookie`, so the two
/// cookies of one request can never be read differently.
fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE) {
        let Ok(raw) = hv.to_str() else { continue };
        for part in raw.split(';') {
            if let Some((k, v)) = part.trim().split_once('=')
                && k == name
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

// ─── binding and failures ────────────────────────────────────────────────────

/// Everything a consent step needs once an envelope is trusted.
struct Bound {
    req: AuthzRequest,
    client: &'static KnownClient,
    redirect: RedirectTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fail {
    /// No `req` in the query or form, and no resume cookie.
    NoRequest,
    /// Form or query unparsable, or `req` / `csrf` repeated. Form level:
    /// never clears a cookie.
    BadForm,
    Malformed,
    BadMac,
    Expired,
    /// `req` != the resume cookie, or no resume cookie (browser binding).
    Mismatch,
    /// The client or its redirect no longer passes the pinned check.
    ClientChanged,
    Csrf,
    /// The admins row is gone.
    AdminMissing,
    Internal,
}

impl Fail {
    fn status(self) -> StatusCode {
        match self {
            Self::Mismatch | Self::Csrf | Self::AdminMissing => StatusCode::FORBIDDEN,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NoRequest
            | Self::BadForm
            | Self::Malformed
            | Self::BadMac
            | Self::Expired
            | Self::ClientChanged => StatusCode::BAD_REQUEST,
        }
    }

    /// `BadForm` and `Malformed` share one page (same copy); they differ only
    /// in cookie handling.
    fn error_kind(self) -> ErrorKind {
        match self {
            Self::NoRequest => ErrorKind::ConsentNoRequest,
            Self::BadForm | Self::Malformed => ErrorKind::ConsentMalformed,
            Self::BadMac => ErrorKind::ConsentBadMac,
            Self::Expired => ErrorKind::ConsentExpired,
            Self::Mismatch => ErrorKind::ConsentMismatch,
            Self::ClientChanged => ErrorKind::ConsentClientChanged,
            Self::Csrf => ErrorKind::ConsentCsrf,
            Self::AdminMissing => ErrorKind::ConsentAdminMissing,
            Self::Internal => ErrorKind::ConsentInternal,
        }
    }
}

/// `open` -> `find_client` -> `redirect_uri_allowed` (checkpoints 2 and 3 of
/// design §4.3 rule 7). The SAME `redirect_uri_allowed` as authorize; never a
/// second comparison. Callers pass `envelope::now_unix().unwrap_or(u64::MAX)`.
fn bind(cfg: &McpOauthConfig, wire: &str, now: u64) -> Result<Bound, Fail> {
    let req = envelope::open(cfg, wire, now).map_err(|e| match e {
        EnvelopeError::Malformed => Fail::Malformed,
        EnvelopeError::BadMac => Fail::BadMac,
        EnvelopeError::Expired { .. } => Fail::Expired,
    })?;
    let client = clients::find_client(&req.client_id).ok_or(Fail::ClientChanged)?;
    let redirect = redirect::redirect_uri_allowed(client, &req.redirect_uri)
        .map_err(|_| Fail::ClientChanged)?;
    Ok(Bound {
        req,
        client,
        redirect,
    })
}

/// "Return to Claude Code": only when `wire` is MAC-valid (an expired one is
/// fine — `Expired` carries the verified request) AND its client and redirect
/// still pass the pinned check. Pair order `error, state?, iss`.
fn return_link(cfg: &McpOauthConfig, wire: &str, now: u64) -> Option<String> {
    let req = match envelope::open(cfg, wire, now) {
        Ok(r) | Err(EnvelopeError::Expired { req: r }) => r,
        Err(_) => return None,
    };
    let client = clients::find_client(&req.client_id)?;
    let target = redirect::redirect_uri_allowed(client, &req.redirect_uri).ok()?;
    Some(error_redirect_location(
        cfg,
        &target.raw,
        AuthzErrorCode::AccessDenied,
        None,
        req.state.as_deref(),
    ))
}

/// The MA0-5 error page for `f`, plus the cookie clears the CALL SITE decided
/// (the decision depends on where the envelope came from, not only on `f`).
fn fail_page(
    locale: Locale,
    theme: Theme,
    f: Fail,
    back_href: Option<String>,
    clear_resume: bool,
    clear_csrf: bool,
) -> Response {
    let mut resp = error_page(
        locale,
        theme,
        f.status(),
        ErrorPageModel {
            kind: f.error_kind(),
            received_redirect: None,
            pinned: None,
            back_href,
        },
    );
    let mut clears = Vec::new();
    if clear_resume {
        clears.push(envelope::clear_resume_cookie());
    }
    if clear_csrf {
        clears.push(clear_csrf_cookie());
    }
    for c in clears {
        if let Ok(v) = HeaderValue::from_str(&c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

fn cookie_required() -> Response {
    crate::error::json_error(
        StatusCode::FORBIDDEN,
        "MCP_CONSENT_COOKIE_REQUIRED",
        "sign in with a browser session to authorize",
    )
}

fn is_cookie(m: &Option<Extension<AuthMethod>>) -> bool {
    matches!(m, Some(Extension(AuthMethod::Cookie)))
}

// ─── GET /oauth/consent ──────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "mcp_oauth_consent.html")]
struct McpOauthConsentPage {
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
    client_display_name: &'static str,
    client_id: &'static str,
    /// `COALESCE(email, username)`: the bootstrap admin has no email.
    email: String,
    role_label: String,
    sees_all: bool,
    tenant_count: i64,
    /// "localhost:53682" | "127.0.0.1" — the validated host and `u16`.
    redirect_host_port: String,
    access_minutes: u32,
    idle_days: u32,
    max_days: u32,
    req: String,
    csrf: String,
}

/// Role label from a literal key (build.rs counts `.rs` literals). An unknown
/// role reads as member: outside the sees-all set, what it sees is what it owns.
fn role_label(t: &Translator, role: &str) -> String {
    match role {
        "owner" => t.s("mcp_oauth.consent.role.owner"),
        "admin" => t.s("mcp_oauth.consent.role.admin"),
        _ => t.s("mcp_oauth.consent.role.member"),
    }
    .into_owned()
}

/// The audit `actor_email_snapshot`: `COALESCE(email, username)`, read the way
/// the GET page reads it. A read failure or a missing row only loses the
/// snapshot, never the request.
fn actor_email_snapshot(conn: &rusqlite::Connection, admin_id: i64) -> Option<String> {
    conn.query_row(
        "SELECT COALESCE(email, username) FROM admins WHERE id = ?1",
        rusqlite::params![admin_id],
        |r| r.get(0),
    )
    .ok()
}

/// `(COALESCE(email, username), role, visible live tenant count)`; `None` when
/// the admins row is gone. Its own query — never `AdminProfileExt`, whose
/// fallback is a placeholder member.
fn load_identity(
    conn: &rusqlite::Connection,
    admin_id: i64,
) -> rusqlite::Result<Option<(String, String, i64)>> {
    use rusqlite::OptionalExtension;
    let Some((email, role)): Option<(String, String)> = conn
        .query_row(
            "SELECT COALESCE(email, username), role FROM admins WHERE id = ?1",
            rusqlite::params![admin_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    // Same predicate as the tenant list (invariant 7).
    let sees_all = crate::mgmt::tenant_authz::sees_all_tenants(&role);
    let clause = crate::mgmt::tenant_authz::visibility_where(sees_all);
    let binds: Vec<i64> = if sees_all { vec![] } else { vec![admin_id] };
    let n: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL{clause}"),
        rusqlite::params_from_iter(binds),
        |r| r.get(0),
    )?;
    Ok(Some((email, role, n)))
}

pub async fn consent_page(
    State(s): State<MgmtState>,
    method: Option<Extension<AuthMethod>>,
    Extension(AdminId(admin_id)): Extension<AdminId>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if !is_cookie(&method) {
        return cookie_required();
    }
    let cfg = &*s.mcp_oauth;
    let now = envelope::now_unix().unwrap_or(u64::MAX);
    let fail = |f, back, clear_resume| fail_page(locale, theme, f, back, clear_resume, false);

    let Ok(p) = params::parse_pairs(query.as_deref().unwrap_or("").as_bytes(), FORM_MAX) else {
        return fail(Fail::BadForm, None, false);
    };
    if p.is_duplicated("req") {
        return fail(Fail::BadForm, None, false);
    }
    // The resume cookie MUST be present; a `req` query value must equal it.
    let from_cookie = envelope::read_resume_cookie(&headers).filter(|c| !c.is_empty());
    let wire = match (p.get("req"), from_cookie) {
        (Some(q), Some(c)) if q == c => c,
        (Some(q), _) => return fail(Fail::Mismatch, return_link(cfg, q, now), false),
        (None, Some(c)) => c,
        (None, None) => return fail(Fail::NoRequest, None, false),
    };
    // From here the envelope is this browser's resume cookie, so a dead one is
    // cleared. The csrf cookie is never cleared by a GET.
    let b = match bind(cfg, &wire, now) {
        Ok(b) => b,
        Err(f) => return fail(f, return_link(cfg, &wire, now), true),
    };

    let identity = {
        let conn = s.meta.lock().await;
        load_identity(&conn, admin_id)
    };
    let (email, role, tenant_count) = match identity {
        Ok(Some(i)) => i,
        Ok(None) => return fail(Fail::AdminMissing, return_link(cfg, &wire, now), false),
        Err(e) => {
            tracing::warn!(error = ?e, "mcp consent page: admin lookup failed");
            return fail(Fail::Internal, return_link(cfg, &wire, now), false);
        }
    };

    let csrf = csrf_for(cfg, admin_id, &wire);
    let t = Translator::new(locale);
    let role_label = role_label(&t, &role);
    let redirect_host_port = match b.redirect.port {
        Some(port) => format!("{}:{port}", b.redirect.host),
        None => b.redirect.host.to_string(),
    };
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    let page = McpOauthConsentPage {
        t,
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
        client_display_name: b.client.display_name,
        client_id: b.client.client_id,
        email,
        role_label,
        sees_all: crate::mgmt::tenant_authz::sees_all_tenants(&role),
        tenant_count,
        redirect_host_port,
        access_minutes: cfg.access_ttl_secs() / 60,
        idle_days: cfg.idle_days(),
        max_days: cfg.max_days(),
        req: wire,
        csrf,
    };
    let html = match page.render() {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "mcp consent page failed to render");
            return fail(Fail::Internal, None, false);
        }
    };
    let Ok(cookie) = HeaderValue::from_str(&build_csrf_cookie(&page.csrf)) else {
        return fail(Fail::Internal, None, false);
    };
    // No Content-Security-Policy here: frame_guard_layers adds
    // `frame-ancestors 'none'` only when the response has none of its own.
    let mut resp = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        html,
    )
        .into_response();
    resp.headers_mut().append(header::SET_COOKIE, cookie);
    resp
}

// ─── POST approve / deny ─────────────────────────────────────────────────────

/// Steps 2-5 shared by approve and deny, after the `AuthMethod` check: parse
/// the form, require resume cookie == `req`, re-bind the envelope, check CSRF.
/// `Err` is the finished error page.
fn bind_form(
    cfg: &McpOauthConfig,
    headers: &HeaderMap,
    admin_id: i64,
    body: &[u8],
    locale: Locale,
    theme: Theme,
    now: u64,
) -> Result<Bound, Response> {
    let page = |f, back, clear| fail_page(locale, theme, f, back, clear, clear);
    // Form level: nothing proves which request the cookies belong to yet.
    let p = params::parse_pairs(body, FORM_MAX).map_err(|_| page(Fail::BadForm, None, false))?;
    if p.is_duplicated("req") || p.is_duplicated("csrf") {
        return Err(page(Fail::BadForm, None, false));
    }
    let Some(wire) = p.get("req") else {
        return Err(page(Fail::NoRequest, None, false));
    };
    let form_csrf = p.get("csrf").unwrap_or("");
    // Browser binding. Neither cookie is cleared: the browser holds ONE csrf
    // cookie, written by the latest consent GET, most likely for the newer
    // request the resume cookie names — clearing would break that tab.
    if envelope::read_resume_cookie(headers).as_deref() != Some(wire) {
        return Err(page(Fail::Mismatch, return_link(cfg, wire, now), false));
    }
    // cookie == req, so a dead envelope IS this browser's cookie: clear both.
    // ClientChanged too: resume_target only opens, it never re-validates the
    // client, so a kept cookie would bring every login back to this page.
    let b = bind(cfg, wire, now).map_err(|f| page(f, return_link(cfg, wire, now), true))?;
    // The resume cookie is still good; reloading the consent page rewrites csrf.
    if !check_csrf(cfg, headers, admin_id, wire, form_csrf) {
        return Err(page(Fail::Csrf, return_link(cfg, wire, now), false));
    }
    Ok(b)
}

/// 303 with `no-store`, `no-referrer` and both cookies cleared (the flow is
/// over). An unencodable `Location` (cannot happen: loopback + form encoding)
/// becomes the internal-error page.
fn finish_redirect(locale: Locale, theme: Theme, location: &str) -> Response {
    let Ok(loc) = HeaderValue::from_str(location) else {
        return fail_page(locale, theme, Fail::Internal, None, true, true);
    };
    let mut resp = StatusCode::SEE_OTHER.into_response();
    let h = resp.headers_mut();
    h.insert(header::LOCATION, loc);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    for c in [envelope::clear_resume_cookie(), clear_csrf_cookie()] {
        if let Ok(v) = HeaderValue::from_str(&c) {
            h.append(header::SET_COOKIE, v);
        }
    }
    resp
}

pub async fn consent_approve(
    State(s): State<MgmtState>,
    method: Option<Extension<AuthMethod>>,
    Extension(AdminId(admin_id)): Extension<AdminId>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    headers: HeaderMap,
    // MUST stay last (body extractor) and MUST be parsed after the AuthMethod
    // check: a `Form` extractor would answer a PAT's bad body with 422 first.
    body: axum::body::Bytes,
) -> Response {
    if !is_cookie(&method) {
        return cookie_required();
    }
    let cfg = &*s.mcp_oauth;
    let now = envelope::now_unix().unwrap_or(u64::MAX);
    let b = match bind_form(cfg, &headers, admin_id, &body, locale, theme, now) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let back = || {
        Some(error_redirect_location(
            cfg,
            &b.redirect.raw,
            AuthzErrorCode::AccessDenied,
            None,
            b.req.state.as_deref(),
        ))
    };

    let outcome = {
        let conn = s.meta.lock().await;
        match conn.unchecked_transaction() {
            Err(e) => Err(e),
            Ok(tx) => match store::insert_grant_and_code(&tx, cfg, admin_id, &b.req, &b.redirect) {
                Ok(nc) => {
                    let email = actor_email_snapshot(&tx, admin_id);
                    tx.commit().map(|_| (nc, email))
                }
                Err(e) => Err(e), // tx drops -> rollback
            },
        }
    }; // meta guard dropped here; audit is written after it
    let (nc, email) = match outcome {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return fail_page(locale, theme, Fail::AdminMissing, back(), true, true);
        }
        Err(e) => {
            tracing::warn!(error = ?e, "mcp consent approve: grant insert failed");
            return fail_page(locale, theme, Fail::Internal, back(), true, true);
        }
    };

    let mut entry =
        crate::safety::audit::AuditEntry::success("-", "-", "mcp_oauth.grant.create", 0)
            .with_extra(serde_json::json!({
                "grant_id": nc.grant_id,
                "client_id": b.client.client_id,
                "redirect_host": b.redirect.host,
            }));
    entry.auth_method = Some("mcp_oauth".to_string());
    entry.actor_admin_id = Some(admin_id);
    entry.actor_email_snapshot = email;
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    // Exactly `code`, `state` (only when authorize carried one), `iss`.
    let mut pairs: Vec<(&str, &str)> = vec![("code", nc.code.as_str())];
    if let Some(st) = b.req.state.as_deref() {
        pairs.push(("state", st));
    }
    let iss = cfg.issuer();
    pairs.push(("iss", iss.as_str()));
    finish_redirect(
        locale,
        theme,
        &redirect::append_query(&b.redirect.raw, &pairs),
    )
}

pub async fn consent_deny(
    State(s): State<MgmtState>,
    method: Option<Extension<AuthMethod>>,
    Extension(AdminId(admin_id)): Extension<AdminId>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    headers: HeaderMap,
    // Same rule as approve: last, and parsed after the AuthMethod check.
    body: axum::body::Bytes,
) -> Response {
    if !is_cookie(&method) {
        return cookie_required();
    }
    let cfg = &*s.mcp_oauth;
    let now = envelope::now_unix().unwrap_or(u64::MAX);
    let b = match bind_form(cfg, &headers, admin_id, &body, locale, theme, now) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    // Its own short lock; the guard is dropped before the audit write.
    let email = actor_email_snapshot(&*s.meta.lock().await, admin_id);
    let mut entry =
        crate::safety::audit::AuditEntry::success("-", "-", "mcp_oauth.consent.deny", 0)
            .with_extra(serde_json::json!({
                "client_id": b.client.client_id,
                "redirect_host": b.redirect.host,
            }));
    entry.auth_method = Some("mcp_oauth".to_string());
    entry.actor_admin_id = Some(admin_id);
    entry.actor_email_snapshot = email;
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
    finish_redirect(
        locale,
        theme,
        &error_redirect_location(
            cfg,
            &b.redirect.raw,
            AuthzErrorCode::AccessDenied,
            None,
            b.req.state.as_deref(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CC: &str = "https://claude.ai/oauth/claude-code-client-metadata";

    fn cfg() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }

    fn other_key_cfg() -> McpOauthConfig {
        McpOauthConfig::from_parts(
            &crate::mgmt::mcp_oauth::config::McpOauthEnv {
                mode: Some("on"),
                public_url: Some("https://drust.test"),
                ..Default::default()
            },
            crate::base_path::base_path(),
            [9; 32],
            [8; 32],
        )
    }

    fn cookies(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn csrf_differs_by_admin_req_and_key() {
        let c = cfg();
        let base = csrf_for(&c, 1, "req-a");
        assert_eq!(base.len(), 43);
        assert_eq!(base, csrf_for(&c, 1, "req-a"), "deterministic");
        assert_ne!(base, csrf_for(&c, 2, "req-a"), "admin_id");
        assert_ne!(base, csrf_for(&c, 1, "req-b"), "req");
        let other = other_key_cfg();
        assert!(other.enabled());
        assert_ne!(base, csrf_for(&other, 1, "req-a"), "csrf_key");
    }

    #[test]
    fn check_csrf_requires_all_three() {
        let c = cfg();
        let good = csrf_for(&c, 7, "R");
        let with = |cookie: &str| cookies(&format!("{CSRF_COOKIE}={cookie}"));
        assert!(!check_csrf(&c, &with(""), 7, "R", ""), "empty form");
        assert!(
            !check_csrf(&c, &HeaderMap::new(), 7, "R", &good),
            "no cookie"
        );
        assert!(
            !check_csrf(&c, &with("something-else"), 7, "R", &good),
            "cookie != form"
        );
        let wrong = csrf_for(&c, 8, "R");
        assert!(
            !check_csrf(&c, &with(&wrong), 7, "R", &wrong),
            "form == cookie but != expected"
        );
        assert!(check_csrf(&c, &with(&good), 7, "R", &good));
        // A cookie in a second Cookie header line still counts.
        let mut split = cookies("a=1");
        split.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{CSRF_COOKIE}={good}")).unwrap(),
        );
        assert!(check_csrf(&c, &split, 7, "R", &good));
    }

    /// The cli_device input shape (no domain tag, raw req instead of its hash)
    /// under the same key never validates here.
    #[test]
    fn check_csrf_rejects_a_cli_device_token() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let c = cfg();
        let mut mac = Hmac::<Sha256>::new_from_slice(c.csrf_key()).unwrap();
        mac.update(7i64.to_le_bytes().as_slice());
        mac.update(b":");
        mac.update(b"R");
        let cli =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let h = cookies(&format!("{CSRF_COOKIE}={cli}"));
        assert!(!check_csrf(&c, &h, 7, "R", &cli));
    }

    #[test]
    fn csrf_cookie_attributes() {
        // Lib tests run with the default "/drust" base and without
        // DRUST_DEV_NO_SECURE_COOKIES.
        assert_eq!(
            build_csrf_cookie("abc"),
            "drust_mcp_oauth_csrf=abc; Path=/drust; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
        );
        assert_eq!(
            clear_csrf_cookie(),
            "drust_mcp_oauth_csrf=; Path=/drust; HttpOnly; SameSite=Lax; Max-Age=0; Secure"
        );
    }

    #[test]
    fn fail_status_and_kind_table() {
        use Fail::*;
        let table = [
            (NoRequest, 400, "consent_no_request"),
            (BadForm, 400, "consent_malformed"),
            (Malformed, 400, "consent_malformed"),
            (BadMac, 400, "consent_bad_mac"),
            (Expired, 400, "consent_expired"),
            (Mismatch, 403, "consent_mismatch"),
            (ClientChanged, 400, "consent_client_changed"),
            (Csrf, 403, "consent_csrf"),
            (AdminMissing, 403, "consent_admin_missing"),
            (Internal, 500, "consent_internal"),
        ];
        for (f, status, kind) in table {
            assert_eq!(f.status().as_u16(), status, "{f:?}");
            assert_eq!(f.error_kind().code(), kind, "{f:?}");
        }
    }

    #[test]
    fn bind_rechecks_the_pinned_client_and_redirect() {
        let c = cfg();
        let now = 1_800_000_000;
        let seal = |client_id: &str, redirect_uri: &str| {
            envelope::seal(
                &c,
                &AuthzRequest {
                    client_id: client_id.into(),
                    redirect_uri: redirect_uri.into(),
                    state: Some("s".into()),
                    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
                    resource: None,
                },
                now,
            )
            .unwrap()
        };
        let ok = seal(CC, "http://localhost:5/callback");
        let b = bind(&c, &ok, now).ok().unwrap();
        assert_eq!(b.redirect.host, "localhost");
        assert_eq!(b.redirect.port, Some(5));
        for (client_id, redirect_uri) in [
            (CC, "http://localhost.evil.com/callback"),
            (CC, "http://127.0.0.1@evil.com/callback"),
            (CC, "http://localhost:1/other"),
            ("https://evil.example/cimd", "http://localhost:5/callback"),
        ] {
            let w = seal(client_id, redirect_uri);
            assert_eq!(
                bind(&c, &w, now).err(),
                Some(Fail::ClientChanged),
                "{redirect_uri}"
            );
            assert_eq!(return_link(&c, &w, now), None, "{redirect_uri}");
        }
        assert_eq!(bind(&c, &ok, now + 600).err(), Some(Fail::Expired));
        assert_eq!(bind(&c, &ok, u64::MAX).err(), Some(Fail::Expired));
        assert_eq!(bind(&c, "!!", now).err(), Some(Fail::Malformed));
        assert_eq!(bind(&other_key_cfg(), &ok, now).err(), Some(Fail::BadMac));
        // An expired envelope still yields its return link; a forged one does not.
        assert_eq!(
            return_link(&c, &ok, now + 600).as_deref(),
            Some(
                "http://localhost:5/callback?error=access_denied&state=s&iss=https%3A%2F%2Fdrust.test%2Fdrust"
            )
        );
        assert_eq!(return_link(&other_key_cfg(), &ok, now), None);
    }

    /// Source pin: the plaintext code (`nc.code`) and the redirect it rides
    /// (`loc`, `location`) never appear in a `tracing::` call or an audit
    /// `with_extra(` argument. Identifiers are matched whole, so `locale` and
    /// `AuthzErrorCode` do not count; log messages therefore avoid the word.
    #[test]
    fn plaintext_code_never_reaches_logs_or_audit() {
        let prod = include_str!("consent.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let mut checked = 0;
        for opener in ["tracing::", "with_extra("] {
            let mut rest = prod;
            while let Some(i) = rest.find(opener) {
                let tail = &rest[i..];
                let end = tail.find(';').unwrap_or(tail.len());
                let stmt = &tail[..end];
                assert!(!stmt.contains("nc.code"), "{stmt}");
                for ident in stmt.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                    assert!(
                        !matches!(ident, "code" | "loc" | "location"),
                        "identifier `{ident}` in: {stmt}"
                    );
                }
                checked += 1;
                rest = &tail[opener.len()..];
            }
        }
        assert!(checked >= 5, "only {checked} log/audit sites scanned");
    }
}

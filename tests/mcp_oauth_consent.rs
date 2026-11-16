//! MA0-6 — the consent page, approve and deny: cookie-only (an admin PAT is
//! refused), browser binding (resume cookie == req), double-submit CSRF bound
//! to the admin and the request, re-validation of the pinned client and
//! redirect, the cookie-clearing rules, the page's content and headers, and
//! what approve writes. Every request goes through the production router at
//! ROOT paths; only `Location`, cookie `Path` and form `action` carry `/drust`.
//!
//! An error page is identified by its status AND `data-kind="consent_…"` on
//! the banner, never by translated copy.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use drust::mgmt::mcp_oauth::config::McpOauthConfig;
use drust::mgmt::mcp_oauth::consent::{CSRF_COOKIE, csrf_for};
use drust::mgmt::mcp_oauth::envelope::{self, AuthzRequest, RESUME_COOKIE};

use crate::common::mcp_oauth::*;

// ─── file-private helpers ────────────────────────────────────────────────────

/// Mints an admin session directly (no argon2, no login budget). Tests about
/// the login itself use `login`.
async fn session_for(fx: &McpOauthFixture, admin_id: i64) -> String {
    let mut c = fx.meta.lock().await;
    let token = drust::auth::session::create_session(&mut c, admin_id, 3600).unwrap();
    format!("drust_session={token}")
}

fn now() -> u64 {
    envelope::now_unix().unwrap()
}

fn cfg() -> McpOauthConfig {
    McpOauthConfig::for_tests(PUBLIC_URL)
}

fn hdr(resp: &Response<Body>, name: header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_string())
}

fn set_cookie_lines(resp: &Response<Body>) -> Vec<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

fn clears(resp: &Response<Body>, name: &str) -> bool {
    set_cookie_lines(resp)
        .iter()
        .any(|l| l.starts_with(&format!("{name}=;")) && l.contains("Max-Age=0"))
}

fn query_keys(url: &str) -> Vec<String> {
    let (_, q) = url.split_once('?').unwrap();
    url::form_urlencoded::parse(q.as_bytes())
        .map(|(k, _)| k.into_owned())
        .collect()
}

async fn grants(fx: &McpOauthFixture) -> i64 {
    count(
        &*fx.meta.lock().await,
        "SELECT COUNT(*) FROM _mcp_oauth_grants",
    )
}

async fn codes(fx: &McpOauthFixture) -> i64 {
    count(
        &*fx.meta.lock().await,
        "SELECT COUNT(*) FROM _mcp_oauth_codes",
    )
}

/// Asserts an HTML consent error page of `status` and `kind`, with no
/// `Location`; returns its body.
async fn error_page(resp: Response<Body>, status: StatusCode, kind: &str) -> String {
    assert_eq!(resp.status(), status, "{kind}");
    assert!(
        hdr(&resp, header::CONTENT_TYPE)
            .unwrap_or_default()
            .starts_with("text/html"),
        "{kind}: not HTML"
    );
    assert!(hdr(&resp, header::LOCATION).is_none(), "{kind}: Location");
    let body = body_text(resp).await;
    assert!(
        body.contains(&format!("data-kind=\"{kind}\"")),
        "expected data-kind={kind}: {body}"
    );
    body
}

/// What a browser holds after authorize: the consent path to GET, the resume
/// cookie `name=value` and the envelope itself.
struct Authorized {
    consent_uri: String,
    resume: String,
    wire: String,
}

async fn authorize_as(
    fx: &McpOauthFixture,
    session: Option<&str>,
    redirect_uri: &str,
    state: Option<&str>,
    resource: Option<&str>,
) -> Authorized {
    let (_verifier, challenge) = pkce();
    let q = authorize_query(&challenge, redirect_uri, state, resource);
    let cookies: Vec<&str> = session.into_iter().collect();
    let resp = get(&fx.app, &format!("/oauth/authorize?{q}"), &cookies).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize");
    let loc = location(&resp);
    Authorized {
        consent_uri: router_path(&loc),
        resume: cookie_kv(&set_cookie(&resp, RESUME_COOKIE).expect("resume cookie")),
        wire: query_param(&loc, "req").expect("req in the consent Location"),
    }
}

/// A browser sitting on the consent page.
struct AtConsent {
    session: String,
    resume: String,
    csrf_cookie: String,
    req: String,
    csrf: String,
    html: String,
}

impl AtConsent {
    fn form(&self) -> Vec<(&str, &str)> {
        vec![("req", &self.req), ("csrf", &self.csrf)]
    }
    fn cookies(&self) -> Vec<&str> {
        vec![&self.session, &self.resume, &self.csrf_cookie]
    }
}

async fn open_consent_at(
    fx: &McpOauthFixture,
    session: &str,
    redirect_uri: &str,
    state: Option<&str>,
    resource: Option<&str>,
) -> AtConsent {
    let a = authorize_as(fx, Some(session), redirect_uri, state, resource).await;
    let resp = get(&fx.app, &a.consent_uri, &[session, &a.resume]).await;
    assert_eq!(resp.status(), StatusCode::OK, "consent page");
    let csrf_cookie = cookie_kv(&set_cookie(&resp, CSRF_COOKIE).expect("csrf cookie"));
    let html = body_text(resp).await;
    AtConsent {
        session: session.to_string(),
        resume: a.resume,
        csrf_cookie,
        req: hidden_field(&html, "req").expect("req field"),
        csrf: hidden_field(&html, "csrf").expect("csrf field"),
        html,
    }
}

async fn open_consent(fx: &McpOauthFixture, session: &str) -> AtConsent {
    open_consent_at(
        fx,
        session,
        &loopback_redirect(53682),
        Some("st"),
        Some(RESOURCE),
    )
    .await
}

async fn approve(fx: &McpOauthFixture, pairs: &[(&str, &str)], cookies: &[&str]) -> Response<Body> {
    post_form(&fx.app, "/oauth/consent/approve", pairs, cookies, &[]).await
}

async fn deny(fx: &McpOauthFixture, pairs: &[(&str, &str)], cookies: &[&str]) -> Response<Body> {
    post_form(&fx.app, "/oauth/consent/deny", pairs, cookies, &[]).await
}

/// Flips one base64url character in the middle (inside the nonce), so the
/// wire stays canonical and opens as BadMac, not Malformed.
fn tamper(wire: &str) -> String {
    let mut b = wire.as_bytes().to_vec();
    b[20] = if b[20] == b'A' { b'B' } else { b'A' };
    String::from_utf8(b).unwrap()
}

/// An enabled fixture's owner, signed in.
async fn signed_in() -> (McpOauthFixture, String) {
    let fx = fixture(true).await;
    let s = session_for(&fx, fx.owner_id).await;
    (fx, s)
}

/// Revokes admin 1's PATs and inserts a fresh one (tests/admin_pat_admin_plane.rs).
async fn seed_pat(fx: &McpOauthFixture) -> String {
    let pat = drust::auth::admin_token::generate_token();
    let c = fx.meta.lock().await;
    c.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') \
         WHERE admin_id = ?1 AND revoked_at IS NULL",
        rusqlite::params![fx.owner_id],
    )
    .unwrap();
    c.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (?1, ?2)",
        rusqlite::params![fx.owner_id, drust::auth::admin_token::hash_token(&pat)],
    )
    .unwrap();
    pat
}

async fn send_with(
    fx: &McpOauthFixture,
    method: &str,
    uri: &str,
    cookies: &[&str],
    headers: &[(&str, &str)],
    body: &str,
) -> Response<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if !cookies.is_empty() {
        b = b.header(header::COOKIE, cookies.join("; "));
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    send(&fx.app, b.body(Body::from(body.to_string())).unwrap()).await
}

async fn assert_cookie_required(resp: Response<Body>) {
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        hdr(&resp, header::CONTENT_TYPE)
            .unwrap_or_default()
            .starts_with("application/json")
    );
    assert!(hdr(&resp, header::LOCATION).is_none());
    assert!(set_cookie_lines(&resp).is_empty());
    let v = body_json(resp).await;
    assert_eq!(v["error_code"], "MCP_CONSENT_COOKIE_REQUIRED", "{v}");
}

// ─── B. flow (browser binding) ───────────────────────────────────────────────

#[tokio::test]
async fn query_only_consent_is_refused_at_get() {
    let (fx, session) = signed_in().await;
    let wire = sealed_envelope(&cfg(), &loopback_redirect(53682), Some("st"), now());
    let resp = get(&fx.app, &format!("/oauth/consent?req={wire}"), &[&session]).await;
    assert!(
        set_cookie_lines(&resp).is_empty(),
        "no cookie written or cleared"
    );
    let body = error_page(resp, StatusCode::FORBIDDEN, "consent_mismatch").await;
    assert!(
        body.contains("href=\"http://localhost:53682/callback?error=access_denied"),
        "return link to the envelope's redirect: {body}"
    );
    // Approving it with a self-computed, consistent csrf is refused the same way.
    let csrf = csrf_for(&cfg(), fx.owner_id, &wire);
    let csrf_cookie = format!("{CSRF_COOKIE}={csrf}");
    let resp = approve(
        &fx,
        &[("req", &wire), ("csrf", &csrf)],
        &[&session, &csrf_cookie],
    )
    .await;
    error_page(resp, StatusCode::FORBIDDEN, "consent_mismatch").await;
    assert_eq!(grants(&fx).await, 0);
}

#[tokio::test]
async fn approve_without_state_has_no_state_key() {
    let (fx, session) = signed_in().await;
    let c = open_consent_at(&fx, &session, &loopback_redirect(5), None, Some(RESOURCE)).await;
    let resp = approve(&fx, &c.form(), &c.cookies()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert_eq!(query_param(&loc, "state"), None);
    assert!(!loc.contains("state="), "{loc}");
    assert_eq!(query_keys(&loc), ["code", "iss"]);
}

/// Pins today's behaviour (MA0-PLAN §3.8.7's abandoned-grant sweep is the
/// counterpart): no idempotence, no UNIQUE — a double click makes two grants.
#[tokio::test]
async fn double_approve_of_one_envelope_creates_two_grants() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    let r1 = approve(&fx, &c.form(), &c.cookies()).await;
    let r2 = approve(&fx, &c.form(), &c.cookies()).await;
    assert_eq!(r1.status(), StatusCode::SEE_OTHER);
    assert_eq!(r2.status(), StatusCode::SEE_OTHER);
    let c1 = query_param(&location(&r1), "code").unwrap();
    let c2 = query_param(&location(&r2), "code").unwrap();
    assert_ne!(c1, c2);
    assert_eq!(grants(&fx).await, 2);
    assert_eq!(codes(&fx).await, 2);
}

// ─── C. cookie only ──────────────────────────────────────────────────────────

#[tokio::test]
async fn pat_get_consent_is_refused() {
    let fx = fixture(true).await;
    let pat = seed_pat(&fx).await;
    let a = authorize_as(&fx, None, &loopback_redirect(53682), Some("st"), None).await;
    let resp = send_with(
        &fx,
        "GET",
        &a.consent_uri,
        &[&a.resume],
        &[("authorization", &format!("Bearer {pat}"))],
        "",
    )
    .await;
    assert_cookie_required(resp).await;
}

#[tokio::test]
async fn pat_approve_with_a_fully_valid_form_is_refused() {
    let (fx, session) = signed_in().await;
    let pat = seed_pat(&fx).await;
    let c = open_consent(&fx, &session).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(c.form())
        .finish();
    let resp = send_with(
        &fx,
        "POST",
        "/oauth/consent/approve",
        &[&c.resume, &c.csrf_cookie],
        &[
            ("authorization", &format!("Bearer {pat}")),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        &body,
    )
    .await;
    assert_cookie_required(resp).await;
    assert_eq!(grants(&fx).await, 0, "refused by AuthMethod, not by CSRF");
}

#[tokio::test]
async fn pat_deny_is_refused() {
    let (fx, session) = signed_in().await;
    let pat = seed_pat(&fx).await;
    let c = open_consent(&fx, &session).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(c.form())
        .finish();
    let resp = send_with(
        &fx,
        "POST",
        "/oauth/consent/deny",
        &[&c.resume, &c.csrf_cookie],
        &[
            ("authorization", &format!("Bearer {pat}")),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        &body,
    )
    .await;
    assert_cookie_required(resp).await;
}

#[tokio::test]
async fn pat_approve_with_an_empty_body_is_refused_not_422() {
    let fx = fixture(true).await;
    let pat = seed_pat(&fx).await;
    for ct in ["application/x-www-form-urlencoded", "text/plain"] {
        let resp = send_with(
            &fx,
            "POST",
            "/oauth/consent/approve",
            &[],
            &[
                ("authorization", &format!("Bearer {pat}")),
                ("content-type", ct),
            ],
            "",
        )
        .await;
        assert_cookie_required(resp).await;
    }
}

#[tokio::test]
async fn browser_session_with_a_pat_header_still_approves() {
    let (fx, session) = signed_in().await;
    let pat = seed_pat(&fx).await;
    let c = open_consent(&fx, &session).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(c.form())
        .finish();
    let resp = send_with(
        &fx,
        "POST",
        "/oauth/consent/approve",
        &c.cookies(),
        &[
            ("authorization", &format!("Bearer {pat}")),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        &body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(grants(&fx).await, 1);
}

// ─── D. CSRF and binding ─────────────────────────────────────────────────────

#[tokio::test]
async fn approve_without_csrf_field_is_refused() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    let resp = approve(&fx, &[("req", &c.req)], &c.cookies()).await;
    error_page(resp, StatusCode::FORBIDDEN, "consent_csrf").await;
    assert_eq!(grants(&fx).await, 0);
}

#[tokio::test]
async fn approve_with_cookie_and_field_mismatch_is_refused() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    let bad_cookie = format!("{CSRF_COOKIE}={}", tamper(&c.csrf));
    let resp = approve(&fx, &c.form(), &[&c.session, &c.resume, &bad_cookie]).await;
    error_page(resp, StatusCode::FORBIDDEN, "consent_csrf").await;
    assert_eq!(grants(&fx).await, 0);
}

#[tokio::test]
async fn approve_with_another_admins_csrf_is_refused() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    let m1 = add_admin(&fx, "m1", "", "member").await;
    let m1_session = session_for(&fx, m1).await;
    let resp = approve(&fx, &c.form(), &[&m1_session, &c.resume, &c.csrf_cookie]).await;
    error_page(resp, StatusCode::FORBIDDEN, "consent_csrf").await;
    assert_eq!(grants(&fx).await, 0);
}

#[tokio::test]
async fn approve_with_req_not_equal_to_resume_cookie_is_refused() {
    let (fx, session) = signed_in().await;
    let x = open_consent_at(&fx, &session, &loopback_redirect(1111), Some("x"), None).await;
    let y = open_consent_at(&fx, &session, &loopback_redirect(2222), Some("y"), None).await;
    // The browser now holds Y's resume and csrf cookies; tab X submits.
    let resp = approve(&fx, &x.form(), &[&session, &y.resume, &y.csrf_cookie]).await;
    assert!(!clears(&resp, RESUME_COOKIE), "resume cookie kept");
    assert!(!clears(&resp, CSRF_COOKIE), "csrf cookie kept");
    assert!(set_cookie_lines(&resp).is_empty());
    let body = error_page(resp, StatusCode::FORBIDDEN, "consent_mismatch").await;
    assert!(body.contains("http://localhost:1111/callback?error=access_denied"));
    assert_eq!(grants(&fx).await, 0);
    // Tab Y was not disturbed.
    let resp = approve(&fx, &y.form(), &y.cookies()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("http://localhost:2222/callback?code="));
}

#[tokio::test]
async fn approve_without_resume_cookie_is_refused() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    let resp = approve(&fx, &c.form(), &[&c.session, &c.csrf_cookie]).await;
    assert!(set_cookie_lines(&resp).is_empty());
    error_page(resp, StatusCode::FORBIDDEN, "consent_mismatch").await;
    assert_eq!(grants(&fx).await, 0);
}

#[tokio::test]
async fn approve_with_another_mac_valid_envelope_is_refused() {
    let (fx, session) = signed_in().await;
    let x = open_consent(&fx, &session).await;
    let y = authorize_as(&fx, Some(&session), &loopback_redirect(2222), None, None).await;
    // Resume cookie and req are both Y; the csrf (cookie and field) was minted for X.
    let resp = approve(
        &fx,
        &[("req", &y.wire), ("csrf", &x.csrf)],
        &[&session, &y.resume, &x.csrf_cookie],
    )
    .await;
    assert!(set_cookie_lines(&resp).is_empty());
    error_page(resp, StatusCode::FORBIDDEN, "consent_csrf").await;
    assert_eq!(grants(&fx).await, 0);
}

#[tokio::test]
async fn deny_requires_csrf() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    let resp = deny(&fx, &[("req", &c.req)], &c.cookies()).await;
    error_page(resp, StatusCode::FORBIDDEN, "consent_csrf").await;
}

#[tokio::test]
async fn duplicate_req_or_csrf_is_refused() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    for pairs in [
        vec![
            ("req", c.req.as_str()),
            ("req", c.req.as_str()),
            ("csrf", c.csrf.as_str()),
        ],
        vec![
            ("req", c.req.as_str()),
            ("csrf", c.csrf.as_str()),
            ("csrf", c.csrf.as_str()),
        ],
    ] {
        let resp = approve(&fx, &pairs, &c.cookies()).await;
        assert!(
            set_cookie_lines(&resp).is_empty(),
            "form level clears nothing"
        );
        error_page(resp, StatusCode::BAD_REQUEST, "consent_malformed").await;
    }
    // An empty csrf is dropped at parse time = missing -> the CSRF check refuses.
    let resp = approve(&fx, &[("req", &c.req), ("csrf", "")], &c.cookies()).await;
    error_page(resp, StatusCode::FORBIDDEN, "consent_csrf").await;
    // The page itself is not tricked by a repeated req either.
    let q = format!("/oauth/consent?req={0}&req={0}", c.req);
    let resp = get(&fx.app, &q, &[&c.session, &c.resume]).await;
    assert!(set_cookie_lines(&resp).is_empty());
    error_page(resp, StatusCode::BAD_REQUEST, "consent_malformed").await;
    assert_eq!(grants(&fx).await, 0);
}

/// MAC-valid envelopes that fail the pinned check (seal only checks field
/// lengths): a look-alike host, userinfo, an unpinned client. Strings from the
/// MA0-5 redirect corpus, so authorize and approve share one predicate.
#[tokio::test]
async fn approve_rechecks_client_and_redirect() {
    let (fx, session) = signed_in().await;
    let cases = [
        (CC_CLIENT_ID, "http://localhost.evil.com/callback"),
        (CC_CLIENT_ID, "http://127.0.0.1@evil.com/callback"),
        ("https://evil.example/cimd", "http://localhost:5/callback"),
    ];
    for (client_id, redirect_uri) in cases {
        let wire = envelope::seal(
            &cfg(),
            &AuthzRequest {
                client_id: client_id.into(),
                redirect_uri: redirect_uri.into(),
                state: Some("s".into()),
                code_challenge: FIXED_CHALLENGE.into(),
                resource: None,
            },
            now(),
        )
        .unwrap();
        let csrf = csrf_for(&cfg(), fx.owner_id, &wire);
        let resume = format!("{RESUME_COOKIE}={wire}");
        let csrf_cookie = format!("{CSRF_COOKIE}={csrf}");
        let resp = approve(
            &fx,
            &[("req", &wire), ("csrf", &csrf)],
            &[&session, &resume, &csrf_cookie],
        )
        .await;
        assert!(clears(&resp, RESUME_COOKIE), "{redirect_uri}");
        assert!(clears(&resp, CSRF_COOKIE), "{redirect_uri}");
        let body = error_page(resp, StatusCode::BAD_REQUEST, "consent_client_changed").await;
        assert!(
            !body.contains("/callback?"),
            "no return link: {redirect_uri}"
        );
    }
    assert_eq!(grants(&fx).await, 0);
    assert_eq!(codes(&fx).await, 0);
}

// ─── E. envelope errors and the return link ──────────────────────────────────

#[tokio::test]
async fn expired_envelope_on_consent_offers_a_return_link() {
    let (fx, session) = signed_in().await;
    let wire = sealed_envelope(&cfg(), &loopback_redirect(5), Some("s1"), now() - 700);
    let resume = format!("{RESUME_COOKIE}={wire}");
    let resp = get(
        &fx.app,
        &format!("/oauth/consent?req={wire}"),
        &[&session, &resume],
    )
    .await;
    assert!(
        clears(&resp, RESUME_COOKIE),
        "this browser's dead resume cookie"
    );
    assert!(!clears(&resp, CSRF_COOKIE), "a GET never clears csrf");
    let body = error_page(resp, StatusCode::BAD_REQUEST, "consent_expired").await;
    assert!(
        body.contains(
            "href=\"http://localhost:5/callback?error=access_denied&#38;state=s1&#38;iss=https%3A%2F%2Fdrust.test%2Fdrust\""
        ),
        "{body}"
    );
}

#[tokio::test]
async fn expired_envelope_without_state_omits_the_state_key() {
    let (fx, session) = signed_in().await;
    let wire = sealed_envelope(&cfg(), &loopback_redirect(5), None, now() - 700);
    let resume = format!("{RESUME_COOKIE}={wire}");
    let resp = get(&fx.app, "/oauth/consent", &[&session, &resume]).await;
    let body = error_page(resp, StatusCode::BAD_REQUEST, "consent_expired").await;
    assert!(body.contains("href=\"http://localhost:5/callback?error=access_denied&#38;iss="));
    assert!(!body.contains("state="), "{body}");
}

#[tokio::test]
async fn bad_mac_envelope_shows_an_error_without_a_return_link() {
    let (fx, session) = signed_in().await;
    let wire = tamper(&sealed_envelope(
        &cfg(),
        &loopback_redirect(5),
        Some("s"),
        now(),
    ));
    let resume = format!("{RESUME_COOKIE}={wire}");
    let resp = get(
        &fx.app,
        &format!("/oauth/consent?req={wire}"),
        &[&session, &resume],
    )
    .await;
    assert!(clears(&resp, RESUME_COOKIE));
    let body = error_page(resp, StatusCode::BAD_REQUEST, "consent_bad_mac").await;
    assert!(!body.contains("/callback?"), "{body}");
}

#[tokio::test]
async fn expired_envelope_on_approve_creates_no_grant() {
    let (fx, session) = signed_in().await;
    let wire = sealed_envelope(&cfg(), &loopback_redirect(5), Some("s1"), now() - 700);
    let csrf = csrf_for(&cfg(), fx.owner_id, &wire);
    let resume = format!("{RESUME_COOKIE}={wire}");
    let csrf_cookie = format!("{CSRF_COOKIE}={csrf}");
    let resp = approve(
        &fx,
        &[("req", &wire), ("csrf", &csrf)],
        &[&session, &resume, &csrf_cookie],
    )
    .await;
    assert!(clears(&resp, RESUME_COOKIE));
    assert!(clears(&resp, CSRF_COOKIE));
    let body = error_page(resp, StatusCode::BAD_REQUEST, "consent_expired").await;
    assert!(body.contains("href=\"http://localhost:5/callback?error=access_denied"));
    assert_eq!(grants(&fx).await, 0);
}

#[tokio::test]
async fn consent_query_and_cookie_disagree() {
    let (fx, session) = signed_in().await;
    let x = sealed_envelope(&cfg(), &loopback_redirect(1111), Some("x"), now());
    let y = sealed_envelope(&cfg(), &loopback_redirect(2222), Some("y"), now());
    let resume = format!("{RESUME_COOKIE}={y}");
    let resp = get(
        &fx.app,
        &format!("/oauth/consent?req={x}"),
        &[&session, &resume],
    )
    .await;
    assert!(set_cookie_lines(&resp).is_empty());
    let body = error_page(resp, StatusCode::FORBIDDEN, "consent_mismatch").await;
    assert!(body.contains("http://localhost:1111/callback?error=access_denied"));
    assert!(!body.contains("localhost:2222"));
}

#[tokio::test]
async fn no_request_at_all() {
    let (fx, session) = signed_in().await;
    let resp = get(&fx.app, "/oauth/consent", &[&session]).await;
    let body = error_page(resp, StatusCode::BAD_REQUEST, "consent_no_request").await;
    assert!(!body.contains("/callback?"));
}

// ─── F. deny ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn deny_redirects_access_denied_with_state_and_iss() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    let resp = deny(&fx, &c.form(), &c.cookies()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert_eq!(
        loc,
        "http://localhost:53682/callback?error=access_denied&state=st&iss=https%3A%2F%2Fdrust.test%2Fdrust"
    );
    assert_eq!(query_keys(&loc), ["error", "state", "iss"]);
    assert!(clears(&resp, RESUME_COOKIE));
    assert!(clears(&resp, CSRF_COOKIE));
    assert_eq!(
        hdr(&resp, header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    assert_eq!(grants(&fx).await, 0);
    assert_eq!(codes(&fx).await, 0);
}

#[tokio::test]
async fn deny_without_state_has_no_state_key() {
    let (fx, session) = signed_in().await;
    let c = open_consent_at(&fx, &session, &loopback_redirect(5), None, None).await;
    let resp = deny(&fx, &c.form(), &c.cookies()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert_eq!(query_param(&loc, "state"), None);
    assert_eq!(query_keys(&loc), ["error", "iss"]);
}

#[tokio::test]
async fn deny_rechecks_the_redirect() {
    let (fx, session) = signed_in().await;
    let wire = sealed_envelope(&cfg(), "http://localhost:1/other", Some("s"), now());
    let csrf = csrf_for(&cfg(), fx.owner_id, &wire);
    let resume = format!("{RESUME_COOKIE}={wire}");
    let csrf_cookie = format!("{CSRF_COOKIE}={csrf}");
    let resp = deny(
        &fx,
        &[("req", &wire), ("csrf", &csrf)],
        &[&session, &resume, &csrf_cookie],
    )
    .await;
    let body = error_page(resp, StatusCode::BAD_REQUEST, "consent_client_changed").await;
    assert!(!body.contains("/other?"), "{body}");
    assert!(!body.contains("/callback?"), "{body}");
}

// ─── G. the admins row ───────────────────────────────────────────────────────

/// FK off: `sessions` -> `admins` has no CASCADE, and `validate_session` does
/// not join `admins`, so the session still reaches the handler.
async fn delete_admin_row(fx: &McpOauthFixture, id: i64) {
    let c = fx.meta.lock().await;
    c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    c.execute("DELETE FROM admins WHERE id = ?1", rusqlite::params![id])
        .unwrap();
    c.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
}

#[tokio::test]
async fn admin_row_deleted_between_consent_and_approve_creates_no_grant() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    delete_admin_row(&fx, fx.owner_id).await;
    let resp = approve(&fx, &c.form(), &c.cookies()).await;
    error_page(resp, StatusCode::FORBIDDEN, "consent_admin_missing").await;
    assert_eq!(grants(&fx).await, 0);
    assert_eq!(codes(&fx).await, 0);
}

#[tokio::test]
async fn consent_for_a_missing_admin_row_is_an_error_not_member_zero() {
    let (fx, session) = signed_in().await;
    let a = authorize_as(&fx, Some(&session), &loopback_redirect(5), None, None).await;
    delete_admin_row(&fx, fx.owner_id).await;
    let resp = get(&fx.app, &a.consent_uri, &[&session, &a.resume]).await;
    let body = error_page(resp, StatusCode::FORBIDDEN, "consent_admin_missing").await;
    assert!(
        !body.contains("every tenant your account can see"),
        "{body}"
    );
}

#[tokio::test]
async fn removed_admin_session_cannot_approve() {
    let (fx, owner_session) = signed_in().await;
    let m1 = add_admin(&fx, "m1", "", "member").await;
    let m1_session = session_for(&fx, m1).await;
    let c = open_consent(&fx, &m1_session).await;
    let resp = send_with(
        &fx,
        "DELETE",
        &format!("/admin/team/{m1}"),
        &[&owner_session],
        &[],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "remove_admin");
    let resp = approve(&fx, &c.form(), &c.cookies()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        "/drust/login",
        "stopped by admin_session_layer"
    );
    assert_eq!(grants(&fx).await, 0);
}

// ─── H. headers ──────────────────────────────────────────────────────────────

fn assert_frame_guarded(resp: &Response<Body>) {
    let csp: Vec<_> = resp
        .headers()
        .get_all("content-security-policy")
        .iter()
        .collect();
    assert_eq!(
        csp.len(),
        1,
        "exactly one CSP (the page sets none of its own)"
    );
    assert_eq!(csp[0], "frame-ancestors 'none'");
    assert_eq!(hdr(resp, header::X_FRAME_OPTIONS).as_deref(), Some("DENY"));
}

#[tokio::test]
async fn consent_page_headers() {
    let (fx, session) = signed_in().await;
    let a = authorize_as(&fx, Some(&session), &loopback_redirect(5), None, None).await;
    let resp = get(&fx.app, &a.consent_uri, &[&session, &a.resume]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        hdr(&resp, header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    assert_eq!(
        hdr(&resp, header::REFERRER_POLICY).as_deref(),
        Some("no-referrer")
    );
    assert_frame_guarded(&resp);
}

#[tokio::test]
async fn approve_and_deny_redirect_headers() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    let a = approve(&fx, &c.form(), &c.cookies()).await;
    let c = open_consent(&fx, &session).await;
    let d = deny(&fx, &c.form(), &c.cookies()).await;
    for resp in [a, d] {
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            hdr(&resp, header::CACHE_CONTROL).as_deref(),
            Some("no-store")
        );
        assert_eq!(
            hdr(&resp, header::REFERRER_POLICY).as_deref(),
            Some("no-referrer")
        );
    }
}

#[tokio::test]
async fn error_pages_have_no_store_and_no_location() {
    let (fx, session) = signed_in().await;
    // The bad-MAC GET page.
    let wire = tamper(&sealed_envelope(
        &cfg(),
        &loopback_redirect(5),
        Some("s"),
        now(),
    ));
    let resume = format!("{RESUME_COOKIE}={wire}");
    let bad_mac = get(&fx.app, "/oauth/consent", &[&session, &resume]).await;
    // The missing-csrf approve page.
    let c = open_consent(&fx, &session).await;
    let no_csrf = approve(&fx, &[("req", &c.req)], &c.cookies()).await;
    for (resp, kind) in [(bad_mac, "consent_bad_mac"), (no_csrf, "consent_csrf")] {
        assert_eq!(
            hdr(&resp, header::CACHE_CONTROL).as_deref(),
            Some("no-store"),
            "{kind}"
        );
        assert_eq!(
            hdr(&resp, header::REFERRER_POLICY).as_deref(),
            Some("no-referrer"),
            "{kind}"
        );
        assert!(hdr(&resp, header::LOCATION).is_none(), "{kind}");
        assert_frame_guarded(&resp);
        let status = resp.status();
        error_page(resp, status, kind).await;
    }
}

// ─── I. content and counts ───────────────────────────────────────────────────

async fn insert_tenant(fx: &McpOauthFixture, id: &str, owner: Option<i64>, deleted: bool) {
    let c = fx.meta.lock().await;
    c.execute(
        "INSERT INTO tenants (id, name, owner_admin_id, deleted_at) \
         VALUES (?1, ?1, ?2, CASE WHEN ?3 THEN datetime('now') END)",
        rusqlite::params![id, owner, deleted],
    )
    .unwrap();
}

#[tokio::test]
async fn owner_sees_all_live_tenants_counted() {
    let (fx, session) = signed_in().await;
    insert_tenant(&fx, "t-owned", Some(fx.owner_id), false).await;
    insert_tenant(&fx, "t-gone", Some(fx.owner_id), true).await;
    insert_tenant(&fx, "t-orphan", None, false).await;
    let c = open_consent(&fx, &session).await;
    assert!(
        c.html.contains("every tenant on this host"),
        "scope_all copy"
    );
    assert!(c.html.contains("Currently 2."), "{}", c.html);
}

#[tokio::test]
async fn member_sees_only_owned_tenants_counted() {
    let fx = fixture(true).await;
    let m1 = add_admin(&fx, "m1", "", "member").await;
    insert_tenant(&fx, "t-m1", Some(m1), false).await;
    insert_tenant(&fx, "t-root", Some(fx.owner_id), false).await;
    insert_tenant(&fx, "t-orphan", None, false).await;
    let session = session_for(&fx, m1).await;
    let c = open_consent(&fx, &session).await;
    assert!(c.html.contains("the tenants you own"), "scope_owned copy");
    assert!(!c.html.contains("every tenant on this host"));
    assert!(c.html.contains("Currently 1."), "{}", c.html);
    assert!(c.html.contains("<strong>m1@example.test</strong> (member)"));
}

#[tokio::test]
async fn consent_page_shows_identity_next_to_the_buttons() {
    let (fx, session) = signed_in().await;
    fx.meta
        .lock()
        .await
        .execute(
            "UPDATE admins SET email = 'root@example.com' WHERE id = 1",
            [],
        )
        .unwrap();
    let c = open_consent(&fx, &session).await;
    let h = &c.html;
    assert!(h.contains("You are signed in as <strong>root@example.com</strong> (owner)."));
    assert!(h.contains("action=\"/drust/oauth/consent/approve\""));
    assert!(h.contains("action=\"/drust/oauth/consent/deny\""));
    assert!(h.contains("action=\"/drust/logout\""));
    assert!(h.contains("href=\"/drust/admin/tenants\""));
    assert!(h.contains("never give it to anyone"), "return_warn");
    assert!(h.contains("Allow Claude Code to use your drust account?"));
    assert!(h.contains("<strong>localhost:53682</strong>"));
    assert!(h.contains("Access tokens last 60 minutes"));
    assert!(h.contains("After 30 days without use, or 90 days in total"));
    // Identity sits right before the Authorize form.
    let who = h.find("You are signed in as").unwrap();
    let form = h.find("/oauth/consent/approve").unwrap();
    assert!(
        who < form && form - who < 400,
        "identity next to the buttons"
    );
    assert_eq!(
        c.req,
        query_param(&format!("?{}", c.resume), RESUME_COOKIE).unwrap()
    );
    assert_eq!(format!("{CSRF_COOKIE}={}", c.csrf), c.csrf_cookie);
}

#[tokio::test]
async fn bootstrap_admin_without_email_falls_back_to_username() {
    let (fx, session) = signed_in().await;
    let c = open_consent(&fx, &session).await;
    assert!(
        c.html
            .contains("You are signed in as <strong>root</strong> (owner)."),
        "{}",
        c.html
    );
}

#[tokio::test]
async fn redirect_127_is_shown_and_recorded() {
    let (fx, session) = signed_in().await;
    let c = open_consent_at(&fx, &session, "http://127.0.0.1:61000/callback", None, None).await;
    assert!(c.html.contains("<strong>127.0.0.1:61000</strong>"));
    let resp = approve(&fx, &c.form(), &c.cookies()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("http://127.0.0.1:61000/callback?code="));
    let host: String = fx
        .meta
        .lock()
        .await
        .query_row("SELECT redirect_host FROM _mcp_oauth_grants", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(host, "127.0.0.1");
}

#[tokio::test]
async fn zh_tw_page_renders_translated() {
    let (fx, session) = signed_in().await;
    let a = authorize_as(&fx, Some(&session), &loopback_redirect(5), None, None).await;
    let resp = send_with(
        &fx,
        "GET",
        &a.consent_uri,
        &[&session, &a.resume],
        &[("accept-language", "zh-TW")],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(html.contains("授權"), "{html}");
    assert!(html.contains("不要貼給任何人"));
    assert!(html.contains("（擁有者）登入"));
}

// ─── K. what approve writes ──────────────────────────────────────────────────

#[tokio::test]
async fn approve_writes_one_grant_and_one_code_hash_only() {
    let (fx, session) = signed_in().await;
    let redirect_uri = loopback_redirect(53682);
    let (_verifier, challenge) = pkce();
    let q = authorize_query(&challenge, &redirect_uri, Some("st"), Some(RESOURCE));
    let resp = get(&fx.app, &format!("/oauth/authorize?{q}"), &[&session]).await;
    let consent_uri = router_path(&location(&resp));
    let resume = cookie_kv(&set_cookie(&resp, RESUME_COOKIE).unwrap());
    let resp = get(&fx.app, &consent_uri, &[&session, &resume]).await;
    let csrf_cookie = cookie_kv(&set_cookie(&resp, CSRF_COOKIE).unwrap());
    let html = body_text(resp).await;
    let req = hidden_field(&html, "req").unwrap();
    let csrf = hidden_field(&html, "csrf").unwrap();
    let resp = approve(
        &fx,
        &[("req", &req), ("csrf", &csrf)],
        &[&session, &resume, &csrf_cookie],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    let code = query_param(&loc, "code").unwrap();
    assert_eq!(code.len(), 43);
    assert_eq!(query_param(&loc, "iss").as_deref(), Some(ISSUER));
    assert!(clears(&resp, RESUME_COOKIE));
    assert!(clears(&resp, CSRF_COOKIE));

    let c = fx.meta.lock().await;
    assert_eq!(count(&c, "SELECT COUNT(*) FROM _mcp_oauth_grants"), 1);
    assert_eq!(count(&c, "SELECT COUNT(*) FROM _mcp_oauth_codes"), 1);
    let ok: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM _mcp_oauth_grants g \
              WHERE g.admin_id = ?1 \
                AND g.admin_created_at = (SELECT created_at FROM admins WHERE id = ?1) \
                AND g.client_id = ?2 AND g.redirect_host = 'localhost' \
                AND g.scope = 'mcp' AND g.kind = 'authorization_code' \
                AND g.absolute_expires_at = datetime(g.created_at, '+90 days') \
                AND g.idle_expires_at = datetime(g.created_at, '+30 days') \
                AND g.revoked_at IS NULL AND g.last_used_at IS NULL",
            rusqlite::params![fx.owner_id, CC_CLIENT_ID],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ok, 1, "grant row shape");
    let ok: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM _mcp_oauth_codes k \
               JOIN _mcp_oauth_grants g ON g.id = k.grant_id \
              WHERE k.code_hash = ?1 AND k.client_id = ?2 AND k.redirect_uri = ?3 \
                AND k.code_challenge = ?4 AND k.resource = ?5 \
                AND k.expires_at = datetime(k.created_at, '+300 seconds') \
                AND k.redeemed_at IS NULL",
            rusqlite::params![
                drust::mgmt::mcp_oauth::tokens::hash(
                    drust::mgmt::mcp_oauth::tokens::TokenKind::Code,
                    &code
                ),
                CC_CLIENT_ID,
                redirect_uri,
                challenge,
                RESOURCE
            ],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ok, 1, "code row shape");
    // The plaintext code is stored nowhere.
    let mut scanned = 0;
    for table in [
        "_mcp_oauth_grants",
        "_mcp_oauth_codes",
        "_mcp_oauth_refresh",
        "_mcp_oauth_access",
        "_mcp_upload_tickets",
    ] {
        let mut st = c.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let n = st.column_count();
        let mut rows = st.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..n {
                if let rusqlite::types::ValueRef::Text(t) = row.get_ref(i).unwrap() {
                    scanned += 1;
                    assert!(
                        !String::from_utf8_lossy(t).contains(&code),
                        "{table} column {i}"
                    );
                }
            }
        }
    }
    assert!(scanned > 5, "scanned {scanned} text cells");
}

#[tokio::test]
async fn authorize_without_resource_stores_null() {
    let (fx, session) = signed_in().await;
    let c = open_consent_at(&fx, &session, &loopback_redirect(5), None, None).await;
    let resp = approve(&fx, &c.form(), &c.cookies()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        count(
            &*fx.meta.lock().await,
            "SELECT COUNT(*) FROM _mcp_oauth_codes WHERE resource IS NULL"
        ),
        1
    );
}

fn store_request() -> (
    AuthzRequest,
    drust::mgmt::mcp_oauth::redirect::RedirectTarget,
) {
    let client = drust::mgmt::mcp_oauth::clients::find_client(CC_CLIENT_ID).unwrap();
    let raw = loopback_redirect(5);
    let target = drust::mgmt::mcp_oauth::redirect::redirect_uri_allowed(client, &raw).unwrap();
    let req = AuthzRequest {
        client_id: CC_CLIENT_ID.into(),
        redirect_uri: raw,
        state: None,
        code_challenge: FIXED_CHALLENGE.into(),
        resource: None,
    };
    (req, target)
}

#[tokio::test]
async fn insert_grant_and_code_caps_idle_at_absolute() {
    let ttls = || cfg().with_ttls_for_tests(3600, 60, 30, 10);
    let fx = fixture_with(ttls()).await;
    let (req, target) = store_request();
    let c = fx.meta.lock().await;
    let tx = c.unchecked_transaction().unwrap();
    let nc = drust::mgmt::mcp_oauth::store::insert_grant_and_code(
        &tx,
        &ttls(),
        fx.owner_id,
        &req,
        &target,
    )
    .unwrap();
    tx.commit().unwrap();
    let (idle_eq_abs, abs_is_10d): (bool, bool) = c
        .query_row(
            "SELECT idle_expires_at = absolute_expires_at, \
                    absolute_expires_at = datetime(created_at, '+10 days') \
               FROM _mcp_oauth_grants WHERE id = ?1",
            rusqlite::params![nc.grant_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(idle_eq_abs, "idle is capped at absolute");
    assert!(abs_is_10d);
}

#[tokio::test]
async fn insert_grant_and_code_for_a_missing_admin_is_no_rows() {
    let fx = fixture(true).await;
    let (req, target) = store_request();
    let c = fx.meta.lock().await;
    let tx = c.unchecked_transaction().unwrap();
    let r = drust::mgmt::mcp_oauth::store::insert_grant_and_code(&tx, &cfg(), 9_999, &req, &target);
    assert!(matches!(r, Err(rusqlite::Error::QueryReturnedNoRows)));
    drop(tx);
    assert_eq!(count(&c, "SELECT COUNT(*) FROM _mcp_oauth_grants"), 0);
    assert_eq!(count(&c, "SELECT COUNT(*) FROM _mcp_oauth_codes"), 0);
}

// ─── A. login without (or with a dead) resume cookie ─────────────────────────

const LANDING: &str = "/drust/admin/tenants";
const CONSENT: &str = "/drust/oauth/consent";

async fn password_login(
    fx: &McpOauthFixture,
    cookies: &[&str],
    headers: &[(&str, &str)],
) -> Response<Body> {
    post_form(
        &fx.app,
        "/login",
        &[("username", OWNER_USER), ("password", OWNER_PASS)],
        cookies,
        headers,
    )
    .await
}

/// `/admin/oauth/<provider>/start`, then its callback with the start's state
/// and PKCE cookies plus `extra` (one callback of the fixture's budget of 5).
async fn provider_login(fx: &McpOauthFixture, provider: &str, extra: &[&str]) -> Response<Body> {
    let start = get(&fx.app, &format!("/admin/oauth/{provider}/start"), &[]).await;
    let state = cookie_kv(&set_cookie(&start, "drust_oauth_state").expect("state cookie"));
    let pkce = cookie_kv(&set_cookie(&start, "drust_oauth_pkce").expect("pkce cookie"));
    let state_value = state.split_once('=').unwrap().1.to_string();
    let mut cookies: Vec<&str> = vec![&state, &pkce];
    cookies.extend_from_slice(extra);
    get(
        &fx.app,
        &format!("/admin/oauth/{provider}/callback?code=C&state={state_value}"),
        &cookies,
    )
    .await
}

/// Set-Cookie lines with the session and OAuth state/PKCE values masked.
fn masked_cookies(resp: &Response<Body>) -> Vec<String> {
    set_cookie_lines(resp)
        .into_iter()
        .map(|l| {
            let (kv, rest) = l.split_once(';').unwrap_or((l.as_str(), ""));
            let name = kv.split('=').next().unwrap_or("");
            format!("{name}=<v>;{rest}")
        })
        .collect()
}

fn no_mcp_cookie(resp: &Response<Body>) -> bool {
    !set_cookie_lines(resp)
        .iter()
        .any(|l| l.starts_with("drust_mcp_oauth_"))
}

#[tokio::test]
async fn password_login_location_is_unchanged_without_resume_cookie() {
    let mut shapes = Vec::new();
    for enabled in [true, false] {
        let fx = fixture(enabled).await;
        let resp = password_login(&fx, &[], &[]).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "enabled={enabled}");
        assert_eq!(location(&resp), LANDING, "enabled={enabled}");
        assert!(set_cookie(&resp, "drust_session").is_some());
        assert!(no_mcp_cookie(&resp), "enabled={enabled}");
        shapes.push(masked_cookies(&resp));
    }
    assert_eq!(shapes[0], shapes[1]);
}

async fn callback_location_is_unchanged(provider: &str) {
    use crate::common::oauth_helpers::{spawn_fake_github, spawn_fake_google};
    let mut shapes = Vec::new();
    for enabled in [true, false] {
        let fake = if provider == "google" {
            spawn_fake_google().await
        } else {
            spawn_fake_github().await
        };
        let fx = fixture_with_provider(enabled, provider, &fake, "kael@example.com").await;
        let resp = provider_login(&fx, provider, &[]).await;
        assert_eq!(
            resp.status(),
            StatusCode::FOUND,
            "{provider} enabled={enabled}"
        );
        assert_eq!(location(&resp), LANDING, "{provider} enabled={enabled}");
        assert!(set_cookie(&resp, "drust_session").is_some());
        assert!(no_mcp_cookie(&resp));
        shapes.push(masked_cookies(&resp));
    }
    assert_eq!(shapes[0], shapes[1]);
}

#[tokio::test]
async fn google_callback_location_is_unchanged_without_resume_cookie() {
    callback_location_is_unchanged("google").await;
}

#[tokio::test]
async fn github_callback_location_is_unchanged_without_resume_cookie() {
    callback_location_is_unchanged("github").await;
}

#[tokio::test]
async fn disabled_mode_ignores_a_valid_resume_cookie() {
    let fake = crate::common::oauth_helpers::spawn_fake_google().await;
    let fx = fixture_with_provider(false, "google", &fake, "kael@example.com").await;
    let resume = format!(
        "{RESUME_COOKIE}={}",
        sealed_envelope(&cfg(), &loopback_redirect(5), Some("s"), now())
    );
    let base = password_login(&fx, &[], &[]).await;
    let with = password_login(&fx, &[&resume], &[]).await;
    assert_eq!(location(&with), LANDING);
    assert_eq!(masked_cookies(&with), masked_cookies(&base));
    let base = provider_login(&fx, "google", &[]).await;
    let with = provider_login(&fx, "google", &[&resume]).await;
    assert_eq!(with.status(), StatusCode::FOUND);
    assert_eq!(location(&with), LANDING);
    assert_eq!(masked_cookies(&with), masked_cookies(&base));
}

#[tokio::test]
async fn stale_resume_cookie_falls_back_and_is_cleared() {
    let fake = crate::common::oauth_helpers::spawn_fake_google().await;
    let fx = fixture_with_provider(true, "google", &fake, "kael@example.com").await;
    let live = sealed_envelope(&cfg(), &loopback_redirect(5), Some("s"), now());
    let stale = [
        sealed_envelope(&cfg(), &loopback_redirect(5), Some("s"), now() - 700),
        tamper(&live),
        "garbage".to_string(),
    ];
    for wire in &stale {
        let resume = format!("{RESUME_COOKIE}={wire}");
        for resp in [
            password_login(&fx, &[&resume], &[]).await,
            provider_login(&fx, "google", &[&resume]).await,
        ] {
            assert!(resp.status().is_redirection());
            assert_eq!(location(&resp), LANDING, "{wire}");
            assert!(set_cookie(&resp, "drust_session").is_some(), "session kept");
            let clear = set_cookie_lines(&resp)
                .into_iter()
                .find(|l| l.starts_with(&format!("{RESUME_COOKIE}=;")))
                .unwrap_or_else(|| panic!("resume cookie not cleared for {wire}"));
            assert!(
                clear.contains("Max-Age=0") && clear.contains("Path=/drust"),
                "{clear}"
            );
        }
    }
}

#[tokio::test]
async fn consent_routes_are_not_mounted_when_disabled() {
    let fx = fixture(false).await;
    let session = session_for(&fx, fx.owner_id).await;
    for (method, uri) in [
        ("GET", "/oauth/consent"),
        ("POST", "/oauth/consent/approve"),
        ("POST", "/oauth/consent/deny"),
    ] {
        // The same method and session on a path that never existed.
        let reference = response_snapshot(
            send_with(&fx, method, "/oauth/nonexistent", &[&session], &[], "").await,
        )
        .await;
        assert_eq!(reference.0, StatusCode::NOT_FOUND, "{method} reference");
        let resp = send_with(&fx, method, uri, &[&session], &[], "").await;
        assert_eq!(
            response_snapshot(resp).await,
            reference,
            "{method} {uri}: status, headers and body"
        );
    }
}

#[tokio::test]
async fn cross_site_login_with_a_valid_resume_cookie_is_still_refused() {
    let fx = fixture(true).await;
    let resume = format!(
        "{RESUME_COOKIE}={}",
        sealed_envelope(&cfg(), &loopback_redirect(5), Some("s"), now())
    );
    let resp = password_login(&fx, &[&resume], &[("sec-fetch-site", "cross-site")]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        set_cookie_lines(&resp).is_empty(),
        "resume cookie neither used nor cleared"
    );
    assert!(hdr(&resp, header::LOCATION).is_none());
    assert_eq!(body_json(resp).await["error_code"], "LOGIN_CROSS_SITE");
    let resp = password_login(&fx, &[&resume], &[]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), CONSENT);
}

// ─── B. login resumes the flow ───────────────────────────────────────────────

async fn insert_live_tenant(fx: &McpOauthFixture) {
    insert_tenant(fx, "t-one", Some(fx.owner_id), false).await;
}

#[tokio::test]
async fn password_login_resumes_to_consent_and_approve_returns_a_code() {
    let fx = fixture(true).await;
    insert_live_tenant(&fx).await;
    let a = authorize_as(
        &fx,
        None,
        &loopback_redirect(53682),
        Some("st-1"),
        Some(RESOURCE),
    )
    .await;
    assert!(a.consent_uri.starts_with("/oauth/consent?req="));
    let resp = get(&fx.app, &a.consent_uri, &[&a.resume]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/drust/login");
    let resp = password_login(&fx, &[&a.resume], &[]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), CONSENT);
    assert!(
        set_cookie_lines(&resp)
            .iter()
            .all(|l| !l.starts_with(RESUME_COOKIE))
    );
    let session = cookie_kv(&set_cookie(&resp, "drust_session").unwrap());
    let resp = get(&fx.app, "/oauth/consent", &[&session, &a.resume]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let csrf_cookie = cookie_kv(&set_cookie(&resp, CSRF_COOKIE).unwrap());
    let html = body_text(resp).await;
    assert!(html.contains("<strong>root</strong> (owner)"));
    assert!(html.contains("Currently 1."));
    assert!(html.contains("localhost:53682"));
    let req = hidden_field(&html, "req").unwrap();
    assert_eq!(req, a.wire);
    let csrf = hidden_field(&html, "csrf").unwrap();
    let resp = approve(
        &fx,
        &[("req", &req), ("csrf", &csrf)],
        &[&session, &a.resume, &csrf_cookie],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(loc.starts_with("http://localhost:53682/callback?"), "{loc}");
    assert_eq!(query_param(&loc, "code").unwrap().len(), 43);
    assert_eq!(query_param(&loc, "state").as_deref(), Some("st-1"));
    assert_eq!(query_param(&loc, "iss").as_deref(), Some(ISSUER));
    assert_eq!(query_keys(&loc), ["code", "state", "iss"]);
    assert!(clears(&resp, RESUME_COOKIE));
    assert!(clears(&resp, CSRF_COOKIE));
    assert_eq!(grants(&fx).await, 1);
    assert_eq!(codes(&fx).await, 1);
}

#[tokio::test]
async fn google_login_resumes_to_consent_exactly_once() {
    let fake = crate::common::oauth_helpers::spawn_fake_google().await;
    let fx = fixture_with_provider(true, "google", &fake, "kael@example.com").await;
    let a = authorize_as(&fx, None, &loopback_redirect(5), Some("g"), None).await;
    let resp = provider_login(&fx, "google", &[&a.resume]).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), CONSENT);
    let session = cookie_kv(&set_cookie(&resp, "drust_session").unwrap());
    let resp = get(&fx.app, "/oauth/consent", &[&session, &a.resume]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let csrf_cookie = cookie_kv(&set_cookie(&resp, CSRF_COOKIE).unwrap());
    let html = body_text(resp).await;
    assert!(html.contains("<strong>kael@example.com</strong> (owner)"));
    let req = hidden_field(&html, "req").unwrap();
    let csrf = hidden_field(&html, "csrf").unwrap();
    let resp = approve(
        &fx,
        &[("req", &req), ("csrf", &csrf)],
        &[&session, &a.resume, &csrf_cookie],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(clears(&resp, RESUME_COOKIE));
    // The browser dropped the resume cookie, so the next login lands normally.
    let resp = provider_login(&fx, "google", &[]).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(location(&resp), LANDING);
}

#[tokio::test]
async fn signed_in_authorize_goes_straight_to_consent() {
    let (fx, session) = signed_in().await;
    let a = authorize_as(&fx, Some(&session), &loopback_redirect(5), None, None).await;
    let resp = get(&fx.app, &a.consent_uri, &[&session, &a.resume]).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn not_you_logout_then_own_login_returns_to_consent() {
    let (fx, session) = signed_in().await;
    let m2 = add_admin(&fx, "m2", "pw-m2-test", "member").await;
    let c = open_consent(&fx, &session).await;
    let resp = post_form(&fx.app, "/logout", &[], &[&session, &c.resume], &[]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/drust/login");
    let resp = post_form(
        &fx.app,
        "/login",
        &[("username", "m2"), ("password", "pw-m2-test")],
        &[&c.resume],
        &[],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), CONSENT);
    let m2_session = cookie_kv(&set_cookie(&resp, "drust_session").unwrap());
    let resp = get(&fx.app, "/oauth/consent", &[&m2_session, &c.resume]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let new_csrf_cookie = cookie_kv(&set_cookie(&resp, CSRF_COOKIE).unwrap());
    let html = body_text(resp).await;
    assert!(html.contains("<strong>m2@example.test</strong> (member)"));
    let new_csrf = hidden_field(&html, "csrf").unwrap();
    // The first admin's token does not work for the second admin.
    let resp = approve(&fx, &c.form(), &[&m2_session, &c.resume, &c.csrf_cookie]).await;
    error_page(resp, StatusCode::FORBIDDEN, "consent_csrf").await;
    let resp = approve(
        &fx,
        &[("req", &c.req), ("csrf", &new_csrf)],
        &[&m2_session, &c.resume, &new_csrf_cookie],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let owner: i64 = fx
        .meta
        .lock()
        .await
        .query_row("SELECT admin_id FROM _mcp_oauth_grants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(owner, m2);
}

#[tokio::test]
async fn each_authorization_shows_consent_and_creates_a_new_grant() {
    let (fx, session) = signed_in().await;
    let g1 = obtain_code(&fx, &session, 5, Some("a")).await;
    let g2 = obtain_code(&fx, &session, 5, Some("b")).await;
    assert_ne!(g1.code, g2.code);
    assert_eq!(g1.state.as_deref(), Some("a"));
    assert_eq!(g2.iss, ISSUER);
    assert_eq!(grants(&fx).await, 2);
    assert_eq!(codes(&fx).await, 2);
}

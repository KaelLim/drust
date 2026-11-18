//! `GET /oauth/authorize`: the error page before redirect validation,
//! the 303 back after it, the success redirect to consent with the resume
//! cookie, and the invariants (writes nothing, takes no lock, absent when
//! disabled). Every request goes through the production router at ROOT paths;
//! only `Location` and cookie strings carry `/drust`.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use drust::mgmt::mcp_oauth::config::{McpOauthConfig, McpOauthEnv};
use drust::mgmt::mcp_oauth::envelope;

use crate::common::mcp_oauth::*;

const PINNED_ON: &str = "2026-11-14";
const RESUME: &str = "drust_mcp_oauth_resume";
const UNKNOWN_CLIENT_SENTENCE: &str = "This server currently accepts only Claude Code.";
const REQUEST_INVALID_TITLE: &str = "The request is malformed";
const REDIRECT_REJECTED_TITLE: &str = "Unregistered return address";

// ─── file-private helpers ────────────────────────────────────────────────────

type Snapshot = (StatusCode, Vec<(String, String)>, Vec<u8>);

async fn snapshot(resp: Response<Body>) -> Snapshot {
    let status = resp.status();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

fn hdr(resp: &Response<Body>, name: header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_string())
}

/// A form-urlencoded query from pairs (the same encoder the SDK uses), so a
/// table value reaches the handler exactly as written.
fn enc(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// `s.replace(from, to)`, asserting the replace really changed something, so a
/// variant cannot silently be the unmodified query.
fn replaced(s: &str, from: &str, to: &str) -> String {
    assert!(s.contains(from), "variant: {from:?} not in {s}");
    s.replace(from, to)
}

async fn authorize(fx: &McpOauthFixture, query: &str) -> Response<Body> {
    get(&fx.app, &format!("/oauth/authorize?{query}"), &[]).await
}

fn sdk_query(port: u16, state: Option<&str>) -> String {
    let (_, challenge) = pkce();
    authorize_query(&challenge, &loopback_redirect(port), state, Some(RESOURCE))
}

/// The error-page contract shared by every pre-validation failure; returns the body.
async fn assert_error_page(resp: Response<Body>, ctx: &str) -> String {
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{ctx}: status");
    assert!(
        hdr(&resp, header::CONTENT_TYPE)
            .unwrap_or_default()
            .starts_with("text/html"),
        "{ctx}: content-type"
    );
    assert_eq!(
        hdr(&resp, header::CACHE_CONTROL).as_deref(),
        Some("no-store"),
        "{ctx}: cache-control"
    );
    assert_eq!(
        hdr(&resp, header::REFERRER_POLICY).as_deref(),
        Some("no-referrer"),
        "{ctx}: referrer-policy"
    );
    assert!(
        resp.headers().get(header::LOCATION).is_none(),
        "{ctx}: location"
    );
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "{ctx}: set-cookie"
    );
    body_text(resp).await
}

/// Test oracle for the handler's `display_received`: cut at '?'/'#', non
/// printable-ASCII -> U+FFFD, at most 96 chars + "...".
fn displayed(raw: &str) -> String {
    let head = raw.split(['?', '#']).next().unwrap();
    let mut out: String = head
        .chars()
        .take(96)
        .map(|c| {
            if (' '..='~').contains(&c) {
                c
            } else {
                '\u{FFFD}'
            }
        })
        .collect();
    if head.chars().count() > 96 {
        out.push_str("...");
    }
    out
}

/// askama 0.16's HTML escaper.
fn html_escape(s: &str) -> String {
    s.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

fn is_oauth_ascii(s: &str) -> bool {
    s.bytes()
        .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// Every table row of `redirect::tests::rejects_with_reason` except the empty
/// string (an empty value is "absent", which is `RedirectMissing`).
const REJECTED_REDIRECTS: &[&str] = &[
    "https://localhost:1/callback",
    "HTTP://localhost:1/callback",
    "http:/localhost/callback",
    " http://localhost:1/callback",
    "http://localhost.evil.com/callback",
    "http://127.0.0.1.evil.com/callback",
    "http://localhostx/callback",
    "http://127.0.0.10:1/callback",
    "http://127.0.0.1@evil.com/callback",
    "http://user@localhost:1/callback",
    "http://localhost\\@evil.com/callback",
    "http://localhost%2F@evil/callback",
    "http://[::1]:1/callback",
    "http://LOCALHOST:1/callback",
    "http://2130706433:1/callback",
    "http://127.1:1/callback",
    "http://0x7f.0.0.1:1/callback",
    "http://localhost",
    "http://localhost:1",
    "http://localhost:/callback",
    "http://localhost:1a/callback",
    "http://localhost:+1/callback",
    "http://localhost:\u{0661}/callback",
    "http://localhost:0/callback",
    "http://localhost:080/callback",
    "http://localhost:00001/callback",
    "http://localhost:65536/callback",
    "http://localhost:123456/callback",
    "http://localhost:1/callback/",
    "http://localhost:1/./callback",
    "http://localhost:1/%63allback",
    "http://localhost:1//callback",
    "http://localhost:1/Callback",
    "http://localhost:1/callback?x=1",
    "http://localhost:1/callback#f",
    "http://localhost:1/callback ",
    "http://localhost:1/callback\n",
];

// ─── A. before validation → error page ──────────────────────────────────────

#[tokio::test]
async fn unknown_client_shows_page_not_redirect() {
    let fx = fixture(true).await;
    let (_, ch) = pkce();
    let q = enc(&[
        ("response_type", "code"),
        ("client_id", "https://evil.example/cimd"),
        ("code_challenge", &ch),
        ("code_challenge_method", "S256"),
        ("redirect_uri", &loopback_redirect(4242)),
    ]);
    let body = assert_error_page(authorize(&fx, &q).await, "unknown client").await;
    assert!(body.contains(UNKNOWN_CLIENT_SENTENCE), "{body}");
    assert!(!body.contains("evil.example"), "client_id echoed");
}

#[tokio::test]
async fn missing_or_duplicated_client_id_is_page() {
    let fx = fixture(true).await;
    let r = loopback_redirect(4242);
    for (what, q) in [
        (
            "missing",
            enc(&[("response_type", "code"), ("redirect_uri", &r)]),
        ),
        (
            "duplicated",
            enc(&[
                ("client_id", CC_CLIENT_ID),
                ("client_id", CC_CLIENT_ID),
                ("redirect_uri", &r),
            ]),
        ),
        (
            "empty value",
            enc(&[("client_id", ""), ("redirect_uri", &r)]),
        ),
        ("no query", String::new()),
    ] {
        let body = assert_error_page(authorize(&fx, &q).await, what).await;
        assert!(body.contains(REQUEST_INVALID_TITLE), "{what}");
    }
    let resp = get(&fx.app, "/oauth/authorize", &[]).await;
    let body = assert_error_page(resp, "no '?'").await;
    assert!(body.contains(REQUEST_INVALID_TITLE));
}

#[tokio::test]
async fn missing_or_duplicated_redirect_is_page() {
    let fx = fixture(true).await;
    let r = loopback_redirect(4242);
    for (what, q) in [
        ("missing", enc(&[("client_id", CC_CLIENT_ID)])),
        (
            "duplicated",
            enc(&[
                ("client_id", CC_CLIENT_ID),
                ("redirect_uri", &r),
                ("redirect_uri", &r),
            ]),
        ),
        (
            "empty value",
            enc(&[("client_id", CC_CLIENT_ID), ("redirect_uri", "")]),
        ),
    ] {
        let body = assert_error_page(authorize(&fx, &q).await, what).await;
        assert!(body.contains(REQUEST_INVALID_TITLE), "{what}");
        assert!(body.contains(PINNED_ON), "{what}: pinned date");
        assert!(body.contains("http://localhost/callback"), "{what}");
        assert!(body.contains("http://127.0.0.1/callback"), "{what}");
    }
}

#[tokio::test]
async fn rejected_redirects_are_pages() {
    let fx = fixture(true).await;
    let (_, ch) = pkce();
    for raw in REJECTED_REDIRECTS {
        let q = enc(&[
            ("response_type", "code"),
            ("client_id", CC_CLIENT_ID),
            ("code_challenge", &ch),
            ("code_challenge_method", "S256"),
            ("redirect_uri", raw),
        ]);
        let ctx = format!("{raw:?}");
        let body = assert_error_page(authorize(&fx, &q).await, &ctx).await;
        assert!(body.contains(REDIRECT_REJECTED_TITLE), "{ctx}");
        // Proof the handler saw exactly the table value.
        let shown = html_escape(&displayed(raw));
        assert!(
            body.contains(&format!("<code class=\"mcp-oauth-code\">{shown}</code>")),
            "{ctx}: expected {shown:?} in the page"
        );
        assert!(body.contains(PINNED_ON), "{ctx}");
    }
}

#[tokio::test]
async fn form_decoding_happens_exactly_once() {
    let fx = fixture(true).await;
    let (_, ch) = pkce();
    let base = |redirect: &str| {
        enc(&[
            ("response_type", "code"),
            ("client_id", CC_CLIENT_ID),
            ("code_challenge", &ch),
            ("code_challenge_method", "S256"),
        ]) + "&redirect_uri="
            + redirect
    };
    // On the wire "%2563allback" decodes once to "/%63allback" -> NotPinned.
    // Decoding twice would make it "/callback" and succeed.
    let once =
        url::form_urlencoded::byte_serialize(b"http://localhost:1/%63allback").collect::<String>();
    assert!(once.contains("%2563allback"), "{once}");
    let resp = authorize(&fx, &base(&once)).await;
    assert_ne!(resp.status(), StatusCode::SEE_OTHER);
    let body = assert_error_page(resp, "%2563allback").await;
    assert!(body.contains("http://localhost:1/%63allback"));
    // Unencoded ':' and '/' are a legal form some clients send.
    let resp = authorize(&fx, &base("http://localhost:1/callback")).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("/drust/oauth/consent?req="));
}

#[tokio::test]
async fn received_redirect_is_stripped_and_escaped() {
    let fx = fixture(true).await;
    let q = enc(&[
        ("client_id", CC_CLIENT_ID),
        ("redirect_uri", "http://localhost:1/callback?x=1"),
    ]);
    let body = assert_error_page(authorize(&fx, &q).await, "query").await;
    assert!(body.contains("<code class=\"mcp-oauth-code\">http://localhost:1/callback</code>"));
    assert!(!body.contains("x=1"));

    let q = enc(&[
        ("client_id", CC_CLIENT_ID),
        ("redirect_uri", "http://localhost:1/<script>x</script>"),
    ]);
    let body = assert_error_page(authorize(&fx, &q).await, "markup").await;
    assert!(
        body.contains("&#60;script&#62;x&#60;/script&#62;"),
        "{body}"
    );
    assert!(!body.contains("<script>x"));
}

#[tokio::test]
async fn oversized_query_is_page() {
    let fx = fixture(true).await;
    let mut q = sdk_query(4242, Some("st"));
    q.push_str("&pad=");
    q.push_str(&"p".repeat(4097 - q.len()));
    assert_eq!(q.len(), 4097);
    let body = assert_error_page(authorize(&fx, &q).await, "4097 bytes").await;
    assert!(body.contains(REQUEST_INVALID_TITLE));
    // 4096 bytes exactly is parsed (and succeeds).
    let mut q = sdk_query(4242, Some("st"));
    q.push_str("&pad=");
    q.push_str(&"p".repeat(4096 - q.len()));
    assert_eq!(q.len(), 4096);
    assert_eq!(authorize(&fx, &q).await.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn error_page_is_html_not_oauth_json() {
    let fx = fixture(true).await;
    let q = enc(&[("client_id", "https://evil.example/cimd")]);
    let resp = authorize(&fx, &q).await;
    assert!(
        !hdr(&resp, header::CONTENT_TYPE)
            .unwrap_or_default()
            .starts_with("application/json")
    );
    let body = assert_error_page(resp, "html").await;
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
    assert!(
        !parsed.is_ok_and(|v| v.get("error").is_some()),
        "rewritten to OAuth JSON"
    );
    assert!(body.contains("<!doctype html>"));
}

#[tokio::test]
async fn error_page_is_frame_guarded_and_scriptless() {
    let fx = fixture(true).await;
    let q = enc(&[
        ("client_id", CC_CLIENT_ID),
        ("redirect_uri", "https://localhost:1/callback"),
    ]);
    let resp = authorize(&fx, &q).await;
    let csp: Vec<_> = resp
        .headers()
        .get_all(header::CONTENT_SECURITY_POLICY)
        .iter()
        .collect();
    assert_eq!(csp.len(), 1);
    assert_eq!(csp[0], "frame-ancestors 'none'");
    let xfo: Vec<_> = resp
        .headers()
        .get_all(header::X_FRAME_OPTIONS)
        .iter()
        .collect();
    assert_eq!(xfo.len(), 1);
    assert_eq!(xfo[0], "DENY");
    let body = assert_error_page(resp, "frame guard").await;
    assert!(!body.contains("<script"), "error page carries a script");
}

#[tokio::test]
async fn error_page_localizes() {
    let fx = fixture(true).await;
    let q = enc(&[("client_id", "https://evil.example/cimd")]);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/oauth/authorize?{q}"))
        .header(header::ACCEPT_LANGUAGE, "zh-TW")
        .body(Body::empty())
        .unwrap();
    let body = assert_error_page(send(&fx.app, req).await, "zh-TW").await;
    assert!(body.contains("此伺服器目前只接受 Claude Code。"), "{body}");
    assert!(body.contains("<html lang=\"zh-TW\">"));
}

// ─── B. after validation → 303 back ─────────────────────────────────────────

type Pairs = Vec<(String, String)>;

/// `(what, redirect_uri, pairs, expected error)` rows; each must come back to
/// that redirect with the expected `error`.
fn back_rows() -> Vec<(&'static str, String, Pairs, &'static str)> {
    let (_, ch) = pkce();
    let base = |redirect: &str, state: Option<&str>| -> Vec<(String, String)> {
        let q = authorize_query(&ch, redirect, state, Some(RESOURCE));
        url::form_urlencoded::parse(q.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    };
    let set = |mut p: Vec<(String, String)>, k: &str, v: &str| {
        p.retain(|(key, _)| key != k);
        p.push((k.into(), v.into()));
        p
    };
    let del = |mut p: Vec<(String, String)>, k: &str| {
        p.retain(|(key, _)| key != k);
        p
    };
    let add = |mut p: Vec<(String, String)>, k: &str, v: &str| {
        p.push((k.into(), v.into()));
        p
    };
    let l = loopback_redirect(4242);
    let ip = "http://127.0.0.1:4243/callback".to_string();
    let s = Some("st&=é");
    vec![
        (
            "missing response_type",
            l.clone(),
            del(base(&l, s), "response_type"),
            "invalid_request",
        ),
        (
            "response_type=token",
            l.clone(),
            set(base(&l, s), "response_type", "token"),
            "unsupported_response_type",
        ),
        (
            "missing method",
            l.clone(),
            del(base(&l, s), "code_challenge_method"),
            "invalid_request",
        ),
        (
            "plain",
            l.clone(),
            set(base(&l, s), "code_challenge_method", "plain"),
            "invalid_request",
        ),
        (
            "s256",
            l.clone(),
            set(base(&l, s), "code_challenge_method", "s256"),
            "invalid_request",
        ),
        (
            "missing challenge",
            l.clone(),
            del(base(&l, s), "code_challenge"),
            "invalid_request",
        ),
        (
            "42-char challenge",
            l.clone(),
            set(base(&l, s), "code_challenge", &"a".repeat(42)),
            "invalid_request",
        ),
        (
            "challenge with +",
            l.clone(),
            set(
                base(&l, s),
                "code_challenge",
                &format!("{}+", "a".repeat(42)),
            ),
            "invalid_request",
        ),
        (
            "duplicated challenge",
            l.clone(),
            add(base(&l, s), "code_challenge", &"a".repeat(43)),
            "invalid_request",
        ),
        (
            "scope=admin",
            l.clone(),
            set(base(&l, s), "scope", "admin"),
            "invalid_scope",
        ),
        (
            "scope=mcp admin",
            l.clone(),
            set(base(&l, s), "scope", "mcp admin"),
            "invalid_scope",
        ),
        (
            "duplicated scope",
            l.clone(),
            add(base(&l, s), "scope", "mcp"),
            "invalid_request",
        ),
        (
            "resource #f",
            l.clone(),
            set(base(&l, s), "resource", &format!("{RESOURCE}#f")),
            "invalid_target",
        ),
        (
            "resource ?x",
            l.clone(),
            set(base(&l, s), "resource", &format!("{RESOURCE}?x")),
            "invalid_target",
        ),
        (
            "resource trailing /",
            l.clone(),
            set(base(&l, s), "resource", &format!("{RESOURCE}/")),
            "invalid_target",
        ),
        (
            "resource other host",
            l.clone(),
            set(base(&l, s), "resource", "https://evil.test/drust/mcp"),
            "invalid_target",
        ),
        (
            "resource /drust/MCP",
            l.clone(),
            set(base(&l, s), "resource", "https://drust.test/drust/MCP"),
            "invalid_target",
        ),
        (
            "two resources",
            l.clone(),
            add(base(&l, s), "resource", RESOURCE),
            "invalid_target",
        ),
        (
            "resource 513, not ours",
            l.clone(),
            set(base(&l, s), "resource", &"r".repeat(513)),
            "invalid_target",
        ),
        (
            "state 513",
            l.clone(),
            set(base(&l, s), "state", &"s".repeat(513)),
            "invalid_request",
        ),
        (
            "state 513, token",
            l.clone(),
            set(
                set(base(&l, s), "state", &"s".repeat(513)),
                "response_type",
                "token",
            ),
            "unsupported_response_type",
        ),
        (
            "duplicated state",
            l.clone(),
            add(base(&l, s), "state", "other"),
            "invalid_request",
        ),
        (
            "no state, token",
            l.clone(),
            set(base(&l, None), "response_type", "token"),
            "unsupported_response_type",
        ),
        (
            "127.0.0.1 variant",
            ip.clone(),
            set(base(&ip, s), "scope", "admin"),
            "invalid_scope",
        ),
    ]
}

#[tokio::test]
async fn errors_after_redirect_validation_go_back_with_iss() {
    let fx = fixture(true).await;
    for (what, redirect, pairs, want) in back_rows() {
        let q = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&pairs)
            .finish();
        let resp = authorize(&fx, &q).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{what}");
        assert!(
            resp.headers().get(header::SET_COOKIE).is_none(),
            "{what}: set-cookie"
        );
        assert_eq!(
            hdr(&resp, header::CACHE_CONTROL).as_deref(),
            Some("no-store"),
            "{what}"
        );
        assert_eq!(
            hdr(&resp, header::REFERRER_POLICY).as_deref(),
            Some("no-referrer"),
            "{what}"
        );
        let loc = location(&resp);
        assert!(loc.starts_with(&format!("{redirect}?")), "{what}: {loc}");
        assert_eq!(query_param(&loc, "error").as_deref(), Some(want), "{what}");
        assert_eq!(query_param(&loc, "iss").as_deref(), Some(ISSUER), "{what}");
        // The first state comes back verbatim, unless it is over 512 bytes:
        // that one is never echoed.
        let sent_state = pairs
            .iter()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.clone())
            .filter(|v| v.len() <= 512);
        assert_eq!(query_param(&loc, "state"), sent_state, "{what}: state");
        if let Some(d) = query_param(&loc, "error_description") {
            assert!(is_oauth_ascii(&d), "{what}: {d:?}");
        }
    }
}

#[tokio::test]
async fn iss_equals_metadata_issuer_byte_for_byte() {
    let fx = fixture(true).await;
    let meta = body_json(get(&fx.app, "/.well-known/oauth-authorization-server", &[]).await).await;
    let issuer = meta["issuer"].as_str().unwrap().to_string();
    assert_eq!(issuer, ISSUER);
    let (_, ch) = pkce();
    let q = replaced(
        &authorize_query(&ch, &loopback_redirect(4242), Some("st"), Some(RESOURCE)),
        "response_type=code",
        "response_type=token",
    );
    let resp = authorize(&fx, &q).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(query_param(&location(&resp), "iss"), Some(issuer));
}

/// A host of 63-byte labels whose own `/mcp` resource is exactly `len` bytes:
/// the only way a resource over the limit can be ours, so the only way to see
/// the length guard refuse it.
fn origin_with_resource_len(len: usize) -> String {
    let mut left = len - "https://".len() - "/drust/mcp".len();
    let mut labels = Vec::new();
    while left > 0 {
        let n = left.min(63);
        let n = if left > 63 && left - n == 1 { 62 } else { n };
        labels.push("a".repeat(n));
        left -= n;
        left = left.saturating_sub(1); // the dot before the next label
    }
    format!("https://{}", labels.join("."))
}

#[tokio::test]
async fn an_own_resource_of_513_bytes_goes_back_with_invalid_target() {
    let (_, ch) = pkce();
    for (len, want) in [(512usize, None), (513, Some("invalid_target"))] {
        let cfg = McpOauthConfig::for_tests(&origin_with_resource_len(len));
        let resource = cfg.resource_url();
        assert_eq!(resource.len(), len);
        assert!(cfg.is_our_resource(&resource), "{len}: ours");
        let fx = fixture_with(cfg).await;
        let q = authorize_query(&ch, &loopback_redirect(4242), Some("st"), Some(&resource));
        let resp = authorize(&fx, &q).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{len}");
        let loc = location(&resp);
        match want {
            None => assert!(loc.starts_with("/drust/oauth/consent?req="), "{len}: {loc}"),
            Some(code) => {
                assert!(
                    loc.starts_with("http://localhost:4242/callback?"),
                    "{len}: {loc}"
                );
                assert_eq!(query_param(&loc, "error").as_deref(), Some(code), "{len}");
            }
        }
    }
}

#[tokio::test]
async fn state_512_ok_513_back() {
    let fx = fixture(true).await;
    let s512 = "s".repeat(512);
    let resp = authorize(&fx, &sdk_query(4242, Some(&s512))).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("/drust/oauth/consent?req="));
    let s513 = "s".repeat(513);
    let resp = authorize(&fx, &sdk_query(4242, Some(&s513))).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(loc.starts_with("http://localhost:4242/callback?"), "{loc}");
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(
        query_param(&loc, "state"),
        None,
        "an over-long state is not echoed"
    );
    assert!(!loc.contains("sss"), "{loc}");
}

// ─── C. success ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn sdk_shape_redirects_to_consent_with_resume_cookie() {
    let fx = fixture(true).await;
    let (_, challenge) = pkce();
    let redirect = loopback_redirect(54321);
    let q = authorize_query(&challenge, &redirect, Some("st"), Some(RESOURCE));
    let resp = authorize(&fx, &q).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        hdr(&resp, header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    assert_eq!(
        hdr(&resp, header::REFERRER_POLICY).as_deref(),
        Some("no-referrer")
    );
    let loc = location(&resp);
    assert!(loc.starts_with("/drust/oauth/consent?req="), "{loc}");
    let wire = query_param(&loc, "req").unwrap();
    let cookie = set_cookie(&resp, RESUME).expect("resume cookie set");
    assert_eq!(
        cookie,
        format!("{RESUME}={wire}; Path=/drust; HttpOnly; SameSite=Lax; Max-Age=600; Secure")
    );
    let cfg = McpOauthConfig::for_tests(PUBLIC_URL); // same fixed test keys as the fixture
    let now = envelope::now_unix().unwrap();
    let req = envelope::open(&cfg, &wire, now).expect("envelope opens");
    assert_eq!(req.client_id, CC_CLIENT_ID);
    assert_eq!(req.redirect_uri, redirect);
    assert_eq!(req.state.as_deref(), Some("st"));
    assert_eq!(req.code_challenge, challenge);
    assert_eq!(req.resource.as_deref(), Some(RESOURCE));
}

#[tokio::test]
async fn tolerated_variants_succeed() {
    let fx = fixture(true).await;
    let (_, ch) = pkce();
    let l = loopback_redirect(4242);
    let sdk = authorize_query(&ch, &l, Some("st"), Some(RESOURCE));
    let no_res = authorize_query(&ch, &l, Some("st"), None);
    let variants: Vec<(&str, String, Option<&str>)> = vec![
        ("no resource", no_res.clone(), None),
        (
            "127.0.0.1",
            authorize_query(&ch, "http://127.0.0.1/callback", Some("st"), Some(RESOURCE)),
            Some(RESOURCE),
        ),
        (
            "prompt=none",
            replaced(&sdk, "prompt=consent", "prompt=none"),
            Some(RESOURCE),
        ),
        ("foo=bar", format!("{sdk}&foo=bar"), Some(RESOURCE)),
        (
            "no scope",
            replaced(&sdk, "&scope=mcp+offline_access", ""),
            Some(RESOURCE),
        ),
        (
            "scope=offline_access",
            replaced(&sdk, "scope=mcp+offline_access", "scope=offline_access"),
            Some(RESOURCE),
        ),
        ("empty resource", format!("{no_res}&resource="), None),
    ];
    let cfg = McpOauthConfig::for_tests(PUBLIC_URL);
    for (what, q, want_resource) in variants {
        let resp = authorize(&fx, &q).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{what}");
        let loc = location(&resp);
        assert!(
            loc.starts_with("/drust/oauth/consent?req="),
            "{what}: {loc}"
        );
        assert!(set_cookie(&resp, RESUME).is_some(), "{what}");
        let wire = query_param(&loc, "req").unwrap();
        let req = envelope::open(&cfg, &wire, envelope::now_unix().unwrap()).unwrap();
        assert_eq!(req.resource.as_deref(), want_resource, "{what}");
    }
}

#[tokio::test]
async fn largest_request_still_fits_a_cookie() {
    let fx = fixture(true).await;
    let s512 = "s".repeat(512);
    let resp = authorize(&fx, &sdk_query(65535, Some(&s512))).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = set_cookie(&resp, RESUME).unwrap();
    assert!(cookie.len() < 4096, "set-cookie is {} bytes", cookie.len());
    assert!(location(&resp).len() < 4096);
}

#[tokio::test]
async fn post_is_not_served() {
    let fx = fixture(true).await;
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/authorize")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(sdk_query(4242, Some("st"))))
        .unwrap();
    let resp = send(&fx.app, req).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(resp.headers().get(header::LOCATION).is_none());
    assert!(resp.headers().get(header::SET_COOKIE).is_none());
}

// ─── D. invariants ──────────────────────────────────────────────────────────

const ROW_TOTAL: &str = "SELECT (SELECT COUNT(*) FROM _mcp_oauth_grants) \
     + (SELECT COUNT(*) FROM _mcp_oauth_codes) \
     + (SELECT COUNT(*) FROM _mcp_oauth_refresh) \
     + (SELECT COUNT(*) FROM _mcp_oauth_access) \
     + (SELECT COUNT(*) FROM _mcp_upload_tickets) \
     + (SELECT COUNT(*) FROM sessions) \
     + (SELECT COUNT(*) FROM admins)";

#[tokio::test]
async fn authorize_writes_nothing() {
    let fx = fixture(true).await;
    // Give the counts something to be stable around.
    {
        let conn = fx.meta.lock().await;
        let g = seed_grant(
            &conn,
            &SeedGrant {
                admin_id: fx.owner_id,
                idle: "+30 days",
                absolute: "+90 days",
                revoked: false,
            },
        );
        seed_tokens(&conn, g);
    }
    let before = count(&*fx.meta.lock().await, ROW_TOTAL);
    assert!(before > 0);
    let success = sdk_query(4242, Some("st"));
    let back = replaced(&success, "response_type=code", "response_type=token");
    let page = enc(&[("client_id", "https://evil.example/cimd")]);
    for (what, q, status) in [
        ("success", success, StatusCode::SEE_OTHER),
        ("back", back, StatusCode::SEE_OTHER),
        ("page", page, StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(authorize(&fx, &q).await.status(), status, "{what}");
        assert_eq!(
            count(&*fx.meta.lock().await, ROW_TOTAL),
            before,
            "{what} wrote a row"
        );
    }
}

#[tokio::test]
async fn authorize_never_takes_the_meta_lock() {
    let fx = fixture(true).await;
    let _guard = fx.meta.lock().await;
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        authorize(&fx, &sdk_query(4242, Some("st"))),
    )
    .await
    .expect("authorize waited on the meta lock");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn authorize_absent_when_disabled() {
    let auto = McpOauthConfig::from_parts(
        &McpOauthEnv {
            mode: Some("auto"),
            public_url: Some(PUBLIC_URL),
            ..Default::default()
        },
        "/drust",
        [1; 32],
        [2; 32],
    );
    // auto under a base path stays off; the same env with an empty base
    // enables, so the base path is what keeps it off here.
    assert!(!auto.enabled());
    assert!(
        McpOauthConfig::from_parts(
            &McpOauthEnv {
                mode: Some("auto"),
                public_url: Some(PUBLIC_URL),
                ..Default::default()
            },
            "",
            [1; 32],
            [2; 32],
        )
        .enabled()
    );
    for (what, fx) in [
        ("off", fixture(false).await),
        ("auto", fixture_with(auto).await),
    ] {
        let never = snapshot(get(&fx.app, "/oauth/nonexistent", &[]).await).await;
        assert_eq!(never.0, StatusCode::NOT_FOUND, "{what}");
        let got = snapshot(authorize(&fx, &sdk_query(4242, Some("st"))).await).await;
        assert_eq!(got, never, "{what}");
    }
}

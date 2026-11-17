//! Empty-base (Docker root) mode proof for the configurable URL prefix.
//!
//! Default mode (`base_path() == "/drust"`) is covered byte-identically by the
//! entire integration + lib suite (every outbound link/cookie asserts `/drust`).
//! This dedicated binary is the counterpart: a separate process — so the
//! `OnceLock` starts unset — that pins the empty-prefix deployment (Docker /
//! root mount, `DRUST_BASE_PATH=""`). It exercises the real public API
//! (`set` -> `base_path` / `base` / `cookie_path`), not just the pure inner
//! helpers covered by the `src/base_path.rs` unit tests.

#[test]
fn empty_base_drops_the_prefix() {
    // First base_path mutation in this process: empty prefix = root mount.
    drust::base_path::set("");

    assert_eq!(
        drust::base_path::base_path(),
        "",
        "raw prefix must be empty"
    );

    // URL builder: prefix vanishes, the remainder is returned verbatim.
    assert_eq!(drust::base_path::base("/login"), "/login");
    assert_eq!(drust::base_path::base("/admin/tenants"), "/admin/tenants");
    assert_eq!(drust::base_path::base("/t/abc/mcp"), "/t/abc/mcp");

    // Cookie Path builder: an otherwise-empty Path collapses to "/" (a cookie
    // Path attribute must be non-empty), non-empty subs pass through.
    assert_eq!(drust::base_path::cookie_path(""), "/");
    assert_eq!(drust::base_path::cookie_path("/admin"), "/admin");
    assert_eq!(
        drust::base_path::cookie_path("/t/abc/oauth/"),
        "/t/abc/oauth/"
    );
}

#[test]
fn mcp_oauth_urls_drop_the_prefix() {
    // Same first-write-wins value as the test above, so order does not matter.
    drust::base_path::set("");
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests("https://drust.test");
    assert_eq!(cfg.issuer(), "https://drust.test"); // no trailing '/'
    assert_eq!(cfg.resource_url(), "https://drust.test/mcp");
    assert_eq!(
        cfg.endpoint_url("/oauth/token"),
        "https://drust.test/oauth/token"
    );
    assert!(cfg.is_our_resource("https://drust.test/mcp"));
    assert!(!cfg.is_our_resource("https://drust.test/drust/mcp"));
}

#[test]
fn mcp_oauth_metadata_under_empty_base() {
    // First-write-wins OnceLock: every #[test] in this binary sets "".
    drust::base_path::set("");
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests("https://drust.test");
    let m = drust::mgmt::mcp_oauth::metadata::metadata_json(&cfg);
    assert_eq!(m["issuer"], "https://drust.test"); // no trailing '/'
    assert_eq!(cfg.issuer(), "https://drust.test");
    assert_eq!(
        m["authorization_endpoint"],
        "https://drust.test/oauth/authorize"
    );
    assert_eq!(m["token_endpoint"], "https://drust.test/oauth/token");
    assert_eq!(m["revocation_endpoint"], "https://drust.test/oauth/revoke");
    assert!(!m["issuer"].as_str().unwrap().ends_with('/'));
}

#[test]
fn mcp_oauth_consent_location_and_resume_cookie_in_root_mode() {
    // First-write-wins OnceLock: every #[test] in this binary sets "".
    drust::base_path::set("");
    assert_eq!(
        drust::mgmt::mcp_oauth::authorize::consent_location("abc"),
        "/oauth/consent?req=abc"
    );
    let c = drust::mgmt::mcp_oauth::envelope::resume_cookie("abc");
    assert!(
        c.starts_with("drust_mcp_oauth_resume=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=600"),
        "{c}"
    );
}

#[test]
fn mcp_oauth_error_redirect_iss_in_root_mode() {
    drust::base_path::set("");
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests("https://drust.test");
    assert_eq!(cfg.issuer(), "https://drust.test"); // no trailing '/'
    assert_eq!(
        drust::mgmt::mcp_oauth::authorize::error_redirect_location(
            &cfg,
            "http://localhost:1/callback",
            drust::mgmt::mcp_oauth::authorize::AuthzErrorCode::InvalidRequest,
            None,
            Some("s"),
        ),
        "http://localhost:1/callback?error=invalid_request&state=s&iss=https%3A%2F%2Fdrust.test"
    );
}

#[test]
fn empty_base_resume_target_is_root_consent() {
    drust::base_path::set("");
    use drust::mgmt::mcp_oauth::envelope::{self, AuthzRequest, ResumeDecision};
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests("https://drust.test");
    let now = envelope::now_unix().unwrap();
    let wire = envelope::seal(
        &cfg,
        &AuthzRequest {
            client_id: "https://claude.ai/oauth/claude-code-client-metadata".into(),
            redirect_uri: "http://localhost:5/callback".into(),
            state: None,
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            resource: None,
        },
        now,
    )
    .unwrap();
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        axum::http::header::COOKIE,
        format!("{}={wire}", envelope::RESUME_COOKIE)
            .parse()
            .unwrap(),
    );
    assert_eq!(
        envelope::resume_target(&cfg, &h, now),
        ResumeDecision::Resume("/oauth/consent".into())
    );
}

#[test]
fn empty_base_consent_cookies_use_root_path() {
    drust::base_path::set("");
    let set = drust::mgmt::mcp_oauth::consent::build_csrf_cookie("x");
    let clear = drust::mgmt::mcp_oauth::consent::clear_csrf_cookie();
    assert!(set.starts_with("drust_mcp_oauth_csrf=x; Path=/;"), "{set}");
    assert!(
        clear.starts_with("drust_mcp_oauth_csrf=; Path=/;"),
        "{clear}"
    );
    assert!(clear.contains("Max-Age=0"), "{clear}");
}

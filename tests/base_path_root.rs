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

#[test]
fn mcp_oauth_prm_url_and_allowed_hosts_under_empty_base() {
    // First-write-wins OnceLock: every #[test] in this binary sets "".
    drust::base_path::set("");
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests("https://drust.test");
    assert_eq!(
        cfg.prm_url(),
        "https://drust.test/.well-known/oauth-protected-resource/mcp"
    );
    assert_eq!(
        cfg.allowed_hosts(),
        ["localhost", "127.0.0.1", "::1", "drust.test"]
    );
    assert!(
        cfg.boot_log_lines()[0].ends_with(" allowed_hosts=[localhost,127.0.0.1,::1,drust.test]"),
        "{:?}",
        cfg.boot_log_lines()
    );
}

#[tokio::test]
async fn account_mcp_urls_drop_the_prefix() {
    use std::sync::Arc;
    use tower::ServiceExt;
    drust::base_path::set("");
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests("https://drust.test");
    assert_eq!(
        cfg.prm_url(),
        "https://drust.test/.well-known/oauth-protected-resource/mcp"
    );
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = drust::storage::meta::open_meta(&data.join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = drust::mgmt::routes::MgmtState::test_default(
        Arc::new(tokio::sync::Mutex::new(conn)),
        data.clone(),
        tenants,
        mcp,
        drust::tenant::events::EventBus::new(),
        drust::tenant::rooms::RoomBus::new(),
    );
    state.mcp_oauth = Arc::new(cfg);
    let app = state.with_data_dir(data);
    let r = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "127.0.0.1")
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(
        r.headers()["www-authenticate"],
        r#"Bearer resource_metadata="https://drust.test/.well-known/oauth-protected-resource/mcp", scope="mcp""#
    );
    let r = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/.well-known/oauth-protected-resource/mcp")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    let prm: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(prm["resource"], "https://drust.test/mcp");
    assert_eq!(prm["authorization_servers"][0], "https://drust.test");
}

#[test]
fn account_ticket_urls_drop_the_prefix() {
    drust::base_path::set("");
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests("https://drust.test");
    assert_eq!(
        drust::mcp::account::ticket_urls(&cfg, "blog"),
        (
            "https://drust.test/t/blog/uploads".to_string(),
            "https://drust.test/t/blog/uploads/".to_string()
        )
    );
}

#[test]
fn connect_and_diagnostics_urls_drop_the_prefix() {
    drust::base_path::set("");
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests("https://drust.test");
    let c = drust::mgmt::mcp_oauth::connect::connect_commands(&cfg).unwrap();
    assert_eq!(
        c.add,
        "claude mcp add --transport http --scope user drust https://drust.test/mcp"
    );
    assert!(
        c.metadata_fallback.is_none(),
        "no authServerMetadataUrl fallback under an empty base"
    );
    let checks: Vec<(&str, String)> = drust::mgmt::mcp_oauth::connect::diag_checks(&cfg)
        .into_iter()
        .map(|c| (c.id, c.url))
        .collect();
    assert_eq!(
        checks,
        vec![
            ("mcp", "https://drust.test/mcp".to_string()),
            (
                "prm",
                "https://drust.test/.well-known/oauth-protected-resource/mcp".to_string()
            ),
            (
                "as_root",
                "https://drust.test/.well-known/oauth-authorization-server".to_string()
            ),
            ("token", "https://drust.test/oauth/token".to_string()),
        ]
    );
    let v = drust::mgmt::mcp_oauth::connect::diagnostics_json(&cfg).unwrap();
    assert_eq!(v["page"], "https://drust.test/admin/mcp/diagnostics");
    assert_eq!(v["issuer"], "https://drust.test");
}

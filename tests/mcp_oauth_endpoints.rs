//! MA0-4 — the OAuth AS routes: mount rule, metadata, the OAuth error layer,
//! the token-endpoint skeleton and RFC 7009 revoke. Every request goes through
//! the production router (`MgmtState::with_data_dir`) at ROOT paths: `/drust`
//! is stripped by the proxy before axum, so only outbound strings carry it.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use drust::mgmt::mcp_oauth::config::{DisabledReason, McpOauthConfig, McpOauthEnv};
use drust::mgmt::mcp_oauth::metadata::metadata_json;
use drust::mgmt::mcp_oauth::store;
use drust::mgmt::mcp_oauth::tokens::{self, TokenKind};
use rusqlite::params;
use tower::ServiceExt;

use crate::common::mcp_oauth::*;

const FORM: &str = "application/x-www-form-urlencoded";
const META_PATH: &str = "/.well-known/oauth-authorization-server";

// ─── file-private helpers ────────────────────────────────────────────────────

type Snapshot = (StatusCode, Vec<(String, String)>, Vec<u8>);

/// Status, every header (sorted by name, value order kept) and the body, for
/// byte-identity comparisons.
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

fn hdr(h: &axum::http::HeaderMap, name: header::HeaderName) -> Option<&str> {
    h.get(name).map(|v| v.to_str().unwrap())
}

/// The full OAuth-error contract; returns the headers for further checks.
async fn assert_oauth_error(
    resp: Response<Body>,
    status: StatusCode,
    code: &str,
    ctx: &str,
) -> axum::http::HeaderMap {
    assert_eq!(resp.status(), status, "{ctx}: status");
    let h = resp.headers().clone();
    let ct = hdr(&h, header::CONTENT_TYPE).unwrap_or_default();
    assert_eq!(
        ct.split(';').next().unwrap().trim(),
        "application/json",
        "{ctx}: content-type"
    );
    assert_eq!(
        hdr(&h, header::CACHE_CONTROL),
        Some("no-store"),
        "{ctx}: cache-control"
    );
    assert!(h.get(header::LOCATION).is_none(), "{ctx}: location");
    assert!(h.get(header::SET_COOKIE).is_none(), "{ctx}: set-cookie");
    let v = body_json(resp).await;
    assert_eq!(v["error"], code, "{ctx}: error code");
    if let Some(d) = v.get("error_description") {
        for b in d.as_str().unwrap().bytes() {
            assert!(
                matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E),
                "{ctx}: error_description byte {b:#x}"
            );
        }
    }
    h
}

/// A well-formed access token that is in no database.
fn random_access() -> String {
    tokens::new_token(TokenKind::Access)
}

fn form_req(
    method: &str,
    uri: &str,
    body: &[u8],
    content_type: Option<&str>,
    extra: &[(&str, &str)],
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(ct) = content_type {
        b = b.header(header::CONTENT_TYPE, ct);
    }
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

async fn post_raw(app: &axum::Router, uri: &str, body: &str) -> Response<Body> {
    send(app, form_req("POST", uri, body.as_bytes(), Some(FORM), &[])).await
}

fn live_grant(conn: &rusqlite::Connection, admin_id: i64) -> i64 {
    seed_grant(
        conn,
        &SeedGrant {
            admin_id,
            idle: "+30 days",
            absolute: "+90 days",
            revoked: false,
        },
    )
}

/// A live grant of the owner plus one access/refresh pair.
async fn grant_with_tokens(fx: &McpOauthFixture) -> (i64, SeededTokens) {
    let conn = fx.meta.lock().await;
    let gid = live_grant(&conn, fx.owner_id);
    let t = seed_tokens(&conn, gid);
    (gid, t)
}

// G1 / G2 / G3 (plan §4.2.5).
async fn g1(fx: &McpOauthFixture, gid: i64) -> (bool, Option<String>) {
    fx.meta
        .lock()
        .await
        .query_row(
            "SELECT revoked_at IS NOT NULL, revoke_reason FROM _mcp_oauth_grants WHERE id = ?1",
            params![gid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

async fn g2(fx: &McpOauthFixture, gid: i64) -> i64 {
    fx.meta
        .lock()
        .await
        .query_row(
            "SELECT COUNT(*) FROM _mcp_oauth_refresh WHERE grant_id = ?1 AND revoked_at IS NULL",
            params![gid],
            |r| r.get(0),
        )
        .unwrap()
}

async fn g3(fx: &McpOauthFixture, gid: i64) -> i64 {
    fx.meta
        .lock()
        .await
        .query_row(
            "SELECT COUNT(*) FROM _mcp_oauth_access WHERE grant_id = ?1 AND revoked_at IS NULL",
            params![gid],
            |r| r.get(0),
        )
        .unwrap()
}

async fn assert_revoked(fx: &McpOauthFixture, gid: i64, ctx: &str) {
    assert_eq!(
        g1(fx, gid).await,
        (true, Some("oauth_revoke".to_string())),
        "{ctx}: G1"
    );
    assert_eq!(g2(fx, gid).await, 0, "{ctx}: G2");
    assert_eq!(g3(fx, gid).await, 0, "{ctx}: G3");
}

async fn assert_not_revoked(fx: &McpOauthFixture, gid: i64, ctx: &str) {
    assert_eq!(g1(fx, gid).await, (false, None), "{ctx}: G1");
}

/// 200, empty body, no-store, no set-cookie.
async fn assert_ok_empty(resp: Response<Body>, ctx: &str) {
    assert_eq!(resp.status(), StatusCode::OK, "{ctx}: status");
    assert_eq!(
        hdr(resp.headers(), header::CACHE_CONTROL),
        Some("no-store"),
        "{ctx}: cache-control"
    );
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "{ctx}: set-cookie"
    );
    assert!(
        resp.headers().get(header::RETRY_AFTER).is_none(),
        "{ctx}: retry-after"
    );
    assert_eq!(body_text(resp).await, "", "{ctx}: body");
}

async fn revoke_with(app: &axum::Router, pairs: &[(&str, &str)]) -> Response<Body> {
    post_form(app, "/oauth/revoke", pairs, &[], &[]).await
}

/// The disabled-mount check shared by the three disabled configurations: each
/// new path answers exactly like a path that never existed.
async fn assert_nothing_mounted(app: &axum::Router) {
    let never_get = snapshot(get(app, "/oauth/nonexistent", &[]).await).await;
    for uri in [
        META_PATH,
        "/oauth/authorize",
        "/.well-known/openid-configuration",
    ] {
        assert_eq!(
            snapshot(get(app, uri, &[]).await).await,
            never_get,
            "GET {uri}"
        );
    }
    let never_post =
        snapshot(post_raw(app, "/oauth/nonexistent", "grant_type=password").await).await;
    for (uri, body) in [
        ("/oauth/token", "grant_type=password"),
        ("/oauth/revoke", "token=abc"),
    ] {
        assert_eq!(
            snapshot(post_raw(app, uri, body).await).await,
            never_post,
            "POST {uri}"
        );
    }
}

// ─── §4.2.1 mount rule ───────────────────────────────────────────────────────

#[tokio::test]
async fn disabled_paths_answer_like_a_path_that_never_existed() {
    let fx = fixture(false).await;
    assert_nothing_mounted(&fx.app).await;
}

#[tokio::test]
async fn auto_mode_mounts_nothing_in_ma0() {
    let cfg = McpOauthConfig::from_parts(
        &McpOauthEnv {
            mode: Some("auto"),
            public_url: Some(PUBLIC_URL),
            ..Default::default()
        },
        "/drust",
        [1; 32],
        [2; 32],
    );
    assert_eq!(cfg.disabled_reason(), Some(&DisabledReason::AutoBeforeMa1d));
    let fx = fixture_with(cfg).await;
    assert_nothing_mounted(&fx.app).await;
}

#[tokio::test]
async fn on_without_a_public_url_mounts_nothing() {
    let cfg = McpOauthConfig::from_parts(
        &McpOauthEnv {
            mode: Some("on"),
            public_url: None,
            ..Default::default()
        },
        "/drust",
        [1; 32],
        [2; 32],
    );
    assert_eq!(
        cfg.disabled_reason(),
        Some(&DisabledReason::PublicUrlMissing)
    );
    let fx = fixture_with(cfg).await;
    assert_nothing_mounted(&fx.app).await;
}

#[tokio::test]
async fn on_mode_from_env_parts_mounts_the_routes() {
    let cfg = McpOauthConfig::from_parts(
        &McpOauthEnv {
            mode: Some("on"),
            public_url: Some(PUBLIC_URL),
            ..Default::default()
        },
        "/drust",
        [1; 32],
        [2; 32],
    );
    assert!(cfg.enabled());
    let fx = fixture_with(cfg).await;
    let resp = get(&fx.app, META_PATH, &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn enabling_does_not_change_unmatched_paths() {
    // Deliberately NOT GET /oauth/authorize: MA0-5 mounts it.
    let on = fixture(true).await;
    let off = fixture(false).await;
    for (method, uri) in [
        ("GET", "/oauth/nonexistent"),
        ("POST", "/oauth/token/extra"),
        ("GET", "/.well-known/openid-configuration"),
    ] {
        let req = || form_req(method, uri, b"grant_type=password", Some(FORM), &[]);
        let a = snapshot(send(&on.app, req()).await).await;
        let b = snapshot(send(&off.app, req()).await).await;
        assert_eq!(a, b, "{method} {uri}");
        assert!(
            !a.1.iter()
                .any(|(k, v)| k == "cache-control" && v == "no-store"),
            "{method} {uri}: no-store leaked onto an unmatched path"
        );
        assert!(
            !a.1.iter()
                .any(|(k, v)| k == "content-type" && v.starts_with("application/json")),
            "{method} {uri}: JSON on an unmatched path"
        );
    }
}

#[tokio::test]
async fn public_routes_alone_keeps_a_plain_404() {
    // The same state `fixture_with` builds, kept here because the fixture does
    // not expose its MgmtState.
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let conn = drust::storage::meta::open_meta(&data_dir.join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let meta = Arc::new(tokio::sync::Mutex::new(conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = drust::mgmt::routes::MgmtState::test_default(
        meta,
        data_dir,
        tenants,
        mcp,
        drust::tenant::events::EventBus::new(),
        drust::tenant::rooms::RoomBus::new(),
    );
    state.mcp_oauth = Arc::new(McpOauthConfig::for_tests(PUBLIC_URL));

    let resp = drust::mgmt::mcp_oauth::public_routes(&state)
        .oneshot(
            Request::builder()
                .uri("/oauth/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // With `Router::layer` instead of `route_layer`, this 404 would be rewritten
    // to {"error":"invalid_request"} with no-store.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(resp.headers().get(header::CACHE_CONTROL).is_none());
    let body = body_text(resp).await;
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).is_err(),
        "body is JSON: {body:?}"
    );
}

// ─── §4.2.2 metadata ─────────────────────────────────────────────────────────

#[tokio::test]
async fn metadata_is_served_with_the_final_shape() {
    let fx = fixture(true).await;
    let resp = get(&fx.app, META_PATH, &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers().clone();
    assert_eq!(hdr(&h, header::CONTENT_TYPE), Some("application/json"));
    assert_eq!(hdr(&h, header::CACHE_CONTROL), Some("public, max-age=300"));
    assert!(h.get(header::LOCATION).is_none());
    let body = body_json(resp).await;
    assert_eq!(body, metadata_json(&McpOauthConfig::for_tests(PUBLIC_URL)));
    assert_eq!(body["issuer"], ISSUER);
}

#[tokio::test]
async fn metadata_never_touches_meta() {
    let fx = fixture(true).await;
    let _held = fx.meta.lock().await;
    let resp = tokio::time::timeout(Duration::from_secs(1), get(&fx.app, META_PATH, &[]))
        .await
        .expect("metadata waited on the meta mutex");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn metadata_is_framed_out_like_the_admin_plane() {
    let fx = fixture(true).await;
    let resp = get(&fx.app, META_PATH, &[]).await;
    let h = resp.headers();
    assert_eq!(hdr(h, header::X_FRAME_OPTIONS), Some("DENY"));
    assert_eq!(
        hdr(h, header::CONTENT_SECURITY_POLICY),
        Some("frame-ancestors 'none'")
    );
}

#[tokio::test]
async fn metadata_ignores_host_and_forwarded_headers() {
    let fx = fixture(true).await;
    let plain = snapshot(get(&fx.app, META_PATH, &[]).await).await;
    let req = Request::builder()
        .uri(META_PATH)
        .header(header::HOST, "evil.example")
        .header("x-forwarded-host", "evil.example")
        .header("x-forwarded-proto", "http")
        .body(Body::empty())
        .unwrap();
    let spoofed = snapshot(send(&fx.app, req).await).await;
    assert_eq!(spoofed.2, plain.2);
    let want = serde_json::to_vec(&metadata_json(&McpOauthConfig::for_tests(PUBLIC_URL))).unwrap();
    assert_eq!(spoofed.2, want);
}

// ─── §4.2.3 the OAuth error layer ────────────────────────────────────────────

struct Case {
    name: &'static str,
    method: &'static str,
    content_type: Option<&'static str>,
    token_body: Vec<u8>,
    revoke_body: Vec<u8>,
    extra: &'static [(&'static str, &'static str)],
    status: StatusCode,
    code: &'static str,
    www: Option<&'static str>,
    allow: bool,
}

fn malformed_cases() -> Vec<Case> {
    let base = |name, method, ct, tb: &str, rb: &str, status, code| Case {
        name,
        method,
        content_type: ct,
        token_body: tb.as_bytes().to_vec(),
        revoke_body: rb.as_bytes().to_vec(),
        extra: &[],
        status,
        code,
        www: None,
        allow: false,
    };
    let bad = StatusCode::BAD_REQUEST;
    let mut v = vec![
        base(
            "empty_form",
            "POST",
            Some(FORM),
            "",
            "",
            bad,
            "invalid_request",
        ),
        base(
            "no_content_type",
            "POST",
            None,
            "grant_type=x",
            "token=x",
            bad,
            "invalid_request",
        ),
        base(
            "json_body",
            "POST",
            Some("application/json"),
            r#"{"grant_type":"refresh_token"}"#,
            r#"{"token":"x"}"#,
            bad,
            "invalid_request",
        ),
        base(
            "multipart",
            "POST",
            Some("multipart/form-data; boundary=b"),
            "--b\r\nContent-Disposition: form-data; name=\"grant_type\"\r\n\r\npassword\r\n--b--\r\n",
            "--b\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\nx\r\n--b--\r\n",
            bad,
            "invalid_request",
        ),
        base(
            "duplicate",
            "POST",
            Some(FORM),
            "grant_type=password&grant_type=password",
            "token=a&token=b",
            bad,
            "invalid_request",
        ),
        base(
            "encoded_duplicate",
            "POST",
            Some(FORM),
            "grant_type=password&grant%5Ftype=password",
            "token=a&tok%65n=b",
            bad,
            "invalid_request",
        ),
    ];
    let mut oversized = base(
        "oversized",
        "POST",
        Some(FORM),
        "",
        "",
        StatusCode::PAYLOAD_TOO_LARGE,
        "invalid_request",
    );
    oversized.token_body = vec![b'a'; 16 * 1024 + 1];
    oversized.revoke_body = vec![b'a'; 16 * 1024 + 1];
    v.push(oversized);
    let mut get_case = base(
        "get",
        "GET",
        None,
        "",
        "",
        StatusCode::METHOD_NOT_ALLOWED,
        "invalid_request",
    );
    get_case.allow = true;
    v.push(get_case);
    v.push(base(
        "put",
        "PUT",
        Some(FORM),
        "grant_type=password",
        "token=x",
        StatusCode::METHOD_NOT_ALLOWED,
        "invalid_request",
    ));
    let mut basic = base(
        "basic_auth",
        "POST",
        Some(FORM),
        "grant_type=password",
        "token=x",
        StatusCode::UNAUTHORIZED,
        "invalid_client",
    );
    basic.extra = &[("authorization", "Basic Y2xpZW50OnNlY3JldA==")];
    basic.www = Some(r#"Basic realm="drust-oauth""#);
    v.push(basic);
    let mut bearer = base(
        "bearer_auth",
        "POST",
        Some(FORM),
        "grant_type=password",
        "token=x",
        StatusCode::UNAUTHORIZED,
        "invalid_client",
    );
    bearer.extra = &[("authorization", "Bearer abc")];
    bearer.www = Some(r#"Bearer realm="drust-oauth""#);
    v.push(bearer);
    v
}

#[tokio::test]
async fn every_malformed_request_gets_an_oauth_json_error() {
    let fx = fixture(true).await;
    for case in malformed_cases() {
        for (uri, body) in [
            ("/oauth/token", &case.token_body),
            ("/oauth/revoke", &case.revoke_body),
        ] {
            let ctx = format!("{} {uri}", case.name);
            let req = form_req(case.method, uri, body, case.content_type, case.extra);
            let h =
                assert_oauth_error(send(&fx.app, req).await, case.status, case.code, &ctx).await;
            assert_eq!(
                hdr(&h, header::WWW_AUTHENTICATE),
                case.www,
                "{ctx}: www-authenticate"
            );
            if case.allow {
                assert_eq!(hdr(&h, header::ALLOW), Some("POST"), "{ctx}: allow");
            }
        }
    }
}

#[tokio::test]
async fn exactly_16_kib_is_not_too_large() {
    let fx = fixture(true).await;
    let mut token_body = String::from("grant_type=password&pad=");
    token_body.push_str(&"a".repeat(16 * 1024 - token_body.len()));
    assert_eq!(token_body.len(), 16 * 1024);
    let resp = post_raw(&fx.app, "/oauth/token", &token_body).await;
    assert_oauth_error(
        resp,
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        "token 16 KiB",
    )
    .await;

    let mut revoke_body = String::from("token=");
    revoke_body.push_str(&"a".repeat(16 * 1024 - revoke_body.len()));
    assert_eq!(revoke_body.len(), 16 * 1024);
    assert_ok_empty(
        post_raw(&fx.app, "/oauth/revoke", &revoke_body).await,
        "revoke 16 KiB",
    )
    .await;
}

#[tokio::test]
async fn content_type_parameters_and_case_are_accepted() {
    let fx = fixture(true).await;
    for ct in [
        "application/x-www-form-urlencoded; charset=UTF-8",
        "Application/X-WWW-Form-Urlencoded",
    ] {
        let req = form_req(
            "POST",
            "/oauth/token",
            b"grant_type=password",
            Some(ct),
            &[],
        );
        assert_oauth_error(
            send(&fx.app, req).await,
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            ct,
        )
        .await;
    }
}

#[tokio::test]
async fn no_response_on_these_paths_is_ever_a_redirect() {
    let fx = fixture(true).await;
    let (_gid, t) = grant_with_tokens(&fx).await;
    let (_gid2, t2) = grant_with_tokens(&fx).await;
    let mut resps = Vec::new();
    resps.push(get(&fx.app, META_PATH, &[]).await);
    for case in malformed_cases() {
        for (uri, body) in [
            ("/oauth/token", &case.token_body),
            ("/oauth/revoke", &case.revoke_body),
        ] {
            resps.push(
                send(
                    &fx.app,
                    form_req(case.method, uri, body, case.content_type, case.extra),
                )
                .await,
            );
        }
    }
    for body in [
        "client_id=x",
        "grant_type=",
        "grant_type=password",
        "grant_type=authorization_code&code=x&code_verifier=y&redirect_uri=z",
        "grant_type=refresh_token&refresh_token=drust_mcprt_x",
        "grant_type=password&resource=a&resource=b",
    ] {
        resps.push(post_raw(&fx.app, "/oauth/token", body).await);
    }
    let rnd = random_access();
    for pairs in [
        vec![("token", t.access.as_str()), ("client_id", CC_CLIENT_ID)],
        vec![("token", t2.refresh.as_str())],
        vec![("token", rnd.as_str())],
        vec![("token", "drust_pat_x")],
        vec![
            ("token", t.access.as_str()),
            ("client_id", "https://example.invalid/c"),
        ],
        vec![("client_id", CC_CLIENT_ID)],
    ] {
        resps.push(revoke_with(&fx.app, &pairs).await);
    }
    for (i, r) in resps.iter().enumerate() {
        assert!(!r.status().is_redirection(), "#{i}: {}", r.status());
        assert!(
            r.headers().get(header::LOCATION).is_none(),
            "#{i}: location"
        );
    }
}

/// (uri, form pairs, expected status)
type CookieCase<'a> = (&'a str, Vec<(&'a str, &'a str)>, StatusCode);

#[tokio::test]
async fn token_and_revoke_ignore_cookies() {
    let fx = fixture(true).await;
    let session = {
        let mut conn = fx.meta.lock().await;
        drust::auth::session::create_session(&mut conn, fx.owner_id, 3600).unwrap()
    };
    let cookie = format!("drust_session={session}");
    let (gid, _t) = grant_with_tokens(&fx).await;
    let rnd = random_access();
    let cases: Vec<CookieCase> = vec![
        (
            "/oauth/revoke",
            vec![("client_id", CC_CLIENT_ID)],
            StatusCode::BAD_REQUEST,
        ),
        (
            "/oauth/revoke",
            vec![("token", rnd.as_str())],
            StatusCode::OK,
        ),
        (
            "/oauth/token",
            vec![("grant_type", "password")],
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (uri, pairs, status) in &cases {
        let with = post_form(&fx.app, uri, pairs, &[cookie.as_str()], &[]).await;
        assert!(
            with.headers().get(header::SET_COOKIE).is_none(),
            "{uri} {pairs:?}"
        );
        let with = snapshot(with).await;
        assert_eq!(with.0, *status, "{uri} {pairs:?}");
        let without = snapshot(post_form(&fx.app, uri, pairs, &[], &[]).await).await;
        assert_eq!(with, without, "{uri} {pairs:?}");
    }
    assert_not_revoked(&fx, gid, "session cookie revoked nothing").await;
}

#[tokio::test]
async fn token_is_never_read_from_the_query() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    let uri = format!("/oauth/revoke?token={}", t.access);
    let resp = post_form(&fx.app, &uri, &[("client_id", CC_CLIENT_ID)], &[], &[]).await;
    assert_oauth_error(
        resp,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "query token",
    )
    .await;
    assert_not_revoked(&fx, gid, "query token").await;
}

// ─── §4.2.4 token skeleton ───────────────────────────────────────────────────

#[tokio::test]
async fn missing_grant_type_is_invalid_request() {
    let fx = fixture(true).await;
    let resp = post_form(
        &fx.app,
        "/oauth/token",
        &[("client_id", CC_CLIENT_ID)],
        &[],
        &[],
    )
    .await;
    assert_oauth_error(resp, StatusCode::BAD_REQUEST, "invalid_request", "missing").await;
}

#[tokio::test]
async fn an_empty_grant_type_counts_as_missing() {
    let fx = fixture(true).await;
    let resp = post_raw(&fx.app, "/oauth/token", "grant_type=").await;
    assert_oauth_error(resp, StatusCode::BAD_REQUEST, "invalid_request", "empty").await;
}

#[tokio::test]
async fn unknown_grant_types_are_unsupported() {
    let fx = fixture(true).await;
    for g in [
        "password",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
        "AUTHORIZATION_CODE",
    ] {
        let resp = post_form(&fx.app, "/oauth/token", &[("grant_type", g)], &[], &[]).await;
        assert_oauth_error(resp, StatusCode::BAD_REQUEST, "unsupported_grant_type", g).await;
    }
}

/// MA0-8 rewrites this test. (The code exchange landed with MA0-7; its tests
/// are in `mcp_oauth_token_code.rs`.)
#[tokio::test]
async fn refresh_token_grant_is_not_yet_supported() {
    let fx = fixture(true).await;
    let refresh = [
        ("grant_type", "refresh_token"),
        ("refresh_token", "drust_mcprt_x"),
    ];
    let resp = post_form(&fx.app, "/oauth/token", &refresh, &[], &[]).await;
    assert_oauth_error(
        resp,
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        "refresh",
    )
    .await;
}

#[tokio::test]
async fn unknown_parameters_are_ignored_even_when_repeated() {
    let fx = fixture(true).await;
    let resp = post_raw(&fx.app, "/oauth/token", "grant_type=password&foo=1&foo=2").await;
    assert_oauth_error(
        resp,
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        "foo",
    )
    .await;
}

#[tokio::test]
async fn a_repeated_resource_is_invalid_request() {
    let fx = fixture(true).await;
    let resp = post_raw(
        &fx.app,
        "/oauth/token",
        "grant_type=password&resource=a&resource=b",
    )
    .await;
    assert_oauth_error(resp, StatusCode::BAD_REQUEST, "invalid_request", "resource").await;
}

#[tokio::test]
async fn token_touches_no_table() {
    let fx = fixture(true).await;
    let _held = fx.meta.lock().await;
    let body = format!(
        "grant_type=refresh_token&refresh_token={}",
        tokens::new_token(TokenKind::Refresh)
    );
    let resp = tokio::time::timeout(
        Duration::from_secs(1),
        post_raw(&fx.app, "/oauth/token", &body),
    )
    .await
    .expect("token waited on the meta mutex");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── §4.2.5 revoke ───────────────────────────────────────────────────────────

#[tokio::test]
async fn revoking_an_access_token_revokes_the_whole_grant() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    let resp = revoke_with(
        &fx.app,
        &[("token", t.access.as_str()), ("client_id", CC_CLIENT_ID)],
    )
    .await;
    assert_ok_empty(resp, "access").await;
    assert_revoked(&fx, gid, "access").await;
    let conn = fx.meta.lock().await;
    assert!(
        store::find_grant_by_refresh(&conn, &t.refresh)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn revoking_an_expired_access_token_still_revokes_the_grant() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    fx.meta
        .lock()
        .await
        .execute(
            "UPDATE _mcp_oauth_access SET expires_at = datetime('now','-1 hour') WHERE grant_id = ?1",
            params![gid],
        )
        .unwrap();
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", t.access.as_str())]).await,
        "expired",
    )
    .await;
    assert_revoked(&fx, gid, "expired access").await;
}

#[tokio::test]
async fn revoking_a_rotated_refresh_revokes_the_grant() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    fx.meta
        .lock()
        .await
        .execute(
            "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now') WHERE grant_id = ?1",
            params![gid],
        )
        .unwrap();
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", t.refresh.as_str())]).await,
        "rotated",
    )
    .await;
    assert_revoked(&fx, gid, "rotated refresh").await;
}

#[tokio::test]
async fn revoking_a_refresh_token_revokes_the_whole_grant() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", t.refresh.as_str())]).await,
        "refresh",
    )
    .await;
    assert_revoked(&fx, gid, "refresh").await;
    let conn = fx.meta.lock().await;
    assert!(
        store::find_grant_by_access(&conn, &t.access)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_type_hint_is_ignored() {
    let fx = fixture(true).await;
    let (g_a, t_a) = grant_with_tokens(&fx).await;
    let (g_r, t_r) = grant_with_tokens(&fx).await;
    let (g_n, t_n) = grant_with_tokens(&fx).await;
    for (gid, token, hint) in [
        (g_a, &t_a.access, "refresh_token"),
        (g_r, &t_r.refresh, "access_token"),
        (g_n, &t_n.access, "nonsense"),
    ] {
        let resp = revoke_with(
            &fx.app,
            &[("token", token.as_str()), ("token_type_hint", hint)],
        )
        .await;
        assert_ok_empty(resp, hint).await;
        assert_revoked(&fx, gid, hint).await;
    }
}

#[tokio::test]
async fn revoke_without_client_id_still_revokes() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", t.access.as_str())]).await,
        "no client_id",
    )
    .await;
    assert_revoked(&fx, gid, "no client_id").await;
}

#[tokio::test]
async fn an_unknown_client_id_is_invalid_client_and_revokes_nothing() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    let resp = revoke_with(
        &fx.app,
        &[
            ("token", t.access.as_str()),
            ("client_id", "https://example.invalid/c"),
        ],
    )
    .await;
    let h = assert_oauth_error(
        resp,
        StatusCode::BAD_REQUEST,
        "invalid_client",
        "unknown client",
    )
    .await;
    assert!(h.get(header::WWW_AUTHENTICATE).is_none());
    assert_not_revoked(&fx, gid, "unknown client").await;
}

#[tokio::test]
async fn a_grant_issued_to_another_client_is_unauthorized_client() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    fx.meta
        .lock()
        .await
        .execute(
            "UPDATE _mcp_oauth_grants SET client_id = 'https://example.invalid/other' WHERE id = ?1",
            params![gid],
        )
        .unwrap();
    let resp = revoke_with(
        &fx.app,
        &[("token", t.access.as_str()), ("client_id", CC_CLIENT_ID)],
    )
    .await;
    assert_oauth_error(
        resp,
        StatusCode::BAD_REQUEST,
        "unauthorized_client",
        "other client",
    )
    .await;
    assert_not_revoked(&fx, gid, "other client").await;
}

#[tokio::test]
async fn missing_or_empty_token_is_invalid_request() {
    let fx = fixture(true).await;
    for body in ["client_id=x", "token="] {
        let resp = post_raw(&fx.app, "/oauth/revoke", body).await;
        assert_oauth_error(resp, StatusCode::BAD_REQUEST, "invalid_request", body).await;
    }
}

#[tokio::test]
async fn an_unknown_token_answers_200() {
    let fx = fixture(true).await;
    let rnd = random_access();
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", rnd.as_str())]).await,
        "unknown",
    )
    .await;
}

#[tokio::test]
async fn a_foreign_prefix_answers_200_without_touching_meta() {
    let fx = fixture(true).await;
    let pat = drust::auth::admin_token::generate_token();
    assert!(pat.starts_with("drust_pat_"), "PAT shape changed");
    let code_shaped = tokens::new_token(TokenKind::Code);
    let _held = fx.meta.lock().await;
    for token in [pat.as_str(), code_shaped.as_str(), "drust_mcpat_short"] {
        let resp = tokio::time::timeout(
            Duration::from_secs(1),
            revoke_with(&fx.app, &[("token", token)]),
        )
        .await
        .expect("revoke waited on the meta mutex for a foreign prefix");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_text(resp).await, "");
    }
}

#[tokio::test]
async fn revoke_never_touches_an_admin_pat() {
    let fx = fixture(true).await;
    let pat = drust::auth::admin_token::generate_token();
    let pat_hash = drust::auth::admin_token::hash_token(&pat);
    {
        let conn = fx.meta.lock().await;
        conn.execute(
            "UPDATE _admin_tokens SET revoked_at = datetime('now') \
             WHERE admin_id = ?1 AND revoked_at IS NULL AND label IS NULL",
            params![fx.owner_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (?1, ?2, ?3)",
            params![fx.owner_id, pat_hash, pat],
        )
        .unwrap();
    }
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", pat.as_str())]).await,
        "pat",
    )
    .await;
    let live: bool = fx
        .meta
        .lock()
        .await
        .query_row(
            "SELECT revoked_at IS NULL FROM _admin_tokens WHERE token_hash = ?1",
            params![pat_hash],
            |r| r.get(0),
        )
        .unwrap();
    assert!(live, "the PAT was revoked");
    let req = Request::builder()
        .uri("/auth/cli/whoami")
        .header(header::AUTHORIZATION, format!("Bearer {pat}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&fx.app, req).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn revoke_never_touches_a_tenant_token() {
    let fx = fixture(true).await;
    let plain = drust::auth::bearer::generate_token();
    let hash = drust::auth::bearer::hash_token(&plain);
    {
        let conn = fx.meta.lock().await;
        conn.execute("INSERT INTO tenants (id, name) VALUES ('t-rv', 'rv')", [])
            .unwrap();
        conn.execute(
            "INSERT INTO tokens (tenant_id, role, token_hash, plaintext) \
             VALUES ('t-rv', 'service', ?1, ?2)",
            params![hash, plain],
        )
        .unwrap();
    }
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", plain.as_str())]).await,
        "tenant key",
    )
    .await;
    let live: bool = fx
        .meta
        .lock()
        .await
        .query_row(
            "SELECT revoked_at IS NULL FROM tokens WHERE token_hash = ?1",
            params![hash],
            |r| r.get(0),
        )
        .unwrap();
    assert!(live, "the tenant key was revoked");
}

#[tokio::test]
async fn revoke_only_touches_the_presented_grant() {
    let fx = fixture(true).await;
    let (g1_id, t1) = grant_with_tokens(&fx).await;
    let (g2_id, t2) = grant_with_tokens(&fx).await;
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", t1.access.as_str())]).await,
        "first",
    )
    .await;
    assert_revoked(&fx, g1_id, "first").await;
    assert_not_revoked(&fx, g2_id, "second").await;
    let conn = fx.meta.lock().await;
    assert!(
        store::find_grant_by_access(&conn, &t2.access)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_token_of_a_revoked_grant_answers_200() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", t.access.as_str())]).await,
        "first",
    )
    .await;
    for i in 0..35 {
        assert_ok_empty(
            revoke_with(&fx.app, &[("token", t.access.as_str())]).await,
            &format!("repeat #{i}"),
        )
        .await;
    }
    assert_revoked(&fx, gid, "repeated").await;

    let (user_gid, ut) = {
        let conn = fx.meta.lock().await;
        let gid = seed_grant(
            &conn,
            &SeedGrant {
                admin_id: fx.owner_id,
                idle: "+30 days",
                absolute: "+90 days",
                revoked: true,
            },
        );
        (gid, seed_tokens(&conn, gid))
    };
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", ut.access.as_str())]).await,
        "user-revoked",
    )
    .await;
    assert_eq!(
        g1(&fx, user_gid).await,
        (true, Some("user".to_string())),
        "an already revoked grant keeps its reason"
    );
}

#[tokio::test]
async fn many_unknown_tokens_all_answer_200() {
    let fx = fixture(true).await;
    for i in 0..40 {
        let rnd = random_access();
        assert_ok_empty(
            revoke_with(&fx.app, &[("token", rnd.as_str())]).await,
            &format!("random #{i}"),
        )
        .await;
    }
    for i in 0..40 {
        let pat = drust::auth::admin_token::generate_token();
        assert_ok_empty(
            revoke_with(&fx.app, &[("token", pat.as_str())]).await,
            &format!("pat #{i}"),
        )
        .await;
    }
    let (gid, t) = grant_with_tokens(&fx).await;
    assert_ok_empty(
        revoke_with(&fx.app, &[("token", t.access.as_str())]).await,
        "live",
    )
    .await;
    assert_revoked(&fx, gid, "live after 80 misses").await;
}

#[tokio::test]
async fn a_revoke_race_still_answers_200() {
    let fx = fixture(true).await;
    let (gid, t) = grant_with_tokens(&fx).await;
    let pairs = [("token", t.access.as_str())];
    let (a, b) = tokio::join!(revoke_with(&fx.app, &pairs), revoke_with(&fx.app, &pairs));
    assert_ok_empty(a, "racer a").await;
    assert_ok_empty(b, "racer b").await;
    assert_revoked(&fx, gid, "race").await;
}

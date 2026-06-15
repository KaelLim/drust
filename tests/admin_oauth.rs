//! Admin OAuth integration tests (v1.11).
//!
//! Spins up a local axum HTTP server that impersonates a Google/GitHub
//! OAuth provider so we can drive `/admin/oauth/{provider}/start|callback`
//! end-to-end without touching the network. The fake server's URL is
//! plugged into a fresh `GoogleAdapter` / `GitHubAdapter` via the
//! per-test `new(...)` constructors.

mod common;
use common::oauth_helpers::*;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::oauth::ProviderRegistry;
use drust::oauth::github::GitHubAdapter;
use drust::oauth::google::GoogleAdapter;
use drust::oauth::provider::OauthProvider;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::{TempDir, tempdir};
use tokio::sync::Mutex;
use tower::ServiceExt;

// ---------- Mgmt router spin-up ----------

fn build_state(
    meta: rusqlite::Connection,
    data_dir: std::path::PathBuf,
    log_dir: std::path::PathBuf,
    registry: ProviderRegistry,
) -> MgmtState {
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data_dir.clone(), 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(meta)),
        data_dir,
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = log_dir;
    state.public_url = "http://test".to_string();
    state.oauth_registry = Arc::new(registry);
    state
}

fn bootstrap_meta_with_email(data_dir: &std::path::Path, email: &str) -> rusqlite::Connection {
    let meta_path = data_dir.join("meta.sqlite");
    {
        let mut conn = open_meta(&meta_path).unwrap();
        bootstrap_admin(&mut conn, "kael", "pass").unwrap();
        // run_migrations adds sessions.token_hash (v1.29.5) and other
        // columns that create_session / validate_session require. Without
        // this call the INSERT in create_session hits "table sessions has
        // no column named token_hash" and maps to oauth_provider_error.
        drust::db::migrations::run_migrations(&conn, data_dir).unwrap();
    }
    drust::bin_helpers::set_admin_password_with_email(&meta_path, "kael", "pass", Some(email))
        .unwrap();
    open_meta(&meta_path).unwrap()
}

/// Variant of `bootstrap_meta_with_email` that leaves `admins.email` NULL.
/// Used to drive the `oauth_admin_email_missing` rejection path: the
/// upstream email is in the allowlist (step 6 passes) but
/// `find_admin_id_by_email` returns `None` (step 7 fails).
fn bootstrap_meta_without_email(data_dir: &std::path::Path) -> rusqlite::Connection {
    let meta_path = data_dir.join("meta.sqlite");
    let mut conn = open_meta(&meta_path).unwrap();
    bootstrap_admin(&mut conn, "kael", "pass").unwrap();
    // Same as bootstrap_meta_with_email: token_hash column required.
    drust::db::migrations::run_migrations(&conn, data_dir).unwrap();
    conn
}

/// Spin up a mgmt router whose `oauth_registry` contains a `google`
/// provider pointed at `fake.base_url`. Returns the router, the data
/// tempdir (kept alive so SQLite files survive), and the audit log dir.
///
/// We use `state.with_data_dir(...)` (not the minimal `build_mgmt_router`)
/// so the public sub-router that mounts `/admin/oauth/{provider}/...` is
/// present — the OAuth routes live there, not on the bare login router.
pub async fn spin_up_admin_with_google_fake(
    fake: &Arc<FakeProvider>,
) -> (axum::Router, TempDir, std::path::PathBuf) {
    // Ensure the global test AuditWriter is running before any callback
    // can emit a row via audit_db::try_send.
    ensure_test_audit_writer();
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let conn = bootstrap_meta_with_email(&data_dir, "kael@example.com");

    let google = GoogleAdapter::new(
        "test-client-id".to_string(),
        "test-client-secret".to_string(),
        format!("{}/authorize", fake.base_url),
        format!("{}/token", fake.base_url),
    );
    let mut providers: HashMap<&'static str, Arc<dyn OauthProvider>> = HashMap::new();
    providers.insert("google", Arc::new(google));
    let registry = ProviderRegistry::from_providers(providers);

    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry);
    (state.with_data_dir(data_dir), dir, log_dir)
}

/// Variant of `spin_up_admin_with_github_fake` that seeds the admin row with a
/// caller-supplied email. Used by the COLLATE NOCASE test: seed a mixed-case
/// `admins.email` and drive a callback whose provider email is lowercased, so
/// the step-6 allowlist match must be case-insensitive to pass. Uses GitHub
/// (auth_method `oauth_github`) to stay isolated from the `oauth_google`
/// success row that `oauth_audit_logged_on_success` asserts on in the shared
/// global test audit DB.
pub async fn spin_up_admin_with_github_fake_email(
    fake: &Arc<FakeProvider>,
    admin_email: &str,
) -> (axum::Router, TempDir, std::path::PathBuf) {
    ensure_test_audit_writer();
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let conn = bootstrap_meta_with_email(&data_dir, admin_email);

    let github = GitHubAdapter::new(
        "test-client-id".to_string(),
        "test-client-secret".to_string(),
        format!("{}/login/oauth/authorize", fake.base_url),
        format!("{}/login/oauth/access_token", fake.base_url),
        fake.base_url.clone(),
    );
    let mut providers: HashMap<&'static str, Arc<dyn OauthProvider>> = HashMap::new();
    providers.insert("github", Arc::new(github));
    let registry = ProviderRegistry::from_providers(providers);

    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry);
    (state.with_data_dir(data_dir), dir, log_dir)
}

/// Variant of `spin_up_admin_with_google_fake` whose admin row has NO email
/// column populated. With DB-driven allowlist (v1.29.0+), `kael@example.com`
/// is not found in `admins.email` so step 6 returns `oauth_not_allowed` —
/// the `oauth_admin_email_missing` path is now unreachable without an email.
pub async fn spin_up_admin_with_google_fake_no_email(
    fake: &Arc<FakeProvider>,
) -> (axum::Router, TempDir, std::path::PathBuf) {
    ensure_test_audit_writer();
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let conn = bootstrap_meta_without_email(&data_dir);

    let google = GoogleAdapter::new(
        "test-client-id".to_string(),
        "test-client-secret".to_string(),
        format!("{}/authorize", fake.base_url),
        format!("{}/token", fake.base_url),
    );
    let mut providers: HashMap<&'static str, Arc<dyn OauthProvider>> = HashMap::new();
    providers.insert("google", Arc::new(google));
    let registry = ProviderRegistry::from_providers(providers);

    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry);
    (state.with_data_dir(data_dir), dir, log_dir)
}

/// Spin up a mgmt router whose `oauth_registry` contains a `github`
/// provider pointed at `fake.base_url`.
pub async fn spin_up_admin_with_github_fake(
    fake: &Arc<FakeProvider>,
) -> (axum::Router, TempDir, std::path::PathBuf) {
    ensure_test_audit_writer();
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let conn = bootstrap_meta_with_email(&data_dir, "kael@example.com");

    let github = GitHubAdapter::new(
        "test-client-id".to_string(),
        "test-client-secret".to_string(),
        format!("{}/login/oauth/authorize", fake.base_url),
        format!("{}/login/oauth/access_token", fake.base_url),
        fake.base_url.clone(),
    );
    let mut providers: HashMap<&'static str, Arc<dyn OauthProvider>> = HashMap::new();
    providers.insert("github", Arc::new(github));
    let registry = ProviderRegistry::from_providers(providers);

    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry);
    (state.with_data_dir(data_dir), dir, log_dir)
}

/// Spin up a mgmt router with no OAuth providers — for T23 button-hidden
/// and "OAuth misconfigured" coverage.
pub async fn spin_up_admin_no_oauth() -> (axum::Router, TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let conn = bootstrap_meta_with_email(&data_dir, "kael@example.com");

    let registry = ProviderRegistry::from_env_empty();
    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry);
    (state.with_data_dir(data_dir), dir, log_dir)
}

// ---------- T16 smoke test ----------

#[tokio::test]
async fn fake_google_server_responds() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "test@x.com".into(),
        email_verified: true,
        provider_user_id: "sub-1".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let resp = reqwest::Client::new()
        .post(format!("{}/token", fake.base_url))
        .form(&[("code", "C"), ("grant_type", "authorization_code")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["id_token"].as_str().unwrap().contains("."));
}

// ---------- T17: happy path google ----------

#[tokio::test]
async fn oauth_happy_path_google() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "kael@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-google-1".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, _log) = spin_up_admin_with_google_fake(&fake).await;

    // 1) /start: 302 to provider auth_url, with state + pkce cookies.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let state = extract_set_cookie(&resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&resp, "drust_oauth_pkce").expect("pkce cookie set");
    assert!(!state.is_empty());
    assert!(!pkce.is_empty());

    // 2) /callback with the same state + pkce cookies → 302 to /drust/admin/tenants
    //    with a fresh drust_session cookie.
    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/google/callback?code=CODE-G&state={state}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_redirect_contains(&resp, "/drust/admin/tenants");
    let session = extract_set_cookie(&resp, "drust_session").expect("session cookie set");
    assert!(!session.is_empty());

    // Sanity-check: the fake provider observed our code.
    let observed = fake.last_code.lock().await.clone();
    assert_eq!(observed.as_deref(), Some("CODE-G"));
}

// ---------- T19: state mismatch + missing state cookie ----------

#[tokio::test]
async fn oauth_state_mismatch_rejected() {
    let fake = spawn_fake_google().await;
    let (app, _dir, _log) = spin_up_admin_with_google_fake(&fake).await;

    // Cookie says ORIGINAL, query says DIFFERENT.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/callback?code=C&state=DIFFERENT")
                .header(
                    header::COOKIE,
                    "drust_oauth_state=ORIGINAL; drust_oauth_pkce=V",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_redirect_contains(&resp, "oauth_error=oauth_state_mismatch");
}

#[tokio::test]
async fn oauth_missing_state_cookie_rejected() {
    let fake = spawn_fake_google().await;
    let (app, _dir, _log) = spin_up_admin_with_google_fake(&fake).await;

    // No state cookie present → cookie value defaults to "" → verify_state fails.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/callback?code=C&state=ANYTHING")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_redirect_contains(&resp, "oauth_error=oauth_state_mismatch");
}

// ---------- T20: provider error on token endpoint ----------

#[tokio::test]
async fn oauth_provider_error_returns_typed_redirect() {
    let fake = spawn_fake_google_returning_400().await;
    let (app, _dir, _log) = spin_up_admin_with_google_fake(&fake).await;

    // Drive a full /start + /callback. We need real state+pkce cookies because
    // the state-mismatch check fires before the exchange call.
    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let state = extract_set_cookie(&start_resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&start_resp, "drust_oauth_pkce").expect("pkce cookie set");

    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/google/callback?code=C&state={state}");
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_redirect_contains(&resp, "oauth_error=oauth_provider_error");
}

// ---------- T21: email unverified ----------

#[tokio::test]
async fn oauth_email_unverified_rejected() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "kael@example.com".into(),
        email_verified: false,
        provider_user_id: "sub-1".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, _log) = spin_up_admin_with_google_fake(&fake).await;

    // Full /start → /callback with real state+pkce cookies.
    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let state = extract_set_cookie(&start_resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&start_resp, "drust_oauth_pkce").expect("pkce cookie set");

    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/google/callback?code=C&state={state}");
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_redirect_contains(&resp, "oauth_error=oauth_email_unverified");
}

// ---------- T22: not allowed + admin email missing ----------

#[tokio::test]
async fn oauth_not_in_allowlist_rejected() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "attacker@evil.com".into(),
        email_verified: true,
        provider_user_id: "sub-2".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    // `spin_up_admin_with_google_fake` sets allowlist = {"kael@example.com"},
    // so "attacker@evil.com" is NOT allowed → step 6 fails.
    let (app, _dir, _log) = spin_up_admin_with_google_fake(&fake).await;

    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let state = extract_set_cookie(&start_resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&start_resp, "drust_oauth_pkce").expect("pkce cookie set");

    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/google/callback?code=C&state={state}");
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_redirect_contains(&resp, "oauth_error=oauth_not_allowed");
}

#[tokio::test]
async fn oauth_admin_email_missing_rejected() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "kael@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-1".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    // v1.29.0: DB-driven allowlist. Admin row was created WITHOUT an email
    // column value, so `SELECT 1 FROM admins WHERE email = ?` returns nothing
    // → step 6 (DB allowlist check) fails with `oauth_not_allowed`.
    // Previously this would reach step 7 (oauth_admin_email_missing); now
    // the two checks collapse into one: no email in admins = not allowed.
    let (app, _dir, _log) = spin_up_admin_with_google_fake_no_email(&fake).await;

    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let state = extract_set_cookie(&start_resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&start_resp, "drust_oauth_pkce").expect("pkce cookie set");

    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/google/callback?code=C&state={state}");
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_redirect_contains(&resp, "oauth_error=oauth_not_allowed");
}

// ---------- T23: button hidden + audit logged + password regression ----------

#[tokio::test]
async fn oauth_button_hidden_when_unconfigured() {
    let (app, _dir, _log) = spin_up_admin_no_oauth().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 256 KB cap: the rendered login page is currently ~80 KB after the
    // v1.15 design overhaul (mascot SVG + design tokens). Give plenty of
    // headroom so a future UI polish doesn't silently retrip this.
    let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(!html.contains("oauth-btn-google"), "google button leaked");
    assert!(!html.contains("oauth-btn-github"), "github button leaked");
}

#[tokio::test]
async fn oauth_audit_logged_on_success() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "kael@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-1".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, log_dir) = spin_up_admin_with_google_fake(&fake).await;

    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let state = extract_set_cookie(&start_resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&start_resp, "drust_oauth_pkce").expect("pkce cookie set");

    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/google/callback?code=C&state={state}");
    let _ = app
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Poll for the audit row instead of a fixed sleep — `write_entry`
    // is async (tokio::fs) and slow CI can lag past any single timeout.
    let row = poll_for_audit_row(&log_dir, "oauth_google", 500).await;
    assert_eq!(row["oauth_email"], "kael@example.com");
    assert_eq!(row["admin_id"].as_i64().unwrap(), 1);
    assert_eq!(row["status"], "ok");
}

// ---------- Fix 4: admin allowlist is case-insensitive (COLLATE NOCASE) ----------

#[tokio::test]
async fn oauth_allowlist_matches_mixed_case_admin_email() {
    // Admin row seeded with a MIXED-case email; the OAuth provider returns the
    // lowercased form (providers lowercase emails). The step-6 allowlist match
    // must be case-insensitive, otherwise the bootstrap admin is locked out
    // with `oauth_not_allowed`.
    let fake = spawn_fake_github().await;
    *fake.script.lock().await = FakeScript {
        email: "mixed@case.com".into(),
        email_verified: true,
        provider_user_id: "424243".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, _log) =
        spin_up_admin_with_github_fake_email(&fake, "Mixed@Case.com").await;

    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/github/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let state = extract_set_cookie(&start_resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&start_resp, "drust_oauth_pkce").expect("pkce cookie set");

    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/github/callback?code=C&state={state}");
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // A successful callback (step 6 allowlist + step 7 find-admin both pass
    // case-insensitively) 302-redirects to the admin app with a session
    // cookie — never the `oauth_error=oauth_not_allowed` login redirect.
    // Pre-fix the case-sensitive query missed `Mixed@Case.com`, so this was
    // `/drust/login?oauth_error=oauth_not_allowed`. Asserting on the redirect
    // (not the shared global audit DB) keeps this test isolated from the
    // sibling `oauth_audit_logged_on_success` row.
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        !loc.contains("oauth_error"),
        "mixed-case admin should not be rejected; got redirect: {loc}"
    );
    assert_eq!(loc, "/drust/admin/tenants", "expected success redirect");
    assert!(
        extract_set_cookie(&resp, "drust_session").is_some(),
        "successful OAuth login must set a session cookie"
    );
}

#[tokio::test]
async fn oauth_existing_password_login_unaffected() {
    let (app, _dir, _log) = spin_up_admin_no_oauth().await;
    // `bootstrap_meta_with_email` (inside spin_up_admin_no_oauth) creates
    // admin "kael" with password "pass".
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("username=kael&password=pass"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(extract_set_cookie(&resp, "drust_session").is_some());
}

// ---------- T2: auth_kind enrichment on admin OAuth callback ----------

#[tokio::test]
async fn admin_oauth_success_carries_auth_kind_admin() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "kael@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-admin-kind".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, log_dir) = spin_up_admin_with_google_fake(&fake).await;

    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let state = extract_set_cookie(&start_resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&start_resp, "drust_oauth_pkce").expect("pkce cookie set");

    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/google/callback?code=CODE-KIND&state={state}");
    let _ = app
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // poll_for_audit_row finds by auth_method; check that row also carries
    // auth_kind=admin in the flattened extra map (T2).
    let row = poll_for_audit_row(&log_dir, "oauth_google", 500).await;
    assert_eq!(row["status"], "ok");
    assert_eq!(
        row["auth_kind"].as_str().unwrap_or(""),
        "admin",
        "admin OAuth success row must carry auth_kind=admin: {row}"
    );
}

// ---------- T18: happy path github ----------

#[tokio::test]
async fn oauth_happy_path_github() {
    let fake = spawn_fake_github().await;
    *fake.script.lock().await = FakeScript {
        email: "kael@example.com".into(),
        email_verified: true,
        provider_user_id: "424242".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, _log) = spin_up_admin_with_github_fake(&fake).await;

    // 1) /start: 302 to provider auth_url, with state + pkce cookies.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/oauth/github/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let state = extract_set_cookie(&resp, "drust_oauth_state").expect("state cookie set");
    let pkce = extract_set_cookie(&resp, "drust_oauth_pkce").expect("pkce cookie set");
    assert!(!state.is_empty());
    assert!(!pkce.is_empty());

    // 2) /callback drives the three-round-trip exchange against the fake
    //    (POST /login/oauth/access_token, GET /user/emails, GET /user).
    let cookie_hdr = format!("drust_oauth_state={state}; drust_oauth_pkce={pkce}");
    let url = format!("/admin/oauth/github/callback?code=CODE-H&state={state}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&url)
                .header(header::COOKIE, cookie_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_redirect_contains(&resp, "/drust/admin/tenants");
    let session = extract_set_cookie(&resp, "drust_session").expect("session cookie set");
    assert!(!session.is_empty());

    let observed = fake.last_code.lock().await.clone();
    assert_eq!(observed.as_deref(), Some("CODE-H"));
}

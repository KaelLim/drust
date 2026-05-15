//! Integration tests for v1.12 per-tenant OAuth. Reuses fake-provider
//! helpers from tests/common/oauth_helpers.rs (factored out in T20).
//!
//! The tenant flow mirrors admin OAuth (v1.11) in shape — `/start` sets
//! state+pkce cookies and 302s to the provider, `/callback` validates the
//! cookies, exchanges the code, gates on email_verified +
//! `allow_self_register`, and 302s back to the frontend with the user
//! session token in the URL fragment.
//!
//! Tests inject a fake `OauthProvider` via
//! `TenantAuthState::oauth_adapter_override` so the exchange call stays
//! local. The fake-provider HTTP server still spins up because GitHub's
//! adapter uses an actual `reqwest::Client`; for Google we still spawn it
//! for parity.

mod common;
use common::oauth_helpers::*;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::oauth::github::GitHubAdapter;
use drust::oauth::google::GoogleAdapter;
use drust::oauth::provider::OauthProvider;
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::safety::rate_limit_ip::IpRateLimit;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::events::EventBus;
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, build_tenant_router};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{TempDir, tempdir};
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Bootstrap a tenant: meta row + service token + tenant data.sqlite +
/// `allow_self_register` flag + one `_system_oauth_providers` row pointing
/// at the fake `provider_name` adapter (already supplied via override).
async fn bootstrap_tenant_with_oauth(
    data_dir: &std::path::Path,
    tenant_id: &str,
    allow_self_register: bool,
    provider_name: &str,
    allowed_redirect_uris: &[&str],
) -> String {
    let meta_path = data_dir.join("meta.sqlite");
    let conn = open_meta(&meta_path).unwrap();
    // `open_meta` runs the in-file `apply_migrations` (admin email etc.)
    // but NOT `db::migrations::run_migrations`, which is where
    // `tenants.allow_self_register` and the per-tenant
    // `_system_oauth_providers` migration live. Run it explicitly here so
    // the test schema matches v1.12 boot.
    drust::db::migrations::run_migrations(&conn, data_dir).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name, allow_self_register) VALUES (?1, ?1, ?2)",
        rusqlite::params![tenant_id, allow_self_register as i64],
    )
    .unwrap();
    let token = generate_token();
    let hash = hash_token(&token);
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label) VALUES (?1, ?2, 'service')",
        rusqlite::params![tenant_id, hash],
    )
    .unwrap();
    // Open writer to materialize SCHEMA_SQL (creates _system_users,
    // _system_sessions, _system_oauth_providers).
    let tconn = drust::storage::tenant_db::open_write(data_dir, tenant_id).unwrap();
    drust::tenant::oauth_config::upsert(
        &tconn,
        provider_name,
        "test-client-id",
        "test-client-secret",
        &allowed_redirect_uris.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )
    .unwrap();
    drop(tconn);
    drop(conn);
    token
}

/// Build a `TenantAuthState` whose oauth_adapter_override carries the
/// supplied fake adapters. `public_url` defaults to `http://test` so the
/// handler doesn't bail with `DRUST_PUBLIC_URL not set`.
fn build_tenant_state(
    data_dir: &std::path::Path,
    audit_log_dir: &std::path::Path,
    overrides: HashMap<String, Arc<dyn OauthProvider>>,
) -> TenantAuthState {
    let meta_path = data_dir.join("meta.sqlite");
    let conn = open_meta(&meta_path).unwrap();
    drust::db::migrations::run_migrations(&conn, data_dir).unwrap();
    TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: Arc::new(TenantRegistry::new(data_dir.to_path_buf(), 2)),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(audit_log_dir.to_path_buf())),
        index_large_table_rows: 1_000_000,
        register_rl: Arc::new(IpRateLimit::new(3, Duration::from_secs(60), 4096)),
        login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        oauth_callback_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        public_url: "http://test".to_string(),
        oauth_adapter_override: Arc::new(overrides),
    }
}

fn build_router(state: TenantAuthState) -> Router {
    let registry = state.registry.clone();
    let bus = EventBus::new();
    let webhooks = drust::tenant::WebhookDispatcher::new(registry.data_root().to_path_buf());
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(registry),
    )));
    build_tenant_router(TenantStack {
        auth: state,
        bus,
        mcp,
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    })
}

/// Spin up a tenant router with a Google provider whose adapter is wired
/// to the supplied fake HTTP server. Returns (router, tempdir, tenant_id,
/// service_token, audit_log_dir).
pub async fn spin_up_tenant_with_google_fake(
    fake: &Arc<FakeProvider>,
) -> (Router, TempDir, String, String, std::path::PathBuf) {
    spin_up_tenant_with_google_fake_opts(
        fake,
        true,
        &["https://app.example.com/auth/callback"],
    )
    .await
}

/// Variant that lets callers opt out of `allow_self_register` and tweak
/// the allowed_redirect_uris list.
pub async fn spin_up_tenant_with_google_fake_opts(
    fake: &Arc<FakeProvider>,
    allow_self_register: bool,
    allowed_redirect_uris: &[&str],
) -> (Router, TempDir, String, String, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let tenant_id = "blog".to_string();
    let token = bootstrap_tenant_with_oauth(
        &data_dir,
        &tenant_id,
        allow_self_register,
        "google",
        allowed_redirect_uris,
    )
    .await;

    let mut overrides: HashMap<String, Arc<dyn OauthProvider>> = HashMap::new();
    overrides.insert(
        "google".into(),
        Arc::new(GoogleAdapter::new(
            "test-client-id".into(),
            "test-client-secret".into(),
            format!("{}/authorize", fake.base_url),
            format!("{}/token", fake.base_url),
        )),
    );

    let state = build_tenant_state(&data_dir, &log_dir, overrides);
    let app = build_router(state);
    (app, dir, tenant_id, token, log_dir)
}

/// GitHub variant of the spin-up.
pub async fn spin_up_tenant_with_github_fake(
    fake: &Arc<FakeProvider>,
) -> (Router, TempDir, String, String, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let tenant_id = "blog".to_string();
    let token = bootstrap_tenant_with_oauth(
        &data_dir,
        &tenant_id,
        true,
        "github",
        &["https://app.example.com/auth/callback"],
    )
    .await;

    let mut overrides: HashMap<String, Arc<dyn OauthProvider>> = HashMap::new();
    overrides.insert(
        "github".into(),
        Arc::new(GitHubAdapter::new(
            "test-client-id".into(),
            "test-client-secret".into(),
            format!("{}/login/oauth/authorize", fake.base_url),
            format!("{}/login/oauth/access_token", fake.base_url),
            fake.base_url.clone(),
        )),
    );

    let state = build_tenant_state(&data_dir, &log_dir, overrides);
    let app = build_router(state);
    (app, dir, tenant_id, token, log_dir)
}

// ---------- Smoke test ----------

#[tokio::test]
async fn tenant_oauth_fake_provider_smoke() {
    let fake = spawn_fake_google().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/token", fake.base_url))
        .form(&[("code", "C"), ("grant_type", "authorization_code")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ---------- T22: happy paths + state-mismatch + missing-cookie ----------

#[tokio::test]
async fn tenant_oauth_happy_path_google() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "alice@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-1".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;

    let frontend = "https://app.example.com/auth/callback";
    let start_uri = format!(
        "/t/{tid}/oauth/google/start?redirect_uri={uri}",
        uri = urlencoding::encode(frontend)
    );
    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&start_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::FOUND);
    let state = extract_set_cookie(&start_resp, "drust_t_oauth_state").expect("state cookie");
    let pkce = extract_set_cookie(&start_resp, "drust_t_oauth_pkce").expect("pkce cookie");
    let red = extract_set_cookie(&start_resp, "drust_t_oauth_redirect_uri")
        .expect("redirect cookie");
    assert_eq!(red, frontend);

    let cb_uri = format!("/t/{tid}/oauth/google/callback?code=CODE-G&state={state}");
    let cb_resp = app
        .oneshot(
            Request::builder()
                .uri(&cb_uri)
                .header(
                    header::COOKIE,
                    format!(
                        "drust_t_oauth_state={state}; drust_t_oauth_pkce={pkce}; drust_t_oauth_redirect_uri={red}"
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cb_resp.status(), StatusCode::FOUND);
    let loc = cb_resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.starts_with(frontend), "loc={loc}");
    assert!(
        loc.contains("#access_token=drust_user_"),
        "missing access_token; loc={loc}"
    );
    assert!(loc.contains("&token_type=Bearer"), "loc={loc}");
    // Fake provider observed our authorization code.
    assert_eq!(fake.last_code.lock().await.as_deref(), Some("CODE-G"));
}

#[tokio::test]
async fn tenant_oauth_happy_path_github() {
    let fake = spawn_fake_github().await;
    *fake.script.lock().await = FakeScript {
        email: "alice@example.com".into(),
        email_verified: true,
        provider_user_id: "424242".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_github_fake(&fake).await;

    let frontend = "https://app.example.com/auth/callback";
    let start_uri = format!(
        "/t/{tid}/oauth/github/start?redirect_uri={uri}",
        uri = urlencoding::encode(frontend)
    );
    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&start_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::FOUND);
    let state = extract_set_cookie(&start_resp, "drust_t_oauth_state").expect("state cookie");
    let pkce = extract_set_cookie(&start_resp, "drust_t_oauth_pkce").expect("pkce cookie");
    let red = extract_set_cookie(&start_resp, "drust_t_oauth_redirect_uri")
        .expect("redirect cookie");

    let cb_uri = format!("/t/{tid}/oauth/github/callback?code=CODE-H&state={state}");
    let cb_resp = app
        .oneshot(
            Request::builder()
                .uri(&cb_uri)
                .header(
                    header::COOKIE,
                    format!(
                        "drust_t_oauth_state={state}; drust_t_oauth_pkce={pkce}; drust_t_oauth_redirect_uri={red}"
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cb_resp.status(), StatusCode::FOUND);
    let loc = cb_resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.starts_with(frontend), "loc={loc}");
    assert!(loc.contains("#access_token=drust_user_"), "loc={loc}");
    assert_eq!(fake.last_code.lock().await.as_deref(), Some("CODE-H"));
}

#[tokio::test]
async fn tenant_oauth_state_mismatch_rejected() {
    let fake = spawn_fake_google().await;
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;
    let cb_uri = format!("/t/{tid}/oauth/google/callback?code=C&state=DIFFERENT");
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&cb_uri)
                .header(
                    header::COOKIE,
                    "drust_t_oauth_state=ORIGINAL; drust_t_oauth_pkce=V; drust_t_oauth_redirect_uri=https://app.example.com/auth/callback",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("oauth_state_mismatch")
    );
}

#[tokio::test]
async fn tenant_oauth_missing_state_cookie_rejected() {
    let fake = spawn_fake_google().await;
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;
    // No cookies at all → cookie_state defaults to "" → verify_state(""," ANYTHING") fails.
    let cb_uri = format!("/t/{tid}/oauth/google/callback?code=C&state=ANYTHING");
    let resp = app
        .oneshot(Request::builder().uri(&cb_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("oauth_state_mismatch")
    );
}

// ---------- T23: provider/cookie/redirect negatives ----------

/// Spin up a tenant whose Google adapter points at a `/token`-returns-400
/// fake. Same as `spin_up_tenant_with_google_fake` otherwise.
async fn spin_up_tenant_with_google_fake_400(
    fake: &Arc<FakeProvider>,
) -> (Router, TempDir, String, String, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let tenant_id = "blog".to_string();
    let token = bootstrap_tenant_with_oauth(
        &data_dir,
        &tenant_id,
        true,
        "google",
        &["https://app.example.com/auth/callback"],
    )
    .await;

    let mut overrides: HashMap<String, Arc<dyn OauthProvider>> = HashMap::new();
    overrides.insert(
        "google".into(),
        Arc::new(GoogleAdapter::new(
            "test-client-id".into(),
            "test-client-secret".into(),
            format!("{}/authorize", fake.base_url),
            format!("{}/token", fake.base_url),
        )),
    );
    let state = build_tenant_state(&data_dir, &log_dir, overrides);
    let app = build_router(state);
    (app, dir, tenant_id, token, log_dir)
}

/// Drive the cookie roundtrip: hit /start, parse the three cookies, then
/// hit /callback with them. Returns the callback response.
async fn drive_callback(
    app: &Router,
    tid: &str,
    provider: &str,
    frontend: &str,
) -> axum::http::Response<Body> {
    let start_uri = format!(
        "/t/{tid}/oauth/{provider}/start?redirect_uri={uri}",
        uri = urlencoding::encode(frontend)
    );
    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&start_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let state = extract_set_cookie(&start_resp, "drust_t_oauth_state").expect("state cookie");
    let pkce = extract_set_cookie(&start_resp, "drust_t_oauth_pkce").expect("pkce cookie");
    let red = extract_set_cookie(&start_resp, "drust_t_oauth_redirect_uri")
        .expect("redirect cookie");

    let cb_uri = format!("/t/{tid}/oauth/{provider}/callback?code=C&state={state}");
    app.clone()
        .oneshot(
            Request::builder()
                .uri(&cb_uri)
                .header(
                    header::COOKIE,
                    format!(
                        "drust_t_oauth_state={state}; drust_t_oauth_pkce={pkce}; drust_t_oauth_redirect_uri={red}"
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn tenant_oauth_provider_error_returns_typed_redirect() {
    let fake = spawn_fake_google_returning_400().await;
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake_400(&fake).await;
    let frontend = "https://app.example.com/auth/callback";
    let resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.starts_with(frontend), "loc={loc}");
    assert!(
        loc.contains("#error=oauth_provider_error"),
        "missing provider_error fragment; loc={loc}"
    );
}

#[tokio::test]
async fn tenant_oauth_email_unverified_rejected() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "alice@example.com".into(),
        email_verified: false,
        provider_user_id: "sub-1".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;
    let frontend = "https://app.example.com/auth/callback";
    let resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.starts_with(frontend), "loc={loc}");
    assert!(loc.contains("#error=oauth_email_unverified"), "loc={loc}");
}

#[tokio::test]
async fn tenant_oauth_invalid_redirect_at_start() {
    let fake = spawn_fake_google().await;
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;
    // redirect_uri not in allowlist → 400 plain-text "oauth_invalid_redirect".
    let bad_uri = format!(
        "/t/{tid}/oauth/google/start?redirect_uri={uri}",
        uri = urlencoding::encode("https://attacker.com/cb")
    );
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&bad_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("oauth_invalid_redirect")
    );
}

#[tokio::test]
async fn tenant_oauth_toctou_invalid_redirect_at_callback() {
    // 1. Start with allowlist = [frontend].
    let fake = spawn_fake_google().await;
    let frontend = "https://app.example.com/auth/callback";
    let (app, dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;

    // 2. /start succeeds (cookie + frontend in allowlist).
    let start_uri = format!(
        "/t/{tid}/oauth/google/start?redirect_uri={uri}",
        uri = urlencoding::encode(frontend)
    );
    let start_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&start_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start_resp.status(), StatusCode::FOUND);
    let state = extract_set_cookie(&start_resp, "drust_t_oauth_state").expect("state");
    let pkce = extract_set_cookie(&start_resp, "drust_t_oauth_pkce").expect("pkce");
    let red = extract_set_cookie(&start_resp, "drust_t_oauth_redirect_uri").expect("red");

    // 3. Admin shrinks the allowlist out from under the in-flight request.
    let tconn = drust::storage::tenant_db::open_write(dir.path(), &tid).unwrap();
    drust::tenant::oauth_config::upsert(
        &tconn,
        "google",
        "test-client-id",
        "test-client-secret",
        &["https://other.example.com/cb".to_string()],
    )
    .unwrap();
    drop(tconn);

    // 4. /callback must 400 with oauth_invalid_redirect — Step 4 fires
    //    AFTER state+PKCE checks but BEFORE token exchange.
    let cb_uri = format!("/t/{tid}/oauth/google/callback?code=C&state={state}");
    let cb_resp = app
        .oneshot(
            Request::builder()
                .uri(&cb_uri)
                .header(
                    header::COOKIE,
                    format!(
                        "drust_t_oauth_state={state}; drust_t_oauth_pkce={pkce}; drust_t_oauth_redirect_uri={red}"
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cb_resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(cb_resp.into_body(), 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("oauth_invalid_redirect")
    );
}

// ---------- T24: user-row negatives ----------

fn open_tenant_db(dir: &TempDir, tid: &str) -> rusqlite::Connection {
    drust::storage::tenant_db::open_write(dir.path(), tid).unwrap()
}

#[tokio::test]
async fn tenant_oauth_not_allowed_when_self_register_off() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "newcomer@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-x".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    // allow_self_register=false, no pre-existing user → step 7 returns None.
    let (app, dir, tid, _service, _log) = spin_up_tenant_with_google_fake_opts(
        &fake,
        false,
        &["https://app.example.com/auth/callback"],
    )
    .await;
    let frontend = "https://app.example.com/auth/callback";
    let resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.starts_with(frontend), "loc={loc}");
    assert!(loc.contains("#error=oauth_not_allowed"), "loc={loc}");

    // No user row should have been inserted.
    let tconn = open_tenant_db(&dir, &tid);
    let count: i64 = tconn
        .query_row("SELECT COUNT(*) FROM _system_users", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0, "no user should be created when self_register=off");
}

#[tokio::test]
async fn tenant_oauth_auto_create_when_self_register_on() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "newcomer@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-y".into(),
        picture: "https://lh3.googleusercontent.com/newcomer".into(),
    };
    let (app, dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;
    let frontend = "https://app.example.com/auth/callback";
    let resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.starts_with(frontend), "loc={loc}");
    assert!(loc.contains("#access_token=drust_user_"), "loc={loc}");

    // The user row exists with sentinel hash + verified=1 + profile JSON.
    let tconn = open_tenant_db(&dir, &tid);
    let (email, phc, verified, profile): (String, String, i64, Option<String>) = tconn
        .query_row(
            "SELECT email, password_hash, verified, profile FROM _system_users \
             WHERE email = ?1 COLLATE NOCASE",
            ["newcomer@example.com"],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(email, "newcomer@example.com");
    assert_eq!(phc, "$oauth-only$");
    assert_eq!(verified, 1);
    let profile_json: serde_json::Value = serde_json::from_str(&profile.unwrap()).unwrap();
    assert_eq!(profile_json["name"], "Kael");
    // Spec §3.3: picture is extracted from the Google id_token claim and
    // persisted in the profile JSON.
    assert_eq!(
        profile_json["picture"],
        "https://lh3.googleusercontent.com/newcomer",
        "profile.picture must carry the Google id_token claim"
    );
}

#[tokio::test]
async fn tenant_oauth_auto_create_picture_from_github() {
    // Mirror of the Google picture assertion via the GitHub `/user.avatar_url`
    // path — the third round-trip is where GitHub returns the avatar.
    let fake = spawn_fake_github().await;
    *fake.script.lock().await = FakeScript {
        email: "ghuser@example.com".into(),
        email_verified: true,
        provider_user_id: "424242".into(),
        picture: "https://avatars.githubusercontent.com/u/424242".into(),
    };
    let (app, dir, tid, _service, _log) = spin_up_tenant_with_github_fake(&fake).await;
    let frontend = "https://app.example.com/auth/callback";
    let resp = drive_callback(&app, &tid, "github", frontend).await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let tconn = open_tenant_db(&dir, &tid);
    let profile: String = tconn
        .query_row(
            "SELECT profile FROM _system_users WHERE email = ?1 COLLATE NOCASE",
            ["ghuser@example.com"],
            |r| r.get(0),
        )
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&profile).unwrap();
    assert_eq!(
        v["picture"],
        "https://avatars.githubusercontent.com/u/424242",
        "profile.picture must carry the GitHub /user.avatar_url field"
    );
}

#[tokio::test]
async fn tenant_oauth_auto_links_existing_email() {
    // Pre-seed a non-OAuth user with a real argon2id hash. After OAuth
    // login the SAME row should be reused — password_hash unchanged so a
    // password login keeps working.
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "alice@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-link".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;

    let original_hash = drust::auth::user::hash_password("secret").unwrap();
    {
        let tconn = open_tenant_db(&dir, &tid);
        tconn
            .execute(
                "INSERT INTO _system_users \
                   (id, email, password_hash, verified, profile, created_at, updated_at) \
                 VALUES ('pre-existing-uid', ?1, ?2, 1, '{\"name\":\"alice-original\"}', \
                         datetime('now'), datetime('now'))",
                rusqlite::params!["alice@example.com", original_hash],
            )
            .unwrap();
    }

    let frontend = "https://app.example.com/auth/callback";
    let resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.contains("#access_token=drust_user_"), "loc={loc}");

    // Row count stayed at one, password_hash unchanged, profile untouched.
    let tconn = open_tenant_db(&dir, &tid);
    let (n, phc, profile): (i64, String, String) = tconn
        .query_row(
            "SELECT COUNT(*), MAX(password_hash), MAX(profile) FROM _system_users",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(n, 1, "auto-link must not create a second row");
    assert_eq!(phc, original_hash, "password_hash must NOT be overwritten");
    assert!(
        drust::auth::user::verify_password("secret", &phc).unwrap_or(false),
        "argon2 verify must still succeed for the original password"
    );
    let profile_json: serde_json::Value = serde_json::from_str(&profile).unwrap();
    assert_eq!(
        profile_json["name"], "alice-original",
        "profile JSON must be untouched on auto-link"
    );
}

#[tokio::test]
async fn tenant_oauth_only_user_me_password_rejected() {
    // After OAuth auto-create, POST /me/password with the issued user
    // session bearer must 409 OAUTH_ONLY_NO_PASSWORD. Symmetric to the
    // login-side rejection above — the production gate at
    // auth_routes.rs:561-567 already exists; this closes the test coverage
    // gap flagged in v1.12 review.
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "oauthonly@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-only".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;

    // 1. Drive OAuth to auto-create the sentinel-hash user + issue a
    //    drust_user_* token in the 302 Location fragment.
    let frontend = "https://app.example.com/auth/callback";
    let cb_resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(cb_resp.status(), StatusCode::FOUND);
    let loc = cb_resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    // Extract the drust_user_* token from `#access_token=<tok>&token_type=Bearer`.
    let fragment = loc.split_once('#').expect("location has #fragment").1;
    let token = fragment
        .split('&')
        .find_map(|kv| kv.strip_prefix("access_token="))
        .expect("access_token in fragment");
    assert!(token.starts_with("drust_user_"), "got {token}");

    // 2. POST /me/password with that bearer + a policy-compliant new password
    //    (>= 8 chars). current_password is irrelevant — the sentinel-hash
    //    gate fires before verify_password runs.
    let body = serde_json::json!({
        "current_password": "anything",
        "new_password": "new-password-123",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/me/password"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "must be 409");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "OAUTH_ONLY_NO_PASSWORD", "got {v}");
}

#[tokio::test]
async fn tenant_oauth_only_user_password_login_rejected() {
    // After auto-create with the sentinel hash, POST /auth/login with any
    // password must return 401 INVALID_CREDENTIALS — NOT a 500 (argon2
    // would panic on the non-PHC `$oauth-only$` string if not gated).
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "oauthonly@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-only".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;

    // 1. Drive OAuth to auto-create the user row with sentinel hash.
    let frontend = "https://app.example.com/auth/callback";
    let cb_resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(cb_resp.status(), StatusCode::FOUND);

    // 2. POST /auth/login with email + arbitrary password.
    let body = serde_json::json!({
        "email": "oauthonly@example.com",
        "password": "anything",
    });
    let login_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/login"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_resp.status(), StatusCode::UNAUTHORIZED, "must be 401");
    let body = axum::body::to_bytes(login_resp.into_body(), 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "INVALID_CREDENTIALS");
}

// ---------- T25: cross-tenant isolation + audit-logged-on-success ----------

#[tokio::test]
async fn tenant_oauth_cross_tenant_config_isolation() {
    // Tenant A has Google configured; Tenant B has none. Hitting B's
    // /oauth/google/start must NOT return Tenant A's adapter URL — the
    // handler reads `_system_oauth_providers` from B's data.sqlite and
    // returns 400 `oauth_misconfigured`.
    let fake = spawn_fake_google().await;
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();

    let _tok_a = bootstrap_tenant_with_oauth(
        &data_dir,
        "ta",
        true,
        "google",
        &["https://app.example.com/auth/callback"],
    )
    .await;
    // Bootstrap tenant B WITHOUT inserting an oauth_providers row.
    {
        let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
        drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
        conn.execute(
            "INSERT INTO tenants (id, name, allow_self_register) VALUES ('tb', 'tb', 1)",
            [],
        )
        .unwrap();
        let tb_tok = generate_token();
        let tb_hash = hash_token(&tb_tok);
        conn.execute(
            "INSERT INTO tokens (tenant_id, token_hash, label) VALUES ('tb', ?1, 'service')",
            rusqlite::params![tb_hash],
        )
        .unwrap();
        let tconn = drust::storage::tenant_db::open_write(&data_dir, "tb").unwrap();
        drop(tconn);
    }

    let mut overrides: HashMap<String, Arc<dyn OauthProvider>> = HashMap::new();
    overrides.insert(
        "google".into(),
        Arc::new(GoogleAdapter::new(
            "ta-cid".into(),
            "ta-sec".into(),
            format!("{}/authorize", fake.base_url),
            format!("{}/token", fake.base_url),
        )),
    );
    let state = build_tenant_state(&data_dir, &log_dir, overrides);
    let app = build_router(state);

    // Tenant B has no providers row → 400 oauth_misconfigured.
    let resp_b = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/t/tb/oauth/google/start?redirect_uri={u}",
                    u = urlencoding::encode("https://app.example.com/auth/callback")
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_b.status(), StatusCode::BAD_REQUEST);
    let body_b = axum::body::to_bytes(resp_b.into_body(), 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&body_b)
            .unwrap()
            .contains("oauth_misconfigured")
    );

    // Tenant A's /start STILL works for sanity.
    let resp_a = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/t/ta/oauth/google/start?redirect_uri={u}",
                    u = urlencoding::encode("https://app.example.com/auth/callback")
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_a.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn tenant_oauth_cross_tenant_user_isolation() {
    // Both tenants configure Google with the SAME allowed_redirect_uris.
    // OAuth callback at /t/ta/oauth/google/callback inserts a row in ta's
    // _system_users; tb's _system_users stays empty.
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "alice@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-cross".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();

    let _ta = bootstrap_tenant_with_oauth(
        &data_dir,
        "ta",
        true,
        "google",
        &["https://app.example.com/auth/callback"],
    )
    .await;
    let _tb = bootstrap_tenant_with_oauth(
        &data_dir,
        "tb",
        true,
        "google",
        &["https://app.example.com/auth/callback"],
    )
    .await;

    let mut overrides: HashMap<String, Arc<dyn OauthProvider>> = HashMap::new();
    overrides.insert(
        "google".into(),
        Arc::new(GoogleAdapter::new(
            "test-cid".into(),
            "test-sec".into(),
            format!("{}/authorize", fake.base_url),
            format!("{}/token", fake.base_url),
        )),
    );
    let state = build_tenant_state(&data_dir, &log_dir, overrides);
    let app = build_router(state);

    // Drive OAuth at ta only.
    let resp = drive_callback(&app, "ta", "google", "https://app.example.com/auth/callback").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.contains("#access_token=drust_user_"), "loc={loc}");

    // ta has one row, tb has zero.
    let ta_conn = drust::storage::tenant_db::open_write(&data_dir, "ta").unwrap();
    let n_a: i64 = ta_conn
        .query_row("SELECT COUNT(*) FROM _system_users", [], |r| r.get(0))
        .unwrap();
    drop(ta_conn);
    let tb_conn = drust::storage::tenant_db::open_write(&data_dir, "tb").unwrap();
    let n_b: i64 = tb_conn
        .query_row("SELECT COUNT(*) FROM _system_users", [], |r| r.get(0))
        .unwrap();
    drop(tb_conn);
    assert_eq!(n_a, 1, "ta got the OAuth user");
    assert_eq!(n_b, 0, "tb's _system_users stays empty");
}

#[tokio::test]
async fn tenant_oauth_audit_logged_on_success() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "alice@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-1".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, tid, _service, log_dir) = spin_up_tenant_with_google_fake(&fake).await;
    let frontend = "https://app.example.com/auth/callback";
    let resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    // Poll for the success row written by audit_oauth_success — `write_entry`
    // is async (tokio::fs) so we may need to wait a beat.
    let row = poll_for_audit_row(&log_dir, "oauth_google", 500).await;
    assert_eq!(row["tenant"], tid);
    assert_eq!(row["oauth_email"], "alice@example.com");
    assert!(row["auth_user_id"].is_string(), "auth_user_id missing");
    assert_eq!(row["status"], "ok");
}

// ---------- existing T21 smoke ----------

#[tokio::test]
async fn tenant_oauth_spin_up_compiles_and_serves_start() {
    // Sanity: the spin-up produces a router that answers `/start` with a
    // 302 + state cookie. Exercises bootstrap + state wiring without
    // touching the callback chain (covered in T22).
    let fake = spawn_fake_google().await;
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;
    let frontend = "https://app.example.com/auth/callback";
    let start_uri = format!(
        "/t/{tid}/oauth/google/start?redirect_uri={uri}",
        uri = urlencoding::encode(frontend)
    );
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&start_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(extract_set_cookie(&resp, "drust_t_oauth_state").is_some());
    assert!(extract_set_cookie(&resp, "drust_t_oauth_pkce").is_some());
    assert_eq!(
        extract_set_cookie(&resp, "drust_t_oauth_redirect_uri").as_deref(),
        Some(frontend)
    );
    let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(loc.contains("/authorize?"), "loc={loc}");
}

// ---------- T6: rate-limit on /callback (5 / 60 s / IP) ----------

#[tokio::test]
async fn tenant_oauth_callback_rate_limit_returns_429() {
    // The handler checks `oauth_callback_rl` BEFORE step 1 (provider
    // lookup, state/PKCE validation, token exchange) — so the request can
    // be totally bogus and still tick the bucket. Fire 6× sequential
    // oneshots from a fixed IP via X-Forwarded-For; the sixth must come
    // back 429 with body `rate_limited`.
    //
    // XFF semantics (src/safety/ip.rs): we send `<client>, 10.0.0.1` so
    // parts.len() >= 2 and client_ip picks XFF[-2] = <client>. Without
    // that, fallback is 127.0.0.1 and the per-IP bucket is shared across
    // tests within the process — but `oauth_callback_rl` is a per-state
    // instance (see TenantAuthState in build_tenant_state), so even the
    // fallback path would work; we send XFF explicitly for clarity.
    let fake = spawn_fake_google().await;
    let (app, _dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;
    let client_ip = "203.0.113.42";
    let xff = format!("{client_ip}, 10.0.0.1");

    let cb_uri = format!("/t/{tid}/oauth/google/callback?code=C&state=ANY");
    let mut last_status = StatusCode::IM_A_TEAPOT;
    let mut last_body = Vec::new();
    for _ in 0..6 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&cb_uri)
                    .header("x-forwarded-for", &xff)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        last_status = resp.status();
        last_body = axum::body::to_bytes(resp.into_body(), 1024)
            .await
            .unwrap()
            .to_vec();
    }
    assert_eq!(
        last_status,
        StatusCode::TOO_MANY_REQUESTS,
        "6th request must be rate-limited, body={:?}",
        std::str::from_utf8(&last_body)
    );
    assert!(
        std::str::from_utf8(&last_body)
            .unwrap()
            .contains("rate_limited"),
        "body should contain rate_limited, got {:?}",
        std::str::from_utf8(&last_body)
    );
}

// ---------- T7: concurrent callbacks for same fresh email ----------

#[tokio::test]
async fn tenant_oauth_concurrent_callbacks_same_email() {
    // Two browsers / devices simultaneously complete OAuth for the SAME
    // brand-new email on a freshly-provisioned tenant. After v1.12 T7-T9
    // fix-up, find_or_create_user + create_session runs in one writer
    // pass — both callbacks must succeed, both tokens must be distinct,
    // and exactly ONE _system_users row must exist.
    //
    // The fake provider single-uses each `code` (overwrites `last_code`,
    // but the script payload is static so calling /token twice with the
    // same script returns the same id_token shape). So we run two full
    // /start → /callback chains in parallel via tokio::join!; each chain
    // gets its own state+pkce cookies. Both fake-provider calls go to the
    // same fake server backing the GoogleAdapter override.
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "race@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-race".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, dir, tid, _service, _log) = spin_up_tenant_with_google_fake(&fake).await;
    let frontend = "https://app.example.com/auth/callback";

    // Two independent /start calls — each returns its own state/pkce.
    let start_uri = format!(
        "/t/{tid}/oauth/google/start?redirect_uri={uri}",
        uri = urlencoding::encode(frontend)
    );
    let (start_a, start_b) = tokio::join!(
        app.clone()
            .oneshot(Request::builder().uri(&start_uri).body(Body::empty()).unwrap()),
        app.clone()
            .oneshot(Request::builder().uri(&start_uri).body(Body::empty()).unwrap()),
    );
    let start_a = start_a.unwrap();
    let start_b = start_b.unwrap();
    let (state_a, pkce_a, red_a) = (
        extract_set_cookie(&start_a, "drust_t_oauth_state").unwrap(),
        extract_set_cookie(&start_a, "drust_t_oauth_pkce").unwrap(),
        extract_set_cookie(&start_a, "drust_t_oauth_redirect_uri").unwrap(),
    );
    let (state_b, pkce_b, red_b) = (
        extract_set_cookie(&start_b, "drust_t_oauth_state").unwrap(),
        extract_set_cookie(&start_b, "drust_t_oauth_pkce").unwrap(),
        extract_set_cookie(&start_b, "drust_t_oauth_redirect_uri").unwrap(),
    );

    let cb_a = format!("/t/{tid}/oauth/google/callback?code=CODE-A&state={state_a}");
    let cb_b = format!("/t/{tid}/oauth/google/callback?code=CODE-B&state={state_b}");
    let req_a = Request::builder()
        .uri(&cb_a)
        .header(
            header::COOKIE,
            format!(
                "drust_t_oauth_state={state_a}; drust_t_oauth_pkce={pkce_a}; drust_t_oauth_redirect_uri={red_a}"
            ),
        )
        .body(Body::empty())
        .unwrap();
    let req_b = Request::builder()
        .uri(&cb_b)
        .header(
            header::COOKIE,
            format!(
                "drust_t_oauth_state={state_b}; drust_t_oauth_pkce={pkce_b}; drust_t_oauth_redirect_uri={red_b}"
            ),
        )
        .body(Body::empty())
        .unwrap();
    let (resp_a, resp_b) = tokio::join!(app.clone().oneshot(req_a), app.clone().oneshot(req_b));
    let resp_a = resp_a.unwrap();
    let resp_b = resp_b.unwrap();
    assert_eq!(resp_a.status(), StatusCode::FOUND, "A must 302");
    assert_eq!(resp_b.status(), StatusCode::FOUND, "B must 302");

    let tok = |resp: &axum::http::Response<Body>| -> String {
        let loc = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        let frag = loc.split_once('#').expect("fragment").1;
        frag.split('&')
            .find_map(|kv| kv.strip_prefix("access_token="))
            .expect("access_token")
            .to_string()
    };
    let tok_a = tok(&resp_a);
    let tok_b = tok(&resp_b);
    assert!(tok_a.starts_with("drust_user_"), "got {tok_a}");
    assert!(tok_b.starts_with("drust_user_"), "got {tok_b}");
    assert_ne!(tok_a, tok_b, "two callbacks must mint distinct sessions");

    // Exactly one _system_users row for this email — the v1.12 T7-T9
    // fix-up coalesces lookup + insert + session into one writer pass so
    // the second callback re-uses the row inserted by the first.
    let tconn = open_tenant_db(&dir, &tid);
    let n: i64 = tconn
        .query_row(
            "SELECT COUNT(*) FROM _system_users WHERE email = ?1 COLLATE NOCASE",
            ["race@example.com"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1, "race must collapse to exactly one user row");
}

// ---------- T2: AuditExtra on admin REST PUT / DELETE ----------

/// Poll a tenant audit dir for a JSONL row whose `op` equals `expected_op`.
/// Mirrors `poll_for_audit_row` (which filters by `auth_method`) but for
/// the admin-REST audit shape (no auth_method on plain bearer rows).
async fn poll_for_audit_op(
    log_dir: &std::path::Path,
    expected_op: &str,
    max_ms: u64,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_ms);
    loop {
        if log_dir.exists() {
            let entries: Vec<_> = std::fs::read_dir(log_dir)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("audit-") && n.ends_with(".jsonl"))
                })
                .collect();
            for p in entries {
                if let Ok(body) = std::fs::read_to_string(&p) {
                    for line in body.lines() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
                            && v["op"] == expected_op
                        {
                            return v;
                        }
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("audit row with op={expected_op} not written within {max_ms}ms");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn admin_put_oauth_provider_writes_audit_extra() {
    // Spin up a tenant that already has a Google config (the spin-up seeds
    // it). Hit PUT to replace and assert the JSONL row carries
    // `provider` + `redirect_uris_count`.
    let fake = spawn_fake_google().await;
    let (app, _dir, tid, service, log_dir) = spin_up_tenant_with_google_fake(&fake).await;

    let body = serde_json::json!({
        "client_id": "cid-2",
        "client_secret": "csec-2",
        "allowed_redirect_uris": [
            "https://app.example.com/auth/callback",
            "https://app.example.com/auth/callback-2"
        ],
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/t/{tid}/admin/oauth-providers/google"))
                .header(header::AUTHORIZATION, format!("Bearer {service}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let row = poll_for_audit_op(&log_dir, "PUT /admin/oauth-providers/google", 500).await;
    assert_eq!(row["status"], "ok");
    assert_eq!(row["provider"], "google");
    assert_eq!(row["redirect_uris_count"], 2);
}

#[tokio::test]
async fn admin_delete_oauth_provider_writes_audit_extra() {
    let fake = spawn_fake_google().await;
    let (app, _dir, tid, service, log_dir) = spin_up_tenant_with_google_fake(&fake).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/t/{tid}/admin/oauth-providers/google"))
                .header(header::AUTHORIZATION, format!("Bearer {service}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let row = poll_for_audit_op(&log_dir, "DELETE /admin/oauth-providers/google", 500).await;
    assert_eq!(row["status"], "ok");
    assert_eq!(row["provider"], "google");
}

// ---------- T4: granular error_codes on admin REST PUT validation ----------

async fn put_oauth_with_body(
    app: &Router,
    tid: &str,
    provider: &str,
    service: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/t/{tid}/admin/oauth-providers/{provider}"))
                .header(header::AUTHORIZATION, format!("Bearer {service}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "expected 400");
    let bytes = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn admin_put_oauth_validation_emits_granular_codes() {
    let fake = spawn_fake_google().await;
    let (app, _dir, tid, service, _log) = spin_up_tenant_with_google_fake(&fake).await;

    // INVALID_PROVIDER: provider in URL is not in the allowlist.
    let v = put_oauth_with_body(
        &app,
        &tid,
        "microsoft",
        &service,
        serde_json::json!({
            "client_id": "cid",
            "client_secret": "csec",
            "allowed_redirect_uris": ["https://app.example.com/cb"],
        }),
    )
    .await;
    assert_eq!(v["error_code"], "INVALID_PROVIDER", "got {v}");

    // EMPTY_REDIRECT_URIS: array is empty.
    let v = put_oauth_with_body(
        &app,
        &tid,
        "google",
        &service,
        serde_json::json!({
            "client_id": "cid",
            "client_secret": "csec",
            "allowed_redirect_uris": [],
        }),
    )
    .await;
    assert_eq!(v["error_code"], "EMPTY_REDIRECT_URIS", "got {v}");

    // INVALID_REDIRECT_URI: plain http (non-localhost) — validator rejects.
    let v = put_oauth_with_body(
        &app,
        &tid,
        "google",
        &service,
        serde_json::json!({
            "client_id": "cid",
            "client_secret": "csec",
            "allowed_redirect_uris": ["http://attacker.com/cb"],
        }),
    )
    .await;
    assert_eq!(v["error_code"], "INVALID_REDIRECT_URI", "got {v}");

    // INVALID_CLIENT_ID: empty client_id.
    let v = put_oauth_with_body(
        &app,
        &tid,
        "google",
        &service,
        serde_json::json!({
            "client_id": "",
            "client_secret": "csec",
            "allowed_redirect_uris": ["https://app.example.com/cb"],
        }),
    )
    .await;
    assert_eq!(v["error_code"], "INVALID_CLIENT_ID", "got {v}");

    // INVALID_CLIENT_SECRET: empty client_secret.
    let v = put_oauth_with_body(
        &app,
        &tid,
        "google",
        &service,
        serde_json::json!({
            "client_id": "cid",
            "client_secret": "",
            "allowed_redirect_uris": ["https://app.example.com/cb"],
        }),
    )
    .await;
    assert_eq!(v["error_code"], "INVALID_CLIENT_SECRET", "got {v}");
}

// ---------- T2: auth_kind enrichment on tenant OAuth callback ----------

#[tokio::test]
async fn tenant_oauth_success_carries_auth_kind_user() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "alice@example.com".into(),
        email_verified: true,
        provider_user_id: "sub-kind".into(),
        picture: "https://example.test/avatar.png".into(),
    };
    let (app, _dir, tid, _service, log_dir) = spin_up_tenant_with_google_fake(&fake).await;
    let frontend = "https://app.example.com/auth/callback";
    let resp = drive_callback(&app, &tid, "google", frontend).await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    // poll_for_audit_row finds by auth_method; check that the same row also
    // carries auth_kind=user (T2) in the flattened extra map.
    let row = poll_for_audit_row(&log_dir, "oauth_google", 500).await;
    assert_eq!(row["status"], "ok");
    assert_eq!(
        row["auth_kind"].as_str().unwrap_or(""),
        "user",
        "tenant OAuth success row must carry auth_kind=user: {row}"
    );
}

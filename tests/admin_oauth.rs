//! Admin OAuth integration tests (v1.11).
//!
//! Spins up a local axum HTTP server that impersonates a Google/GitHub
//! OAuth provider so we can drive `/admin/oauth/{provider}/start|callback`
//! end-to-end without touching the network. The fake server's URL is
//! plugged into a fresh `GoogleAdapter` / `GitHubAdapter` via the
//! per-test `new(...)` constructors.

use axum::body::Body;
use axum::extract::Form;
use axum::http::{Request, Response, StatusCode, header};
use axum::response::Json;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use drust::mgmt::routes::MgmtState;
use drust::oauth::ProviderRegistry;
use drust::oauth::github::GitHubAdapter;
use drust::oauth::google::GoogleAdapter;
use drust::oauth::provider::OauthProvider;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tempfile::{TempDir, tempdir};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ---------- Fake provider server ----------

#[derive(Clone)]
pub struct FakeScript {
    pub email: String,
    pub email_verified: bool,
    pub provider_user_id: String,
}

impl Default for FakeScript {
    fn default() -> Self {
        Self {
            email: "kael@example.com".to_string(),
            email_verified: true,
            provider_user_id: "sub-default".to_string(),
        }
    }
}

pub struct FakeProvider {
    pub base_url: String,
    pub last_code: Mutex<Option<String>>,
    pub script: Mutex<FakeScript>,
}

/// Spawn a fake Google OIDC provider on 127.0.0.1:0. Returns an Arc whose
/// `base_url` is the live `http://127.0.0.1:<port>` and whose `/token`
/// endpoint returns a synthesized id_token built from the current script.
pub async fn spawn_fake_google() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st = state.clone();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
            let st = st.clone();
            async move {
                if let Some(code) = form.get("code") {
                    *st.last_code.lock().await = Some(code.clone());
                }
                let script = st.script.lock().await.clone();
                let claims = serde_json::json!({
                    "sub": script.provider_user_id,
                    "email": script.email,
                    "email_verified": script.email_verified,
                    "name": "Kael",
                });
                let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
                let id_token = format!("header.{payload}.sig");
                Json(serde_json::json!({ "id_token": id_token }))
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

/// Variant of `spawn_fake_google` whose `/token` endpoint returns 400 so
/// `GoogleAdapter::exchange` (which calls `.error_for_status()?`) fails —
/// exercising the `oauth_provider_error` branch in `oauth_callback`.
pub async fn spawn_fake_google_returning_400() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st = state.clone();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
            let st = st.clone();
            async move {
                if let Some(code) = form.get("code") {
                    *st.last_code.lock().await = Some(code.clone());
                }
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

/// Spawn a fake GitHub OAuth provider on 127.0.0.1:0. Exposes the three
/// endpoints `GitHubAdapter::exchange` calls.
pub async fn spawn_fake_github() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st1 = state.clone();
    let st2 = state.clone();
    let st3 = state.clone();
    let app = axum::Router::new()
        .route(
            "/login/oauth/access_token",
            axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
                let st = st1.clone();
                async move {
                    if let Some(code) = form.get("code") {
                        *st.last_code.lock().await = Some(code.clone());
                    }
                    Json(serde_json::json!({
                        "access_token": "fake-token",
                        "token_type": "bearer",
                        "scope": "read:user user:email",
                    }))
                }
            }),
        )
        .route(
            "/user/emails",
            axum::routing::get(move || {
                let st = st2.clone();
                async move {
                    let script = st.script.lock().await.clone();
                    Json(serde_json::json!([{
                        "email": script.email,
                        "primary": true,
                        "verified": script.email_verified,
                    }]))
                }
            }),
        )
        .route(
            "/user",
            axum::routing::get(move || {
                let st = st3.clone();
                async move {
                    let script = st.script.lock().await.clone();
                    let id: u64 = script.provider_user_id.parse().unwrap_or(0);
                    Json(serde_json::json!({
                        "id": id,
                        "name": "Kael",
                    }))
                }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

// ---------- Mgmt router spin-up ----------

fn build_state(
    meta: rusqlite::Connection,
    data_dir: std::path::PathBuf,
    log_dir: std::path::PathBuf,
    registry: ProviderRegistry,
    allowlist: HashSet<String>,
) -> MgmtState {
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data_dir, 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    MgmtState {
        meta: Arc::new(Mutex::new(meta)),
        session_ttl_days: 7,
        garage: None,
        public_base_url: "http://localhost:8793".to_string(),
        max_upload_bytes: 52_428_800,
        garage_client_key_id: String::new(),
        disk_min_free_pct: 20,
        log_dir,
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: "http://test".to_string(),
        oauth_registry: Arc::new(registry),
        oauth_allowlist: Arc::new(allowlist),
    }
}

fn bootstrap_meta_with_email(data_dir: &std::path::Path, email: &str) -> rusqlite::Connection {
    let meta_path = data_dir.join("meta.sqlite");
    {
        let mut conn = open_meta(&meta_path).unwrap();
        bootstrap_admin(&mut conn, "kael", "pass").unwrap();
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

    let allow: HashSet<String> = ["kael@example.com".to_string()].into_iter().collect();
    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry, allow);
    (state.with_data_dir(data_dir), dir, log_dir)
}

/// Variant of `spin_up_admin_with_google_fake` whose admin row has NO email
/// column populated. The allowlist still contains `kael@example.com` so the
/// callback gets past step 6 (allowlist check) before step 7 fails on
/// `find_admin_id_by_email`.
pub async fn spin_up_admin_with_google_fake_no_email(
    fake: &Arc<FakeProvider>,
) -> (axum::Router, TempDir, std::path::PathBuf) {
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

    let allow: HashSet<String> = ["kael@example.com".to_string()].into_iter().collect();
    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry, allow);
    (state.with_data_dir(data_dir), dir, log_dir)
}

/// Spin up a mgmt router whose `oauth_registry` contains a `github`
/// provider pointed at `fake.base_url`.
pub async fn spin_up_admin_with_github_fake(
    fake: &Arc<FakeProvider>,
) -> (axum::Router, TempDir, std::path::PathBuf) {
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

    let allow: HashSet<String> = ["kael@example.com".to_string()].into_iter().collect();
    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry, allow);
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
    let allow: HashSet<String> = HashSet::new();
    let state = build_state(conn, data_dir.clone(), log_dir.clone(), registry, allow);
    (state.with_data_dir(data_dir), dir, log_dir)
}

// ---------- Response helpers ----------

/// Pull a cookie VALUE (the bit before the first `;`) by name from all
/// `Set-Cookie` headers on a response. Returns `None` if absent.
pub fn extract_set_cookie(resp: &Response<Body>, name: &str) -> Option<String> {
    for v in resp.headers().get_all(header::SET_COOKIE).iter() {
        let raw = v.to_str().ok()?;
        let first = raw.split(';').next().unwrap_or("");
        if let Some((k, val)) = first.split_once('=') {
            if k.trim() == name {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

pub fn assert_redirect_contains(resp: &Response<Body>, fragment: &str) {
    let status = resp.status();
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got {status}"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap_or_else(|| panic!("no Location header on {status} response"))
        .to_str()
        .unwrap();
    assert!(loc.contains(fragment), "expected {fragment:?} in {loc:?}");
}

// ---------- T16 smoke test ----------

#[tokio::test]
async fn fake_google_server_responds() {
    let fake = spawn_fake_google().await;
    *fake.script.lock().await = FakeScript {
        email: "test@x.com".into(),
        email_verified: true,
        provider_user_id: "sub-1".into(),
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
    };
    // Email IS in allowlist (step 6 passes) but no admin row matches —
    // admin row was created without an email column value.
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
    assert_redirect_contains(&resp, "oauth_error=oauth_admin_email_missing");
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
    let body = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
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

async fn poll_for_audit_row(
    log_dir: &std::path::Path,
    auth_method: &str,
    max_ms: u64,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_ms);
    loop {
        if let Some(row) = try_find_audit_row(log_dir, auth_method) {
            return row;
        }
        if std::time::Instant::now() >= deadline {
            panic!("audit row with auth_method={auth_method} not written within {max_ms}ms");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

fn try_find_audit_row(log_dir: &std::path::Path, auth_method: &str) -> Option<serde_json::Value> {
    let latest = std::fs::read_dir(log_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("audit-") && n.ends_with(".jsonl"))
        })
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())?;
    let body = std::fs::read_to_string(&latest).ok()?;
    body.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["auth_method"] == auth_method)
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

// ---------- T18: happy path github ----------

#[tokio::test]
async fn oauth_happy_path_github() {
    let fake = spawn_fake_github().await;
    *fake.script.lock().await = FakeScript {
        email: "kael@example.com".into(),
        email_verified: true,
        provider_user_id: "424242".into(),
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

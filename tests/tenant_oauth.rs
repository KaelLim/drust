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
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(registry),
    )));
    build_tenant_router(TenantStack {
        auth: state,
        bus,
        mcp,
        files: None,
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

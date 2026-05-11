mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn app_with_limiter(
    tenant: &str,
    budget: u32,
    window: Duration,
) -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) \
         VALUES (?1, ?2, 'svc', 'service')",
        rusqlite::params![tenant, hash_token(&tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: tenants.clone(),
        limiter: Arc::new(RateLimiter::new(budget, window)),
        audit: Arc::new(AuditLog::new(dir.path().join("audit"))),
        index_large_table_rows: 1_000_000,
        register_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(3, Duration::from_secs(60), 4096)),
        login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, Duration::from_secs(60), 4096)),
    };
    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        cors_origins: Vec::new(),
    });
    (app, tok, dir)
}

fn get_collections(tenant: &str, bearer: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/t/{tenant}/collections"))
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn third_request_is_rate_limited_with_budget_two() {
    let (app, tok, _d) = app_with_limiter("rl", 2, Duration::from_secs(10)).await;
    let r1 = app
        .clone()
        .oneshot(get_collections("rl", &tok))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let r2 = app
        .clone()
        .oneshot(get_collections("rl", &tok))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let r3 = app
        .clone()
        .oneshot(get_collections("rl", &tok))
        .await
        .unwrap();
    assert_eq!(r3.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r3.headers().contains_key(header::RETRY_AFTER));
    let body = axum::body::to_bytes(r3.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "RATE_LIMITED");
}

#[tokio::test]
async fn independent_tokens_have_independent_buckets() {
    let (app, tok_a, dir) = app_with_limiter("rl2", 1, Duration::from_secs(10)).await;
    // Add a second service token for the same tenant.
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let tok_b = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) \
         VALUES ('rl2', ?1, 'svc-b', 'service')",
        rusqlite::params![hash_token(&tok_b)],
    )
    .unwrap();
    drop(conn);

    // Each token should get its own bucket — budget 1 means each is allowed
    // one request. A's second request is denied, but B's first still goes
    // through.
    let r_a1 = app
        .clone()
        .oneshot(get_collections("rl2", &tok_a))
        .await
        .unwrap();
    assert_eq!(r_a1.status(), StatusCode::OK);
    let r_a2 = app
        .clone()
        .oneshot(get_collections("rl2", &tok_a))
        .await
        .unwrap();
    assert_eq!(r_a2.status(), StatusCode::TOO_MANY_REQUESTS);
    let r_b1 = app
        .clone()
        .oneshot(get_collections("rl2", &tok_b))
        .await
        .unwrap();
    assert_eq!(r_b1.status(), StatusCode::OK);
}

#[tokio::test]
async fn rate_limit_runs_before_auth_lookup_for_bad_tokens_too() {
    // Even an invalid bearer should be rate-limited on its hash — otherwise
    // an attacker could burn meta.sqlite with unbounded lookups.
    let (app, _valid, _d) = app_with_limiter("rl3", 1, Duration::from_secs(10)).await;
    let bogus = "definitely-not-a-real-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let r1 = app
        .clone()
        .oneshot(get_collections("rl3", bogus))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::UNAUTHORIZED);
    let r2 = app
        .clone()
        .oneshot(get_collections("rl3", bogus))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
}

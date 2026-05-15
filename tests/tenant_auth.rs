use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use drust::auth::bearer::{generate_token, hash_token};
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::router::{TenantAuthState, TenantRef, bearer_auth_layer};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn app() -> (Router, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('blog', 'b')", [])
        .unwrap();
    let tok = generate_token();
    let hash = hash_token(&tok);
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash) VALUES ('blog', ?1)",
        rusqlite::params![hash],
    )
    .unwrap();
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: Arc::new(TenantRegistry::new(data.clone(), 2)),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(dir.path().join("audit"))),
        index_large_table_rows: 1_000_000,
        register_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(3, Duration::from_secs(60), 4096)),
        login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        public_url: String::new(),
        oauth_adapter_override: Arc::new(std::collections::HashMap::new()),
    };
    // Need to seed tenant data file
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let app =
        Router::new()
            .route(
                "/t/{tenant}/echo",
                get(|ext: axum::Extension<TenantRef>| async move {
                    format!("tenant={}", ext.tenant_id)
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                bearer_auth_layer,
            ))
            .with_state(state);
    (app, tok, dir)
}

#[tokio::test]
async fn missing_bearer_401() {
    let (app, _tok, _d) = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/echo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_bearer_passes() {
    let (app, tok, _d) = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/echo")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(std::str::from_utf8(&body).unwrap(), "tenant=blog");
}

#[tokio::test]
async fn wrong_tenant_token_404() {
    let (app, tok, _d) = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/nonexistent/echo")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

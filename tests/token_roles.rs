mod helpers;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use helpers::{grab_pool, test_mcp_http};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn tenant_with_two_tokens(tenant: &str) -> (axum::Router, String, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let anon_tok = generate_token();
    let service_tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'test-anon', 'anon')",
        rusqlite::params![tenant, hash_token(&anon_tok)],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'test-service', 'service')",
        rusqlite::params![tenant, hash_token(&service_tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();

    let pool = grab_pool(tenant, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                value INTEGER,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
            INSERT INTO items (name, value) VALUES ('seed-a', 1), ('seed-b', 2);",
        )
    })
    .await
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: tenants.clone(),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(dir.path().join("audit"))),
    };
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, anon_tok, service_tok, dir)
}

#[tokio::test]
async fn anon_token_can_list_records() {
    let (app, anon, _svc, _d) = tenant_with_two_tokens("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/items")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn anon_token_cannot_create_record() {
    let (app, anon, _svc, _d) = tenant_with_two_tokens("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/items")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"name":"x"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "WRITE_DENIED");
}

#[tokio::test]
async fn anon_token_cannot_update_record() {
    let (app, anon, _svc, _d) = tenant_with_two_tokens("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/t/blog/records/items/1")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"name":"y"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "WRITE_DENIED");
}

#[tokio::test]
async fn anon_token_cannot_delete_record() {
    let (app, anon, _svc, _d) = tenant_with_two_tokens("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/t/blog/records/items/1")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "WRITE_DENIED");
}

#[tokio::test]
async fn anon_token_can_post_query_select() {
    let (app, anon, _svc, _d) = tenant_with_two_tokens("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/query")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"sql":"SELECT COUNT(*) AS n FROM items"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn service_token_can_create_record() {
    let (app, _anon, svc, _d) = tenant_with_two_tokens("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/items")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"name":"svc-create"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn migration_preserves_existing_tokens_as_service() {
    // Simulate a v0.1.0 DB by opening meta.sqlite, dropping the role column
    // (SQLite 3.35+), reinserting a token without role, then reopening —
    // open_meta should re-add the role column with default 'service'.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");

    let conn = open_meta(&path).unwrap();
    // Force-drop role column to simulate pre-migration state.
    conn.execute("ALTER TABLE tokens DROP COLUMN role", [])
        .unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('legacy', 'L')", [])
        .unwrap();
    let legacy_tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label) VALUES ('legacy', ?1, 'old')",
        rusqlite::params![hash_token(&legacy_tok)],
    )
    .unwrap();
    drop(conn);

    // Reopen — migration should add role='service' default.
    let conn2 = open_meta(&path).unwrap();
    let role: String = conn2
        .query_row("SELECT role FROM tokens WHERE label = 'old'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(role, "service");
}

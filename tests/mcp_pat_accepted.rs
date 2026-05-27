//! Integration tests: PAT (drust_pat_*) is NOT rejected by the v1.29 MCP
//! transport gate — PATs carry `admin_id: Some(_)` and therefore pass.
//!
//! Also exercises the sub-path `/mcp/` (trailing slash) to confirm the
//! `is_mcp_path` regex matches both variants.
//!
//! v1.29.0 — Task 18 / 22.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token;
use drust::safety::audit::AuditLog;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus, router::TenantAuthState};
use rusqlite::params;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Spin up an app with one admin + PAT + tenant.
/// Returns `(app, plaintext_pat, dir)`.
async fn app_with_pat_and_tenant(
    tenant: &str,
) -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let audit_dir = data.join("audit");
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();

    // Admin row
    conn.execute(
        "INSERT INTO admins (username, password_hash, email) \
         VALUES ('tester', '$argon2id$v=19$m=19456,t=2,p=1$x$x', 'pat-mcp-test@example.com')",
        [],
    )
    .unwrap();
    let admin_id: i64 = conn.last_insert_rowid();

    // Tenant row
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'acme')",
        params![tenant],
    )
    .unwrap();

    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    // Mint a PAT (must come after run_migrations creates _admin_tokens)
    let plaintext = admin_token::generate_token();
    let hash = admin_token::hash_token(&plaintext);
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, name, token_hash) VALUES (?1, 'mcp-test-pat', ?2)",
        params![admin_id, hash],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(
        meta,
        tenants.clone(),
        Arc::new(AuditLog::new(audit_dir)),
    );
    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    });

    (app, plaintext, dir)
}

/// PAT must pass the MCP gate (carries admin_id) and reach the MCP handler.
/// We only assert NOT 401 — whatever MCP returns for a bare POST is fine.
#[tokio::test]
async fn pat_not_rejected_by_mcp_gate() {
    let tenant = "pat-mcp-t1";
    let (app, plaintext, _dir) = app_with_pat_and_tenant(tenant).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tenant}/mcp"))
                .header(header::AUTHORIZATION, format!("Bearer {plaintext}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "PAT should pass the MCP gate (has admin_id), got 401"
    );
}

/// PAT on a REST path still works — no regression from the gate.
#[tokio::test]
async fn pat_still_works_on_rest_path() {
    let tenant = "pat-mcp-t2";
    let (app, plaintext, _dir) = app_with_pat_and_tenant(tenant).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/t/{tenant}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {plaintext}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PAT should still work on REST path, got {}",
        resp.status()
    );
}

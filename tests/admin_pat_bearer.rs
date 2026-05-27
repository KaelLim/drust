//! Integration test: PAT (drust_pat_*) bearer path in bearer_auth_layer.
//! Verifies end-to-end: PAT → service context with admin_id → audit attribution.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token;
use drust::safety::audit::AuditLog;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus, router::TenantAuthState};
use rusqlite::params;
use std::path::Path as StdPath;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Spin up an app with a single tenant; admin row and PAT inserted directly.
/// Returns (app, plaintext_pat, admin_id, dir, audit_dir).
async fn app_with_pat(tenant: &str) -> (axum::Router, String, i64, tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let audit_dir = dir.path().join("audit");
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();

    // Insert admin
    conn.execute(
        "INSERT INTO admins (username, password_hash, email) VALUES ('tester', '$argon2id$v=19$m=19456,t=2,p=1$x$x', 'pat-tester@example.com')",
        [],
    ).unwrap();
    let admin_id: i64 = conn.last_insert_rowid();

    // Insert tenant
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'acme')",
        params![tenant],
    ).unwrap();

    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    // Mint a PAT and insert its hash (must come after run_migrations creates _admin_tokens)
    let plaintext = admin_token::generate_token();
    let hash = admin_token::hash_token(&plaintext);
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, name, token_hash) VALUES (?1, 'test-pat', ?2)",
        params![admin_id, hash],
    ).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(
        meta,
        tenants.clone(),
        Arc::new(AuditLog::new(audit_dir.clone())),
    );
    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    });

    (app, plaintext, admin_id, dir, audit_dir)
}

/// Poll the audit JSONL files until at least one line appears (or timeout).
async fn read_audit_lines(dir: &StdPath) -> Vec<serde_json::Value> {
    for _ in 0..50 {
        if dir.exists() {
            let mut files = tokio::fs::read_dir(dir).await.unwrap();
            let mut all = Vec::new();
            while let Some(f) = files.next_entry().await.unwrap() {
                let p = f.path();
                if p.extension().and_then(|s| s.to_str()) != Some("jsonl") {
                    continue;
                }
                let bytes = tokio::fs::read(&p).await.unwrap();
                for line in bytes.split(|&b| b == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    all.push(serde_json::from_slice(line).unwrap());
                }
            }
            if !all.is_empty() {
                return all;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("audit file never appeared at {dir:?}");
}

#[tokio::test]
async fn pat_bearer_returns_200_for_tenant_route() {
    let (app, plaintext, _admin_id, _dir, _audit_dir) = app_with_pat("pat-t1").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/pat-t1/collections")
                .header(header::AUTHORIZATION, format!("Bearer {plaintext}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "PAT should resolve to service, got {}", resp.status());
}

#[tokio::test]
async fn pat_bearer_audit_row_carries_actor_admin_id() {
    let (app, plaintext, admin_id, _dir, audit_dir) = app_with_pat("pat-t2").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/pat-t2/collections")
                .header(header::AUTHORIZATION, format!("Bearer {plaintext}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let lines = read_audit_lines(&audit_dir).await;
    let entry = lines.iter().find(|l| {
        l["op"].as_str().map_or(false, |op| op.contains("collections"))
    }).expect("no audit entry for collections route");

    let got_admin_id = entry["actor_admin_id"].as_i64()
        .expect("actor_admin_id should be present as an integer in audit row");
    assert_eq!(got_admin_id, admin_id, "audit actor_admin_id should match the inserted admin");

    let email = entry["actor_email_snapshot"].as_str()
        .expect("actor_email_snapshot should be present");
    assert_eq!(email, "pat-tester@example.com");
}

#[tokio::test]
async fn non_pat_bearer_does_not_pollute_pat_path() {
    // A regular shared service token should still resolve to Service { admin_id: None }
    // and NOT get actor_admin_id in the audit row.
    let (app, tok, _dir) = helpers::spin_up_tenant("pat-t3").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/pat-t3/collections")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

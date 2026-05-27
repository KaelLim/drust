//! Integration tests: OAuth access token (`drust_at_*`) bearer path in
//! `bearer_auth_layer`. Covers:
//!   (a) Happy path → resolves to Service { admin_id } + audit attribution.
//!   (b) Wrong resource_uri → 403 INVALID_RESOURCE.
//!
//! v1.29.0 — Task 17 / 22.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::db::migrations::{
    SQL_CREATE_OAUTH_ACCESS_TOKENS_IF_NOT_EXISTS, SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS,
};
use drust::mgmt::oauth_server::storage::{new_access_token, sha256_b64};
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

// ─── shared constants ─────────────────────────────────────────────────────────

/// Fake public base URL. Must match the prefix used in resource_uri inserts.
const BASE: &str = "https://drust.example.test";

// ─── setup helper ─────────────────────────────────────────────────────────────

/// Spin up a router with one admin + one OAuth client + one tenant.
/// Returns `(app, meta_mutex, admin_id, dir, audit_dir)`.
async fn app_with_oauth_client(
    tenant: &str,
) -> (
    axum::Router,
    Arc<Mutex<rusqlite::Connection>>,
    i64,
    tempfile::TempDir,
    std::path::PathBuf,
) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let audit_dir = data.join("audit");
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();

    // Admin row
    conn.execute(
        "INSERT INTO admins (username, password_hash, email) \
         VALUES ('tester', '$argon2id$v=19$m=19456,t=2,p=1$x$x', 'oauth-bearer-test@example.com')",
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

    // Ensure OAuth tables exist (run_migrations should cover this, but be explicit)
    conn.execute_batch(SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS)
        .unwrap();
    conn.execute_batch(SQL_CREATE_OAUTH_ACCESS_TOKENS_IF_NOT_EXISTS)
        .unwrap();

    // OAuth client row
    conn.execute(
        "INSERT OR IGNORE INTO _oauth_clients (id, client_name, redirect_uris_json) \
         VALUES ('drust_client_oauthbearertest', 'TestApp', '[]')",
        [],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let mut state = TenantAuthState::test_default(
        meta.clone(),
        tenants.clone(),
        Arc::new(AuditLog::new(audit_dir.clone())),
    );
    // Set public_url so the RFC 8707 resource check has a real base to compare.
    state.public_url = BASE.to_string();

    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    });

    (app, meta, admin_id, dir, audit_dir)
}

/// Insert an OAuth access token into `_oauth_access_tokens`.
/// Returns the plaintext token.
async fn insert_access_token(
    meta: &Arc<Mutex<rusqlite::Connection>>,
    admin_id: i64,
    resource_uri: &str,
) -> String {
    let plaintext = new_access_token();
    let hash = sha256_b64(&plaintext);
    let conn = meta.lock().await;
    conn.execute(
        "INSERT INTO _oauth_access_tokens \
         (token_hash, client_id, admin_id, resource_uri, expires_at) \
         VALUES (?1, 'drust_client_oauthbearertest', ?2, ?3, datetime('now', '+1 hour'))",
        params![hash, admin_id, resource_uri],
    )
    .unwrap();
    plaintext
}

// ─── audit poll helper ────────────────────────────────────────────────────────

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
                    if let Ok(v) = serde_json::from_slice(line) {
                        all.push(v);
                    }
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

// ─── tests ────────────────────────────────────────────────────────────────────

/// (a) Happy path: OAuth access token bound to the correct resource resolves
/// to `AuthCtx::Service { admin_id: Some(_) }` and returns 200.
///
/// We bind the token's resource_uri to `/t/<tenant>/collections` (a REST
/// endpoint) so we can hit the same URL in the test assertion and observe a
/// real 200 without needing to speak the MCP Streamable HTTP protocol.
#[tokio::test]
async fn oauth_access_token_resolves_to_service_with_admin_id() {
    let tenant = "ob-t1";
    let (app, meta, admin_id, _dir, audit_dir) = app_with_oauth_client(tenant).await;

    // Bind token to the collections REST endpoint (not /mcp) so we can hit it directly.
    let resource_uri = format!("{BASE}/drust/t/{tenant}/collections");
    let plaintext = insert_access_token(&meta, admin_id, &resource_uri).await;

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
        "OAuth access token should resolve to service, got {}",
        resp.status()
    );

    // Audit: actor_admin_id must be set to our admin.
    let lines = read_audit_lines(&audit_dir).await;
    let entry = lines
        .iter()
        .find(|l| {
            l["op"]
                .as_str()
                .map_or(false, |op| op.contains("collections"))
        })
        .expect("no audit entry for collections route");

    let got_admin_id = entry["actor_admin_id"]
        .as_i64()
        .expect("actor_admin_id should be present as an integer in audit row");
    assert_eq!(
        got_admin_id, admin_id,
        "audit actor_admin_id should match the inserted admin"
    );

    let email = entry["actor_email_snapshot"]
        .as_str()
        .expect("actor_email_snapshot should be present");
    assert_eq!(email, "oauth-bearer-test@example.com");
}

/// (b) Token bound to tenant_a's resource_uri must be rejected with 403
/// INVALID_RESOURCE when presented to tenant_b's route.
#[tokio::test]
async fn oauth_token_for_wrong_resource_rejected() {
    let tenant_a = "ob-t2a";
    let tenant_b = "ob-t2b";

    // Build the app from tenant_a's setup (both tenants share one meta.sqlite).
    let (app, meta, admin_id, dir, _audit_dir) = app_with_oauth_client(tenant_a).await;

    // Also create tenant_b in the same meta.sqlite and on disk.
    {
        let conn = meta.lock().await;
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES (?1, 'b')",
            params![tenant_b],
        )
        .unwrap();
    }
    let _ = drust::storage::tenant_db::open_write(&dir.path().to_path_buf(), tenant_b).unwrap();

    // Token is bound to tenant_a's MCP endpoint.
    let resource_uri_a = format!("{BASE}/drust/t/{tenant_a}/mcp");
    let plaintext = insert_access_token(&meta, admin_id, &resource_uri_a).await;

    // Present to tenant_b → must get 403.
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/t/{tenant_b}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {plaintext}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "token bound to tenant_a must not work for tenant_b"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["error_code"], "INVALID_RESOURCE",
        "error_code should be INVALID_RESOURCE, got: {}",
        json
    );
}

/// (c) An expired OAuth access token must fall through to the anon/service
/// meta.sqlite lookup path and ultimately return 401 (unknown token).
#[tokio::test]
async fn expired_oauth_token_falls_through_to_unauthenticated() {
    let tenant = "ob-t3";
    let (app, meta, admin_id, _dir, _audit_dir) = app_with_oauth_client(tenant).await;

    let plaintext = new_access_token();
    let hash = sha256_b64(&plaintext);
    {
        let conn = meta.lock().await;
        conn.execute(
            "INSERT INTO _oauth_access_tokens \
             (token_hash, client_id, admin_id, resource_uri, expires_at) \
             VALUES (?1, 'drust_client_oauthbearertest', ?2, ?3, datetime('now', '-1 second'))",
            params![
                hash,
                admin_id,
                format!("{BASE}/drust/t/{tenant}/mcp")
            ],
        )
        .unwrap();
    }

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

    // lookup_access_token filters out expired rows; the token has no row in
    // _admin_tokens or meta.sqlite tokens table → falls to UNAUTHENTICATED.
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired OAuth token should yield 401, got {}",
        resp.status()
    );
}

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use std::path::Path as StdPath;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn app_with_audit(
    tenant: &str,
) -> (axum::Router, String, tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let audit_dir = dir.path().join("audit");
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
    let webhooks = drust::tenant::WebhookDispatcher::new(data.clone());
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: tenants.clone(),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(audit_dir.clone())),
        index_large_table_rows: 1_000_000,
        register_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(3, Duration::from_secs(60), 4096)),
        login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        public_url: String::new(),
        oauth_adapter_override: Arc::new(std::collections::HashMap::new()),
    };
    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    });
    (app, tok, dir, audit_dir)
}

/// The audit append goes through an mpsc to a dedicated writer task,
/// so the JSONL file may not exist the instant the response returns.
/// Poll briefly.
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
async fn successful_request_writes_ok_entry() {
    let (app, tok, _d, audit_dir) = app_with_audit("ab1").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/ab1/collections")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let lines = read_audit_lines(&audit_dir).await;
    assert_eq!(lines.len(), 1);
    let e = &lines[0];
    assert_eq!(e["tenant"], "ab1");
    assert_eq!(e["status"], "ok");
    assert_eq!(e["op"], "GET /collections");
    assert!(e["token_hint"].as_str().unwrap().starts_with("drust_"));
    assert!(e["duration_ms"].as_u64().is_some());
}

#[tokio::test]
async fn missing_bearer_writes_error_entry() {
    let (app, _tok, _d, audit_dir) = app_with_audit("ab2").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/ab2/collections")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let lines = read_audit_lines(&audit_dir).await;
    assert_eq!(lines.len(), 1);
    let e = &lines[0];
    assert_eq!(e["tenant"], "ab2");
    assert_eq!(e["status"], "error");
    assert_eq!(e["error_code"], "HTTP_401");
    assert_eq!(e["op"], "GET /collections");
    // No bearer at all → token_hint is "-".
    assert_eq!(e["token_hint"], "-");
}

#[tokio::test]
async fn strips_tenant_prefix_from_op_path() {
    let (app, tok, _d, audit_dir) = app_with_audit("deep-tenant-id").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/deep-tenant-id/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 500 because the `posts` collection does not exist, but the audit
    // middleware still fires and should strip the tenant prefix.
    assert!(!resp.status().is_success());

    let lines = read_audit_lines(&audit_dir).await;
    assert_eq!(lines.len(), 1);
    let op = lines[0]["op"].as_str().unwrap();
    assert!(
        op.starts_with("GET /records/posts"),
        "op should strip /t/{{tenant}} prefix, got {op:?}"
    );
    assert!(
        !op.contains("/t/deep-tenant-id"),
        "op should not contain the tenant-id segment, got {op:?}"
    );
}

#[tokio::test]
async fn create_index_writes_audit_with_extra_fields() {
    let (app, tok, dir, audit_dir) = app_with_audit("ax1").await;

    // Seed a `posts` table with an `author_id INTEGER` field directly via pool.
    let pool = helpers::grab_pool("ax1", &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author_id INTEGER
            );",
        )
    })
    .await
    .unwrap();

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/ax1/collections/posts/indexes")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let lines = read_audit_lines(&audit_dir).await;
    let line = lines
        .iter()
        .find(|l| l["op"] == "POST /collections/posts/indexes")
        .expect("no audit entry for POST /collections/posts/indexes");
    assert_eq!(line["status"], "ok");
    assert_eq!(line["index_name"], "idx_posts_author_id");
    assert_eq!(line["index_fields"], serde_json::json!(["author_id"]));
    assert!(
        line["row_count"].is_number(),
        "row_count should be a number, got {:?}",
        line["row_count"]
    );
    assert_eq!(line["force_used"], false);
}

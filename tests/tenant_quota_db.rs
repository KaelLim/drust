//! v1.50 (Spec B, Task 3) — per-tenant hard quota on DB write choke points.
//!
//! A tier-1 tenant caps at 10 GiB (`db_bytes + files_bytes`). These tests push
//! a tenant OVER the cap by inserting a single oversized `_system_files`
//! metadata row (so the writer-time `usage_on_conn` probe reports over-limit
//! without materialising real bytes), then prove every growth-shaped write is
//! rejected with 507 `TENANT_QUOTA_EXCEEDED` — for the DEFAULT (service) bearer
//! too — while reads and deletes stay allowed. Covers all three DB write
//! surfaces: REST `/records`, MCP `insert_record`, and write-mode stored RPC.

mod helpers;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use helpers::{grab_pool, spin_up_tenant};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// 11 GiB — comfortably over the tier-1 (10 GiB) cap once the tiny db page
/// bytes are added on top.
const OVER_LIMIT_BYTES: i64 = 11 * 1024 * 1024 * 1024;

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// Create a `posts` collection with ONE seed row (while under quota), then
/// inflate `_system_files` past the tier-1 cap. Returns the seed row id.
async fn seed_over_quota(dir: &tempfile::TempDir, tenant: &str) -> i64 {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;
        c.execute("INSERT INTO posts (title) VALUES ('seed')", [])?;
        let id = c.last_insert_rowid();
        c.execute(
            "INSERT INTO \"_system_files\" (key, original_name, size_bytes, uploader) \
             VALUES ('quota-filler', 'filler', ?1, 'service')",
            rusqlite::params![OVER_LIMIT_BYTES],
        )?;
        Ok(id)
    })
    .await
    .unwrap()
}

/// Insert a write-mode stored RPC directly into `_system_rpc` (mirrors the
/// helper in tests/rpc_v2_mutation.rs).
async fn create_write_rpc(
    pool: &drust::storage::pool::SharedTenantPool,
    name: &str,
    sql: &str,
    params_json: &str,
) {
    let name = name.to_string();
    let sql = sql.to_string();
    let params_json = params_json.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_rpc \
             (name, sql, params_json, description, anon_callable, mode, \
              anon_calls, service_calls, last_called_at, created_at, updated_at) \
             VALUES (?1, ?2, ?3, '', 0, 'write', 0, 0, NULL, \
                     datetime('now'), datetime('now'))",
            rusqlite::params![name, sql, params_json],
        )
    })
    .await
    .unwrap();
}

// ────────────────────────────────────────────────────────────────────
// REST /records — service bearer (the spin_up_tenant default role).
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn over_quota_service_rest_writes_507_reads_ok() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    let id = seed_over_quota(&d, "blog").await;

    // INSERT (growth) → 507. The default spin_up_tenant token is a SERVICE key,
    // so this also pins "service key is capped too".
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"x"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "insert over quota must be 507"
    );
    let v = body_json(r).await;
    assert_eq!(v["error_code"], "TENANT_QUOTA_EXCEEDED", "body: {v}");
    assert!(
        !v["suggested_fix"].as_str().unwrap_or("").is_empty(),
        "507 must carry a suggested_fix: {v}"
    );

    // UPDATE → allowed even over quota (adversarial F3: a shrink / in-place
    // update must never be blocked so an over-cap tenant can recover; UPDATE
    // is not quota-gated — only INSERT / upload / write-RPC growth is).
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"y"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "update must be allowed over quota (recovery), got {}",
        r.status()
    );

    // GET one → 200 (reads always allowed).
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "GET must stay allowed over quota"
    );

    // LIST → 200.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "list must stay allowed over quota"
    );

    // DELETE → success (frees space, always allowed).
    let r = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "delete must stay allowed over quota, got {}",
        r.status()
    );
}

// ────────────────────────────────────────────────────────────────────
// MCP insert_record — the shared write-core choke point.
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn over_quota_mcp_insert_507() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let meta_conn = drust::storage::meta::open_meta(&data.join("meta.sqlite")).unwrap();
    meta_conn
        .execute("INSERT INTO tenants (id, name) VALUES ('blog', 'x')", [])
        .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();

    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let pool = tenants.get_or_open("blog").unwrap();
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, \
             created_at TEXT NOT NULL DEFAULT (datetime('now')), \
             updated_at TEXT NOT NULL DEFAULT (datetime('now')));",
        )?;
        c.execute(
            "INSERT INTO \"_system_files\" (key, original_name, size_bytes, uploader) \
             VALUES ('quota-filler', 'filler', ?1, 'service')",
            rusqlite::params![OVER_LIMIT_BYTES],
        )?;
        Ok(())
    })
    .await
    .unwrap();

    let meta = Arc::new(Mutex::new(meta_conn));
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let mcp = drust::mcp::server::DrustMcp::new(
        "blog",
        pool.clone(),
        drust::tenant::events::EventBus::new(),
        drust::tenant::WebhookDispatcher::new(tenants.clone(), None),
        None,
        String::new(),
        Arc::new([0u8; 32]),
        Some(meta),
        52_428_800,
        1_000_000,
        Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        drust::tenant::rooms::RoomBus::new(),
        bucket,
        rooms_cfg,
        None,
        None,
    );

    let err =
        drust::mcp::tools::write::insert_record(&mcp, "posts", serde_json::json!({"title":"x"}))
            .await
            .unwrap_err();
    assert!(
        err.to_string().contains("TENANT_QUOTA_EXCEEDED"),
        "MCP insert over quota must carry TENANT_QUOTA_EXCEEDED, got: {err}"
    );
}

// ────────────────────────────────────────────────────────────────────
// Write-mode stored RPC (REST /rpc, dry_run=false) — service bearer.
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn over_quota_write_rpc_507() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    let _ = seed_over_quota(&d, "blog").await;
    let pool = grab_pool("blog", &d).await;
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, qty INTEGER);")
    })
    .await
    .unwrap();
    create_write_rpc(
        &pool,
        "add_order",
        "INSERT INTO orders (qty) VALUES (:q)",
        r#"[{"name":"q","type":"integer"}]"#,
    )
    .await;

    let r = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/rpc/add_order?dry_run=false")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"q":5}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "write-rpc over quota must be 507"
    );
    let v = body_json(r).await;
    assert_eq!(v["error_code"], "TENANT_QUOTA_EXCEEDED", "body: {v}");
}

//! v1.32.1 D1 — middleware audit emit test, ported from JSONL to SQLite.
//!
//! Before: `bearer_auth_layer` called `state.audit.append(entry)` which
//! routed through a per-tenant `Arc<AuditLog>` and a JSONL writer task.
//! After: it calls `crate::safety::audit_db::try_send(&entry)` against
//! the process-global `AuditWriter` initialised in `main`.
//!
//! These tests share one global writer + temp SQLite DB across the binary
//! (mirrors `admin_pat_reroll.rs`'s `Box::leak` pattern) and filter rows
//! by tenant to stay isolated from sibling tests running in parallel.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Initialise the process-wide audit writer once and return the DB
/// path. The writer runs on a dedicated `std::thread` with its own
/// tokio runtime so the writer task outlives individual `#[tokio::test]`
/// runtimes (each test gets a fresh runtime that drops at the end).
/// Mirrors the pattern in `tests/common/oauth_helpers.rs::TEST_AUDIT_DB`.
fn ensure_global_audit_writer() -> &'static PathBuf {
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_audit_middleware.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-audit-middleware-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build test-audit-writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    drust::safety::audit_db::init_globals(writer);
                    let _ = tx_ready.send(());
                    // Park forever so the writer task keeps draining
                    // long after the initialising test's runtime drops.
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

async fn app_with_audit(tenant: &str) -> (axum::Router, String, tempfile::TempDir) {
    ensure_global_audit_writer();
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
    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());
    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    });
    (app, tok, dir)
}

/// Poll the global audit SQLite DB for rows matching `tenant`, returning
/// a JSON shape that mirrors what the old JSONL reader produced.
async fn read_audit_rows_for_tenant(tenant: &str) -> Vec<serde_json::Value> {
    let path = ensure_global_audit_writer();
    for _ in 0..50 {
        let r = open_audit_db_read(path).unwrap();
        let _ = r.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
        let mut stmt = r
            .prepare(
                "SELECT tenant, status, op, token_hint, duration_ms, error_code, extra \
                 FROM audit WHERE tenant = ?1 ORDER BY id ASC",
            )
            .unwrap();
        let rows: Vec<serde_json::Value> = stmt
            .query_map(rusqlite::params![tenant], |r| {
                let tenant: Option<String> = r.get(0)?;
                let status: Option<String> = r.get(1)?;
                let op: Option<String> = r.get(2)?;
                let token_hint: Option<String> = r.get(3)?;
                let duration_ms: Option<i64> = r.get(4)?;
                let error_code: Option<String> = r.get(5)?;
                let extra_json: Option<String> = r.get(6)?;
                let mut map = serde_json::Map::new();
                if let Some(t) = tenant {
                    map.insert("tenant".into(), serde_json::Value::String(t));
                }
                if let Some(s) = status {
                    map.insert("status".into(), serde_json::Value::String(s));
                }
                if let Some(o) = op {
                    map.insert("op".into(), serde_json::Value::String(o));
                }
                if let Some(h) = token_hint {
                    map.insert("token_hint".into(), serde_json::Value::String(h));
                }
                if let Some(d) = duration_ms {
                    map.insert("duration_ms".into(), serde_json::Value::Number(d.into()));
                }
                if let Some(c) = error_code {
                    map.insert("error_code".into(), serde_json::Value::String(c));
                }
                // Flatten extra so callers can read row["index_name"] etc.
                if let Some(extra_str) = extra_json {
                    if let Ok(serde_json::Value::Object(extra_map)) =
                        serde_json::from_str::<serde_json::Value>(&extra_str)
                    {
                        for (k, v) in extra_map {
                            map.entry(k).or_insert(v);
                        }
                    }
                }
                Ok(serde_json::Value::Object(map))
            })
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        if !rows.is_empty() {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no audit rows for tenant {tenant} after 1s");
}

#[tokio::test]
async fn successful_request_writes_ok_entry() {
    let (app, tok, _d) = app_with_audit("md-ab1").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/md-ab1/collections")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = read_audit_rows_for_tenant("md-ab1").await;
    assert_eq!(rows.len(), 1);
    let e = &rows[0];
    assert_eq!(e["tenant"], "md-ab1");
    assert_eq!(e["status"], "ok");
    assert_eq!(e["op"], "GET /collections");
    assert!(e["token_hint"].as_str().unwrap().starts_with("drust_"));
    assert!(e["duration_ms"].as_i64().is_some());
}

#[tokio::test]
async fn missing_bearer_writes_error_entry() {
    let (app, _tok, _d) = app_with_audit("md-ab2").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/md-ab2/collections")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let rows = read_audit_rows_for_tenant("md-ab2").await;
    assert_eq!(rows.len(), 1);
    let e = &rows[0];
    assert_eq!(e["tenant"], "md-ab2");
    assert_eq!(e["status"], "error");
    assert_eq!(e["error_code"], "HTTP_401");
    assert_eq!(e["op"], "GET /collections");
    // No bearer at all → token_hint is "-".
    assert_eq!(e["token_hint"], "-");
}

#[tokio::test]
async fn strips_tenant_prefix_from_op_path() {
    let (app, tok, _d) = app_with_audit("md-deep-tenant-id").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/md-deep-tenant-id/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 500 because the `posts` collection does not exist, but the audit
    // middleware still fires and should strip the tenant prefix.
    assert!(!resp.status().is_success());

    let rows = read_audit_rows_for_tenant("md-deep-tenant-id").await;
    assert_eq!(rows.len(), 1);
    let op = rows[0]["op"].as_str().unwrap();
    assert!(
        op.starts_with("GET /records/posts"),
        "op should strip /t/{{tenant}} prefix, got {op:?}"
    );
    assert!(
        !op.contains("/t/md-deep-tenant-id"),
        "op should not contain the tenant-id segment, got {op:?}"
    );
}

#[tokio::test]
async fn create_index_writes_audit_with_extra_fields() {
    let (app, tok, dir) = app_with_audit("md-ax1").await;

    // Seed a `posts` table with an `author_id INTEGER` field directly via pool.
    let pool = helpers::grab_pool("md-ax1", &dir).await;
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
                .uri("/t/md-ax1/collections/posts/indexes")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let rows = read_audit_rows_for_tenant("md-ax1").await;
    let line = rows
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

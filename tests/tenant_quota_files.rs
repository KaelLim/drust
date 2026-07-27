//! v1.50 (Spec B, Task 4) — per-tenant hard quota on the FILE upload choke
//! points: Mode A multipart (`tenant_files::upload`), Mode B tus
//! (`uploads::create` / `patch` / finalize), and the edge-function `put-file`
//! host op (`functions::enforce::put_file_raw`).
//!
//! Same trick as `tests/tenant_quota_db.rs`: a tier-1 tenant caps at 10 GiB
//! (`db_bytes + files_bytes`). We push a tenant OVER the cap by inserting a
//! single oversized `_system_files` metadata row (so the writer-time
//! `usage_on_conn` probe reports over-limit without materialising real bytes),
//! then prove every upload path is rejected with 507 `TENANT_QUOTA_EXCEEDED`
//! (or the string-equivalent host-op error), and that freeing space lets a
//! retry succeed. `TenantFilesState::test_default` threads `meta: None`, so the
//! tier defaults to 1 — exactly what these over-cap tests need.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse;
use drust::mgmt::tenant_files::{TenantFilesState, upload};
use drust::storage::garage::GarageClient;
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use drust::tenant::router::{TenantRef, TokenRole};
use drust::tenant::uploads;
use object_store::memory::InMemory;
use std::sync::Arc;
use tower::ServiceExt;

mod helpers;

/// 11 GiB — comfortably over the tier-1 (10 GiB) cap once the tiny db page
/// bytes are added on top.
const OVER_LIMIT_BYTES: i64 = 11 * 1024 * 1024 * 1024;

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn caps() -> axum::Extension<drust::tenant::file_caps::TenantFileCaps> {
    axum::Extension(Default::default())
}

fn actx() -> axum::Extension<drust::auth::middleware::AuthCtx> {
    axum::Extension(drust::auth::middleware::AuthCtx::Service { admin_id: None })
}

/// Insert an oversized `_system_files` filler row so `usage_on_conn` reports
/// over the tier-1 cap.
async fn inflate_over_quota(pool: &SharedTenantPool) {
    pool.with_writer(|c| {
        c.execute(
            "INSERT INTO \"_system_files\" (key, original_name, size_bytes, uploader) \
             VALUES ('quota-filler', 'filler', ?1, 'service')",
            rusqlite::params![OVER_LIMIT_BYTES],
        )
        .map(|_| ())
    })
    .await
    .unwrap();
}

async fn file_row_count(pool: &SharedTenantPool) -> i64 {
    pool.with_reader(|c| c.query_row("SELECT COUNT(*) FROM \"_system_files\"", [], |r| r.get(0)))
        .await
        .unwrap()
}

/// Build a fresh tenant (full `_system_*` schema) + a files router mounting the
/// Mode A `upload` handler over an in-memory Garage. Returns
/// `(router, state, pool, tempdir)`.
fn setup_mode_a(
    tid: &str,
) -> (
    axum::Router,
    TenantFilesState,
    SharedTenantPool,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open(tid).unwrap();
    let garage = Arc::new(GarageClient::from_store(
        Arc::new(InMemory::new()),
        "private",
    ));
    let mut state =
        TenantFilesState::test_default(Some(garage), dir.path().to_path_buf(), registry);
    state.disk_min_free_pct = 0; // the CI/host disk is often <20% free
    let app = axum::Router::new()
        .route("/t/{tenant}/files", axum::routing::post(upload))
        .with_state(state.clone());
    (app, state, pool, dir)
}

/// Minimal multipart body carrying one `file` part (mirrors the helper in
/// tests/admin_files_upgrade.rs / helpers.rs).
const BOUNDARY: &str = "drustquotaboundary";
fn multipart_file(bytes: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"q.bin\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn post_upload(app: &axum::Router, tid: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/files"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                )
                .body(Body::from(multipart_file(b"hello")))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ────────────────────────────────────────────────────────────────────
// Mode A multipart upload.
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mode_a_upload_over_quota_507_then_delete_allows_retry() {
    let (app, _state, pool, _d) = setup_mode_a("blog");
    inflate_over_quota(&pool).await;

    // Over quota → 507 TENANT_QUOTA_EXCEEDED (service caller too).
    let r = post_upload(&app, "blog").await;
    assert_eq!(
        r.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "Mode A upload over quota must be 507"
    );
    let v = body_json(r).await;
    assert_eq!(v["error_code"], "TENANT_QUOTA_EXCEEDED", "body: {v}");
    assert!(
        !v["suggested_fix"].as_str().unwrap_or("").is_empty(),
        "507 must carry a suggested_fix: {v}"
    );

    // Nothing was charged: only the filler row exists.
    assert_eq!(
        file_row_count(&pool).await,
        1,
        "no file row should be added"
    );

    // Free space (delete the filler) → retry succeeds.
    pool.with_writer(|c| {
        c.execute(
            "DELETE FROM \"_system_files\" WHERE key = 'quota-filler'",
            [],
        )
        .map(|_| ())
    })
    .await
    .unwrap();

    let r = post_upload(&app, "blog").await;
    assert!(
        r.status().is_success(),
        "upload must succeed once under quota, got {}",
        r.status()
    );
    assert_eq!(
        file_row_count(&pool).await,
        1,
        "the uploaded row now exists"
    );
}

// ────────────────────────────────────────────────────────────────────
// Mode B tus — create (Upload-Length pre-check).
// ────────────────────────────────────────────────────────────────────

fn tref(tid: &str, pool: SharedTenantPool) -> TenantRef {
    TenantRef {
        tenant_id: tid.to_string(),
        token_hint: "svc".into(),
        pool,
        role: TokenRole::Service,
    }
}

#[tokio::test]
async fn tus_create_over_quota_507() {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), "blog").unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open("blog").unwrap();
    inflate_over_quota(&pool).await;
    let mut state = TenantFilesState::test_default(None, dir.path().to_path_buf(), registry);
    state.disk_min_free_pct = 0;

    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "1000".parse().unwrap());
    headers.insert(
        "upload-metadata",
        format!("filename {}", b64("f.bin")).parse().unwrap(),
    );
    let resp = uploads::create(
        State(state),
        axum::Extension(tref("blog", pool.clone())),
        caps(),
        actx(),
        Path("blog".to_string()),
        headers,
    )
    .await
    .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "tus create declaring Upload-Length over quota must be 507"
    );
    let v = body_json(resp).await;
    assert_eq!(v["error_code"], "TENANT_QUOTA_EXCEEDED", "body: {v}");
    // No session row was created.
    let sessions: i64 = pool
        .with_reader(|c| {
            c.query_row("SELECT COUNT(*) FROM _system_upload_sessions", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(sessions, 0, "over-quota create must not open a session");
}

// ────────────────────────────────────────────────────────────────────
// Mode B tus — patch (cumulative usage + spool + chunk hard point).
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tus_patch_cumulative_over_quota_507_and_not_charged() {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), "blog").unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open("blog").unwrap();
    let garage = Arc::new(GarageClient::from_store(
        Arc::new(InMemory::new()),
        "private",
    ));
    let mut state =
        TenantFilesState::test_default(Some(garage), dir.path().to_path_buf(), registry);
    state.disk_min_free_pct = 0;
    let t = tref("blog", pool.clone());

    // Create a session on a still-empty tenant → passes the create pre-check.
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "5".parse().unwrap());
    headers.insert(
        "upload-metadata",
        format!("filename {}", b64("f.bin")).parse().unwrap(),
    );
    let created = uploads::create(
        State(state.clone()),
        axum::Extension(t.clone()),
        caps(),
        actx(),
        Path("blog".to_string()),
        headers,
    )
    .await
    .into_response();
    assert_eq!(
        created.status(),
        StatusCode::CREATED,
        "create should succeed"
    );
    let token = created
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    // Now the tenant crosses the cap (concurrent growth). The PATCH is the
    // hard point: usage + spool_offset + chunk_len > limit → 507.
    inflate_over_quota(&pool).await;

    let mut h = HeaderMap::new();
    h.insert("upload-offset", "0".parse().unwrap());
    let resp = uploads::patch(
        State(state.clone()),
        axum::Extension(t.clone()),
        caps(),
        actx(),
        Path(("blog".to_string(), token.clone())),
        h,
        axum::body::Bytes::from_static(b"hello"),
    )
    .await
    .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "tus patch pushing cumulative usage over quota must be 507"
    );

    // The spooled bytes are NOT charged into _system_files (only the filler).
    assert_eq!(
        file_row_count(&pool).await,
        1,
        "a rejected chunk must not create a _system_files row"
    );
}

// ────────────────────────────────────────────────────────────────────
// Mode B tus — finalize hard re-check (idempotent-retry path).
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tus_finalize_over_quota_507() {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), "blog").unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open("blog").unwrap();
    let garage = Arc::new(GarageClient::from_store(
        Arc::new(InMemory::new()),
        "private",
    ));
    let mut state =
        TenantFilesState::test_default(Some(garage), dir.path().to_path_buf(), registry);
    state.disk_min_free_pct = 0;
    let t = tref("blog", pool.clone());

    // Create a 5-byte session while empty.
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "5".parse().unwrap());
    headers.insert(
        "upload-metadata",
        format!("filename {}", b64("f.bin")).parse().unwrap(),
    );
    let created = uploads::create(
        State(state.clone()),
        axum::Extension(t.clone()),
        caps(),
        actx(),
        Path("blog".to_string()),
        headers,
    )
    .await
    .into_response();
    assert_eq!(created.status(), StatusCode::CREATED);
    let token = created
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    // Manually fill the spool to the full declared length so the next PATCH
    // takes the `cur == total_length` idempotent-finalize branch directly (the
    // finalize accounting point — the hard re-check under test).
    let spool = drust::storage::tenant_db::tenant_dir(dir.path(), "blog")
        .join("_uploads")
        .join(format!("{token}.part"));
    tokio::fs::write(&spool, b"hello").await.unwrap();

    // Cross the cap after the spool is full.
    inflate_over_quota(&pool).await;

    let mut h = HeaderMap::new();
    h.insert("upload-offset", "5".parse().unwrap());
    let resp = uploads::patch(
        State(state.clone()),
        axum::Extension(t.clone()),
        caps(),
        actx(),
        Path(("blog".to_string(), token.clone())),
        h,
        axum::body::Bytes::new(),
    )
    .await
    .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "finalize accounting point over quota must be 507"
    );
    // Not charged.
    assert_eq!(
        file_row_count(&pool).await,
        1,
        "finalize must not add a row"
    );
}

// ────────────────────────────────────────────────────────────────────
// Edge-function `put-file` host op (functions::enforce::put_file_raw).
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn edge_put_file_over_quota_denied() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let pool = tenants.get_or_open("blog").unwrap();
    inflate_over_quota(&pool).await;

    let garage = Arc::new(GarageClient::from_store(
        Arc::new(InMemory::new()),
        "private",
    ));
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let mcp = drust::mcp::server::DrustMcp::new(
        "blog",
        pool.clone(),
        drust::tenant::events::EventBus::new(),
        drust::tenant::WebhookDispatcher::new(tenants.clone(), None),
        Some(garage),
        String::new(),
        Arc::new([0u8; 32]),
        None, // meta None → tier 1 (10 GiB)
        52_428_800,
        1_000_000,
        Arc::new(tokio::sync::Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        drust::tenant::rooms::RoomBus::new(),
        bucket,
        rooms_cfg,
        None,
        None,
    );

    let err = drust::functions::enforce::put_file_raw(
        &mcp,
        "some-key.bin",
        b"hello".to_vec(),
        "application/octet-stream",
        "private",
        0, // disk_min_free_pct
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("TENANT_QUOTA_EXCEEDED"),
        "edge put-file over quota must carry TENANT_QUOTA_EXCEEDED, got: {err}"
    );
    // Nothing charged.
    assert_eq!(
        file_row_count(&pool).await,
        1,
        "edge put-file must not add a row"
    );
}

// ────────────────────────────────────────────────────────────────────
// Task 5 — quota_tier rides the bearer CTE + auth cache. Two properties
// this pins:
//   1. A cache HIT serves the tier captured at fill time (it does NOT
//      re-read meta), so an out-of-band tier bump is INVISIBLE until the
//      tenant's cache entry is evicted.
//   2. Evicting the tenant entry (the hook the T6 approve/PATCH handlers
//      call) makes the raised tier take effect on the very NEXT request —
//      no waiting for the safety TTL.
// The over-quota tenant sits at ~11 GiB; tier 1 caps at 10 GiB (deny),
// tier 2 at 20 GiB (allow), so the same insert flips 507 → 201 exactly
// when the fresh tier is read.
// ────────────────────────────────────────────────────────────────────

/// Create an `items` collection (bare table — inserts accepted) and inflate
/// `_system_files` past the tier-1 cap on `tenant`.
async fn seed_items_over_quota(pool: &SharedTenantPool) {
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )?;
        c.execute(
            "INSERT INTO \"_system_files\" (key, original_name, size_bytes, uploader) \
             VALUES ('quota-filler', 'filler', ?1, 'service')",
            rusqlite::params![OVER_LIMIT_BYTES],
        )
        .map(|_| ())
    })
    .await
    .unwrap();
}

/// Out-of-band `quota_tier` change via a second meta connection — mirrors a
/// raw column flip with NO production handler running, so no invalidation
/// hook fires (the test drives eviction itself).
fn set_tier_out_of_band(dir: &tempfile::TempDir, tenant: &str, tier: i64) {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.execute(
        "UPDATE tenants SET quota_tier = ?2 WHERE id = ?1",
        rusqlite::params![tenant, tier],
    )
    .unwrap();
}

async fn insert_item(app: &axum::Router, tenant: &str, tok: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tenant}/records/items"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"name":"x"}}"#))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn quota_tier_rides_cache_and_eviction_makes_change_immediate() {
    let (app, tok, cache, dir) = helpers::spin_up_tenant_with_role_cached("blog", "service").await;
    let pool = helpers::grab_pool("blog", &dir).await;
    seed_items_over_quota(&pool).await;

    // Request 1 — cache MISS: the CTE reads tier=1 → over the 10 GiB cap → 507.
    // This also WARMS the cache entry (with the tier captured on the CTE).
    assert_eq!(
        insert_item(&app, "blog", &tok).await,
        StatusCode::INSUFFICIENT_STORAGE,
        "tier-1 over-quota insert must 507"
    );
    assert_eq!(cache.misses(), 1, "first request is a cache miss");
    assert_eq!(cache.hits(), 0);

    // Bump the tenant to tier 2 (20 GiB) OUT OF BAND. No handler ran, so no
    // eviction hook fired: the warm cache entry still carries tier=1.
    set_tier_out_of_band(&dir, "blog", 2);

    // Request 2 — cache HIT serves the STALE tier=1 → still 507. Pins that
    // quota_tier rides the cache (a hit does NOT re-read meta for the tier).
    assert_eq!(
        insert_item(&app, "blog", &tok).await,
        StatusCode::INSUFFICIENT_STORAGE,
        "a stale tier-1 cache hit must still 507 (tier rides the cache)"
    );
    assert_eq!(cache.hits(), 1, "second request must be a cache hit");

    // Evict the tenant's cache entry — exactly what the T6 approve/PATCH tier
    // change will do (per-tenant scan-clear, no waiting for the safety TTL).
    cache.clear_tenant("blog");

    // Request 3 — cache MISS: the CTE re-reads tier=2 → 11 GiB < 20 GiB → the
    // insert now succeeds. The raised tier took effect on the next request.
    assert_eq!(
        insert_item(&app, "blog", &tok).await,
        StatusCode::CREATED,
        "after eviction the raised tier takes effect immediately"
    );
}

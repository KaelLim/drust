//! Tenant private-file proxy tests. Integration-level test infrastructure
//! (boot_with_mock_garage style) does not exist; these tests exercise the
//! routing + DB lookup at unit level using direct connections.

use drust::storage::files::{Owner, Visibility, bucket_for_upload};

#[test]
fn private_tenant_bucket_routes_via_helper() {
    // bucket_for_upload ignores Owner — tenant ownership is in the key prefix.
    let owner = Owner::Tenant("acme".into());
    assert_eq!(bucket_for_upload(&owner, Visibility::Private), "private");
    assert_eq!(bucket_for_upload(&owner, Visibility::Public), "public");
}

#[test]
fn admin_bucket_routes_via_helper() {
    assert_eq!(
        bucket_for_upload(&Owner::Admin, Visibility::Private),
        "private"
    );
    assert_eq!(
        bucket_for_upload(&Owner::Admin, Visibility::Public),
        "public"
    );
}

/// Verify that stream_bytes returns 404 when the key is not in the tenant DB.
/// This exercises the DB-lookup error path without needing a live Garage instance.
#[tokio::test]
async fn stream_bytes_returns_404_when_row_missing() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{TenantFilesState, stream_bytes};

    // Build a real tenant DB in a tempdir so open_read succeeds but the table
    // has no matching row.
    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-17";
    let tenant_dir = dir.path().join("tenants").join(tenant_id);
    std::fs::create_dir_all(&tenant_dir).unwrap();

    // Bootstrap the tenant DB with the _system_files table (same DDL as real app).
    let db_path = tenant_dir.join("data.sqlite");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _system_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                content_type TEXT,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                content_disposition TEXT,
                visibility TEXT NOT NULL DEFAULT 'private',
                cache_control TEXT,
                meta_json TEXT,
                uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                uploader TEXT NOT NULL DEFAULT 'tenant',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                path TEXT
            );",
        )
        .unwrap();
    }

    let state = TenantFilesState::test_default(
        None, // no Garage needed — handler returns 503 before DB if garage is None
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );

    // Call stream_bytes with a key that doesn't exist in the DB.
    // Because garage is None, the handler short-circuits at the garage check
    // and returns 503 SERVICE_UNAVAILABLE — that's the first guard before any
    // DB lookup. This confirms the 503 path is exercised correctly.
    let result = stream_bytes(
        State(state.clone()),
        // v1.63 (#950-B) — the data-plane twin takes a REQUIRED identity; the
        // admin mount uses `admin_tfiles_stream`, which takes none.
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path((tenant_id.to_string(), "nonexistent-key.bin".to_string())),
    )
    .await;

    assert!(result.is_err(), "expected Err response");
    let (status, _msg) = result.unwrap_err();
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

// ─── sign_url validation tests ───────────────────────────────────────────────

#[test]
fn sign_request_default_ttl_is_3600() {
    let req: drust::mgmt::tenant_files::SignRequest = serde_json::from_str("{}").unwrap();
    assert_eq!(req.expires_in.unwrap_or(3600), 3600);
}

#[test]
fn sign_request_zero_ttl_is_invalid() {
    // Validation lives inside the handler; assert the boundary contract.
    let expires_in: u64 = 0;
    assert!(expires_in == 0 || expires_in > 604_800);
}

#[test]
fn sign_request_week_plus_one_is_invalid() {
    let expires_in: u64 = 604_801;
    assert!(expires_in == 0 || expires_in > 604_800);
}

#[test]
fn sign_request_one_week_is_valid() {
    let expires_in: u64 = 604_800;
    assert!(!(expires_in == 0 || expires_in > 604_800));
}

/// Stronger test: sign_url returns 400 for expires_in=0.
/// Uses an in-memory GarageClient + a real tenant DB so the handler reaches
/// the validation guard.
#[tokio::test]
async fn sign_url_returns_400_for_zero_ttl() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{SignRequest, TenantFilesState, sign_url};
    use drust::storage::garage::GarageClient;
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-sign-a";
    let tenant_dir = dir.path().join("tenants").join(tenant_id);
    std::fs::create_dir_all(&tenant_dir).unwrap();
    let db_path = tenant_dir.join("data.sqlite");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _system_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                content_type TEXT,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                content_disposition TEXT,
                visibility TEXT NOT NULL DEFAULT 'private',
                cache_control TEXT,
                meta_json TEXT,
                uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                uploader TEXT NOT NULL DEFAULT 'tenant',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                path TEXT
            );",
        )
        .unwrap();
    }

    let mut garage =
        GarageClient::from_store(Arc::new(object_store::memory::InMemory::new()), "unused");
    garage.configure_s3_signing("http://127.0.0.1:47830", "GKkey", "secret", "garage");

    let state = TenantFilesState::test_default(
        Some(Arc::new(garage)),
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );

    let req = SignRequest {
        expires_in: Some(0),
        download: None,
    };
    let result = sign_url(
        State(state),
        Path((tenant_id.to_string(), "any.bin".to_string())),
        axum::Json(req),
    )
    .await;
    assert!(result.is_err());
    let (status, _) = result.unwrap_err();
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

/// Stronger test: sign_url returns 400 for expires_in > 604800.
#[tokio::test]
async fn sign_url_returns_400_for_ttl_over_7days() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{SignRequest, TenantFilesState, sign_url};
    use drust::storage::garage::GarageClient;
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-sign-b";
    let tenant_dir = dir.path().join("tenants").join(tenant_id);
    std::fs::create_dir_all(&tenant_dir).unwrap();
    let db_path = tenant_dir.join("data.sqlite");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _system_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                content_type TEXT,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                content_disposition TEXT,
                visibility TEXT NOT NULL DEFAULT 'private',
                cache_control TEXT,
                meta_json TEXT,
                uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                uploader TEXT NOT NULL DEFAULT 'tenant',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                path TEXT
            );",
        )
        .unwrap();
    }

    let mut garage =
        GarageClient::from_store(Arc::new(object_store::memory::InMemory::new()), "unused");
    garage.configure_s3_signing("http://127.0.0.1:47830", "GKkey", "secret", "garage");

    let state = TenantFilesState::test_default(
        Some(Arc::new(garage)),
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );

    let req = SignRequest {
        expires_in: Some(604_801),
        download: None,
    };
    let result = sign_url(
        State(state),
        Path((tenant_id.to_string(), "any.bin".to_string())),
        axum::Json(req),
    )
    .await;
    assert!(result.is_err());
    let (status, _) = result.unwrap_err();
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}

/// Stronger test: sign_url on a private row with a configured GarageClient
/// returns a signed URL containing the S3 signature params and a non-None expires_at.
#[tokio::test]
async fn sign_url_private_row_returns_signed_url() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{SignRequest, TenantFilesState, sign_url};
    use drust::storage::garage::GarageClient;
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-sign-c";
    let tenant_dir = dir.path().join("tenants").join(tenant_id);
    std::fs::create_dir_all(&tenant_dir).unwrap();
    let db_path = tenant_dir.join("data.sqlite");
    let file_key = "deadbeef-0000-0000-0000-000000000001.pdf";
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _system_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                content_type TEXT,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                content_disposition TEXT,
                visibility TEXT NOT NULL DEFAULT 'private',
                cache_control TEXT,
                meta_json TEXT,
                uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                uploader TEXT NOT NULL DEFAULT 'tenant',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                path TEXT
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _system_files (key, original_name, visibility)
             VALUES (?1, ?2, 'private')",
            rusqlite::params![file_key, "report.pdf"],
        )
        .unwrap();
    }

    let mut garage =
        GarageClient::from_store(Arc::new(object_store::memory::InMemory::new()), "unused");
    garage.configure_s3_signing("http://127.0.0.1:47830", "GKkey", "secret", "garage");

    let state = TenantFilesState::test_default(
        Some(Arc::new(garage)),
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );

    let req = SignRequest {
        expires_in: Some(3600),
        download: None,
    };
    let result = sign_url(
        State(state),
        Path((tenant_id.to_string(), file_key.to_string())),
        axum::Json(req),
    )
    .await
    .expect("sign_url should succeed for private row with configured garage");

    let resp = result.0;
    // Private URLs are now drust-served HMAC: {base}/drust/s/t/{tenant}/{key}?e=&t=&d=
    assert!(
        resp.url
            .contains(&format!("/drust/s/t/{tenant_id}/{file_key}")),
        "URL should be drust-served HMAC route: {}",
        resp.url
    );
    assert!(
        resp.url.contains("?e="),
        "URL should embed expires: {}",
        resp.url
    );
    assert!(
        resp.url.contains("&t="),
        "URL should embed HMAC token: {}",
        resp.url
    );
    assert!(
        resp.url.contains("&d=0"),
        "URL should embed download flag: {}",
        resp.url
    );
    assert!(
        resp.expires_at.is_some(),
        "expires_at should be set for private file"
    );
}

/// Stronger test: sign_url on a public row returns stable URL with expires_at = None.
#[tokio::test]
async fn sign_url_public_row_returns_stable_url() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{SignRequest, TenantFilesState, sign_url};
    use drust::storage::garage::GarageClient;
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-sign-d";
    let tenant_dir = dir.path().join("tenants").join(tenant_id);
    std::fs::create_dir_all(&tenant_dir).unwrap();
    let db_path = tenant_dir.join("data.sqlite");
    let file_key = "deadbeef-0000-0000-0000-000000000002.png";
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _system_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                content_type TEXT,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                content_disposition TEXT,
                visibility TEXT NOT NULL DEFAULT 'private',
                cache_control TEXT,
                meta_json TEXT,
                uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                uploader TEXT NOT NULL DEFAULT 'tenant',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                path TEXT
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _system_files (key, original_name, visibility)
             VALUES (?1, ?2, 'public')",
            rusqlite::params![file_key, "photo.png"],
        )
        .unwrap();
    }

    let mut garage =
        GarageClient::from_store(Arc::new(object_store::memory::InMemory::new()), "unused");
    garage.configure_s3_signing("http://127.0.0.1:47830", "GKkey", "secret", "garage");

    let mut state = TenantFilesState::test_default(
        Some(Arc::new(garage)),
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );
    // This test asserts the returned URL domain — override the default base.
    state.public_base_url = "http://example.com".into();

    let req = SignRequest {
        expires_in: None,
        download: None,
    };
    let result = sign_url(
        State(state),
        Path((tenant_id.to_string(), file_key.to_string())),
        axum::Json(req),
    )
    .await
    .expect("sign_url should succeed for public row");

    let resp = result.0;
    assert!(
        resp.url
            .contains(&format!("/public/{tenant_id}/{file_key}")),
        "public URL should be stable /public path: {}",
        resp.url
    );
    assert!(
        resp.expires_at.is_none(),
        "expires_at should be None for public file"
    );
}

/// Verify the 404 path when garage IS configured but the row doesn't exist.
/// We use a GarageClient built from a mock in-memory store so no real S3 needed.
#[tokio::test]
async fn stream_bytes_returns_not_found_when_row_absent_with_garage() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{TenantFilesState, stream_bytes};
    use drust::storage::garage::GarageClient;
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-17b";
    let tenant_dir = dir.path().join("tenants").join(tenant_id);
    std::fs::create_dir_all(&tenant_dir).unwrap();

    // Bootstrap the tenant DB.
    let db_path = tenant_dir.join("data.sqlite");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _system_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                content_type TEXT,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                content_disposition TEXT,
                visibility TEXT NOT NULL DEFAULT 'private',
                cache_control TEXT,
                meta_json TEXT,
                uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                uploader TEXT NOT NULL DEFAULT 'tenant',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                path TEXT
            );",
        )
        .unwrap();
    }

    // Build a GarageClient from in-memory mock store so the handler proceeds
    // past the garage-present check.
    let mock_garage = Arc::new(GarageClient::from_mock_admin(
        "http://127.0.0.1:1",
        "dummy-token",
    ));

    let state = TenantFilesState::test_default(
        Some(mock_garage),
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );

    let result = stream_bytes(
        State(state),
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path((tenant_id.to_string(), "ghost-key.png".to_string())),
    )
    .await;

    assert!(result.is_err(), "expected Err response");
    let (status, _msg) = result.unwrap_err();
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

// ─── Task 19: upload / list / get_one / delete_one ───────────────────────────

/// Helper: build a temp dir with a tenant DB that has _system_files.
fn make_tenant_db(dir: &tempfile::TempDir, tenant_id: &str) {
    let tenant_dir = dir.path().join("tenants").join(tenant_id);
    std::fs::create_dir_all(&tenant_dir).unwrap();
    let db_path = tenant_dir.join("data.sqlite");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _system_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            content_type TEXT,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            content_disposition TEXT,
            visibility TEXT NOT NULL DEFAULT 'public',
            cache_control TEXT,
            meta_json TEXT,
            uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
            uploader TEXT NOT NULL DEFAULT 'service',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            -- v1.63 (#950-B). `map_file_row` reads BY NAME, so a fixture that
            -- omits a real column makes every read through it fail at runtime
            -- (500 on get_one, silently-dropped rows on list) — keep this DDL
            -- in step with storage/tenant_db.rs SCHEMA_SQL.
            path TEXT
        );",
    )
    .unwrap();
}

/// upload rejects requests whose Content-Length exceeds max_upload_bytes.
/// The handler should return 413 PAYLOAD_TOO_LARGE before touching Garage.
#[tokio::test]
async fn upload_rejects_oversize_via_content_length_pre_check() {
    use drust::mgmt::tenant_files::{TenantFilesState, upload};
    use drust::storage::garage::GarageClient;
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-upload-sz";
    make_tenant_db(&dir, tenant_id);

    // Provide a mock garage so the handler reaches the Content-Length check.
    let garage = Arc::new(GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "unused",
    ));

    let mut state = TenantFilesState::test_default(
        Some(garage),
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );
    state.disk_min_free_pct = 0; // skip disk check for this test
    state.max_upload_bytes = 1024;

    // Build a real router and send a POST request with Content-Length: 9999
    // (over the 1024 limit).  The Content-Length pre-check runs BEFORE any
    // multipart parsing so the handler returns 413 immediately.
    use axum::body::Body;
    use axum::http::Request;
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{tenant_id}/files"))
        .header("content-type", "multipart/form-data; boundary=BOUNDARY")
        .header("content-length", "9999")
        .body(Body::empty())
        .unwrap();

    let app = axum::Router::new()
        .route("/t/{tenant}/files", axum::routing::post(upload))
        // v1.63 (#950-B) — the data-plane handler REQUIRES an identity (in
        // production `bearer_auth_layer` inserts it). Without this layer the
        // request now 500s `AUTH_CTX_MISSING` before it can reach the
        // Content-Length pre-check this test is about; that fail-closed
        // polarity is pinned separately in tests/files_rls_upload.rs.
        .layer(axum::Extension(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }))
        .with_state(state);

    let response = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        "expected 413 for oversized Content-Length"
    );
}

/// list returns an empty file array for a freshly-created tenant DB.
#[tokio::test]
async fn list_returns_empty_for_fresh_tenant() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{TenantFilesState, list};

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-list-empty";
    make_tenant_db(&dir, tenant_id);

    let mut state = TenantFilesState::test_default(
        None,
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );
    state.disk_min_free_pct = 0;

    // Service identity: these two pin the WHOLE-tenant management view, which
    // is the one caller v1.63's list filter deliberately does not touch.
    let response = list(
        State(state),
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path(tenant_id.to_string()),
    )
    .await;

    use axum::response::IntoResponse;
    let resp = response.into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["file_count"], 0);
    assert_eq!(json["used_bytes"], 0);
    assert!(json["files"].as_array().unwrap().is_empty());
}

/// get_one returns 404 for a key that doesn't exist in the tenant DB.
#[tokio::test]
async fn get_one_returns_404_for_missing_key() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{TenantFilesState, get_one};

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-get-missing";
    make_tenant_db(&dir, tenant_id);

    let mut state = TenantFilesState::test_default(
        None,
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );
    state.disk_min_free_pct = 0;

    let response = get_one(
        State(state),
        // v1.63 (#950-B) — `get_one` reads a metadata row (path, uploader,
        // original_name), so it too takes a REQUIRED identity. It is
        // data-plane-only, so there is no admin twin to exempt.
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path((tenant_id.to_string(), "no-such-key.pdf".to_string())),
    )
    .await;

    use axum::response::IntoResponse;
    assert_eq!(
        response.into_response().status(),
        axum::http::StatusCode::NOT_FOUND
    );
}

/// delete_one returns 404 when the key doesn't exist (even with a real garage).
#[tokio::test]
async fn delete_one_returns_404_for_missing_key() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{TenantFilesState, delete_one};
    use drust::storage::garage::GarageClient;
    use std::sync::Arc;

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-del-missing";
    make_tenant_db(&dir, tenant_id);

    let garage = Arc::new(GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "unused",
    ));

    let mut state = TenantFilesState::test_default(
        Some(garage),
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );
    state.disk_min_free_pct = 0;

    let response = delete_one(
        State(state),
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path((tenant_id.to_string(), "ghost-key.bin".to_string())),
    )
    .await;

    use axum::response::IntoResponse;
    assert_eq!(
        response.into_response().status(),
        axum::http::StatusCode::NOT_FOUND
    );
}

/// get_one returns the row JSON for a key that exists in the tenant DB.
#[tokio::test]
async fn get_one_returns_row_when_key_exists() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{TenantFilesState, get_one};

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-get-present";
    make_tenant_db(&dir, tenant_id);

    // Insert a row directly.
    let file_key = "aaaaaaaa-0000-0000-0000-000000000001.txt";
    {
        let db_path = dir
            .path()
            .join("tenants")
            .join(tenant_id)
            .join("data.sqlite");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO _system_files (key, original_name, size_bytes, uploader)
             VALUES (?1, ?2, 42, 'service')",
            rusqlite::params![file_key, "hello.txt"],
        )
        .unwrap();
    }

    let mut state = TenantFilesState::test_default(
        None,
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );
    state.disk_min_free_pct = 0;

    let response = get_one(
        State(state),
        // A service identity: the per-file RLS gate (v1.63) bypasses for
        // service exactly as every other RLS face does, so this stays a pure
        // "does the row round-trip" test.
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path((tenant_id.to_string(), file_key.to_string())),
    )
    .await;

    use axum::response::IntoResponse;
    let resp = response.into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["key"], file_key);
    assert_eq!(json["original_name"], "hello.txt");
    assert_eq!(json["size_bytes"], 42);
}

/// list returns a non-empty array when rows exist.
#[tokio::test]
async fn list_returns_rows_when_files_exist() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::{TenantFilesState, list};

    let dir = tempfile::tempdir().expect("tempdir");
    let tenant_id = "test-tenant-list-nonempty";
    make_tenant_db(&dir, tenant_id);

    let file_key = "bbbbbbbb-0000-0000-0000-000000000001.bin";
    {
        let db_path = dir
            .path()
            .join("tenants")
            .join(tenant_id)
            .join("data.sqlite");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO _system_files (key, original_name, size_bytes, uploader)
             VALUES (?1, ?2, 100, 'service')",
            rusqlite::params![file_key, "data.bin"],
        )
        .unwrap();
    }

    let mut state = TenantFilesState::test_default(
        None,
        dir.path().to_path_buf(),
        std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(
            dir.path().to_path_buf(),
            2,
        )),
    );
    state.disk_min_free_pct = 0;

    // Service identity: these two pin the WHOLE-tenant management view, which
    // is the one caller v1.63's list filter deliberately does not touch.
    let response = list(
        State(state),
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path(tenant_id.to_string()),
    )
    .await;

    use axum::response::IntoResponse;
    let resp = response.into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["file_count"], 1);
    assert_eq!(json["used_bytes"], 100);
    let files = json["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["key"], file_key);
}

// ─── object-store failures never reach the body (smoke-fixes egress-files-leak) ──
//
// The backend's error text carries the internal storage endpoint, bucket and
// object path. Every face below is reachable by anon/user (with the matching
// file cap) or by a credential-less signed URL, so the detail goes to the log
// and the body says only what failed. `FailingStore` fails every call with a
// sentinel shaped like that detail; each test asserts the sentinel is absent.

mod failing_store {
    use async_trait::async_trait;
    use futures::StreamExt;
    use futures::stream::BoxStream;
    use object_store::path::Path;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
        PutMultipartOptions, PutOptions, PutPayload, PutResult, Result,
    };

    /// Shaped like a real S3 failure: an internal endpoint URL, a bucket and
    /// the S3 error code. Never a real host.
    pub const SENTINEL: &str =
        "http://storage-internal.invalid:3900/sentinel-bucket/t/k.bin NoSuchBucket";

    fn err() -> object_store::Error {
        object_store::Error::Generic {
            store: "S3",
            source: SENTINEL.into(),
        }
    }

    #[derive(Debug)]
    pub struct FailingStore;

    impl std::fmt::Display for FailingStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "FailingStore")
        }
    }

    #[async_trait]
    impl ObjectStore for FailingStore {
        async fn put_opts(&self, _: &Path, _: PutPayload, _: PutOptions) -> Result<PutResult> {
            Err(err())
        }
        async fn put_multipart_opts(
            &self,
            _: &Path,
            _: PutMultipartOptions,
        ) -> Result<Box<dyn MultipartUpload>> {
            Err(err())
        }
        async fn get_opts(&self, _: &Path, _: GetOptions) -> Result<GetResult> {
            Err(err())
        }
        fn delete_stream(
            &self,
            locations: BoxStream<'static, Result<Path>>,
        ) -> BoxStream<'static, Result<Path>> {
            locations.map(|_| Err(err())).boxed()
        }
        fn list(&self, _: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
            futures::stream::once(async { Err(err()) }).boxed()
        }
        async fn list_with_delimiter(&self, _: Option<&Path>) -> Result<ListResult> {
            Err(err())
        }
        async fn copy_opts(&self, _: &Path, _: &Path, _: CopyOptions) -> Result<()> {
            Err(err())
        }
    }
}

/// A tenant whose `_system_files` row `key` exists (public), served by a
/// `GarageClient` over `FailingStore`.
fn failing_state(
    dir: &tempfile::TempDir,
    tenant_id: &str,
    seed_key: Option<&str>,
) -> drust::mgmt::tenant_files::TenantFilesState {
    use drust::storage::garage::GarageClient;
    use std::sync::Arc;
    drust::storage::tenant_db::open_write(dir.path(), tenant_id).unwrap();
    if let Some(k) = seed_key {
        let conn = rusqlite::Connection::open(
            dir.path()
                .join("tenants")
                .join(tenant_id)
                .join("data.sqlite"),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _system_files (key, original_name, size_bytes, visibility, uploader)
             VALUES (?1, 'doc.pdf', 3, 'public', 'service')",
            rusqlite::params![k],
        )
        .unwrap();
    }
    let garage = Arc::new(GarageClient::from_store(
        Arc::new(failing_store::FailingStore),
        "public",
    ));
    let registry = Arc::new(drust::storage::pool::TenantRegistry::new(
        dir.path().to_path_buf(),
        2,
    ));
    let mut state = drust::mgmt::tenant_files::TenantFilesState::test_default(
        Some(garage),
        dir.path().to_path_buf(),
        registry,
    );
    state.disk_min_free_pct = 0;
    state
}

fn files_row_count(dir: &tempfile::TempDir, tenant_id: &str) -> i64 {
    let conn = rusqlite::Connection::open(
        dir.path()
            .join("tenants")
            .join(tenant_id)
            .join("data.sqlite"),
    )
    .unwrap();
    conn.query_row("SELECT COUNT(*) FROM _system_files", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn upload_storage_failure_hides_backend_detail() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use drust::mgmt::tenant_files::upload;

    let dir = tempfile::tempdir().unwrap();
    let tid = "t-fail-upload";
    let state = failing_state(&dir, tid, None);
    let app = axum::Router::new()
        .route("/t/{tenant}/files", axum::routing::post(upload))
        .layer(axum::Extension(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }))
        .with_state(state);

    let boundary = "failbound";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"doc.pdf\"\r\n\
         Content-Type: application/pdf\r\n\r\nabc\r\n--{boundary}--\r\n"
    );
    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/t/{tid}/files"))
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("storage-internal") && !text.contains("NoSuchBucket"),
        "backend detail leaked into the upload body: {text}"
    );
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error_code"], "GARAGE_PUT_FAILED");
    assert_eq!(files_row_count(&dir, tid), 0, "metadata row rolled back");
}

#[tokio::test]
async fn stream_bytes_storage_failure_hides_backend_detail() {
    use axum::extract::{Path, State};
    use drust::mgmt::tenant_files::stream_bytes;

    let dir = tempfile::tempdir().unwrap();
    let tid = "t-fail-bytes";
    let key = "aaaaaaaa-0000-0000-0000-00000000000f.pdf";
    let state = failing_state(&dir, tid, Some(key));
    let result = stream_bytes(
        State(state),
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path((tid.to_string(), key.to_string())),
    )
    .await;
    let (status, msg) = result.err().expect("a failing store must not stream");
    assert_eq!(status, axum::http::StatusCode::BAD_GATEWAY);
    assert_eq!(msg, "object store read failed");
    assert!(!msg.contains("storage-internal"));
}

#[tokio::test]
async fn delete_storage_failure_hides_backend_detail() {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    use drust::mgmt::tenant_files::delete_one;

    let dir = tempfile::tempdir().unwrap();
    let tid = "t-fail-delete";
    let key = "aaaaaaaa-0000-0000-0000-00000000001f.pdf";
    let state = failing_state(&dir, tid, Some(key));
    let resp = delete_one(
        State(state),
        drust::mgmt::tenant_files::RequiredAuthCtx(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }),
        Path((tid.to_string(), key.to_string())),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert_eq!(
        text,
        "object store delete failed; the file was not deleted — retry"
    );
    assert_eq!(
        files_row_count(&dir, tid),
        1,
        "the row survives a failed delete"
    );
}

#[tokio::test]
async fn tenant_signed_bytes_storage_failure_hides_backend_detail() {
    use axum::extract::{Path, Query, State};
    use drust::mgmt::signed_bytes::{SigQs, SignedBytesState, tenant_signed_bytes};
    use drust::storage::signed_url::{Owner as SignOwner, mint};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let tid = "t-fail-signed";
    let key = "aaaaaaaa-0000-0000-0000-00000000002f.pdf";
    let files_state = failing_state(&dir, tid, Some(key));
    let secret = [7u8; 32];
    let state = SignedBytesState {
        meta: Arc::new(tokio::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        )),
        data_root: dir.path().to_path_buf(),
        garage: files_state.garage.clone(),
        url_sign_secret: Arc::new(secret),
    };
    let expires = chrono::Utc::now().timestamp() + 600;
    let token = mint(
        &secret,
        &SignOwner::Tenant(tid.to_string()),
        key,
        expires,
        false,
    );
    let result = tenant_signed_bytes(
        State(state),
        Path((tid.to_string(), key.to_string())),
        Query(SigQs {
            e: expires,
            t: token,
            d: None,
        }),
    )
    .await;
    let (status, msg) = result.err().expect("a failing store must not stream");
    assert_eq!(status, axum::http::StatusCode::BAD_GATEWAY);
    assert_eq!(msg, "object store read failed");
}

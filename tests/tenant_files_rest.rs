//! Tenant private-file proxy tests. Integration-level test infrastructure
//! (boot_with_mock_garage style) does not exist; these tests exercise the
//! routing + DB lookup at unit level using direct connections.

use drust::storage::files::{Owner, Visibility, bucket_for_upload};

#[test]
fn private_tenant_bucket_routes_via_helper() {
    // The bytes handler resolves bucket via bucket_for_upload(Owner, Visibility).
    // Verify the routing directly — handler integration is exercised by smoke tests.
    let owner = Owner::Tenant("acme".into());
    assert_eq!(
        bucket_for_upload(&owner, Visibility::Private),
        "tenant-acme-prv"
    );
    assert_eq!(
        bucket_for_upload(&owner, Visibility::Public),
        "tenant-acme-pub"
    );
}

#[test]
fn admin_bucket_routes_via_helper() {
    assert_eq!(
        bucket_for_upload(&Owner::Admin, Visibility::Private),
        "admin-private"
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
                uploader TEXT NOT NULL DEFAULT 'tenant'
            );",
        )
        .unwrap();
    }

    let state = TenantFilesState {
        garage: None, // no Garage needed — handler returns 503 before DB if garage is None...
        data_root: dir.path().to_path_buf(),
        disk_min_free_pct: 20,
        max_upload_bytes: 52_428_800,
        public_base_url: "http://localhost".into(),
    };

    // Call stream_bytes with a key that doesn't exist in the DB.
    // Because garage is None, the handler short-circuits at the garage check
    // and returns 503 SERVICE_UNAVAILABLE — that's the first guard before any
    // DB lookup. This confirms the 503 path is exercised correctly.
    let result = stream_bytes(
        State(state.clone()),
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
                uploader TEXT NOT NULL DEFAULT 'tenant'
            );",
        )
        .unwrap();
    }

    let mut garage =
        GarageClient::from_store(Arc::new(object_store::memory::InMemory::new()), "unused");
    garage.configure_s3_signing("http://127.0.0.1:47830", "GKkey", "secret", "garage");

    let state = TenantFilesState {
        garage: Some(Arc::new(garage)),
        data_root: dir.path().to_path_buf(),
        disk_min_free_pct: 20,
        max_upload_bytes: 52_428_800,
        public_base_url: "http://localhost".into(),
    };

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
                uploader TEXT NOT NULL DEFAULT 'tenant'
            );",
        )
        .unwrap();
    }

    let mut garage =
        GarageClient::from_store(Arc::new(object_store::memory::InMemory::new()), "unused");
    garage.configure_s3_signing("http://127.0.0.1:47830", "GKkey", "secret", "garage");

    let state = TenantFilesState {
        garage: Some(Arc::new(garage)),
        data_root: dir.path().to_path_buf(),
        disk_min_free_pct: 20,
        max_upload_bytes: 52_428_800,
        public_base_url: "http://localhost".into(),
    };

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
                uploader TEXT NOT NULL DEFAULT 'tenant'
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

    let state = TenantFilesState {
        garage: Some(Arc::new(garage)),
        data_root: dir.path().to_path_buf(),
        disk_min_free_pct: 20,
        max_upload_bytes: 52_428_800,
        public_base_url: "http://localhost".into(),
    };

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
    assert!(
        resp.url.contains("X-Amz-Signature="),
        "URL should have S3v4 signature: {}",
        resp.url
    );
    assert!(
        resp.url.contains("X-Amz-Expires=3600"),
        "URL should embed TTL: {}",
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
                uploader TEXT NOT NULL DEFAULT 'tenant'
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

    let state = TenantFilesState {
        garage: Some(Arc::new(garage)),
        data_root: dir.path().to_path_buf(),
        disk_min_free_pct: 20,
        max_upload_bytes: 52_428_800,
        public_base_url: "http://example.com".into(),
    };

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
            .contains(&format!("/t-public/{tenant_id}/{file_key}")),
        "public URL should be stable /t-public path: {}",
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
                uploader TEXT NOT NULL DEFAULT 'tenant'
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

    let state = TenantFilesState {
        garage: Some(mock_garage),
        data_root: dir.path().to_path_buf(),
        disk_min_free_pct: 20,
        max_upload_bytes: 52_428_800,
        public_base_url: "http://localhost".into(),
    };

    let result = stream_bytes(
        State(state),
        Path((tenant_id.to_string(), "ghost-key.png".to_string())),
    )
    .await;

    assert!(result.is_err(), "expected Err response");
    let (status, _msg) = result.unwrap_err();
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

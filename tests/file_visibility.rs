//! Tests for in-place file visibility toggle (public <-> private).
//!
//! Core: `drust::storage::visibility::change_visibility` moves the Garage
//! object between the `public`/`private` buckets and updates the
//! `_system_files` row. Uses a `from_store` GarageClient (empty s3_endpoint)
//! backed by an in-memory object store, which — via the test affordance added
//! to put/get/delete_object_in — namespaces objects by `<bucket>/<key>` so the
//! two buckets are distinguishable.

use drust::storage::files::{Owner, Visibility, compose_key};
use drust::storage::garage::GarageClient;
use drust::storage::pool::TenantRegistry;
use drust::storage::visibility::{VisibilityOutcome, change_visibility};
use std::sync::Arc;

fn mem_garage() -> Arc<GarageClient> {
    Arc::new(GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "unused",
    ))
}

/// Build a temp dir with a tenant data.sqlite carrying _system_files, and
/// return an open pool for it via the registry.
fn make_tenant(
    dir: &tempfile::TempDir,
    tenant_id: &str,
) -> drust::storage::pool::SharedTenantPool {
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
            uploader TEXT NOT NULL DEFAULT 'service'
        );",
    )
    .unwrap();
    drop(conn);
    let reg = TenantRegistry::new(dir.path().to_path_buf(), 2);
    reg.get_or_open(tenant_id).unwrap()
}

async fn insert_row(pool: &drust::storage::pool::SharedTenantPool, key: &str, vis: &str) {
    let key = key.to_string();
    let vis = vis.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_files
                (key, original_name, content_type, size_bytes, content_disposition,
                 visibility, cache_control, uploader)
             VALUES (?1, 'hello.txt', 'text/plain', 5, 'inline', ?2, ?3, 'service')",
            rusqlite::params![
                key,
                vis,
                if vis == "public" {
                    "public, max-age=86400"
                } else {
                    "private, no-store"
                }
            ],
        )
        .map(|_| ())
    })
    .await
    .unwrap();
}

async fn read_vis_cc(pool: &drust::storage::pool::SharedTenantPool, key: &str) -> (String, String) {
    let key = key.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT visibility, COALESCE(cache_control,'') FROM _system_files WHERE key=?1",
            rusqlite::params![key],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
    })
    .await
    .unwrap()
}

/// Affordance: put/get/delete_object_in route to the in-memory store for a
/// from_store client and namespace by bucket so public != private.
#[tokio::test]
async fn garage_object_methods_distinguish_buckets_in_memory() {
    let garage = mem_garage();
    let key = "acme/file-1.txt";
    garage
        .put_object_in(
            "public",
            key,
            bytes::Bytes::from_static(b"hello"),
            Some("text/plain"),
            "inline",
            "file-1.txt",
            Some("public, max-age=86400"),
            None,
        )
        .await
        .unwrap();

    // Present in public, absent in private.
    let got = garage.get_object_bytes_in("public", key).await.unwrap();
    assert_eq!(&got[..], b"hello");
    assert!(garage.get_object_bytes_in("private", key).await.is_err());

    // Delete is idempotent and bucket-scoped.
    garage.delete_object_in("public", key).await.unwrap();
    assert!(garage.get_object_bytes_in("public", key).await.is_err());
    garage.delete_object_in("public", key).await.unwrap(); // idempotent
}

#[tokio::test]
async fn change_public_to_private_moves_bucket_and_updates_row() {
    let dir = tempfile::tempdir().unwrap();
    let tenant_id = "tnt-vis-1";
    let pool = make_tenant(&dir, tenant_id);
    let garage = mem_garage();
    let key = "ffffffff-0000-0000-0000-000000000001.txt";
    let object_key = compose_key(&Owner::Tenant(tenant_id.to_string()), key);

    // Seed: object in public bucket + public row.
    garage
        .put_object_in(
            "public",
            &object_key,
            bytes::Bytes::from_static(b"hello"),
            Some("text/plain"),
            "inline",
            "hello.txt",
            Some("public, max-age=86400"),
            None,
        )
        .await
        .unwrap();
    insert_row(&pool, key, "public").await;

    let outcome = change_visibility(&garage, &pool, tenant_id, key, Visibility::Private)
        .await
        .unwrap();
    assert!(matches!(outcome, VisibilityOutcome::Changed { .. }));

    // Row flipped + cache_control reset to private default.
    let (vis, cc) = read_vis_cc(&pool, key).await;
    assert_eq!(vis, "private");
    assert_eq!(cc, "private, no-store");

    // Object physically moved: in private, gone from public.
    let moved = garage.get_object_bytes_in("private", &object_key).await.unwrap();
    assert_eq!(&moved[..], b"hello");
    assert!(garage.get_object_bytes_in("public", &object_key).await.is_err());
}

#[tokio::test]
async fn change_noop_when_target_equals_current() {
    let dir = tempfile::tempdir().unwrap();
    let tenant_id = "tnt-vis-2";
    let pool = make_tenant(&dir, tenant_id);
    let garage = mem_garage();
    let key = "ffffffff-0000-0000-0000-000000000002.txt";
    insert_row(&pool, key, "public").await;

    let outcome = change_visibility(&garage, &pool, tenant_id, key, Visibility::Public)
        .await
        .unwrap();
    assert!(matches!(outcome, VisibilityOutcome::NoOp));
    // Row unchanged.
    let (vis, _) = read_vis_cc(&pool, key).await;
    assert_eq!(vis, "public");
}

#[tokio::test]
async fn change_not_found_for_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let tenant_id = "tnt-vis-3";
    let pool = make_tenant(&dir, tenant_id);
    let garage = mem_garage();

    let outcome = change_visibility(&garage, &pool, tenant_id, "ghost.txt", Visibility::Private)
        .await
        .unwrap();
    assert!(matches!(outcome, VisibilityOutcome::NotFound));
}

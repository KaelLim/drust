mod common;
use common::mock_garage_admin::MockAdminServer;
use drust::storage::garage::GarageClient;
use drust::storage::meta::open_meta;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

#[tokio::test]
async fn tenant_create_provisions_two_buckets_with_grants() {
    let mock = MockAdminServer::start().await;
    let garage = GarageClient::from_mock_admin(&mock.base_url(), "admin-token");
    let client_key = "GKdrustclient";

    drust::mgmt::tenants::provision_storage_for_tenant(&garage, client_key, "foo")
        .await
        .unwrap();

    let reqs = mock.requests();
    // Exactly 2 create_bucket calls
    assert_eq!(
        reqs.iter()
            .filter(|r| r.path == "/v1/bucket" && r.method == "POST")
            .count(),
        2,
        "two create_bucket: {reqs:?}"
    );
    // Exactly 1 website call (pub only)
    assert_eq!(
        reqs.iter().filter(|r| r.path.ends_with("/website")).count(),
        1,
        "one set_website"
    );
    // Exactly 2 allow calls (one per bucket)
    assert_eq!(
        reqs.iter().filter(|r| r.path == "/v1/bucket/allow").count(),
        2,
        "two bucket_allow"
    );
}

#[tokio::test]
async fn tenant_create_errors_when_first_call_fails() {
    let mock = MockAdminServer::start().await;
    let garage = GarageClient::from_mock_admin(&mock.base_url(), "admin-token");
    mock.fail_next_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    let res =
        drust::mgmt::tenants::provision_storage_for_tenant(&garage, "GKkey", "foo-fail").await;
    assert!(res.is_err(), "must propagate error from first failing call");
    // When the FIRST call (lookup_bucket for pub) fails, nothing was created —
    // no compensating deletes. The only call should be the failed one.
    assert_eq!(mock.requests().len(), 1, "only one call made before error");
}

struct SoftDeleteHarness {
    _tmp: TempDir,
    meta: Arc<Mutex<rusqlite::Connection>>,
    garage: GarageClient,
    mock: MockAdminServer,
}

async fn setup_soft_delete() -> SoftDeleteHarness {
    let tmp = TempDir::new().unwrap();
    let meta_path = tmp.path().join("meta.sqlite");
    let meta = Arc::new(Mutex::new(open_meta(&meta_path).unwrap()));
    let mock = MockAdminServer::start().await;
    let garage = GarageClient::from_mock_admin(&mock.base_url(), "admin-token");
    SoftDeleteHarness {
        _tmp: tmp,
        meta,
        garage,
        mock,
    }
}

#[tokio::test]
async fn tenant_soft_delete_revokes_access_and_disables_website() {
    let h = setup_soft_delete().await;
    h.mock.seed_bucket("tenant-demo-pub", "bkt-pub-1");
    h.mock.seed_bucket("tenant-demo-prv", "bkt-prv-1");
    h.mock.clear_requests();

    drust::mgmt::tenants::soft_delete_storage_for_tenant(&h.garage, &h.meta, "GKkey", "demo")
        .await
        .unwrap();

    let reqs = h.mock.requests();
    assert_eq!(
        reqs.iter().filter(|r| r.path == "/v1/bucket/deny").count(),
        2,
        "deny called for both buckets"
    );
    assert!(
        reqs.iter()
            .any(|r| r.path.ends_with("/website") && r.body.contains("\"enabled\":false")),
        "website disabled on pub bucket"
    );
}

#[tokio::test]
async fn tenant_soft_delete_queues_pending_when_garage_fails() {
    let h = setup_soft_delete().await;
    h.mock.seed_bucket("tenant-stuck-pub", "bkt-pub-2");
    h.mock.seed_bucket("tenant-stuck-prv", "bkt-prv-2");
    h.mock.clear_requests();
    // Force the FIRST call (lookup pub) to fail, propagating up to our queue logic.
    h.mock
        .fail_next_with(axum::http::StatusCode::SERVICE_UNAVAILABLE);

    // Soft-delete must succeed locally even when Garage fails.
    drust::mgmt::tenants::soft_delete_storage_for_tenant(&h.garage, &h.meta, "GKkey", "stuck")
        .await
        .unwrap();

    let pending: i64 = {
        let conn = h.meta.lock().await;
        conn.query_row(
            "SELECT COUNT(*) FROM _trash_pending_revokes WHERE tenant_id='stuck'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(pending, 1, "pending revoke row inserted");
}

#[tokio::test]
async fn tenant_restore_regrants_and_reenables_website() {
    let h = setup_soft_delete().await;
    h.mock.seed_bucket("tenant-back-pub", "bkt-back-pub");
    h.mock.seed_bucket("tenant-back-prv", "bkt-back-prv");
    // Pre-populate a stale pending-revoke row so the test can assert it's cleared.
    h.meta.lock().await.execute(
        "INSERT INTO _trash_pending_revokes (tenant_id, detected_at) VALUES ('back', datetime('now'))",
        []
    ).unwrap();
    h.mock.clear_requests();

    drust::mgmt::tenants::restore_storage_for_tenant(&h.garage, &h.meta, "GKkey", "back")
        .await
        .unwrap();

    let reqs = h.mock.requests();
    assert_eq!(
        reqs.iter().filter(|r| r.path == "/v1/bucket/allow").count(),
        2,
        "two bucket_allow calls"
    );
    assert!(
        reqs.iter()
            .any(|r| r.path.ends_with("/website") && r.body.contains("\"enabled\":true")),
        "website re-enabled on pub"
    );

    let pending: i64 = h
        .meta
        .lock()
        .await
        .query_row(
            "SELECT COUNT(*) FROM _trash_pending_revokes WHERE tenant_id='back'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0, "pending row cleared on restore");
}

#[tokio::test]
async fn tenant_restore_errors_when_garage_unreachable() {
    let h = setup_soft_delete().await;
    h.mock.seed_bucket("tenant-err-pub", "bkt-err-pub");
    // Force the very first call (lookup_bucket pub) to fail.
    h.mock
        .fail_next_with(axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    let res =
        drust::mgmt::tenants::restore_storage_for_tenant(&h.garage, &h.meta, "GKkey", "err").await;
    assert!(
        res.is_err(),
        "restore must propagate Garage failure (not silently queue like soft-delete)"
    );
}

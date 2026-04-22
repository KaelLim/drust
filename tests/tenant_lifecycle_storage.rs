mod common;
use common::mock_garage_admin::MockAdminServer;
use drust::storage::garage::GarageClient;

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

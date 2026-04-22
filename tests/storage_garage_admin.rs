mod common;
use common::mock_garage_admin::MockAdminServer;
use drust::storage::garage::GarageClient;

#[tokio::test]
async fn garage_client_can_reach_mock_admin_server() {
    let srv = MockAdminServer::start().await;
    let body = reqwest::Client::new()
        .get(format!("{}/v1/status", srv.base_url()))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(body.status(), 200);
    assert_eq!(srv.requests().len(), 1);
}

#[tokio::test]
async fn create_bucket_posts_global_alias_payload() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "admin-token");

    let id = c.create_bucket("tenant-foo-pub").await.unwrap();
    assert_eq!(id, "bkt-1");

    let reqs = srv.requests();
    let last = reqs.last().unwrap();
    assert_eq!(last.method, "POST");
    assert_eq!(last.path, "/v1/bucket");
    assert!(last.body.contains("tenant-foo-pub"), "body: {}", last.body);
    assert_eq!(last.auth.as_deref(), Some("Bearer admin-token"));
}

#[tokio::test]
async fn create_bucket_propagates_admin_error() {
    let srv = MockAdminServer::start().await;
    srv.fail_next_with(axum::http::StatusCode::CONFLICT);
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");

    let err = c.create_bucket("x").await.unwrap_err();
    assert!(err.to_string().contains("409"));
}

#[tokio::test]
async fn lookup_bucket_returns_id_when_present() {
    let srv = MockAdminServer::start().await;
    srv.seed_bucket("public", "bkt-existing");
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");

    let info = c.lookup_bucket("public").await.unwrap();
    assert_eq!(info.unwrap().id, "bkt-existing");
}

#[tokio::test]
async fn lookup_bucket_returns_none_on_404() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");
    let info = c.lookup_bucket("nonexistent").await.unwrap();
    assert!(info.is_none());
}

#[tokio::test]
async fn delete_bucket_sends_id_query() {
    let srv = MockAdminServer::start().await;
    let c = GarageClient::from_mock_admin(&srv.base_url(), "t");
    c.delete_bucket("bkt-123").await.unwrap();

    let last = srv.requests().last().unwrap().clone();
    assert_eq!(last.method, "DELETE");
    assert_eq!(last.path, "/v1/bucket");
    assert!(last.query.contains("id=bkt-123"));
}

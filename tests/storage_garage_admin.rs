mod common;
use common::mock_garage_admin::MockAdminServer;

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

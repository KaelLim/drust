use drust_cli::client::http::DrustClient;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn get_sends_bearer_and_parses_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/t/9f/collections"))
        .and(header("authorization", "Bearer drust_pat_cli_x"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"collections":[]})),
        )
        .mount(&server)
        .await;

    let c = DrustClient::new(server.uri(), "drust_pat_cli_x");
    let v = c.get("/t/9f/collections").await.unwrap();
    assert_eq!(v["collections"], serde_json::json!([]));
}

#[tokio::test]
async fn non_2xx_becomes_apierror() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/t/9f/collections"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error_code":"WRITE_DENIED","message":"nope"})))
        .mount(&server)
        .await;
    let c = DrustClient::new(server.uri(), "tok");
    let e = c.get("/t/9f/collections").await.unwrap_err();
    assert_eq!(e.error_code, "WRITE_DENIED");
    assert_eq!(e.exit_code(), 1);
}

/// Matches a request that carries NO Authorization header (device-flow unauth POST).
struct NoAuthHeader;
impl wiremock::Match for NoAuthHeader {
    fn matches(&self, request: &wiremock::Request) -> bool {
        request.headers.get("authorization").is_none()
    }
}

#[tokio::test]
async fn post_unauth_sends_no_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/cli/device/start"))
        .and(NoAuthHeader)
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"device_code":"d"})),
        )
        .mount(&server)
        .await;
    // anonymous() carries no token; post_unauth never adds the Authorization header.
    let c = DrustClient::anonymous(server.uri());
    let v = c
        .post_unauth(
            "/auth/cli/device/start",
            serde_json::json!({"client_name":"lappy"}),
        )
        .await
        .unwrap();
    assert_eq!(v["device_code"], "d");
}

#[tokio::test]
async fn restore_redirect_capture() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/admin/backups/x.tar.zst/restore"))
        .respond_with(ResponseTemplate::new(303).insert_header(
            "location",
            "/drust/admin/backups/x/inspect?restored=9f&dest=%2Ftrash",
        ))
        .mount(&server)
        .await;
    let c = DrustClient::new(server.uri(), "tok");
    let info = c
        .post_form_capture_redirect("/admin/backups/x.tar.zst/restore", &[("tenant_id", "9f")])
        .await
        .unwrap();
    assert_eq!(info.status, 303);
    assert!(info.location.contains("dest="));
}

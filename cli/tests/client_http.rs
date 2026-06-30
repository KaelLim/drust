use drust_cli::client::http::DrustClient;
use wiremock::matchers::{method, path, header};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn get_sends_bearer_and_parses_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/t/9f/collections"))
        .and(header("authorization", "Bearer drust_pat_cli_x"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"collections":[]})))
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

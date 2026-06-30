use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cli(h: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("drust").unwrap();
    c.env("XDG_CONFIG_HOME", h);
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn device_login_then_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/cli/device/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code":"d","user_code":"ABCD-1234",
            "verification_uri_complete": format!("{}/auth/cli/device?code=ABCD-1234", server.uri()),
            "interval":0,"expires_in":900})))
        .mount(&server)
        .await;
    // First poll → pending (exactly once), then the fallback poll → approved.
    Mock::given(method("POST"))
        .and(path("/auth/cli/device/poll"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"status":"pending"})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/cli/device/poll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status":"approved","access_token":"drust_pat_cli_LIVE",
            "expires_at":"2026-07-01T00:00:00Z","consoles":[{"id":"default"}]})))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = server.uri();
    let home = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        cli(&home)
            .args([
                "auth",
                "login",
                "--host",
                "t",
                "--url",
                &uri,
                "--no-browser",
            ])
            .assert()
            .success();
        cli(&home)
            .args(["auth", "status"])
            .assert()
            .success()
            .stdout(predicate::str::contains("t"));
    })
    .await
    .unwrap();
}

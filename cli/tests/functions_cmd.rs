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
async fn functions_list_and_invoke() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/t/9f/functions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"functions":[{"name":"f1"}]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/t/9f/functions/f1/invoke"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"status":"ok","result":null,"logs":"","duration_ms":3}),
        ))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args([
            "auth",
            "login",
            "--host",
            "t",
            "--url",
            &server.uri(),
            "--with-token",
            "drust_pat_cli_a",
        ])
        .assert()
        .success();
    cli(tmp.path()).args(["use", "9f"]).assert().success();
    cli(tmp.path())
        .args(["--json", "functions", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("f1"));
    cli(tmp.path())
        .args(["--json", "functions", "invoke", "f1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":\"ok\""));
}

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
async fn files_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/t/9f/files"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"files":[],"file_count":0,"used_bytes":0})),
        )
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
        .args(["--json", "files", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("file_count"));
}

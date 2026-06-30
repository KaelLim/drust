use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
fn cli(h: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("drust").unwrap();
    c.env("XDG_CONFIG_HOME", h);
    c
}
async fn login(tmp: &std::path::Path, uri: &str) {
    cli(tmp)
        .args([
            "auth",
            "login",
            "--host",
            "t",
            "--url",
            uri,
            "--with-token",
            "drust_pat_cli_a",
        ])
        .assert()
        .success();
    cli(tmp).args(["use", "9f"]).assert().success();
}

#[tokio::test(flavor = "multi_thread")]
async fn rpc_call_posts_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/t/9f/rpc/top_posts"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"rows":[],"row_count":0})),
        )
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    login(tmp.path(), &server.uri()).await;
    cli(tmp.path())
        .args([
            "--json",
            "rpc",
            "call",
            "top_posts",
            "--params",
            "{\"limit\":5}",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("row_count"));
}

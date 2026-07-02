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
    Command::cargo_bin("drust")
        .unwrap()
        .env("XDG_CONFIG_HOME", tmp)
        .args([
            "auth", "login", "--host", "t", "--url", uri, "--with-token", "drust_pat_cli_a",
        ])
        .assert()
        .success();
    Command::cargo_bin("drust")
        .unwrap()
        .env("XDG_CONFIG_HOME", tmp)
        .args(["use", "9f"])
        .assert()
        .success();
}

#[tokio::test(flavor = "multi_thread")]
async fn set_caps_propagates_mcp_error() {
    let server = MockServer::start().await;
    // MCP tools/call returns a JSON-RPC error → call_tool must surface it.
    Mock::given(method("POST"))
        .and(path("/t/9f/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}})))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    login(tmp.path(), &server.uri()).await;
    cli(tmp.path())
        .args(["collections", "set-caps", "posts", "--anon", "[\"select\"]"])
        .assert()
        .failure();
}

#[tokio::test(flavor = "multi_thread")]
async fn set_caps_requires_a_scope() {
    let tmp = tempfile::tempdir().unwrap();
    // login against an arbitrary https host — no MCP call should be made.
    login(tmp.path(), "https://tool.example/drust").await;
    cli(tmp.path())
        .args(["collections", "set-caps", "posts"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--anon"));
}

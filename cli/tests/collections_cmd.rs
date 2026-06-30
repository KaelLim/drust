use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cli(h:&std::path::Path)->Command{let mut c=Command::cargo_bin("drust").unwrap();c.env("XDG_CONFIG_HOME",h);c}

#[tokio::test(flavor="multi_thread")]
async fn collections_list_and_create_via_mcp() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/t/9f/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"collections":["posts"]})))
        .mount(&server).await;
    // schema mutation routes through MCP tools/call
    Mock::given(method("POST")).and(path("/t/9f/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"ok\":true}"}]}})))
        .mount(&server).await;

    let tmp=tempfile::tempdir().unwrap();
    cli(tmp.path()).args(["auth","login","--host","t","--url",&server.uri(),"--with-token","drust_pat_cli_a"]).assert().success();
    cli(tmp.path()).args(["use","9f"]).assert().success();
    cli(tmp.path()).args(["--json","collections","list"]).assert().success().stdout(predicate::str::contains("posts"));
    cli(tmp.path()).args(["collections","create","blog","--fields","[]"]).assert().success();
}

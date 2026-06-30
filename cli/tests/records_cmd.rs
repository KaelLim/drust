use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path, body_json};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cli(h: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("drust").unwrap();
    c.env("XDG_CONFIG_HOME", h);
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn records_list_hits_post_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/t/9f/collections/posts/list"))
        .and(body_json(serde_json::json!({"page":1,"per_page":50})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "records":[{"id":1,"title":"hi"}],"total":1,"page":1,"perPage":50})))
        .mount(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path()).args(["auth","login","--host","t","--url",&server.uri(),"--with-token","drust_pat_cli_a"]).assert().success();
    cli(tmp.path()).args(["use","9f"]).assert().success();
    cli(tmp.path()).args(["--json","records","list","posts"]).assert().success()
        .stdout(predicate::str::contains("\"title\":\"hi\""));
}

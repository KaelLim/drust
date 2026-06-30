use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cli(h: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("drust").unwrap();
    c.env("XDG_CONFIG_HOME", h);
    c
}

fn login(home: &std::path::Path, uri: &str) {
    cli(home)
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
}

#[tokio::test(flavor = "multi_thread")]
async fn tenants_create_list_rm() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/admin/api/tenants"))
        .and(body_json(serde_json::json!({"name":"blog"})))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "tenant":{"id":"9f","name":"blog"},
            "initial_tokens":{"anon":"a","service":"s"},
            "initial_token":"s"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/admin/api/tenants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tenants":[{"id":"9f","name":"blog"}]})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/admin/api/tenants/9f"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = server.uri();
    let home = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        login(&home, &uri);
        cli(&home)
            .args(["--json", "admin", "tenants", "create", "--name", "blog"])
            .assert()
            .success()
            .stdout(predicate::str::contains("initial_token"));
        cli(&home)
            .args(["--json", "admin", "tenants", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains("blog"));
        cli(&home)
            .args(["admin", "tenants", "rm", "9f"])
            .assert()
            .success();
    })
    .await
    .unwrap();
}

use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path};
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
async fn keys_reroll_and_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/admin/api/tenants/9f/tokens/service/reroll"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "role":"service","token":"drust_pat_NEW","id":7,
            "created_at":"2026-06-30T00:00:00Z","revoked_legacy_count":1})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/admin/api/tenants/9f/tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tokens":[{"role":"anon","plaintext":"a"},{"role":"service","plaintext":"s"}]})))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = server.uri();
    let home = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        login(&home, &uri);
        cli(&home)
            .args(["--json", "admin", "keys", "reroll", "9f", "service"])
            .assert()
            .success()
            .stdout(predicate::str::contains("revoked_legacy_count"));
        cli(&home)
            .args(["--json", "admin", "keys", "list", "9f"])
            .assert()
            .success()
            .stdout(predicate::str::contains("service"));
    })
    .await
    .unwrap();
}

use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path, query_param};
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
async fn audit_host_and_per_tenant() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin/api/audit"))
        .and(query_param("window", "24h"))
        .and(query_param("op", "record.created"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "overview":{"total":3,"error_count":0},"entries":[]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/admin/api/tenants/9f/audit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "overview":{"total":1,"error_count":0},"entries":[]})))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = server.uri();
    let home = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        login(&home, &uri);
        cli(&home)
            .args([
                "--json",
                "admin",
                "audit",
                "--window",
                "24h",
                "--op",
                "record.created",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("overview"));
        cli(&home)
            .args(["--json", "admin", "audit", "--tenant", "9f"])
            .assert()
            .success()
            .stdout(predicate::str::contains("overview"));
    })
    .await
    .unwrap();
}

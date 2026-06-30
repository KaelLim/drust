//! Cross-family smoke: device-flow login (interval:0) then one call per admin family.
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
async fn device_login_then_one_call_per_admin_family() {
    let server = MockServer::start().await;
    // device flow: start → approved (interval:0 makes the poll loop instant)
    Mock::given(method("POST"))
        .and(path("/auth/cli/device/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code":"d","user_code":"ABCD-2345",
            "verification_uri":"http://x/drust/auth/cli/device",
            "interval":0,"expires_in":900})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/cli/device/poll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status":"approved","access_token":"drust_pat_cli_LIVE",
            "consoles":[{"id":"default"}]})))
        .mount(&server)
        .await;
    // one endpoint per admin family
    Mock::given(method("GET"))
        .and(path("/admin/api/tenants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tenants":[{"id":"9f","name":"blog"}]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/admin/api/tenants/9f/tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tokens":[{"role":"service","plaintext":"s"}]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/admin/team"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "admins":[{"id":1,"email":"a@b.com","role":"owner"}]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/admin/api/audit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "overview":{"total":0,"error_count":0},"entries":[]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/admin/api/backups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "backups":[],"total_size_human":"0 B"})))
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
            .args(["--json", "admin", "tenants", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains("blog"));
        cli(&home)
            .args(["--json", "admin", "keys", "list", "9f"])
            .assert()
            .success()
            .stdout(predicate::str::contains("service"));
        cli(&home)
            .args(["--json", "admin", "team", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains("owner"));
        cli(&home)
            .args(["--json", "admin", "audit"])
            .assert()
            .success()
            .stdout(predicate::str::contains("overview"));
        cli(&home)
            .args(["--json", "admin", "backups", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains("total_size_human"));
    })
    .await
    .unwrap();
}

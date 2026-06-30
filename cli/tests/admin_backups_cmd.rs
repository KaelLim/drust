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

const F: &str = "drust-2026-06-30-000000.tar.zst";

#[tokio::test(flavor = "multi_thread")]
async fn backups_list_inspect_download_restore() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin/api/backups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "backups":[{"filename":F,"size_human":"1.0 MB"}],"total_size_human":"1.0 MB"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/admin/api/backups/{F}/inspect")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "filename":F,"tenants":[{"id":"9f","name":"x","db_present":true}]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/admin/backups/{F}/download")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ZSTDBYTES".to_vec()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/admin/backups/{F}/restore")))
        .respond_with(ResponseTemplate::new(303).insert_header(
            "location",
            format!(
                "/drust/admin/backups/{F}/inspect?restored=9f&dest=%2Fdata%2F_trash%2F9f-restored-x"
            ),
        ))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = server.uri();
    let home = tmp.path().to_path_buf();
    let out = tmp.path().join("snap.tar.zst");
    let out_s = out.to_string_lossy().to_string();
    tokio::task::spawn_blocking(move || {
        login(&home, &uri);
        cli(&home)
            .args(["--json", "admin", "backups", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains(F));
        cli(&home)
            .args(["--json", "admin", "backups", "inspect", F])
            .assert()
            .success()
            .stdout(predicate::str::contains("db_present"));
        cli(&home)
            .args(["admin", "backups", "download", F, "-o", &out_s])
            .assert()
            .success();
        assert_eq!(std::fs::read(&out).unwrap(), b"ZSTDBYTES");
        cli(&home)
            .args(["admin", "backups", "restore", F, "--tenant", "9f"])
            .assert()
            .success()
            .stdout(predicate::str::contains("_trash"))
            .stdout(predicate::str::contains("mv"));
    })
    .await
    .unwrap();
}

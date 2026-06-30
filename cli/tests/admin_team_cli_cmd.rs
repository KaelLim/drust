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
async fn team_list_invite_role_rm() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin/team"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "admins":[{"id":1,"email":"a@b.com","display_name":null,"role":"owner",
                       "created_at":"2026-06-30T00:00:00Z"}]})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/admin/team"))
        .and(body_json(
            serde_json::json!({"email":"new@b.com","role":"member"}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id":2,"email":"new@b.com","role":"member"})))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/admin/team/2/role"))
        .and(body_json(serde_json::json!({"role":"owner"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id":2,"role":"owner"})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/admin/team/2"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = server.uri();
    let home = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        login(&home, &uri);
        cli(&home)
            .args(["--json", "admin", "team", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains("a@b.com"));
        cli(&home)
            .args([
                "--json",
                "admin",
                "team",
                "invite",
                "new@b.com",
                "--role",
                "member",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("new@b.com"));
        cli(&home)
            .args(["--json", "admin", "team", "role", "2", "owner"])
            .assert()
            .success();
        cli(&home)
            .args(["admin", "team", "rm", "2"])
            .assert()
            .success();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn team_invite_403_not_owner_surfaces_code() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/admin/team"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error_code":"NOT_OWNER","message":"only owners can invite admins"})))
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
                "team",
                "invite",
                "new@b.com",
                "--role",
                "member",
            ])
            .assert()
            .code(1) // 4xx app error → exit 1 (no client-side role gate)
            .stderr(predicate::str::contains("NOT_OWNER"));
    })
    .await
    .unwrap();
}

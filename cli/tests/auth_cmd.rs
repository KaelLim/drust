use assert_cmd::Command;
use predicates::prelude::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cli(cfg_home: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("drust").unwrap();
    c.env("XDG_CONFIG_HOME", cfg_home); // isolate hosts.toml under a tempdir
    c
}

#[test]
fn login_then_status_then_logout() {
    let tmp = tempfile::tempdir().unwrap();
    // login with a pasted token + explicit base url
    cli(tmp.path())
        .args([
            "auth",
            "login",
            "--host",
            "tool",
            "--url",
            "https://tool.example/drust",
            "--with-token",
            "drust_pat_cli_abc",
        ])
        .assert()
        .success();
    // status shows the host
    cli(tmp.path())
        .args(["auth", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("tool"));
    // logout
    cli(tmp.path())
        .args(["auth", "logout", "--host", "tool"])
        .assert()
        .success();
    // status now errors (no host)
    cli(tmp.path()).args(["auth", "status"]).assert().failure();
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_warns_when_server_revoke_fails() {
    let server = MockServer::start().await;
    // Server-side revoke fails (500) — logout must still clear local state,
    // exit 0, and emit a warning (not swallow the error).
    Mock::given(method("DELETE"))
        .and(path("/auth/cli/token"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error_code":"INTERNAL","message":"boom"})))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args([
            "auth",
            "login",
            "--host",
            "t",
            "--url",
            &server.uri(),
            "--with-token",
            "drust_pat_cli_a",
        ])
        .assert()
        .success();
    cli(tmp.path())
        .args(["auth", "logout", "--host", "t"])
        .assert()
        .success()
        .stderr(predicate::str::contains("server-side revoke failed"));
    // local state cleared: status errors.
    cli(tmp.path()).args(["auth", "status"]).assert().failure();
}

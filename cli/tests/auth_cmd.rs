use assert_cmd::Command;
use predicates::prelude::*;

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

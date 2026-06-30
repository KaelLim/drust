use assert_cmd::Command;
use predicates::prelude::*;

fn cli(h: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("drust").unwrap();
    c.env("XDG_CONFIG_HOME", h);
    c
}

#[test]
fn use_sets_default_tenant() {
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args([
            "auth",
            "login",
            "--host",
            "t",
            "--url",
            "https://x/drust",
            "--with-token",
            "drust_pat_cli_a",
        ])
        .assert()
        .success();
    cli(tmp.path()).args(["use", "9f1c"]).assert().success();
    cli(tmp.path())
        .args(["auth", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("9f1c"));
}

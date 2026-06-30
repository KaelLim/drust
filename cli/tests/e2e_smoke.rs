use assert_cmd::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
fn cli(h: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("drust").unwrap();
    c.env("XDG_CONFIG_HOME", h);
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn full_loop() {
    let s = MockServer::start().await;
    for (m, p, body) in [
        (
            "POST",
            "/t/9f/collections/posts/list",
            serde_json::json!({"records":[],"total":0}),
        ),
        (
            "GET",
            "/t/9f/collections",
            serde_json::json!({"collections":[]}),
        ),
        (
            "GET",
            "/t/9f/functions",
            serde_json::json!({"functions":[]}),
        ),
        ("GET", "/t/9f/files", serde_json::json!({"files":[]})),
    ] {
        Mock::given(method(m))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&s)
            .await;
    }
    let tmp = tempfile::tempdir().unwrap();
    cli(tmp.path())
        .args([
            "auth",
            "login",
            "--host",
            "t",
            "--url",
            &s.uri(),
            "--with-token",
            "drust_pat_cli_a",
        ])
        .assert()
        .success();
    cli(tmp.path()).args(["use", "9f"]).assert().success();
    for args in [
        vec!["records", "list", "posts"],
        vec!["collections", "list"],
        vec!["functions", "list"],
        vec!["files", "list"],
    ] {
        let mut a = vec!["--json"];
        a.extend(args);
        cli(tmp.path()).args(&a).assert().success();
    }
}

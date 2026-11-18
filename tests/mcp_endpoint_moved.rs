//! The retired per-tenant path `/t/<id>/mcp` answers one 410 for every
//! tenant id, method, Host and credential: it is not an existence oracle,
//! never touches meta and writes no audit row. Mounting it leaves the app's
//! JSON 404 for unmatched paths unchanged.

mod helpers;

use axum::http::StatusCode;

/// Status, every response header sorted by name (content-length dropped for
/// HEAD, whose body is empty by definition) and body.
type Answer = (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>);

async fn answer(app: &axum::Router, method: &str, uri: &str, extra: &[(&str, &str)]) -> Answer {
    let body = (method == "POST").then(|| helpers::mcp_init("2025-06-18"));
    let (s, hs, b) = helpers::http_raw(app, method, uri, extra, body).await;
    let mut h: Vec<(String, Vec<u8>)> = hs
        .iter()
        .filter(|(k, _)| !(method == "HEAD" && *k == axum::http::header::CONTENT_LENGTH))
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();
    h.sort();
    (s, h, if method == "HEAD" { Vec::new() } else { b })
}

/// Every credential a caller could present, each valid where it belongs.
async fn credentials(h: &helpers::AccountMcpHarness) -> Vec<(&'static str, String)> {
    helpers::account_allow_self_register(h).await;
    let (ui, cli) = {
        let m = h.meta.lock().await;
        let ui: String = m
            .query_row(
                "SELECT plaintext FROM _admin_tokens \
                 WHERE admin_id = ?1 AND label IS NULL AND revoked_at IS NULL",
                [h.admin_id],
                |r| r.get(0),
            )
            .unwrap();
        let cli = drust::auth::admin_token::mint_cli_token(&m, h.admin_id, "test", 3600)
            .unwrap()
            .1;
        (ui, cli)
    }; // guard dropped before the app runs: its handlers lock meta too
    let user = helpers::register_and_login_via_app(
        &h.app,
        &h.tid,
        "u@example.test",
        "a-long-test-password-1",
    )
    .await;
    vec![
        ("authorization", String::new()),
        ("authorization", "Bearer x".to_string()),
        ("authorization", format!("Bearer {}", h.svc)),
        ("authorization", format!("Bearer {}", h.anon)),
        ("authorization", format!("Bearer {user}")),
        ("authorization", format!("Bearer {ui}")),
        ("authorization", format!("Bearer {cli}")),
        ("authorization", format!("Bearer {}", h.access)),
        // a cookie header in the admin session's shape; the value is a placeholder
        ("cookie", "drust_session=placeholder".to_string()),
    ]
}

#[tokio::test]
async fn moved_answer_ignores_tenant_and_credentials() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let creds = credentials(&h).await;
    let first = answer(&h.app, "POST", "/t/t1/mcp", &[]).await;
    assert_eq!(first.0, StatusCode::GONE);
    assert!(
        first
            .1
            .iter()
            .any(|(k, v)| k == "cache-control" && v == b"no-store"),
        "{:?}",
        first.1
    );
    let text = String::from_utf8(first.2.clone()).unwrap();
    assert!(
        text.starts_with(r#"{"message":"MOVED: claude mcp"#),
        "{text}"
    );
    assert!(text.contains("https://drust.test/drust/mcp"), "{text}");
    let head_headers: Vec<(String, Vec<u8>)> = first
        .1
        .iter()
        .filter(|(k, _)| k != "content-length")
        .cloned()
        .collect();
    for uri in ["/t/t1/mcp", "/t/no-such-tenant/mcp", "/t/BAD%20ID/mcp"] {
        for (name, value) in &creds {
            for host in ["127.0.0.1", "evil.example", ""] {
                let extra = [(*name, value.as_str()), ("host", host)];
                for m in ["POST", "GET", "DELETE", "PUT", "PATCH", "OPTIONS"] {
                    assert_eq!(
                        answer(&h.app, m, uri, &extra).await,
                        first,
                        "{m} {uri} {name} host={host:?}"
                    );
                }
                let head = answer(&h.app, "HEAD", uri, &extra).await;
                assert_eq!(
                    (head.0, &head.1),
                    (first.0, &head_headers),
                    "HEAD {uri} {name} host={host:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn moved_answer_never_touches_meta() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let svc = format!("Bearer {}", h.svc);
    let guard = h.meta.lock().await; // held across the request: a meta read would hang
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        answer(
            &h.app,
            "POST",
            "/t/t1/mcp",
            &[("authorization", svc.as_str())],
        ),
    )
    .await
    .expect("the 410 must not wait on meta");
    drop(guard);
    assert_eq!(r.0, StatusCode::GONE);
}

#[tokio::test]
async fn unmatched_paths_keep_the_json_not_found() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let svc = format!("Bearer {}", h.svc);
    for uri in ["/no-such-path", "/t/t1/no-such", "/t/t1/mcp/extra"] {
        for auth in ["", "Bearer x", svc.as_str()] {
            let (s, hs, b) =
                helpers::http_raw(&h.app, "GET", uri, &[("authorization", auth)], None).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
            assert!(
                hs["content-type"]
                    .to_str()
                    .unwrap()
                    .starts_with("application/json"),
                "{uri}"
            );
            let v: serde_json::Value = serde_json::from_slice(&b).expect("JSON 404 body");
            assert_eq!(v["error_code"], "NOT_FOUND", "{uri}: {v}");
        }
    }
}

#[tokio::test]
async fn disabled_host_answers_the_disabled_moved_text() {
    let h = helpers::spin_up_account_mcp_with(helpers::AccountMcpOpts {
        admins: vec![("mcp-owner", "owner")],
        tenants: vec![("t1", Some(0))],
        files: false,
        mcp_enabled: false,
    })
    .await;
    let (s, hs, b) = answer(&h.app, "GET", "/t/t1/mcp", &[]).await;
    assert_eq!(s, StatusCode::GONE);
    assert!(
        hs.iter()
            .any(|(k, v)| k == "cache-control" && v == b"no-store"),
        "{hs:?}"
    );
    assert_eq!(
        b,
        br#"{"message":"MOVED: MCP is now one account-level OAuth endpoint, not enabled on this server yet; ask the operator","error_code":"MCP_ENDPOINT_MOVED"}"#
    );
}

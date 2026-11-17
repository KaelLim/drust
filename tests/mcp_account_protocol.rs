//! The account-level MCP endpoint (`/mcp`) at the protocol level, on the app
//! assembled the way `main` assembles it: version negotiation, the empty
//! server surface, the stateless SSE transport, the host list rmcp receives,
//! the Origin gate, the challenge URL, metadata agreement, and that paths near
//! `/mcp` and a disabled host answer like a path that never existed.

mod helpers;

use axum::http::{HeaderMap, StatusCode};
use drust::mgmt::mcp_oauth::config::McpOauthConfig;
use helpers::mcp_init as init;
use serde_json::{Value, json};

fn req(id: i64, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {}})
}

fn cfg() -> McpOauthConfig {
    McpOauthConfig::for_tests(helpers::MCP_PUBLIC_URL)
}

type Sorted = (StatusCode, Vec<(String, String)>, Vec<u8>);

/// status + headers sorted by name (then value) + body: the byte-identity
/// comparison.
fn sorted((s, h, b): (StatusCode, HeaderMap, Vec<u8>)) -> Sorted {
    let mut v: Vec<(String, String)> = h
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    v.sort();
    (s, v, b)
}

const H3: &[u8] = br#"{"message":"browser Origin not allowed; MCP clients send no Origin header","error_code":"MCP_ORIGIN_NOT_ALLOWED"}"#;

#[tokio::test]
async fn initialize_negotiates_the_protocol_version() {
    let h = helpers::spin_up_account_mcp("t1").await;
    for (asked, want) in [
        ("2024-11-05", "2024-11-05"),
        ("2025-03-26", "2025-03-26"),
        ("2025-06-18", "2025-06-18"),
        ("2025-11-25", "2025-11-25"),
        ("2026-07-28", "2025-11-25"),
        ("1999-01-01", "2025-11-25"),
    ] {
        let (s, _, m) = helpers::mcp_rpc(&h.app, Some(&h.access), init(asked)).await;
        assert_eq!(s, StatusCode::OK, "{asked}");
        assert_eq!(m[0]["result"]["protocolVersion"], want, "{asked}");
        assert_eq!(
            m[0]["result"]["capabilities"],
            json!({"prompts": {}, "resources": {}, "tools": {}})
        );
        assert_eq!(m[0]["result"]["serverInfo"]["name"], "drust");
        assert!(
            m[0]["result"]["instructions"].as_str().is_some_and(|s| s
                .starts_with("drust — one MCP endpoint for every tenant your account can see.")),
            "{asked}"
        );
    }
}

#[tokio::test]
async fn future_revision_in_header_and_body_still_gets_the_fallback() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let auth = format!("Bearer {}", h.access);
    let (s, hd, b) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[
            ("authorization", &auth),
            ("mcp-protocol-version", "2026-07-28"),
        ],
        Some(init("2026-07-28")),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        hd["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    assert!(
        String::from_utf8(b)
            .unwrap()
            .contains(r#""protocolVersion":"2025-11-25""#)
    );
    let (s, _, b) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[
            ("authorization", &auth),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        Some(req(2, "tools/list")),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        String::from_utf8(b)
            .unwrap()
            .contains(r#""name":"list_tenants""#)
    );
}

#[tokio::test]
async fn shell_lists_only_list_tenants_and_knows_no_method_beyond_the_spec() {
    let h = helpers::spin_up_account_mcp("t1").await;
    for (method, key) in [
        ("resources/list", "resources"),
        ("resources/templates/list", "resourceTemplates"),
        ("prompts/list", "prompts"),
    ] {
        // No initialize first: the transport is stateless.
        let (s, _, m) = helpers::mcp_rpc(&h.app, Some(&h.access), req(1, method)).await;
        assert_eq!(s, StatusCode::OK, "{method}");
        assert_eq!(m[0]["result"][key], json!([]), "{method}");
    }
    let (s, _, m) = helpers::mcp_rpc(&h.app, Some(&h.access), req(2, "tools/list")).await;
    assert_eq!(s, StatusCode::OK);
    let names: Vec<&str> = m[0]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["list_tenants"]);
    let r = helpers::mcp_call(&h.app, &h.access, &h.tid, "no_such_tool", json!({})).await;
    assert_eq!(r["error"]["code"], -32602);
    assert_eq!(r["error"]["message"], "tool not found");
    let (_, _, m) = helpers::mcp_rpc(&h.app, Some(&h.access), req(3, "server/discover")).await;
    assert_eq!(
        m[0]["error"]["code"], -32601,
        "probe fallback: unknown method stays method-not-found"
    );
}

#[tokio::test]
async fn transport_is_stateless_sse() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let auth = format!("Bearer {}", h.access);
    let (s, hd, b) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("authorization", &auth), ("mcp-session-id", "made-up")],
        Some(req(1, "tools/list")),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(hd.get("mcp-session-id").is_none());
    assert_eq!(hd["x-accel-buffering"], "no");
    // The stream ended (mcp_raw returned within its timeout) after exactly one message.
    let body = String::from_utf8(b).unwrap();
    let data: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("data:") && l.len() > "data:".len())
        .collect();
    assert_eq!(
        data.len(),
        1,
        "a stateless reply carries exactly one message"
    );
    for m in ["GET", "DELETE"] {
        // No body headers: the answer depends on the method alone.
        let (s, hd, _) = helpers::http_raw(
            &h.app,
            m,
            "/mcp",
            &[
                ("authorization", &auth),
                ("accept", "text/event-stream"),
                ("content-type", ""),
            ],
            None,
        )
        .await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED, "{m}");
        assert_eq!(hd["allow"], "POST", "{m}");
        assert!(
            hd.get("content-type")
                .is_none_or(|v| !v.to_str().unwrap().starts_with("text/event-stream")),
            "{m}"
        );
    }
    let (s, _, b) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("authorization", &auth)],
        Some(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert!(b.is_empty());
    let (s, _, _) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("authorization", &auth), ("accept", "application/json")],
        Some(req(1, "tools/list")),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::NOT_ACCEPTABLE,
        "rmcp's 406 is visible only after auth"
    );
    let (s, _, _) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("accept", "application/json")],
        Some(req(1, "tools/list")),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the gate answers before rmcp");
}

#[tokio::test]
async fn public_and_loopback_hosts_reach_rmcp() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let auth = format!("Bearer {}", h.access);
    for host in [
        "127.0.0.1:47826",
        "drust.test",
        "drust.test:8443",
        "localhost:47826",
        "[::1]:47826",
    ] {
        let (s, _, _) = helpers::mcp_raw(
            &h.app,
            "POST",
            &[("authorization", &auth), ("host", host)],
            Some(init("2025-06-18")),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{host}");
    }
    for host in ["drust.test.evil.example", "evil.example"] {
        let (s, hd, b) = helpers::mcp_raw(
            &h.app,
            "POST",
            &[("authorization", &auth), ("host", host)],
            Some(init("2025-06-18")),
        )
        .await;
        assert_eq!(s, StatusCode::MISDIRECTED_REQUEST, "{host}");
        assert_eq!(hd["cache-control"], "no-store");
        assert_eq!(
            b,
            br#"{"message":"proxy must send Host: 127.0.0.1:47826 or the public host","error_code":"MCP_HOST_NOT_ALLOWED"}"#
        );
    }
}

#[tokio::test]
async fn browser_origins_are_judged_before_rmcp() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let auth = format!("Bearer {}", h.access);
    let (s, hd, b) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("authorization", &auth), ("origin", "https://evil.example")],
        Some(init("2025-06-18")),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(hd["cache-control"], "no-store");
    assert_eq!(b, H3);
    for origin in ["https://drust.test", "http://localhost:5173"] {
        let (s, _, _) = helpers::mcp_raw(
            &h.app,
            "POST",
            &[("authorization", &auth), ("origin", origin)],
            Some(init("2025-06-18")),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{origin}");
    }
}

#[tokio::test]
async fn unmatched_mcp_paths_answer_like_any_unknown_path() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let hs = [("authorization", "Bearer junk")];
    for (m, uri) in [
        ("POST", "/mcp/"),
        ("GET", "/mcp/x"),
        ("GET", "/.well-known/oauth-protected-resource/mcp/"),
    ] {
        let got = helpers::http_raw(&h.app, m, uri, &hs, None).await;
        let never = helpers::http_raw(&h.app, m, "/no-such-path", &hs, None).await;
        assert_eq!(sorted(got), sorted(never), "{m} {uri}");
    }
}

#[tokio::test]
async fn unauthenticated_post_is_challenged_with_the_prm_url() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let (s, hd, _) = helpers::mcp_rpc(&h.app, None, init("2025-06-18")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        hd["www-authenticate"],
        format!(
            r#"Bearer resource_metadata="{}", scope="mcp""#,
            cfg().prm_url()
        )
        .as_str()
    );
    let (s, hd, _) = helpers::mcp_rpc(&h.app, Some("not-an-oauth-token"), init("2025-06-18")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(
        hd["www-authenticate"]
            .to_str()
            .unwrap()
            .ends_with(r#", error="invalid_token""#)
    );
}

#[tokio::test]
async fn metadata_documents_agree_byte_for_byte() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let no_body = [("accept", ""), ("content-type", "")];
    let (_, _, b) = helpers::http_raw(
        &h.app,
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
        &no_body,
        None,
    )
    .await;
    let prm: Value = serde_json::from_slice(&b).unwrap();
    let (_, _, b) = helpers::http_raw(
        &h.app,
        "GET",
        "/.well-known/oauth-authorization-server",
        &no_body,
        None,
    )
    .await;
    let asm: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(prm["resource"], cfg().resource_url().as_str());
    assert_eq!(prm["authorization_servers"], json!([asm["issuer"].clone()]));
    assert_eq!(asm["issuer"], cfg().issuer().as_str());
    assert_eq!(prm["scopes_supported"], json!(["mcp"]));
    let mut keys: Vec<_> = prm.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "authorization_servers",
            "bearer_methods_supported",
            "resource",
            "resource_name",
            "scopes_supported"
        ]
    );
}

#[tokio::test]
async fn disabled_host_answers_mcp_like_an_unknown_path() {
    let h = helpers::spin_up_account_mcp_with(helpers::AccountMcpOpts {
        admins: vec![("mcp-owner", "owner")],
        tenants: vec![("t1", Some(0))],
        files: false,
        mcp_enabled: false,
    })
    .await;
    for (m, uri) in [
        ("POST", "/mcp"),
        ("GET", "/mcp"),
        ("GET", "/.well-known/oauth-protected-resource/mcp"),
    ] {
        let body = (m == "POST").then(|| init("2025-06-18"));
        let hs = [("authorization", "Bearer x")];
        let got = helpers::http_raw(&h.app, m, uri, &hs, body.clone()).await;
        let never = helpers::http_raw(&h.app, m, "/no-such-path", &hs, body).await;
        assert_eq!(sorted(got), sorted(never), "{m} {uri}");
    }
}

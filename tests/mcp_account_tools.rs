//! Account-level /mcp tool surface: injected tenant, strict top-level arguments, forwarding, one isError shape, fixed instructions.

mod helpers;
use helpers::*;
use serde_json::json;

#[tokio::test]
async fn initialize_returns_the_account_instructions() {
    let h = spin_up_account_mcp("acct-tools").await;
    let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});
    let (st, _, msgs) = mcp_rpc(&h.app, Some(&h.access), body).await;
    assert_eq!(st, 200);
    let s = msgs[0]["result"]["instructions"]
        .as_str()
        .expect("instructions string");
    assert!(s.starts_with("drust — one MCP endpoint for every tenant your account can see."));
    assert!(s.chars().count() <= 4096 && s.encode_utf16().count() <= 4096);
    assert!(!s.contains("acct-tools") && !s.contains("/t/"));
}

#[tokio::test]
async fn tools_list_is_the_inner_tools_plus_list_tenants() {
    let h = spin_up_account_mcp("acct-tools").await;
    let (st, _, msgs) = mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    let tools = msgs[0]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 77);
    for t in tools {
        let name = t["name"].as_str().unwrap();
        if name == "list_tenants" {
            assert!(
                t["inputSchema"]["required"]
                    .as_array()
                    .is_none_or(|r| r.is_empty())
            );
            assert_eq!(t["inputSchema"]["properties"], json!({}));
        } else {
            assert_eq!(t["inputSchema"]["required"][0], "tenant", "{name}");
            assert_eq!(
                t["inputSchema"]["properties"]["tenant"]["type"], "string",
                "{name}"
            );
        }
    }
    let who = tools.iter().find(|t| t["name"] == "whoami").unwrap();
    assert!(
        !who["description"]
            .as_str()
            .unwrap()
            .contains("both bearer tokens")
    );
    assert_eq!(drust::mcp::handler::DrustMcpService::tool_count(), 76);
}

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

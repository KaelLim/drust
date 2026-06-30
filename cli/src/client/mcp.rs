//! Minimal MCP JSON-RPC `tools/call` client for schema mutation (spec D-1).
use crate::client::error::ApiError;
use crate::client::http::DrustClient;
use reqwest::Method;

pub async fn call_tool(
    client: &DrustClient,
    tenant: &str,
    tool: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":tool,"arguments":args}
    });
    let resp = client.send_json(Method::POST, &format!("/t/{tenant}/mcp"), req).await?;
    if let Some(err) = resp.get("error") {
        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("mcp error").to_string();
        return Err(ApiError { status: 400, error_code: "MCP_ERROR".into(), message: msg, suggested_fix: None, error_aliases: vec![] });
    }
    Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

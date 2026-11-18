//! Minimal MCP JSON-RPC `tools/call` client for schema mutation (spec D-1).
//!
//! A server whose per-tenant MCP path is retired answers 410
//! `MCP_ENDPOINT_MOVED`; the CLI says to use the admin UI or Claude Code
//! instead of relaying the server's Claude Code instructions.
use crate::client::error::ApiError;
use crate::client::http::DrustClient;
use reqwest::Method;

/// What the CLI says instead of the server's Claude Code instructions.
pub const MOVED_HINT: &str = "schema changes: use the admin UI or Claude Code for now";

fn moved_hint(mut e: ApiError) -> ApiError {
    if e.matches("MCP_ENDPOINT_MOVED") {
        e.message = MOVED_HINT.to_string();
        e.suggested_fix = None;
    }
    e
}

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
    let resp = client
        .send_json(Method::POST, &format!("/t/{tenant}/mcp"), req)
        .await
        .map_err(moved_hint)?;
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("mcp error")
            .to_string();
        return Err(ApiError {
            status: 400,
            error_code: "MCP_ERROR".into(),
            message: msg,
            suggested_fix: None,
            error_aliases: vec![],
        });
    }
    Ok(resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_moved_endpoint_gets_the_cli_hint() {
        let e = moved_hint(ApiError::from_body(
            410,
            &json!({
                "message": "MOVED: claude mcp add --transport http drust https://x.test/mcp",
                "error_code": "MCP_ENDPOINT_MOVED"}),
        ));
        assert_eq!(e.message, MOVED_HINT);
        assert_eq!(e.error_code, "MCP_ENDPOINT_MOVED");
        assert_eq!(e.exit_code(), 1);
        assert!(!e.to_string().contains("claude mcp"), "{e}");
    }

    /// The server's two 410 bodies, byte for byte (`moved_message` in the
    /// server's `route_layer.rs`): MCP on with a short public URL, and MCP off.
    const MOVED_BODIES: [&str; 2] = [
        r#"{"message":"MOVED: claude mcp remove <name>; claude mcp add --transport http drust https://x.test/mcp (no --header)","error_code":"MCP_ENDPOINT_MOVED"}"#,
        r#"{"message":"MOVED: MCP is now one account-level OAuth endpoint, not enabled on this server yet; ask the operator","error_code":"MCP_ENDPOINT_MOVED"}"#,
    ];

    #[tokio::test]
    async fn call_tool_turns_the_servers_410_into_the_hint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for body in MOVED_BODIES {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/t/9f/mcp"))
                .respond_with(
                    ResponseTemplate::new(410)
                        .insert_header("cache-control", "no-store")
                        .set_body_raw(body, "application/json"),
                )
                .expect(1)
                .mount(&server)
                .await;
            let client = DrustClient::new(server.uri(), "svc");
            let e = call_tool(&client, "9f", "create_collection", json!({"name": "c"}))
                .await
                .expect_err("a 410 is an error");
            assert_eq!(
                (e.status, e.error_code.as_str(), e.message.as_str()),
                (410, "MCP_ENDPOINT_MOVED", MOVED_HINT),
                "{body}"
            );
            assert_eq!(e.suggested_fix, None);
            assert_eq!(e.exit_code(), 1);
            assert!(!e.to_string().contains("MOVED:"), "{e}");
        }
    }

    #[test]
    fn other_errors_pass_through() {
        let e = moved_hint(ApiError::from_body(
            403,
            &json!({"message":"nope","error_code":"WRITE_DENIED"}),
        ));
        assert_eq!(
            (e.message.as_str(), e.error_code.as_str()),
            ("nope", "WRITE_DENIED")
        );
    }
}

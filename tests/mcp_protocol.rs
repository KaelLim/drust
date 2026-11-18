//! Smoke-level integration test for the rmcp Streamable HTTP transport
//! at the account-level `/mcp` endpoint. Exercises the real HTTP surface —
//! JSON-RPC initialize, tools/list, tools/call — without a full rmcp client.
//!
//! We keep it deliberately minimal: the goal is to prove the wiring is
//! real (rmcp handler → axum route → OAuth bearer layer → per-call tenant
//! service) rather than to re-test every tool. Per-tool behavior is covered by
//! the in-process tests in `mcp_write_schema.rs`, `mcp_read.rs`,
//! `mcp_exploration.rs`.
//!
//! NOTE: every request must carry an allowed `Host` header — the endpoint's
//! Host check answers anything else before authentication. In production
//! Caddy sets this via `header_up Host "127.0.0.1:47826"`; `helpers::http_raw`
//! sends `Host: 127.0.0.1` by default.

mod helpers;

use axum::http::StatusCode;
use serde_json::{Value, json};

/// One `tools/call` with `"tenant"` added; the JSON-RPC message.
async fn call(h: &helpers::AccountMcpHarness, name: &str, args: Value) -> Value {
    helpers::mcp_call(&h.app, &h.access, &h.tid, name, args).await
}

/// A harness whose tenant already has a `t` collection (title TEXT).
async fn with_collection(tenant: &'static str) -> helpers::AccountMcpHarness {
    let h = helpers::spin_up_account_mcp(tenant).await;
    let m = call(
        &h,
        "create_collection",
        json!({"name": "t", "fields": [{"name": "title", "sql_type": "text"}]}),
    )
    .await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    h
}

/// The `result` of one JSON-RPC request to `/mcp`, sent with the harness's
/// access token.
async fn rpc_result(h: &helpers::AccountMcpHarness, body: Value) -> Value {
    let (status, _, msgs) = helpers::mcp_rpc(&h.app, Some(&h.access), body).await;
    assert_eq!(status, StatusCode::OK);
    msgs.into_iter()
        .find_map(|m| m.get("result").cloned())
        .expect("the answer must carry a result")
}

#[tokio::test]
async fn initialize_then_tools_list_returns_core_tools() {
    let h = helpers::spin_up_account_mcp("mcp1").await;
    let (status, headers, msgs) =
        helpers::mcp_rpc(&h.app, Some(&h.access), helpers::mcp_init("2024-11-05")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get("mcp-session-id").is_none(),
        "the account endpoint is stateless"
    );
    assert!(!msgs.is_empty());
    let result = &msgs[0]["result"];
    assert_eq!(result["serverInfo"]["name"], "drust");

    // tools/list — assert the core read/write/schema tools are present. We do
    // NOT assert the total count: new tools get added over time and a strict
    // count just rots. No session: a stateless endpoint answers it directly.
    let tl = rpc_result(
        &h,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }),
    )
    .await;
    let tools = tl["tools"]
        .as_array()
        .cloned()
        .expect("tools/list must return a tools array");
    let names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    for expected in [
        "list_collections",
        "describe_collection",
        "query",
        "explain",
        "create_collection",
        "add_field",
        "drop_field",
        "drop_collection",
        "insert_record",
        "update_record",
        "delete_record",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing tool {expected:?}; got {names:?}"
        );
    }
}

#[tokio::test]
async fn anon_tenant_key_is_rejected_with_401() {
    let h = helpers::spin_up_account_mcp("mcp2").await;
    let auth = format!("Bearer {}", h.anon);
    let (status, headers, body) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("authorization", auth.as_str())],
        Some(helpers::mcp_init("2025-06-18")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "MCP_OAUTH_REQUIRED");
    assert!(
        headers["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("error=\"invalid_token\"")
    );
}

#[tokio::test]
async fn missing_bearer_is_rejected_with_401() {
    let h = helpers::spin_up_account_mcp("mcp3").await;
    let (status, headers, _) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[],
        Some(json!({"jsonrpc":"2.0","id":1,"method":"initialize"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let www = headers["www-authenticate"].to_str().unwrap();
    assert!(
        www.starts_with(
            "Bearer resource_metadata=\"https://drust.test/drust/.well-known/oauth-protected-resource/mcp\""
        ),
        "{www}"
    );
    assert!(
        !www.contains("error="),
        "a request without a token gets a bare challenge: {www}"
    );
}

#[tokio::test]
async fn tools_call_list_collections_succeeds() {
    let h = helpers::spin_up_account_mcp("mcp4").await;
    // Seed a table so list_collections has something to report.
    let pool = h.tenants.get_or_create(&h.tid).unwrap();
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE stuff (id INTEGER PRIMARY KEY AUTOINCREMENT, x TEXT);")
    })
    .await
    .unwrap();

    let m = call(&h, "list_collections", json!({})).await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let content = m["result"]["content"]
        .as_array()
        .cloned()
        .expect("tools/call must return a content array");
    let text = content[0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).unwrap();
    let cols = parsed["collections"].as_array().unwrap();
    assert!(
        cols.iter().any(|c| c["name"] == "stuff"),
        "expected `stuff` in collections list, got {parsed:?}"
    );
}

/// The annotations Claude Code acts on (auto-resend after a dropped connection
/// for readOnly OR idempotent tools) as they actually leave the server —
/// `Some(false)` must serialize, not vanish into the spec default.
#[tokio::test]
async fn tools_list_wire_annotations_for_retry_sensitive_tools() {
    let h = helpers::spin_up_account_mcp("mcpann").await;
    let tools = rpc_result(
        &h,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await["tools"]
        .as_array()
        .cloned()
        .expect("tools/list must return a tools array");
    let ann = |name: &str| -> Value {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("tool {name} missing from tools/list"))["annotations"]
            .clone()
    };
    for (tool, key, want) in [
        ("update_record", "idempotentHint", false),
        ("upsert_records", "idempotentHint", false),
        ("call_rpc", "readOnlyHint", true),
        ("list_records", "openWorldHint", false),
        ("invoke_function", "openWorldHint", true),
        ("set_file_visibility", "destructiveHint", true),
    ] {
        let a = ann(tool);
        assert_eq!(
            a[key],
            Value::Bool(want),
            "{tool}.annotations.{key} on the wire; got annotations {a}"
        );
    }
}

/// A tool-execution failure leaves the server as an `isError: true`
/// result — not `isError: false` with an error object in the text.
#[tokio::test]
async fn tools_call_describe_missing_collection_is_error_on_wire() {
    let h = helpers::spin_up_account_mcp("mcpiserr").await;
    let m = call(&h, "describe_collection", json!({"collection": "nope"})).await;
    let result = m
        .get("result")
        .cloned()
        .expect("tools/call must return a result");
    assert_eq!(
        result["isError"],
        Value::Bool(true),
        "result on the wire: {result}"
    );
    let text = result["content"][0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["error_code"], "COLLECTION_NOT_FOUND", "{parsed}");
}

/// The `initialize` result the client actually receives fits Claude Code's
/// 4,096-character read and carries the dry_run rule.
#[tokio::test]
async fn initialize_instructions_fit_and_lead_with_the_dry_run_rule() {
    let h = helpers::spin_up_account_mcp("mcpinstr").await;
    let result = rpc_result(&h, helpers::mcp_init("2024-11-05")).await;
    let s = result["instructions"]
        .as_str()
        .expect("initialize result must carry string instructions");
    let n = s.encode_utf16().count();
    assert!(
        n <= 4096,
        "instructions on the wire are {n} UTF-16 units (cap 4096)"
    );
    assert!(
        s.contains("Only delete_record, drop_collection and drop_index accept"),
        "instructions on the wire: {s}"
    );
}

/// The isError body of a tools/call answer, parsed.
fn tool_error_body(m: &Value) -> Value {
    assert_eq!(m["result"]["isError"], Value::Bool(true), "{m}");
    let text = m["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("isError without text content: {m}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("isError text is not JSON ({e}): {text}"))
}

/// `(message, error_code)` of a refused tool call's isError body.
fn tool_err(m: &Value) -> (String, String) {
    let b = tool_error_body(m);
    (
        b["message"]
            .as_str()
            .unwrap_or_else(|| panic!("isError body without a message: {m}"))
            .to_string(),
        b["error_code"].as_str().unwrap_or("").to_string(),
    )
}

/// rmcp 1.8 answers a malformed argument with its own plain-text isError;
/// drust reshapes it into its one isError body (`finish_tool_call`).
#[tokio::test]
async fn tools_call_missing_argument_is_invalid_params_tool_error() {
    let h = helpers::spin_up_account_mcp("mcparg1").await;
    let m = call(&h, "describe_collection", json!({})).await;
    let b = tool_error_body(&m);
    assert_eq!(b["error_code"], "INVALID_PARAMS", "{b}");
    assert!(
        b["message"]
            .as_str()
            .unwrap()
            .contains("missing field `collection`"),
        "{b}"
    );
    assert!(b["suggested_fix"].as_str().is_some(), "{b}");
}

#[tokio::test]
async fn tools_call_wrongly_typed_argument_is_invalid_params_tool_error() {
    let h = helpers::spin_up_account_mcp("mcparg2").await;
    let m = call(&h, "delete_record", json!({"collection": "x", "id": "abc"})).await;
    let b = tool_error_body(&m);
    assert_eq!(b["error_code"], "INVALID_PARAMS", "{b}");
    assert!(
        b["message"].as_str().unwrap().contains("expected i64"),
        "{b}"
    );
}

#[tokio::test]
async fn tools_call_unknown_tool_stays_protocol_error() {
    let h = helpers::spin_up_account_mcp("mcparg3").await;
    let m = call(&h, "no_such_tool", json!({})).await;
    assert_eq!(m["error"]["code"], -32602, "{m}");
    assert_eq!(m["error"]["message"], "tool not found", "{m}");
}

/// `query`'s write refusal used to ship the prose before its first colon as
/// its `error_code`.
#[tokio::test]
async fn query_write_refusal_carries_query_forbidden() {
    let h = with_collection("mcpqf").await;
    let m = call(&h, "query", json!({"sql": "DELETE FROM t"})).await;
    let b = tool_error_body(&m);
    assert!(
        b["message"]
            .as_str()
            .unwrap()
            .contains("`query` is read-only"),
        "{m}"
    );
    assert_eq!(b["error_code"], "QUERY_FORBIDDEN", "{m}");
}

/// The unknown-key refusal names the caller's key first; a key shaped like a
/// code must not become the code.
#[tokio::test]
async fn insert_unknown_key_carries_field_not_found() {
    let h = with_collection("mcpfnf").await;
    let m = call(
        &h,
        "insert_record",
        json!({"collection": "t", "data": {"A_B: x": 1}}),
    )
    .await;
    let b = tool_error_body(&m);
    let msg = b["message"].as_str().unwrap_or_else(|| panic!("{m}"));
    assert!(msg.starts_with("unknown field 'A_B: x'"), "{m}");
    assert_eq!(b["error_code"], "FIELD_NOT_FOUND", "{m}");
}

/// `create_rpc` refusals used to carry no code at all. Each stage now names
/// its own code; the message is unchanged.
#[tokio::test]
async fn create_rpc_refusals_carry_exact_codes() {
    let h = with_collection("mcprpc1").await;
    let m = call(
        &h,
        "create_rpc",
        json!({"name": "bad", "sql": "SELECT name FROM sqlite_master", "params": []}),
    )
    .await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("prepare-time validation"), "{m}");
    assert_eq!(ec, "INVALID_SQL_FOR_MODE", "{m}");

    let ok = json!({"name": "r", "sql": "SELECT title FROM t", "params": []});
    let m = call(&h, "create_rpc", ok.clone()).await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let m = call(&h, "create_rpc", ok).await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("rpc already exists"), "{m}");
    assert_eq!(ec, "RPC_EXISTS", "{m}");
    assert!(
        tool_error_body(&m)["suggested_fix"].as_str().is_some(),
        "{m}"
    );

    let m = call(
        &h,
        "create_rpc",
        json!({"name": "q", "kind": "query", "query": {"collection": "_system_users"}, "params": []}),
    )
    .await;
    assert_eq!(tool_err(&m).1, "PROTECTED_COLLECTION", "{m}");

    // A template rejection with no sentinel of its own: the stage knows it
    // was the query arm (RPC_QUERY_TEMPLATE_INVALID, the admin form's code);
    // the message alone would only classify as a generic prepare failure.
    let m = call(
        &h,
        "create_rpc",
        json!({"name": "q1", "kind": "query",
               "query": {"collection": "t", "filter": {"title": {"$param": "x"}}},
               "params": []}),
    )
    .await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("undeclared param"), "{m}");
    assert_eq!(ec, "RPC_QUERY_TEMPLATE_INVALID", "{m}");

    // The shape check runs before any DB work (`invalid_params`): the
    // backstop finds the sentinel right after PrepareError's prefix.
    let m = call(
        &h,
        "create_rpc",
        json!({"name": "q2", "kind": "query", "params": []}),
    )
    .await;
    let (_, ec) = tool_err(&m);
    assert_eq!(ec, "RPC_KIND_INVALID", "{m}");
}

/// The RPC_ANON_OWNER_SCOPED guard family: create, the update flip, and the
/// two config surfaces that wrap a PrepareError (set_owner_field, set_policy)
/// all carry the sentinel, not PrepareError's prose prefix.
#[tokio::test]
async fn owner_field_guard_carries_rpc_anon_owner_scoped() {
    let h = helpers::spin_up_account_mcp("mcprpc2").await;
    let m = call(
        &h,
        "create_collection",
        json!({"name": "pub", "fields": [
            {"name": "title", "sql_type": "text"},
            {"name": "owner", "sql_type": "text", "foreign_key": "_system_users"}
        ]}),
    )
    .await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let m = call(
        &h,
        "create_rpc",
        json!({"name": "r_pub", "sql": "SELECT id, title FROM pub", "params": [], "anon_callable": true}),
    )
    .await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");

    let m = call(
        &h,
        "set_owner_field",
        json!({"collection": "pub", "field": "owner"}),
    )
    .await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("RPC_ANON_OWNER_SCOPED"), "{m}");
    assert_eq!(ec, "RPC_ANON_OWNER_SCOPED", "{m}");

    let m = call(
        &h,
        "set_policy",
        json!({"collection": "pub", "op": "select", "using": {"title": "x"}}),
    )
    .await;
    assert_eq!(tool_err(&m).1, "RPC_ANON_OWNER_SCOPED", "{m}");

    // An owner-scoped collection: the create guard refuses an anon_callable
    // RPC over it, and the update guard refuses flipping a service-only one.
    let m = call(
        &h,
        "create_collection",
        json!({"name": "own", "fields": [
            {"name": "title", "sql_type": "text"},
            {"name": "owner", "sql_type": "text", "foreign_key": "_system_users"}
        ]}),
    )
    .await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let m = call(
        &h,
        "set_owner_field",
        json!({"collection": "own", "field": "owner"}),
    )
    .await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let m = call(
        &h,
        "create_rpc",
        json!({"name": "r_own", "sql": "SELECT id, title FROM own", "params": [], "anon_callable": true}),
    )
    .await;
    assert_eq!(tool_err(&m).1, "RPC_ANON_OWNER_SCOPED", "{m}");
    let m = call(
        &h,
        "create_rpc",
        json!({"name": "r_own_svc", "sql": "SELECT id, title FROM own", "params": []}),
    )
    .await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let m = call(
        &h,
        "update_rpc",
        json!({"name": "r_own_svc", "anon_callable": true}),
    )
    .await;
    assert_eq!(tool_err(&m).1, "RPC_ANON_OWNER_SCOPED", "{m}");
}

#[tokio::test]
async fn update_and_delete_rpc_missing_name_is_rpc_not_found() {
    let h = helpers::spin_up_account_mcp("mcprpc3").await;
    let m = call(
        &h,
        "update_rpc",
        json!({"name": "nope", "description": "x"}),
    )
    .await;
    let (_, ec) = tool_err(&m);
    assert_eq!(ec, "RPC_NOT_FOUND", "{m}");

    let m = call(&h, "delete_rpc", json!({"name": "nope"})).await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("rpc not found"), "{m}");
    assert_eq!(ec, "RPC_NOT_FOUND", "{m}");
}

/// `update_rpc`'s template stage names its own code. Only the side channel
/// can say RPC_QUERY_TEMPLATE_INVALID here: the message alone is a generic
/// prepare failure, which the `call_tool` backstop would call
/// INVALID_SQL_FOR_MODE.
#[tokio::test]
async fn update_rpc_template_rejection_is_rpc_query_template_invalid() {
    let h = with_collection("mcprpc5").await;
    let m = call(
        &h,
        "create_rpc",
        json!({"name": "q", "kind": "query",
               "query": {"collection": "t", "filter": {"title": "a"}},
               "params": []}),
    )
    .await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let m = call(
        &h,
        "update_rpc",
        json!({"name": "q",
               "query": {"collection": "t", "filter": {"title": {"$param": "x"}}}}),
    )
    .await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("undeclared param"), "{m}");
    assert_eq!(ec, "RPC_QUERY_TEMPLATE_INVALID", "{m}");
}

/// `create_collection` has no existence pre-check, so a repeat forwards
/// SQLite's `table "<name>" already exists`. A name containing "index" must
/// still be COLLECTION_EXISTS, not INDEX_EXISTS.
#[tokio::test]
async fn create_collection_repeat_is_collection_exists_whatever_the_name() {
    let h = helpers::spin_up_account_mcp("mcpdup").await;
    let args = json!({"name": "index_log", "fields": [{"name": "title", "sql_type": "text"}]});
    let m = call(&h, "create_collection", args.clone()).await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let m = call(&h, "create_collection", args).await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("already exists"), "{m}");
    assert_eq!(ec, "COLLECTION_EXISTS", "{m}");
    assert!(
        tool_error_body(&m)["suggested_fix"].as_str().is_some(),
        "{m}"
    );
}

/// `call_rpc` answers with the codes REST's RPC handler uses.
#[tokio::test]
async fn call_rpc_errors_carry_rest_param_codes() {
    let h = with_collection("mcprpc4").await;
    let m = call(&h, "call_rpc", json!({"name": "nope"})).await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("no such rpc"), "{m}");
    assert_eq!(ec, "RPC_NOT_FOUND", "{m}");

    let m = call(
        &h,
        "create_rpc",
        json!({"name": "by_id", "sql": "SELECT title FROM t WHERE id > :n",
               "params": [{"name": "n", "type": "integer"}]}),
    )
    .await;
    assert_ne!(m["result"]["isError"], json!(true), "{m}");
    let m = call(&h, "call_rpc", json!({"name": "by_id"})).await;
    let (msg, ec) = tool_err(&m);
    assert!(msg.contains("missing required param"), "{m}");
    assert_eq!(ec, "PARAM_MISSING", "{m}");

    let m = call(
        &h,
        "call_rpc",
        json!({"name": "by_id", "body": {"n": "abc"}}),
    )
    .await;
    assert_eq!(tool_err(&m).1, "PARAM_TYPE_MISMATCH", "{m}");
}

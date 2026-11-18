//! v1.58 — `recent_writes` returned 50 rows while telling the model it returned
//! 100. The tool is used to reconcile after a failed or retried write, so a
//! model that believes it has seen the last 100 mutations when it has seen 50
//! will redo the ones that fell in the gap.
//!
//! The default lives in the MCP handler, not in `query_recent`, so the only
//! honest place to observe it is a real `tools/call` with no `limit` argument.
//! The fixture keeps a handle on the very `meta_logs.sqlite` connection the
//! account-level endpoint's per-call `DrustMcp` reads from
//! (`AccountMcpHarness::audit`), seeds it with more write rows than any limit
//! under test, and drives the tool over `/mcp`.

mod helpers;

use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Rows seeded into the audit DB — comfortably above the 200 clamp ceiling so
/// both the new default and the clamp are observable.
const SEEDED_WRITES: usize = 250;

/// Seed `SEEDED_WRITES` `insert_record` audit rows for `tenant`, ascending in
/// time so the newest-first ordering has something to cut.
async fn seed_writes(audit: &Arc<Mutex<Connection>>, tenant: &str) {
    let guard = audit.lock().await;
    for i in 0..SEEDED_WRITES {
        guard
            .execute(
                "INSERT INTO audit (ts, tenant, token_hint, op, status, duration_ms, extra) \
                 VALUES (?1, ?2, '-', 'insert_record', 'ok', 1, '{\"collection\":\"rows\"}')",
                rusqlite::params![
                    format!("2026-08-02T00:{:02}:{:02}.000Z", i / 60, i % 60),
                    tenant
                ],
            )
            .unwrap();
    }
}

/// `recent_writes` over the account-level endpoint; the rows it returned.
async fn recent_writes(
    h: &helpers::AccountMcpHarness,
    limit: Option<u32>,
) -> Vec<serde_json::Value> {
    let mut args = serde_json::Map::new();
    if let Some(l) = limit {
        args.insert("limit".into(), serde_json::json!(l));
    }
    let text = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "recent_writes",
        serde_json::Value::Object(args),
    )
    .await;
    serde_json::from_str::<Vec<serde_json::Value>>(&text)
        .unwrap_or_else(|e| panic!("recent_writes returned {text}: {e}"))
}

#[tokio::test]
async fn recent_writes_default_matches_its_advertised_limit() {
    let h = helpers::spin_up_account_mcp("rwlimit").await;
    seed_writes(&h.audit, "rwlimit").await;
    let rows = recent_writes(&h, None).await;
    assert_eq!(
        rows.len(),
        100,
        "the default must match the 100 the tool description and the instructions both promise"
    );
}

/// The instructions point the model at `tools/list` for each tool's full
/// schema, and schemars publishes the `RecentWritesArgs::limit`
/// doc comment verbatim as that parameter's description. So the doc comment is
/// not prose — it is the machine-readable half of the same promise, and the one
/// most MCP clients render into the system prompt. If it disagrees with what
/// the handler actually does, the model holds two numbers for one parameter.
#[tokio::test]
async fn tools_list_schema_advertises_the_same_default() {
    let h = helpers::spin_up_account_mcp("rwlimit3").await;
    let (status, _, msgs) = helpers::mcp_rpc(
        &h.app,
        Some(&h.access),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let tools = msgs
        .iter()
        .find_map(|m| m["result"]["tools"].as_array().cloned())
        .unwrap_or_else(|| panic!("no tools array in {msgs:?}"));
    let tool = tools
        .iter()
        .find(|t| t["name"] == "recent_writes")
        .expect("recent_writes listed");
    let desc = tool["inputSchema"]["properties"]["limit"]["description"]
        .as_str()
        .unwrap_or_else(|| panic!("no description on limit: {}", tool["inputSchema"]));
    assert!(
        !desc.contains("50"),
        "old default still advertised: {desc:?}"
    );
    assert!(
        desc.contains("100"),
        "the real default of 100 must be stated: {desc:?}"
    );
}

#[tokio::test]
async fn an_explicit_limit_still_wins_and_is_clamped() {
    let h = helpers::spin_up_account_mcp("rwlimit2").await;
    seed_writes(&h.audit, "rwlimit2").await;
    assert_eq!(
        recent_writes(&h, Some(3)).await.len(),
        3,
        "an explicit limit still wins"
    );
    // Above the clamp ceiling: `query_recent` clamps to 1..=200.
    assert_eq!(
        recent_writes(&h, Some(9_999)).await.len(),
        200,
        "clamped to the 200 ceiling, not {SEEDED_WRITES}"
    );
}

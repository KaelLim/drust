//! Tenant visibility on the account-level MCP endpoint: list_tenants shows
//! exactly the tenants the signed-in account can see, decided on every call,
//! and a revoked grant or a deleted admin is refused on the next call.

mod helpers;

use serde_json::{Value, json};

fn list_body() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "list_tenants", "arguments": {}}})
}
async fn list(h: &helpers::AccountMcpHarness, token: &str) -> Value {
    let (status, _, msgs) = helpers::mcp_rpc(&h.app, Some(token), list_body()).await;
    assert_eq!(status, 200);
    let text = msgs[0]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(text).unwrap()
}
fn ids(v: &Value) -> Vec<String> {
    v["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap().to_string())
        .collect()
}
async fn sql(h: &helpers::AccountMcpHarness, q: &str, p: impl rusqlite::Params) {
    h.meta.lock().await.execute(q, p).unwrap();
}
fn sorted(v: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = v.iter().map(|s| s.to_string()).collect();
    v.sort();
    v
}

/// admins[0] "mcp-owner" (h.admin_id, owns "blog" = h.tid), admins[1] "other"
/// (member, owns "zz-foreign"); plus an orphan and a soft-deleted tenant of admins[0].
async fn harness() -> helpers::AccountMcpHarness {
    let h = helpers::spin_up_account_mcp_with(helpers::AccountMcpOpts {
        admins: vec![("mcp-owner", "owner"), ("other", "member")],
        tenants: vec![("blog", Some(0)), ("zz-foreign", Some(1))],
        files: false,
        mcp_enabled: true,
    })
    .await;
    sql(
        &h,
        "INSERT INTO tenants (id, name) VALUES ('zz-orphan', 'O')",
        [],
    )
    .await;
    sql(
        &h,
        "INSERT INTO tenants (id, name, owner_admin_id, deleted_at) \
            VALUES ('zz-gone', 'G', ?1, datetime('now'))",
        [h.admin_id],
    )
    .await;
    h
}

#[tokio::test]
async fn member_lists_only_the_tenants_it_owns() {
    let h = harness().await;
    sql(
        &h,
        "UPDATE admins SET role = 'member' WHERE id = ?1",
        [h.admin_id],
    )
    .await;
    let v = list(&h, &h.access).await;
    assert_eq!(ids(&v), vec![h.tid.clone()]);
    assert_eq!(v["admin"]["id"], h.admin_id);
    assert_eq!(v["admin"]["role"], "member");
    assert!(v["mcp_url"].as_str().unwrap().ends_with("/mcp"));
}

#[tokio::test]
async fn sees_all_admin_sees_orphans_but_not_deleted() {
    let h = harness().await;
    sql(
        &h,
        "UPDATE admins SET role = 'admin' WHERE id = ?1",
        [h.admin_id],
    )
    .await;
    assert_eq!(
        ids(&list(&h, &h.access).await),
        sorted(&["blog", "zz-foreign", "zz-orphan"])
    );
}

#[tokio::test]
async fn a_demotion_takes_effect_on_the_next_call() {
    let h = harness().await;
    assert!(ids(&list(&h, &h.access).await).contains(&"zz-foreign".to_string()));
    sql(
        &h,
        "UPDATE admins SET role = 'member' WHERE id = ?1",
        [h.admin_id],
    )
    .await;
    assert_eq!(ids(&list(&h, &h.access).await), vec![h.tid.clone()]);
}

#[tokio::test]
async fn an_owner_transfer_moves_visibility_on_the_next_call() {
    let h = harness().await;
    let other = &h.accesses[1];
    sql(
        &h,
        "UPDATE admins SET role = 'member' WHERE id = ?1",
        [h.admin_id],
    )
    .await;
    assert_eq!(ids(&list(&h, &h.access).await), vec![h.tid.clone()]);
    sql(
        &h,
        "UPDATE tenants SET owner_admin_id = ?1 WHERE id = ?2",
        rusqlite::params![other.admin_id, h.tid],
    )
    .await;
    assert!(
        ids(&list(&h, &h.access).await).is_empty(),
        "the previous owner no longer sees it"
    );
    assert_eq!(
        ids(&list(&h, &other.access).await),
        sorted(&["blog", "zz-foreign"]),
        "the new owner does"
    );
}

#[tokio::test]
async fn a_revoked_grant_is_refused_on_the_next_call() {
    let h = harness().await;
    assert!(!ids(&list(&h, &h.access).await).is_empty());
    sql(
        &h,
        "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now') WHERE id = ?1",
        [h.grant_id],
    )
    .await;
    let (status, hd, _) = helpers::mcp_rpc(&h.app, Some(&h.access), list_body()).await;
    assert_eq!(status, 401);
    assert!(
        hd["www-authenticate"]
            .to_str()
            .unwrap()
            .ends_with(r#"error="invalid_token""#)
    );
}

#[tokio::test]
async fn a_deleted_admin_is_refused_on_the_next_call() {
    let h = harness().await;
    let other = &h.accesses[1];
    assert_eq!(
        ids(&list(&h, &other.access).await),
        vec!["zz-foreign".to_string()]
    );
    sql(&h, "DELETE FROM admins WHERE id = ?1", [other.admin_id]).await;
    let (status, hd, _) = helpers::mcp_rpc(&h.app, Some(&other.access), list_body()).await;
    assert_eq!(status, 401);
    assert!(
        hd["www-authenticate"]
            .to_str()
            .unwrap()
            .ends_with(r#"error="invalid_token""#)
    );
    assert!(
        ids(&list(&h, &h.access).await).contains(&"zz-foreign".to_string()),
        "owner still sees the orphaned tenant"
    );
}

#[tokio::test]
async fn tools_list_names_only_list_tenants() {
    let h = helpers::spin_up_account_mcp("blog").await;
    let (status, _, msgs) = helpers::mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
    )
    .await;
    assert_eq!(status, 200);
    let tools = msgs[0]["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["list_tenants"]);
}

#[tokio::test]
async fn tools_list_entry_for_list_tenants_carries_its_annotations() {
    let h = helpers::spin_up_account_mcp("blog").await;
    let (_, _, msgs) = helpers::mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
    )
    .await;
    let t = msgs[0]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "list_tenants")
        .expect("list_tenants advertised");
    assert_eq!(
        t["annotations"],
        json!({"readOnlyHint": true, "openWorldHint": false})
    );
    assert_eq!(t["_meta"], json!({"anthropic/alwaysLoad": true}));
    assert_eq!(
        t["inputSchema"],
        json!({"type": "object", "properties": {}})
    );
}

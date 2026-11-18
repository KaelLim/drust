mod helpers;

/// The account harness the original self-register fixture stood for: one
/// tenant, self-registration on, tools driven over `/mcp`.
async fn harness(t: &'static str) -> helpers::AccountMcpHarness {
    let h = helpers::spin_up_account_mcp(t).await;
    helpers::account_allow_self_register(&h).await;
    h
}

/// The first content text of a `tools/call` on the account endpoint.
async fn tool(h: &helpers::AccountMcpHarness, name: &str, args: serde_json::Value) -> String {
    helpers::mcp_tool_text(&h.app, &h.access, &h.tid, name, args).await
}

#[tokio::test]
async fn set_description_dispatches_by_target() {
    let h = harness("t-setdesc").await;
    let pool = h.tenants.get_or_create(&h.tid).unwrap();
    pool.with_writer(|c| c.execute_batch(
        "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));\n         CREATE INDEX idx_posts_title ON posts(title);")).await.unwrap();

    let c = tool(
        &h,
        "set_description",
        serde_json::json!({"target":"collection","collection":"posts","description":"Blog posts"}),
    )
    .await;
    assert!(c.contains("Blog posts"), "collection desc: {c}");
    let f = tool(&h, "set_description", serde_json::json!({"target":"field","collection":"posts","field":"title","description":"Post title"})).await;
    assert!(f.contains("Post title"), "field desc: {f}");
    let i = tool(&h, "set_description", serde_json::json!({"target":"index","collection":"posts","index_name":"idx_posts_title","description":"title lookup"})).await;
    assert!(i.contains("title lookup"), "index desc: {i}");
    let nf = tool(&h, "set_description", serde_json::json!({"target":"field","collection":"posts","field":"ghost","description":"x"})).await;
    assert!(
        nf.contains("FIELD_NOT_FOUND"),
        "missing-field still errors: {nf}"
    );
}

// §Isolation #2 — the merged set_description path must still refuse _system_* tables.
// (The is_protected_collection check lives inside each schema::set_* impl; this locks
// it for the merged dispatch entry.)
#[tokio::test]
async fn set_description_on_system_table_is_protected() {
    let h = harness("t-setdesc-prot").await;
    let r = tool(&h, "set_description",
        serde_json::json!({"target":"collection","collection":"_system_files","description":"nope"})).await;
    assert!(
        r.contains("PROTECTED_COLLECTION"),
        "_system_* must stay protected on set_description: {r}"
    );
}

#[tokio::test]
async fn set_owner_field_null_clears() {
    let h = harness("t-ofnull").await;
    let pool = h.tenants.get_or_create(&h.tid).unwrap();
    pool.with_writer(|c| c.execute_batch(
        "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT REFERENCES _system_users(id), title TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));")).await.unwrap();

    let set = tool(
        &h,
        "set_owner_field",
        serde_json::json!({"collection":"posts","field":"user_id","read_scope":"own"}),
    )
    .await;
    assert!(
        set.contains("owner_field") && set.contains("user_id"),
        "set: {set}"
    );

    let cleared = tool(
        &h,
        "set_owner_field",
        serde_json::json!({"collection":"posts","field":serde_json::Value::Null}),
    )
    .await;
    assert!(cleared.contains("cleared"), "null clears: {cleared}");

    // Verify persisted state: owner_field back to NULL.
    let of: Option<String> = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT owner_field FROM _system_collection_meta WHERE collection_name='posts'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert!(
        of.is_none(),
        "owner_field should be NULL after clear, got {of:?}"
    );
}

#[tokio::test]
async fn sample_and_count_removed_list_records_covers() {
    let h = harness("t-nosample").await;
    let pool = h.tenants.get_or_create(&h.tid).unwrap();
    pool.with_writer(|c| c.execute_batch(
        "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));\n         INSERT INTO posts (title) VALUES ('a'),('b'),('c');")).await.unwrap();

    // tools/list must NOT contain the removed names.
    let (_, _, msgs) = helpers::mcp_rpc(
        &h.app,
        Some(&h.access),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    )
    .await;
    let names: Vec<String> = msgs
        .iter()
        .find_map(|m| m["result"]["tools"].as_array().cloned())
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n == "sample_rows"),
        "sample_rows must be gone: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "count_rows"),
        "count_rows must be gone: {names:?}"
    );

    // list_records subsumes both: it returns total + perPage.
    let lr = tool(
        &h,
        "list_records",
        serde_json::json!({"collection":"posts","per_page":2}),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&lr).unwrap();
    assert_eq!(v["total"], 3, "total covers count_rows: {lr}");
    assert_eq!(v["perPage"], 2, "perPage present: {lr}");
    assert_eq!(
        v["records"].as_array().unwrap().len(),
        2,
        "per_page sample covers sample_rows: {lr}"
    );
}

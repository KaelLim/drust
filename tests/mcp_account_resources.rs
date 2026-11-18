//! Account-level /mcp resources and prompts: tenant-first, checked on every call, one answer for every refusal.

#[path = "helpers.rs"]
mod helpers;

use axum::http::StatusCode;
use helpers::{
    AccountMcpHarness, McpAccess, mcp_call, mcp_rpc, seed_mcp_access, spin_up_account_mcp,
};
use serde_json::{Value, json};

fn rpc(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

/// member owns live "mine-r"; "gone-r" is member-owned and soft-deleted;
/// "acct-res" is foreign to the member; "nope-r" does not exist.
async fn member_world(h: &AccountMcpHarness) -> McpAccess {
    let m = {
        let g = h.meta.lock().await;
        seed_mcp_access(&g, "member", "mallory-res")
    };
    h.tenants.get_or_create("mine-r").unwrap();
    {
        let g = h.meta.lock().await;
        g.execute(
            "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('mine-r', 'Mine', ?1)",
            [m.admin_id],
        )
        .unwrap();
        g.execute(
            "INSERT INTO tenants (id, name, owner_admin_id, deleted_at) \
             VALUES ('gone-r', 'Gone', ?1, datetime('now'))",
            [m.admin_id],
        )
        .unwrap();
    }
    m
}

/// One `resources/read`: (HTTP status, content-type, first message).
async fn read(h: &AccountMcpHarness, token: &str, uri: &str) -> (StatusCode, String, Value) {
    let (s, hd, mut m) = mcp_rpc(
        &h.app,
        Some(token),
        rpc("resources/read", json!({"uri": uri})),
    )
    .await;
    let ct = hd
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(!m.is_empty(), "resources/read {uri}: no message");
    (s, ct, m.swap_remove(0))
}

/// One `prompts/get`: (HTTP status, content-type, first message).
async fn prompt(
    h: &AccountMcpHarness,
    token: &str,
    name: &str,
    args: Value,
) -> (StatusCode, String, Value) {
    let (s, hd, mut m) = mcp_rpc(
        &h.app,
        Some(token),
        rpc("prompts/get", json!({"name": name, "arguments": args})),
    )
    .await;
    let ct = hd
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(!m.is_empty(), "prompts/get {name}: no message");
    (s, ct, m.swap_remove(0))
}

/// The refusal of a resource read; `shown` is the URI as the message shows it.
fn not_found(shown: &str) -> Value {
    json!({"code": -32002, "message": format!("no such resource: {shown}")})
}

fn prompt_text(m: &Value) -> String {
    m["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no prompt text: {m}"))
        .to_string()
}

#[tokio::test]
async fn resources_list_is_empty_and_templates_are_fourteen() {
    let h = spin_up_account_mcp("acct-res").await;
    let (_, _, m) = mcp_rpc(&h.app, Some(&h.access), rpc("resources/list", json!({}))).await;
    assert_eq!(m[0]["result"]["resources"], json!([]));
    let (_, _, m) = mcp_rpc(
        &h.app,
        Some(&h.access),
        rpc("resources/templates/list", json!({})),
    )
    .await;
    let t = m[0]["result"]["resourceTemplates"].as_array().unwrap();
    assert_eq!(t.len(), 14);
    for x in t {
        assert!(
            x["uriTemplate"]
                .as_str()
                .unwrap()
                .starts_with("drust://{tenant}/"),
            "{x}"
        );
    }
}

#[tokio::test]
async fn denied_resource_reads_match_a_bad_uri() {
    let h = spin_up_account_mcp("acct-res").await;
    let m = member_world(&h).await;
    let mut uris: Vec<String> = ["acct-res", "gone-r", "nope-r", "Bad_Id"]
        .iter()
        .map(|t| format!("drust://{t}/schema.md"))
        .collect();
    uris.push("drust://mine-r/no-such-path".into());
    let mut first: Option<(StatusCode, String)> = None;
    for uri in &uris {
        let (s, ct, msg) = read(&h, &m.access, uri).await;
        // A URI that does not parse is never echoed back.
        let shown = if uri.contains("Bad_Id") || uri.contains("no-such-path") {
            "<invalid>"
        } else {
            uri.as_str()
        };
        assert_eq!(msg["error"], not_found(shown), "{uri}");
        match &first {
            None => first = Some((s, ct)),
            Some(f) => assert_eq!(&(s, ct), f, "{uri}"),
        }
    }
    let (_, _, ok) = read(&h, &m.access, "drust://mine-r/schema.md").await;
    assert_eq!(
        ok["result"]["contents"][0]["mimeType"], "text/markdown",
        "{ok}"
    );
}

#[tokio::test]
async fn odd_resource_uris_are_plain_not_found() {
    let h = spin_up_account_mcp("acct-res").await;
    // nope-r does not exist; the harness owner sees every live tenant.
    let mut first: Option<(StatusCode, String)> = None;
    for uri in [
        "drust://{tenant}/schema",
        "drust://ACCT-RES/schema",
        "drust://acct-res:1/schema",
        "drust://u@acct-res/schema",
        "drust://acct-res@nope-r/schema",
        "drust://%61cct-res/schema",
        "drust:schema",
        "not a uri",
    ] {
        let (s, ct, msg) = read(&h, &h.access, uri).await;
        assert_eq!(msg["error"], not_found("<invalid>"), "{uri}");
        assert_eq!(s, StatusCode::OK, "{uri}");
        match &first {
            None => first = Some((s, ct)),
            Some(f) => assert_eq!(&(s, ct), f, "{uri}"),
        }
    }
}

#[tokio::test]
async fn account_files_guide_has_no_service_key_instructions() {
    let h = spin_up_account_mcp("acct-res").await;
    let (_, _, msg) = read(&h, &h.access, "drust://acct-res/files-guide.md").await;
    let text = msg["result"]["contents"][0]["text"].as_str().unwrap();
    for gone in [
        "DRUST_SERVICE_TOKEN",
        "(service bearer)",
        "whoami` tool for the service",
    ] {
        assert!(!text.contains(gone), "{gone:?}");
    }
    assert!(text.contains("## 5. Uploading from this connection"));
    assert!(text.contains("## 6. This tenant's publish grants (live)"));
}

#[tokio::test]
async fn prompts_take_tenant_first() {
    let h = spin_up_account_mcp("acct-res").await;
    let (_, _, m) = mcp_rpc(&h.app, Some(&h.access), rpc("prompts/list", json!({}))).await;
    let p = m[0]["result"]["prompts"].as_array().unwrap();
    assert_eq!(p.len(), 6);
    for x in p {
        assert_eq!(
            x["arguments"][0],
            json!({"name": "tenant", "description": "Tenant id (from list_tenants).", "required": true}),
            "{x}"
        );
    }
}

#[tokio::test]
async fn denied_prompts_are_identical() {
    let h = spin_up_account_mcp("acct-res").await;
    let m = member_world(&h).await;
    let mut first: Option<(StatusCode, String)> = None;
    for t in ["acct-res", "gone-r", "nope-r", "Bad_Id"] {
        let (s, ct, msg) = prompt(
            &h,
            &m.access,
            "secure_collection",
            json!({"tenant": t, "collection": "posts"}),
        )
        .await;
        assert_eq!(
            msg["error"],
            json!({"code": -32602, "message": "tenant not found", "data": {"error_code": "TENANT_NOT_FOUND"}}),
            "{t}"
        );
        match &first {
            None => first = Some((s, ct)),
            Some(f) => assert_eq!(&(s, ct), f, "{t}"),
        }
    }
}

#[tokio::test]
async fn prompt_argument_errors_are_distinct() {
    let h = spin_up_account_mcp("acct-res").await;
    for args in [json!({"tenant": 7}), json!({})] {
        let (_, _, msg) = prompt(&h, &h.access, "bootstrap", args.clone()).await;
        assert_eq!(
            msg["error"]["data"]["error_code"], "TENANT_REQUIRED",
            "{args}"
        );
        assert_eq!(
            msg["error"]["message"], "missing required argument: tenant",
            "{args}"
        );
    }
    let (_, _, msg) = prompt(
        &h,
        &h.access,
        "secure_collection",
        json!({"tenant": "acct-res"}),
    )
    .await;
    assert_eq!(
        msg["error"],
        json!({"code": -32602, "message": "missing required argument: collection"})
    );
}

#[tokio::test]
async fn account_prompts_point_uploads_at_the_admin_ui() {
    let h = spin_up_account_mcp("acct-res").await;
    let (_, _, msg) = prompt(
        &h,
        &h.access,
        "write_edge_function",
        json!({"tenant": "acct-res", "trigger": "record.created"}),
    )
    .await;
    let t = prompt_text(&msg);
    for gone in ["service-token", "whoami", "curl -X POST"] {
        assert!(!t.contains(gone), "{gone:?}");
    }
    assert!(t.contains("Build it, then ask the user to upload the .wasm"));
    assert!(t.contains("EGRESS_NOT_ALLOWLISTED"));
    assert_eq!(t.matches("GOTCHA — the #1 first-run failure").count(), 1);
    let (_, _, msg) = prompt(&h, &h.access, "bootstrap", json!({"tenant": "acct-res"})).await;
    let t = prompt_text(&msg);
    assert!(t.contains("`resources/templates/list`"));
    assert!(!t.contains("`resources/list` +"));
    assert!(t.contains("tenant `acct-res`"));
}

#[tokio::test]
async fn list_tenants_schema_md_uris_are_readable() {
    let h = spin_up_account_mcp("acct-res").await;
    let (_, _, m) = mcp_rpc(
        &h.app,
        Some(&h.access),
        rpc(
            "tools/call",
            json!({"name": "list_tenants", "arguments": {}}),
        ),
    )
    .await;
    let v: Value =
        serde_json::from_str(m[0]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let tenants = v["tenants"].as_array().unwrap();
    assert!(!tenants.is_empty());
    for t in tenants {
        let id = t["id"].as_str().unwrap();
        let uri = t["resources"]["schema_md"].as_str().unwrap();
        assert_eq!(uri, format!("drust://{id}/schema.md"));
        let (_, _, msg) = read(&h, &h.access, uri).await;
        assert!(
            msg["result"]["contents"][0]["text"].is_string(),
            "{uri}: {msg}"
        );
    }
}

#[tokio::test]
async fn resources_and_prompts_follow_an_owner_transfer_on_the_next_call() {
    let h = spin_up_account_mcp("acct-res").await;
    let m = member_world(&h).await;
    let uri = "drust://mine-r/schema.md";
    let (_, _, msg) = read(&h, &m.access, uri).await;
    assert!(msg["result"]["contents"][0]["text"].is_string(), "{msg}");
    let args = json!({"tenant": "mine-r", "collection": "posts"});
    let (_, _, msg) = prompt(&h, &m.access, "secure_collection", args.clone()).await;
    assert_eq!(
        msg["error"]["message"], "no such collection: posts",
        "{msg}"
    );
    {
        let g = h.meta.lock().await;
        g.execute(
            "UPDATE tenants SET owner_admin_id = ?1 WHERE id = 'mine-r'",
            [h.admin_id],
        )
        .unwrap();
    }
    let (_, _, msg) = read(&h, &m.access, uri).await;
    assert_eq!(msg["error"], not_found(uri));
    let (_, _, msg) = prompt(&h, &m.access, "secure_collection", args).await;
    assert_eq!(msg["error"]["message"], "tenant not found");
}

/// `-` is the host audit key and reserved as a tenant id. A live row with that
/// id (one that predates the reservation, owned by the caller) changes no
/// answer: a tool call, a resource read and a prompt naming it answer exactly
/// what they answered before the row existed, which is the missing-tenant
/// answer.
#[tokio::test]
async fn the_host_audit_key_answers_like_a_missing_tenant_even_when_a_row_has_it() {
    let h = spin_up_account_mcp("acct-res").await;
    let tool = |t: &'static str| {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "list_collections", "arguments": {"tenant": t}}})
    };
    let answers = || async {
        let (ts, _, mut tm) = mcp_rpc(&h.app, Some(&h.access), tool("-")).await;
        let (rs, rct, r) = read(&h, &h.access, "drust://-/schema").await;
        let (ps, pct, p) = prompt(
            &h,
            &h.access,
            "secure_collection",
            json!({"tenant": "-", "collection": "posts"}),
        )
        .await;
        (ts, tm.swap_remove(0), rs, rct, r, ps, pct, p)
    };
    let before = answers().await;
    let (_, _, mut missing) = mcp_rpc(&h.app, Some(&h.access), tool("nope-dash")).await;
    assert_eq!(before.1["result"], missing.swap_remove(0)["result"]);
    assert_eq!(
        before.1["result"]["isError"], true,
        "the tool answer is the missing-tenant refusal"
    );

    h.tenants.get_or_create("-").unwrap();
    {
        let g = h.meta.lock().await;
        g.execute(
            "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('-', 'Dash', ?1)",
            [h.admin_id],
        )
        .unwrap();
    }
    let after = answers().await;
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1, "tools/call");
    assert_eq!(
        (after.2, &after.3, &after.4),
        (before.2, &before.3, &before.4),
        "resources/read"
    );
    assert_eq!(
        (after.5, &after.6, &after.7),
        (before.5, &before.6, &before.7),
        "prompts/get"
    );
    assert_eq!(after.4["error"]["code"], -32002);
    assert_eq!(after.7["error"]["data"]["error_code"], "TENANT_NOT_FOUND");
}

/// rmcp logs every error response at WARN, so caller text in a resource or
/// prompt error reaches the log: it is cut, and shown only when well-formed.
/// A tenant the caller cannot see and one that does not exist still answer
/// the same message for the same URI shape.
#[tokio::test]
async fn refusals_bound_the_caller_text_they_echo() {
    let h = spin_up_account_mcp("acct-res").await;
    let m = member_world(&h).await;
    let long = "c".repeat(10_000);
    let foreign = format!("drust://acct-res/collections/{long}/schema");
    let missing = format!("drust://nope-rrr/collections/{long}/schema");
    let (_, _, a) = read(&h, &m.access, &foreign).await;
    let (_, _, b) = read(&h, &m.access, &missing).await;
    let msg = |v: &Value| v["error"]["message"].as_str().unwrap().to_string();
    assert!(msg(&a).chars().count() <= 300, "{}", msg(&a).len());
    assert!(msg(&a).starts_with("no such resource: drust://acct-res/collections/ccc"));
    assert_eq!(msg(&a).replace("acct-res", "nope-rrr"), msg(&b));
    assert_eq!(a["error"]["code"], b["error"]["code"]);

    // A URI that does not parse is never echoed, on either refusal.
    for uri in [
        format!("drust://acct-res/{long}"),
        format!("drust://mine-r/{long}"),
        format!("not a uri {long}"),
    ] {
        let (_, _, r) = read(&h, &m.access, &uri).await;
        assert_eq!(msg(&r), "no such resource: <invalid>", "{}", &uri[..40]);
    }

    // Prompt errors: an identifier is cut, anything else is not shown.
    let (_, _, p) = prompt(
        &h,
        &m.access,
        "secure_collection",
        json!({"tenant": "mine-r", "collection": long}),
    )
    .await;
    assert!(msg(&p).starts_with("no such collection: ccc"));
    assert!(msg(&p).chars().count() <= 200, "{}", msg(&p).len());
    let (_, _, p) = prompt(
        &h,
        &m.access,
        "secure_collection",
        json!({"tenant": "mine-r", "collection": "Bad Name!"}),
    )
    .await;
    assert_eq!(msg(&p), "no such collection: <invalid>");
    let (_, _, p) = prompt(&h, &m.access, &long, json!({"tenant": "mine-r"})).await;
    assert!(msg(&p).starts_with("no such prompt: ccc"));
    assert!(msg(&p).chars().count() <= 200, "{}", msg(&p).len());

    // The records template: an absent collection and an unknown sort field
    // are each answered with bounded text, keeping their error code.
    mcp_call(
        &h.app,
        &h.access,
        "acct-res",
        "create_collection",
        json!({"name": "posts", "fields": [{"name": "title", "sql_type": "text"}]}),
    )
    .await;
    let (_, _, r) = read(
        &h,
        &h.access,
        &format!("drust://acct-res/collections/{long}/records"),
    )
    .await;
    assert_eq!(r["error"]["code"], -32002, "{}", &msg(&r)[..80]);
    assert!(
        msg(&r).starts_with("COLLECTION_NOT_FOUND"),
        "{}",
        &msg(&r)[..80]
    );
    assert!(msg(&r).chars().count() <= 300, "{}", msg(&r).len());
    let (_, _, r) = read(
        &h,
        &h.access,
        &format!("drust://acct-res/collections/posts/records?sort={long}"),
    )
    .await;
    assert_eq!(r["error"]["code"], -32603, "{}", &msg(&r)[..80]);
    assert!(msg(&r).chars().count() <= 300, "{}", msg(&r).len());
}

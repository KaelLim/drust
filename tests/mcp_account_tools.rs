//! Account-level /mcp tool surface: injected tenant, strict top-level arguments, forwarding, one isError shape, fixed instructions.

mod helpers;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use futures::StreamExt;
use helpers::*;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

fn tools_call(id: u64, name: &str, args: Option<Value>) -> Value {
    let mut p = json!({"name": name});
    if let Some(a) = args {
        p["arguments"] = a;
    }
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":p})
}

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
    assert_eq!(tools.len(), 78);
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

#[tokio::test]
async fn recent_writes_account_description_is_the_override() {
    let h = spin_up_account_mcp("acct-tools").await;
    let (_, _, msgs) = mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    let t = msgs[0]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "recent_writes")
        .unwrap();
    let d = t["description"].as_str().unwrap();
    assert!(
        d.starts_with("Recent write events recorded in this tenant's audit log (ts/op/collection/status/error_code), newest first:"),
        "{d}"
    );
    assert!(
        !d.contains("NOT POPULATED") && !d.contains("Service-key"),
        "{d}"
    );
    assert_eq!(t["inputSchema"]["required"][0], "tenant");
}

async fn call(h: &AccountMcpHarness, token: &str, name: &str, args: Option<Value>) -> Value {
    let (st, _, msgs) = mcp_rpc(&h.app, Some(token), tools_call(9, name, args)).await;
    assert_eq!(st, 200, "{name}");
    msgs.into_iter()
        .find(|m| m["id"] == 9)
        .expect("a response to id 9")
}
fn text(r: &Value) -> Value {
    serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}
fn err_body(r: &Value) -> Value {
    assert_eq!(r["result"]["isError"], true, "{r}");
    text(r)
}
fn ok_body(r: &Value) -> Value {
    assert_ne!(r["result"]["isError"], true, "{r}");
    text(r)
}
fn not_found() -> Value {
    json!({"error_code":"TENANT_NOT_FOUND","message":"tenant not found","suggested_fix":"call list_tenants"})
}
/// admins[0] owner (h.access, owns h.tid), admins[1] member (owns nothing live);
/// plus "gone" (member's, soft-deleted), "gone2" (owner's, soft-deleted) and an orphan.
async fn two_admins() -> (AccountMcpHarness, String) {
    let h = spin_up_account_mcp_with(AccountMcpOpts {
        admins: vec![("mcp-owner", "owner"), ("member1", "member")],
        tenants: vec![("acct-tools", Some(0))],
        files: false,
        mcp_enabled: true,
    })
    .await;
    let (m_id, m_access) = (h.accesses[1].admin_id, h.accesses[1].access.clone());
    {
        let c = h.meta.lock().await;
        c.execute(
            "INSERT INTO tenants (id, name, owner_admin_id, deleted_at) VALUES ('gone','Gone',?1,datetime('now'))",
            [m_id],
        )
        .unwrap();
        c.execute(
            "INSERT INTO tenants (id, name, owner_admin_id, deleted_at) VALUES ('gone2','Gone2',?1,datetime('now'))",
            [h.admin_id],
        )
        .unwrap();
        c.execute(
            "INSERT INTO tenants (id, name) VALUES ('orphan','Orphan')",
            [],
        )
        .unwrap();
    }
    (h, m_access)
}
async fn posts(h: &AccountMcpHarness) {
    ok_body(
        &call(
            h,
            &h.access,
            "create_collection",
            Some(json!({"tenant": h.tid,
        "name":"posts","fields":[{"name":"title","sql_type":"text"}]})),
        )
        .await,
    );
}
async fn rest(
    h: &AccountMcpHarness,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> axum::response::Response {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("/t/{}{path}", h.tid))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = body
        .map(|v| Body::from(v.to_string()))
        .unwrap_or_else(Body::empty);
    h.app.clone().oneshot(b.body(body).unwrap()).await.unwrap()
}
async fn collection_names(h: &AccountMcpHarness) -> Vec<String> {
    let v = ok_body(
        &call(
            h,
            &h.access,
            "list_collections",
            Some(json!({"tenant": h.tid})),
        )
        .await,
    );
    v["collections"]
        .as_array()
        .expect("a collection list")
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn unknown_argument_and_missing_tenant_are_refused() {
    let h = spin_up_account_mcp("acct-tools").await;
    let b = err_body(
        &call(
            &h,
            &h.access,
            "insert_record",
            Some(json!({"tenant": h.tid,
        "collection":"posts","data":{"title":"a"},"dry_run":true})),
        )
        .await,
    );
    assert_eq!(
        (b["error_code"].as_str(), b["message"].as_str()),
        (
            Some("INVALID_ARGUMENTS"),
            Some("unknown argument(s): dry_run")
        )
    );
    for args in [
        None,
        Some(json!({})),
        Some(json!({"tenant":5})),
        Some(json!({"tenant":""})),
    ] {
        assert_eq!(
            err_body(&call(&h, &h.access, "list_collections", args.clone()).await)["error_code"],
            "TENANT_REQUIRED",
            "{args:?}"
        );
    }
}

#[tokio::test]
async fn foreign_missing_deleted_and_malformed_tenants_answer_identically() {
    let (h, m) = two_admins().await;
    // member view: foreign, missing, own soft-deleted, orphan, malformed
    let mut rs = Vec::new();
    for t in [
        h.tid.as_str(),
        "nope",
        "gone",
        "orphan",
        " acct-tools ",
        "Acct-Tools",
    ] {
        rs.push(call(&h, &m, "list_collections", Some(json!({"tenant": t}))).await);
    }
    // sees-all view: missing and soft-deleted take a different branch in resolution
    for t in ["nope", "gone2"] {
        rs.push(
            call(
                &h,
                &h.access,
                "list_collections",
                Some(json!({"tenant": t})),
            )
            .await,
        );
    }
    assert_eq!(err_body(&rs[0]), not_found());
    for r in &rs[1..] {
        assert_eq!(r["result"], rs[0]["result"]);
    }
}

/// Regression gate for every change to call_tool: names come from the live
/// tools/list, never from a hand-kept list.
#[tokio::test]
async fn every_tenant_tool_refuses_an_invisible_tenant_identically() {
    let (h, m) = two_admins().await;
    let (_, _, msgs) = mcp_rpc(
        &h.app,
        Some(&m),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    let names: Vec<String> = msgs[0]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .filter(|n| n != "list_tenants")
        .collect();
    // 76 inner tools plus create_upload_url, the one outer tool that takes a tenant.
    assert_eq!(names.len(), 77);
    let want = not_found();
    for n in &names {
        for t in [h.tid.as_str(), "nope"] {
            let r = call(&h, &m, n, Some(json!({"tenant": t}))).await;
            assert_eq!(err_body(&r), want, "{n} on {t}");
        }
    }
    let r = call(
        &h,
        &m,
        "create_collection",
        Some(json!({"tenant": h.tid,
        "name":"x","fields":[{"name":"title","sql_type":"text"}]})),
    )
    .await;
    assert_eq!(err_body(&r), want);
    assert!(
        !collection_names(&h).await.contains(&"x".to_string()),
        "a refused write must not land"
    );
}

#[tokio::test]
async fn argument_errors_do_not_depend_on_tenant_visibility() {
    let (h, m) = two_admins().await;
    let args = |t: &str| Some(json!({"tenant": t, "collection":"p","data":{},"dry_run":true}));
    let visible = call(&h, &h.access, "insert_record", args(&h.tid)).await;
    let invisible = call(&h, &m, "insert_record", args(&h.tid)).await;
    let missing = call(&h, &m, "insert_record", args("nope")).await;
    assert_eq!(err_body(&visible)["error_code"], "INVALID_ARGUMENTS");
    assert_eq!(visible["result"], invisible["result"]);
    assert_eq!(visible["result"], missing["result"]);
}

#[tokio::test]
async fn list_tenants_takes_no_arguments() {
    let h = spin_up_account_mcp("acct-tools").await;
    let b = err_body(
        &call(
            &h,
            &h.access,
            "list_tenants",
            Some(json!({"tenant": h.tid})),
        )
        .await,
    );
    assert_eq!(b["message"], "unknown argument(s): tenant");
    for args in [None, Some(Value::Null), Some(json!({}))] {
        let ok = ok_body(&call(&h, &h.access, "list_tenants", args.clone()).await);
        assert!(
            ok["tenants"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"] == h.tid.as_str()),
            "{args:?}"
        );
    }
}

#[tokio::test]
async fn whoami_over_the_account_endpoint_hides_the_service_key() {
    let h = spin_up_account_mcp("acct-tools").await;
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        call(&h, &h.access, "whoami", Some(json!({"tenant": h.tid}))),
    )
    .await
    .expect("whoami must not deadlock on the meta lock");
    let raw = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!raw.contains(&h.svc), "whoami leaked the service key");
    assert!(!raw.contains(&h.access), "whoami leaked the access token");
    assert!(
        !raw.contains(concat!("drust_", "mcpat_")),
        "whoami carries an OAuth token"
    );
    assert_eq!(ok_body(&r)["tokens"]["service"]["redacted"], true);
}

#[tokio::test]
async fn inner_protocol_errors_become_is_error() {
    let h = spin_up_account_mcp("acct-tools").await;
    let b = err_body(
        &call(
            &h,
            &h.access,
            "call_rpc",
            Some(json!({"tenant": h.tid, "name":"nope"})),
        )
        .await,
    );
    assert_eq!(
        (b["error_code"].as_str(), b["message"].as_str()),
        (Some("RPC_NOT_FOUND"), Some("no such rpc: nope"))
    );
    posts(&h).await;
    let b = err_body(
        &call(
            &h,
            &h.access,
            "delete_record",
            Some(json!({"tenant": h.tid, "collection":"posts","id":999,"dry_run":true})),
        )
        .await,
    );
    assert_eq!(b["error_code"], "RECORD_NOT_FOUND");
    assert!(b["suggested_fix"].is_string());
    let b = err_body(
        &call(
            &h,
            &h.access,
            "list_records",
            Some(json!({"tenant": h.tid, "collection": 5})),
        )
        .await,
    );
    assert_eq!(b["error_code"], "INVALID_PARAMS");
    assert!(
        b["message"]
            .as_str()
            .unwrap()
            .starts_with("failed to deserialize parameters:")
    );
}

#[tokio::test]
async fn unknown_tool_stays_a_protocol_error() {
    let h = spin_up_account_mcp("acct-tools").await;
    let r = call(
        &h,
        &h.access,
        "no_such_tool",
        Some(json!({"tenant": h.tid})),
    )
    .await;
    assert_eq!(
        (r["error"]["code"].as_i64(), r["error"]["message"].as_str()),
        (Some(-32602), Some("tool not found"))
    );
    assert!(r.get("result").is_none());
}

/// rmcp checks task support through get_tool and, for a name get_tool does not
/// know, hands the request to enqueue_task without ever calling call_tool.
#[tokio::test]
async fn task_augmented_calls_never_reach_call_tool() {
    let h = spin_up_account_mcp("acct-tools").await;
    let cases = [
        (
            "list_tenants",
            json!({}),
            -32602,
            "Tool does not support task-based invocation",
        ),
        (
            "create_collection",
            json!({"tenant": h.tid, "name":"y",
            "fields":[{"name":"title","sql_type":"text"}]}),
            -32602,
            "Tool does not support task-based invocation",
        ),
        (
            "no_such_tool",
            json!({"tenant": h.tid}),
            -32603,
            "Task processing not implemented",
        ),
    ];
    for (name, args, code, msg) in cases {
        let mut body = tools_call(3, name, Some(args));
        body["params"]["task"] = json!({});
        let (_, _, msgs) = mcp_rpc(&h.app, Some(&h.access), body).await;
        assert_eq!(
            (
                msgs[0]["error"]["code"].as_i64(),
                msgs[0]["error"]["message"].as_str()
            ),
            (Some(code), Some(msg)),
            "{name}"
        );
    }
    assert!(
        !collection_names(&h).await.contains(&"y".to_string()),
        "a task call must not run the tool"
    );
}

/// Invariant 4 on the account path: the forwarded DrustMcp carries the shared auth cache.
#[tokio::test]
async fn delete_user_over_the_account_endpoint_ends_the_users_rest_session() {
    let h = spin_up_account_mcp("acct-tools").await;
    let u = ok_body(
        &call(
            &h,
            &h.access,
            "create_user",
            Some(json!({"tenant": h.tid,
        "email":"u@example.test","password":"longpassword","verified":true})),
        )
        .await,
    );
    let uid = u["user_id"].as_str().unwrap().to_string();
    let login = rest(
        &h,
        "POST",
        "/auth/login",
        None,
        Some(json!({"email":"u@example.test","password":"longpassword"})),
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    let v: Value = serde_json::from_slice(
        &axum::body::to_bytes(login.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    let token = v["token"].as_str().unwrap().to_string();
    assert_eq!(
        rest(&h, "GET", "/me", Some(&token), None).await.status(),
        StatusCode::OK,
        "caches the session"
    );
    let epoch = h.bus_rooms.tenant_epoch_handle(&h.tid);
    let before = epoch.load(std::sync::atomic::Ordering::SeqCst);
    ok_body(
        &call(
            &h,
            &h.access,
            "delete_user",
            Some(json!({"tenant": h.tid, "user_id": uid})),
        )
        .await,
    );
    let after = rest(&h, "GET", "/me", Some(&token), None).await;
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "the cached session must be cleared, not left to the safety TTL"
    );
    // A stale cache entry would still pass the bearer layer and reach /me,
    // which answers 401 TOKEN_REVOKED for the missing user row; only a cleared
    // entry is refused by the bearer layer itself.
    let v: Value = serde_json::from_slice(
        &axum::body::to_bytes(after.into_body(), 1 << 16)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        v["error_code"], "UNAUTHENTICATED",
        "the bearer layer, not /me, must refuse the session"
    );
    assert!(
        epoch.load(std::sync::atomic::Ordering::SeqCst) > before,
        "the tenant's rooms must be evicted"
    );
}

/// Invariant 5 on the account path: the forwarded DrustMcp carries the shared event bus.
#[tokio::test]
async fn disabling_realtime_over_the_account_endpoint_closes_anon_streams() {
    let h = spin_up_account_mcp("acct-tools").await;
    posts(&h).await;
    ok_body(
        &call(
            &h,
            &h.access,
            "set_anon_caps",
            Some(json!({"tenant": h.tid, "collection":"posts", "caps":["select"]})),
        )
        .await,
    );
    ok_body(
        &call(
            &h,
            &h.access,
            "set_realtime",
            Some(json!({"tenant": h.tid, "collection":"posts", "enabled":true})),
        )
        .await,
    );
    let req = Request::builder()
        .uri(format!("/t/{}/records/posts/subscribe", h.tid))
        .header(header::AUTHORIZATION, format!("Bearer {}", h.anon))
        .header(header::ACCEPT, "text/event-stream")
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "anon subscribe");
    let mut stream = resp.into_body().into_data_stream();
    ok_body(
        &call(
            &h,
            &h.access,
            "set_realtime",
            Some(json!({"tenant": h.tid, "collection":"posts", "enabled":false})),
        )
        .await,
    );
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while stream.next().await.is_some() {}
    })
    .await;
    assert!(
        ended.is_ok(),
        "the anon stream stayed open after realtime was disabled"
    );
}

fn tickets_in(c: &rusqlite::Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM _mcp_upload_tickets", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn create_upload_url_is_listed_with_its_schema_and_annotations() {
    let h = spin_up_account_mcp("acct-upl").await;
    let (st, _, msgs) = mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    let tools = msgs[0]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 78);
    let t: Vec<_> = tools
        .iter()
        .filter(|t| t["name"] == "create_upload_url")
        .collect();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0]["inputSchema"]["required"], json!(["tenant", "size"]));
    for (k, v) in [
        ("readOnlyHint", false),
        ("destructiveHint", false),
        ("idempotentHint", false),
        ("openWorldHint", false),
    ] {
        assert_eq!(t[0]["annotations"][k], v, "{k}");
    }
}

#[tokio::test]
async fn create_upload_url_denial_is_byte_identical_to_other_tools() {
    // files: false on purpose: a tenant the caller cannot see must answer TENANT_NOT_FOUND,
    // never STORAGE_UNAVAILABLE, so the storage check cannot become an existence oracle.
    let h = spin_up_account_mcp_with(AccountMcpOpts {
        admins: vec![("mcp-owner", "owner"), ("upl-member", "member")],
        tenants: vec![("acct-upl", Some(1)), ("theirs", Some(0))],
        files: false,
        mcp_enabled: true,
    })
    .await;
    let m = &h.accesses[1];
    {
        let c = h.meta.lock().await;
        c.execute(
            "INSERT INTO tenants (id, name, owner_admin_id, deleted_at) VALUES ('gone','Gone',?1,datetime('now'))",
            [m.admin_id],
        )
        .unwrap();
    }
    let up = |t: &str| json!({"tenant": t, "size": 1});
    for t in ["theirs", "gone", "nope", "Bad Id!"] {
        let a = call(&h, &m.access, "create_upload_url", Some(up(t))).await;
        let b = call(
            &h,
            &m.access,
            "list_collections",
            Some(json!({"tenant": t})),
        )
        .await;
        assert_eq!(a["result"], b["result"], "{t}");
        assert_eq!(err_body(&a)["error_code"], "TENANT_NOT_FOUND", "{t}");
    }
    // the member's own tenant passes resolve and stops at storage
    assert_eq!(
        err_body(&call(&h, &m.access, "create_upload_url", Some(up("acct-upl"))).await)["error_code"],
        "STORAGE_UNAVAILABLE"
    );
    // transferred away: the next call is the same TENANT_NOT_FOUND as a tenant that never existed
    {
        let c = h.meta.lock().await;
        c.execute(
            "UPDATE tenants SET owner_admin_id = ?1 WHERE id = 'acct-upl'",
            [h.admin_id],
        )
        .unwrap();
    }
    let a = call(&h, &m.access, "create_upload_url", Some(up("acct-upl"))).await;
    let b = call(&h, &m.access, "create_upload_url", Some(up("nope"))).await;
    assert_eq!(a["result"], b["result"]);
    assert_eq!(err_body(&a)["error_code"], "TENANT_NOT_FOUND");
    assert_eq!(tickets_in(&*h.meta.lock().await), 0);
}

#[tokio::test]
async fn create_upload_url_without_storage_is_storage_unavailable_and_writes_no_ticket() {
    let h = spin_up_account_mcp("acct-upl").await; // files: false
    let r = call(
        &h,
        &h.access,
        "create_upload_url",
        Some(json!({"tenant": h.tid, "size": 1})),
    )
    .await;
    assert_eq!(r["result"]["isError"], true);
    assert_eq!(
        r["result"]["content"][0]["text"],
        r#"{"error_code":"STORAGE_UNAVAILABLE","message":"file storage is not configured on this server"}"#
    );
    assert_eq!(tickets_in(&*h.meta.lock().await), 0);
}

#[tokio::test]
async fn account_files_guide_and_descriptions_over_the_wire() {
    let h = spin_up_account_mcp("acct-upl").await;
    let (st, _, msgs) = mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc":"2.0","id":3,"method":"resources/read",
            "params":{"uri":"drust://acct-upl/files-guide.md"}}),
    )
    .await;
    assert_eq!(st, 200);
    let text = msgs[0]["result"]["contents"][0]["text"].as_str().unwrap();
    assert!(text.contains("create_upload_url"));
    assert!(text.contains("## 1. Uploading a file"));
    assert!(!text.contains("DRUST_SERVICE_TOKEN"));
    let (st, _, msgs) = mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    assert_eq!(st, 200);
    let tools = msgs[0]["result"]["tools"].as_array().unwrap();
    let desc = |n: &str| -> String {
        let t: Vec<_> = tools.iter().filter(|t| t["name"] == n).collect();
        assert_eq!(t.len(), 1, "{n}");
        t[0]["description"].as_str().unwrap().to_string()
    };
    assert!(desc("list_functions").contains("there is no function-deploy tool"));
    assert!(desc("whoami").contains("To upload a file, call create_upload_url."));
}

/// The account endpoint's tools clear the PROCESS auth cache: `build_live`
/// must hand every call the registry's cache, or the invariant-4 hooks of the
/// MCP tools clear a private one and stale grants keep serving.
#[tokio::test]
async fn account_tool_calls_clear_the_process_auth_cache() {
    let h = spin_up_account_mcp("acct-cache").await;
    let entry = |uid: &str| drust::tenant::auth_cache::CachedAuth::User {
        tenant_id: h.tid.clone(),
        user_id: uid.to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        publish_user_allowed: false,
        publish_anon_allowed: false,
        file_caps: Default::default(),
        quota_tier: 1,
    };

    h.auth_cache.insert("pub-h".to_string(), entry("u-pub"));
    let r = call(
        &h,
        &h.access,
        "set_publish_policy",
        Some(json!({"tenant": h.tid, "allow_user_publish": true})),
    )
    .await;
    ok_body(&r);
    assert!(
        h.auth_cache.get("pub-h").is_none(),
        "set_publish_policy clears the tenant's cached entries"
    );

    h.auth_cache.insert("rev-h".to_string(), entry("u-rev"));
    let r = call(
        &h,
        &h.access,
        "revoke_user_sessions",
        Some(json!({"tenant": h.tid, "user_id": "u-rev"})),
    )
    .await;
    ok_body(&r);
    assert!(
        h.auth_cache.get("rev-h").is_none(),
        "revoke_user_sessions clears the user's cached entries"
    );
}

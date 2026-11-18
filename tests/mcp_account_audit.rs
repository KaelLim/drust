//! Audit rows written by the account-level MCP endpoint (`/mcp`).
//!
//! Own binary: asserts on audit-row contents in the DB it installs through
//! the first-write-wins `audit_db::init_globals` OnceLock. Every test uses its
//! own tenant id and filters on it, because the tests share one audit file.

#[path = "helpers.rs"]
mod helpers;

use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use helpers::{
    mcp_call, mcp_rpc, mcp_tool_text, seed_mcp_access, seed_upload_ticket, spin_up_account_mcp,
    spin_up_ticket_harness,
};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Installs the global writer once, on its own thread so it outlives every
/// test's runtime, and returns the audit DB path.
fn audit_path() -> &'static PathBuf {
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempfile::tempdir().unwrap());
        let path = dir.path().join("test_mcp_account_audit.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-mcp-account-audit-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    drust::safety::audit_db::init_globals(writer);
                    let _ = tx_ready.send(());
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

/// Rows now, no waiting, as JSON objects keyed by column name.
fn rows_now(sql: &str, p1: &str) -> Vec<Value> {
    let conn = open_audit_db_read(audit_path()).unwrap();
    let mut stmt = conn.prepare(sql).unwrap();
    let names: Vec<String> = stmt.column_names().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map([p1], |r| {
            let mut o = serde_json::Map::new();
            for (i, n) in names.iter().enumerate() {
                let v = match r.get_ref(i)? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(n) => json!(n),
                    rusqlite::types::ValueRef::Real(f) => json!(f),
                    rusqlite::types::ValueRef::Text(t) => {
                        Value::String(String::from_utf8_lossy(t).into_owned())
                    }
                    rusqlite::types::ValueRef::Blob(_) => Value::String("<blob>".into()),
                };
                o.insert(n.clone(), v);
            }
            Ok(Value::Object(o))
        })
        .unwrap();
    rows.map(Result::unwrap).collect()
}

/// Polls every 50 ms for up to 5 s until `sql` (one `?1` param) returns
/// exactly `want` rows; panics at once if it returns more, and on timeout.
async fn rows_eventually(sql: &str, p1: &str, want: usize) -> Vec<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let rows = rows_now(sql, p1);
        assert!(
            rows.len() <= want,
            "{} rows, want {want}: {sql} [{p1}]",
            rows.len()
        );
        if rows.len() == want {
            return rows;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out with {} rows, want {want}: {sql} [{p1}]",
            rows.len()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Sends a call that writes one host denial naming `marker` (a tenant id that
/// does not exist) and waits for that row. The writer is FIFO, so once it is
/// visible every row this test caused before it is in the file too, and an
/// absence check that follows is not a race against the writer.
async fn fence(h: &helpers::AccountMcpHarness, marker: &str) {
    let text = mcp_tool_text(&h.app, &h.access, marker, "list_collections", json!({})).await;
    assert!(text.contains("TENANT_NOT_FOUND"), "{text}");
    rows_eventually(
        "SELECT op FROM audit WHERE tenant = '-' AND op = 'mcp_denied' \
         AND json_extract(extra, '$.requested_tenant') = ?1",
        marker,
        1,
    )
    .await;
}

/// recent_writes as the tool computes it, read straight from the writer's file.
async fn recent(
    tenant: &str,
    collection: Option<&str>,
) -> Vec<drust::safety::recent_writes::RecentWrite> {
    let conn = std::sync::Arc::new(tokio::sync::Mutex::new(
        open_audit_db_read(audit_path()).unwrap(),
    ));
    drust::safety::recent_writes::query_recent(&conn, tenant, 50, collection, None)
        .await
        .unwrap()
}

const COLS: &str = "tenant, token_hint, op, status, error_code, auth_method, actor_admin_id, \
                    actor_email_snapshot, extra";
const POSTS: &str = r#"{"name": "posts", "fields": [{"name": "title", "sql_type": "text"}]}"#;

fn extra_of(row: &Value) -> Value {
    serde_json::from_str(row["extra"].as_str().expect("extra is set")).unwrap()
}

fn tools_call(name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": args}})
}

#[tokio::test]
async fn allowed_tool_call_writes_one_row_in_that_tenant() {
    audit_path();
    let h = spin_up_account_mcp("aud-call").await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "create_collection",
        serde_json::from_str(POSTS).unwrap(),
    )
    .await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "insert_record",
        json!({"collection": "posts", "data": {"title": "value-7f3a"}}),
    )
    .await;
    let r = rows_eventually(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'insert_record'"),
        "aud-call",
        1,
    )
    .await;
    let x = &r[0];
    assert_eq!(x["token_hint"], "-");
    assert_eq!(x["status"], "ok");
    assert!(x["error_code"].is_null());
    assert_eq!(x["auth_method"], "mcp_oauth");
    assert_eq!(x["actor_admin_id"], json!(h.admin_id));
    assert_eq!(
        extra_of(x),
        json!({"grant_id": h.grant_id, "collection": "posts"})
    );
    let c = rows_eventually(
        "SELECT extra FROM audit WHERE tenant = ?1 AND op = 'create_collection'",
        "aud-call",
        1,
    )
    .await;
    assert!(
        c[0]["extra"]
            .as_str()
            .unwrap()
            .contains("\"collection\":\"posts\"")
    );
    // no argument value and no credential anywhere in this tenant's rows
    for row in rows_now(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1"),
        "aud-call",
    ) {
        let s = row.to_string();
        assert!(!s.contains("value-7f3a"));
        assert!(
            !s.contains(h.access.as_str()),
            "a row carries the access token"
        );
    }
}

#[tokio::test]
async fn recent_writes_query_sees_account_writes() {
    audit_path();
    let h = spin_up_account_mcp("aud-rw").await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "create_collection",
        serde_json::from_str(POSTS).unwrap(),
    )
    .await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "insert_record",
        json!({"collection": "posts", "data": {"title": "a"}}),
    )
    .await;
    rows_eventually(
        "SELECT op FROM audit WHERE tenant = ?1 AND op = 'insert_record'",
        "aud-rw",
        1,
    )
    .await;
    let got = recent("aud-rw", Some("posts")).await;
    assert!(
        got.iter()
            .any(|w| w.op == "insert_record" && w.collection.as_deref() == Some("posts"))
    );
    assert!(got.iter().any(|w| w.op == "create_collection"));
}

#[tokio::test]
async fn dry_runs_are_not_listed_as_writes() {
    audit_path();
    let h = spin_up_account_mcp("aud-dry").await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "create_collection",
        serde_json::from_str(POSTS).unwrap(),
    )
    .await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "insert_record",
        json!({"collection": "posts", "data": {"title": "keep"}}),
    )
    .await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "delete_record",
        json!({"collection": "posts", "id": 1, "dry_run": true}),
    )
    .await;
    let p = rows_eventually(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'delete_record.dry_run'"),
        "aud-dry",
        1,
    )
    .await;
    assert_eq!(p[0]["status"], "ok");
    assert!(
        !recent("aud-dry", None)
            .await
            .iter()
            .any(|w| w.op == "delete_record"),
        "a preview is listed as a delete"
    );
    let text = mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "list_records",
        json!({"collection": "posts"}),
    )
    .await;
    assert!(text.contains("keep"), "the preview changed nothing: {text}");
}

#[tokio::test]
async fn failed_tool_call_is_recorded_with_its_code() {
    audit_path();
    let h = spin_up_account_mcp("aud-fail").await;
    let body: Value = serde_json::from_str(
        &mcp_tool_text(
            &h.app,
            &h.access,
            &h.tid,
            "insert_record",
            json!({"collection": "nope", "data": {"a": 1}}),
        )
        .await,
    )
    .unwrap();
    assert!(body["error_code"].is_string(), "{body}");
    let r = rows_eventually(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'insert_record'"),
        "aud-fail",
        1,
    )
    .await;
    assert_eq!(r[0]["status"], "error");
    assert_eq!(r[0]["error_code"], body["error_code"]);
    assert_eq!(
        extra_of(&r[0]),
        json!({"grant_id": h.grant_id, "collection": "nope"})
    );
}

#[tokio::test]
async fn member_denied_on_foreign_tenant_pollutes_nothing() {
    audit_path();
    let h = spin_up_account_mcp("aud-deny").await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "create_collection",
        serde_json::from_str(POSTS).unwrap(),
    )
    .await;
    let before = rows_eventually(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1"),
        "aud-deny",
        1,
    )
    .await
    .len();
    let rw_before = recent("aud-deny", None).await.len();
    assert_eq!(rw_before, 1, "the owner's create_collection is listed");
    let m = {
        let g = h.meta.lock().await;
        seed_mcp_access(&g, "member", "mallory-aud")
    };
    let text = mcp_tool_text(
        &h.app,
        &m.access,
        "aud-deny",
        "insert_record",
        json!({"collection": "posts", "data": {"title": "planted"}}),
    )
    .await;
    assert!(text.contains("TENANT_NOT_FOUND"));
    let d = rows_eventually(
        &format!(
            "SELECT {COLS} FROM audit WHERE tenant = '-' AND op = 'mcp_denied' \
             AND json_extract(extra, '$.requested_tenant') = ?1"
        ),
        "aud-deny",
        1,
    )
    .await;
    assert_eq!(d[0]["error_code"], "TENANT_NOT_FOUND");
    assert_eq!(d[0]["actor_admin_id"], json!(m.admin_id));
    assert_eq!(
        extra_of(&d[0]),
        json!({"surface": "tool", "name": "insert_record", "requested_tenant": "aud-deny", "grant_id": m.grant_id})
    );
    fence(&h, "fence-deny").await;
    assert_eq!(
        rows_now(
            &format!("SELECT {COLS} FROM audit WHERE tenant = ?1"),
            "aud-deny"
        )
        .len(),
        before
    );
    assert_eq!(recent("aud-deny", None).await.len(), rw_before);
    // Scoped to this test's tenant: admin ids repeat across the harnesses
    // that share this audit file.
    let mine = rows_now(
        &format!(
            "SELECT {COLS} FROM audit WHERE tenant = ?1 AND actor_admin_id = {}",
            m.admin_id
        ),
        "aud-deny",
    );
    assert!(
        mine.is_empty(),
        "the denied member's identity landed in a tenant row"
    );
}

#[tokio::test]
async fn precheck_denials_are_host_rows() {
    audit_path();
    let h = spin_up_account_mcp("aud-pre").await;
    // An unknown top-level key: insert_record has no dry_run.
    let text = mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "insert_record",
        json!({"collection": "posts", "data": {"title": "a"}, "dry_run": true}),
    )
    .await;
    assert!(text.contains("INVALID_ARGUMENTS"), "{text}");
    let a = rows_eventually(
        &format!(
            "SELECT {COLS} FROM audit WHERE tenant = '-' AND op = 'mcp_denied' \
             AND json_extract(extra, '$.requested_tenant') = ?1"
        ),
        "aud-pre",
        1,
    )
    .await;
    assert_eq!(a[0]["error_code"], "INVALID_ARGUMENTS");
    assert_eq!(extra_of(&a[0])["name"], "insert_record");
    // No tenant at all (mcp_call would inject one).
    let (_, _, m) = mcp_rpc(
        &h.app,
        Some(&h.access),
        tools_call("list_collections", json!({})),
    )
    .await;
    assert!(
        m[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("TENANT_REQUIRED")
    );
    let b = rows_eventually(
        &format!(
            "SELECT {COLS} FROM audit WHERE tenant = '-' AND op = 'mcp_denied' \
             AND json_extract(extra, '$.name') = ?1 AND error_code = 'TENANT_REQUIRED'"
        ),
        "list_collections",
        1,
    )
    .await;
    assert!(
        extra_of(&b[0]).get("requested_tenant").is_none(),
        "{}",
        b[0]
    );
    fence(&h, "fence-pre").await;
    assert!(rows_now("SELECT op FROM audit WHERE tenant = ?1", "aud-pre").is_empty());
}

#[tokio::test]
async fn list_tenants_and_unknown_tools_write_nothing() {
    audit_path();
    let h = spin_up_account_mcp("aud-quiet").await;
    for body in [
        tools_call("list_tenants", json!({})),
        tools_call("list_tenants", json!({"tenant": "aud-quiet"})),
        tools_call("no_such_tool", json!({"tenant": "aud-quiet"})),
    ] {
        let (s, _, m) = mcp_rpc(&h.app, Some(&h.access), body).await;
        assert_eq!(s, axum::http::StatusCode::OK);
        assert!(!m.is_empty());
    }
    fence(&h, "fence-quiet").await;
    assert!(rows_now("SELECT op FROM audit WHERE tenant = ?1", "aud-quiet").is_empty());
    assert!(rows_now("SELECT op FROM audit WHERE op = ?1", "list_tenants").is_empty());
    assert!(
        rows_now(
            "SELECT op FROM audit WHERE op = 'mcp_denied' \
             AND json_extract(extra, '$.name') IN ('list_tenants', 'no_such_tool') \
             AND json_extract(extra, '$.requested_tenant') = ?1",
            "aud-quiet"
        )
        .is_empty()
    );
}

#[tokio::test]
async fn account_broadcast_rows_carry_the_admin() {
    audit_path();
    let h = spin_up_account_mcp("aud-bcast").await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "broadcast",
        json!({"room": "lobby", "payload": {"n": 1}}),
    )
    .await;
    // the `_system_` prefix is reserved: PROTECTED_ROOM, written by the failure audit
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "broadcast",
        json!({"room": "_system_x", "payload": {"n": 1}}),
    )
    .await;
    let q = format!(
        "SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'broadcast.publish' AND status = "
    );
    let ok = rows_eventually(&format!("{q}'ok'"), "aud-bcast", 1).await;
    let err = rows_eventually(&format!("{q}'error'"), "aud-bcast", 1).await;
    assert_eq!(err[0]["error_code"], "PROTECTED_ROOM");
    for x in [&ok[0], &err[0]] {
        assert_eq!(x["op"], "broadcast.publish");
        assert_eq!(x["token_hint"], "-");
        assert_eq!(x["actor_admin_id"], json!(h.admin_id));
    }
}

#[tokio::test]
async fn account_egress_set_row_has_no_token_hint() {
    audit_path();
    let h = spin_up_account_mcp("aud-egress").await;
    mcp_call(
        &h.app,
        &h.access,
        &h.tid,
        "set_egress_allowlist",
        json!({"entries": [{"system": "webhook", "uri": "https://a.com"}]}),
    )
    .await;
    let r = rows_eventually(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'tenant.egress.set'"),
        "aud-egress",
        1,
    )
    .await;
    assert_eq!(r[0]["op"], "tenant.egress.set");
    assert_eq!(r[0]["status"], "ok");
    assert_eq!(r[0]["token_hint"], "-");
    assert!(
        r[0]["actor_admin_id"].is_null(),
        "set_allowlist takes no actor"
    );
}

#[tokio::test]
async fn resource_read_writes_one_row_with_the_uri() {
    audit_path();
    let h = spin_up_account_mcp("aud-res").await;
    let (_, _, m) = mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read",
               "params": {"uri": "drust://aud-res/schema.md"}}),
    )
    .await;
    assert!(
        m[0]["result"]["contents"][0]["text"].is_string(),
        "{}",
        m[0]
    );
    let q = format!("SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'mcp.resource.read'");
    let r = rows_eventually(&q, "aud-res", 1).await;
    assert_eq!(r[0]["auth_method"], "mcp_oauth");
    assert_eq!(r[0]["actor_admin_id"], json!(h.admin_id));
    assert_eq!(
        extra_of(&r[0]),
        json!({"grant_id": h.grant_id, "uri": "drust://aud-res/schema.md"})
    );
    let (_, _, m) = mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
               "params": {"name": "bootstrap", "arguments": {"tenant": "aud-res"}}}),
    )
    .await;
    assert!(m[0]["result"]["messages"].is_array(), "{}", m[0]);
    fence(&h, "fence-res").await;
    assert!(
        rows_now(
            "SELECT op FROM audit WHERE tenant = ?1 AND op LIKE '%prompt%'",
            "aud-res"
        )
        .is_empty()
    );
    assert_eq!(rows_now(&q, "aud-res").len(), 1);
}

#[tokio::test]
async fn denied_resource_and_prompt_reads_are_host_rows() {
    audit_path();
    let h = spin_up_account_mcp("aud-rdeny").await;
    let m = {
        let g = h.meta.lock().await;
        seed_mcp_access(&g, "member", "mallory-rdeny")
    };
    let (_, _, r) = mcp_rpc(
        &h.app,
        Some(&m.access),
        json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read",
               "params": {"uri": "drust://aud-rdeny/schema"}}),
    )
    .await;
    assert_eq!(r[0]["error"]["code"], -32002);
    let host = format!(
        "SELECT {COLS} FROM audit WHERE tenant = '-' AND op = 'mcp_denied' \
         AND json_extract(extra, '$.requested_tenant') = ?1 AND json_extract(extra, '$.surface') = "
    );
    let d = rows_eventually(&format!("{host}'resource'"), "aud-rdeny", 1).await;
    assert_eq!(d[0]["error_code"], "TENANT_NOT_FOUND");
    assert_eq!(
        extra_of(&d[0]),
        json!({"surface": "resource", "name": "drust://aud-rdeny/schema",
               "requested_tenant": "aud-rdeny", "grant_id": m.grant_id})
    );
    let (_, _, r) = mcp_rpc(
        &h.app,
        Some(&m.access),
        json!({"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
               "params": {"name": "secure_collection",
                          "arguments": {"tenant": "aud-rdeny", "collection": "posts"}}}),
    )
    .await;
    assert_eq!(r[0]["error"]["message"], "tenant not found");
    let p = rows_eventually(&format!("{host}'prompt'"), "aud-rdeny", 1).await;
    let x = extra_of(&p[0]);
    assert_eq!(
        (&x["surface"], &x["name"], &x["requested_tenant"]),
        (
            &json!("prompt"),
            &json!("secure_collection"),
            &json!("aud-rdeny")
        )
    );
    fence(&h, "fence-rdeny").await;
    // Nothing at all in the tenant, so the member's identity is not there either.
    assert!(rows_now("SELECT op FROM audit WHERE tenant = ?1", "aud-rdeny").is_empty());
}

/// An upload ticket for `tenant` from the harness's own access token.
async fn upload_ticket_for(h: &helpers::AccountMcpHarness, tenant: &str) -> String {
    seed_upload_ticket(
        &h.meta,
        &h.access,
        &drust::mgmt::mcp_oauth::store::TicketRequest {
            tenant_id: tenant,
            max_bytes: 4,
            path: None,
            public: false,
        },
    )
    .await
}

/// One tus request with a ticket; status and headers.
async fn tus(
    app: &axum::Router,
    method: &str,
    uri: &str,
    presented: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (axum::http::StatusCode, axum::http::HeaderMap) {
    use tower::ServiceExt;
    let mut b = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("tus-resumable", "1.0.0")
        .header("authorization", format!("Bearer {presented}"));
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let resp = app
        .clone()
        .oneshot(b.body(axum::body::Body::from(body)).unwrap())
        .await
        .unwrap();
    (resp.status(), resp.headers().clone())
}

const TICKET_DENIALS: &str = "SELECT tenant, token_hint, op, status, error_code, actor_admin_id, extra \
     FROM audit WHERE tenant = '-' AND op = 'mcp_denied' \
     AND json_extract(extra, '$.surface') = 'upload_ticket' \
     AND json_extract(extra, '$.requested_tenant') = ?1";

#[tokio::test]
async fn ticket_create_writes_one_attributed_row_on_its_tenant() {
    audit_path();
    let h = spin_up_ticket_harness(&["aud-upl-create"], true).await;
    let t = upload_ticket_for(&h, "aud-upl-create").await;
    let (s, hd) = tus(
        &h.app,
        "POST",
        "/t/aud-upl-create/uploads",
        &t,
        &[("upload-length", "4")],
        vec![],
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::CREATED);
    let r = rows_eventually(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'POST /uploads'"),
        "aud-upl-create",
        1,
    )
    .await;
    let x = &r[0];
    assert_eq!(x["status"], "ok");
    let hint = x["token_hint"].as_str().unwrap();
    assert!(hint.starts_with("drust_upl_") && hint.ends_with('\u{2026}'));
    assert_eq!(x["auth_method"], "mcp_upload_ticket");
    assert_eq!(x["actor_admin_id"], json!(h.admin_id));
    assert_eq!(extra_of(x)["grant_id"], json!(h.grant_id));

    let tok = hd["location"]
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let (s, _) = tus(
        &h.app,
        "PATCH",
        &format!("/t/aud-upl-create/uploads/{tok}"),
        &t,
        &[
            ("upload-offset", "0"),
            ("content-type", "application/offset+octet-stream"),
        ],
        b"abcd".to_vec(),
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::NO_CONTENT);
    rows_eventually(
        &format!(
            "SELECT op FROM audit WHERE tenant = ?1 AND op = 'PATCH /uploads/{tok}' \
             AND status = 'ok'"
        ),
        "aud-upl-create",
        1,
    )
    .await;
}

#[tokio::test]
async fn foreign_tenant_ticket_use_writes_only_a_host_denial() {
    audit_path();
    let h = spin_up_ticket_harness(&["aud-upl-a", "aud-upl-b"], true).await;
    let t = upload_ticket_for(&h, "aud-upl-a").await;
    let (s, _) = tus(
        &h.app,
        "POST",
        "/t/aud-upl-b/uploads",
        &t,
        &[("upload-length", "4")],
        vec![],
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::UNAUTHORIZED);
    let (s, _) = tus(
        &h.app,
        "PATCH",
        "/t/aud-upl-b/uploads/0f8fad5b-d9cb-469f-a165-70867728950e",
        &t,
        &[("upload-offset", "0")],
        vec![],
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::UNAUTHORIZED);
    let r = rows_eventually(TICKET_DENIALS, "aud-upl-b", 2).await;
    for x in &r {
        assert_eq!(extra_of(x)["grant_id"], json!(h.grant_id));
        assert_eq!(x["actor_admin_id"], json!(h.admin_id));
    }
    // The writer is FIFO: anything written for aud-upl-b came before these.
    assert_eq!(
        rows_now("SELECT op FROM audit WHERE tenant = ?1", "aud-upl-b").len(),
        0
    );
}

#[tokio::test]
async fn ticket_on_a_non_tus_route_is_a_host_denial() {
    audit_path();
    let h = spin_up_ticket_harness(&["aud-upl-other"], true).await;
    let t = upload_ticket_for(&h, "aud-upl-other").await;
    let (s, _) = tus(&h.app, "GET", "/t/aud-upl-other/files", &t, &[], vec![]).await;
    assert_eq!(s, axum::http::StatusCode::UNAUTHORIZED);
    let r = rows_eventually(TICKET_DENIALS, "aud-upl-other", 1).await;
    assert_eq!(r[0]["actor_admin_id"], json!(h.admin_id));
    assert_eq!(
        rows_now("SELECT op FROM audit WHERE tenant = ?1", "aud-upl-other").len(),
        0
    );
}

#[tokio::test]
async fn no_audit_row_carries_the_ticket_or_its_hash() {
    use drust::mgmt::mcp_oauth::tokens::{TokenKind, hash};
    audit_path();
    let h = spin_up_ticket_harness(&["aud-upl-leak"], true).await;
    let t = upload_ticket_for(&h, "aud-upl-leak").await;
    let hashed = hash(TokenKind::UploadTicket, &t);
    let (s, hd) = tus(
        &h.app,
        "POST",
        "/t/aud-upl-leak/uploads",
        &t,
        &[("upload-length", "4")],
        vec![],
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::CREATED);
    let tok = hd["location"]
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let (s, _) = tus(
        &h.app,
        "PATCH",
        &format!("/t/aud-upl-leak/uploads/{tok}"),
        &t,
        &[
            ("upload-offset", "0"),
            ("content-type", "application/offset+octet-stream"),
        ],
        b"abcd".to_vec(),
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::NO_CONTENT);
    let (s, _) = tus(&h.app, "GET", "/t/aud-upl-leak/files", &t, &[], vec![]).await;
    assert_eq!(s, axum::http::StatusCode::UNAUTHORIZED);
    rows_eventually(TICKET_DENIALS, "aud-upl-leak", 1).await;
    let rows = rows_now(
        "SELECT op, token_hint, extra, error_code FROM audit \
         WHERE tenant = ?1 OR json_extract(extra, '$.requested_tenant') = ?1",
        "aud-upl-leak",
    );
    assert!(rows.len() >= 3, "anti-vacuous: {} rows", rows.len());
    let leaked = rows.iter().any(|row| {
        ["op", "token_hint", "extra", "error_code"].iter().any(|k| {
            row[*k]
                .as_str()
                .is_some_and(|v| v.contains(t.as_str()) || v.contains(hashed.as_str()))
        })
    });
    assert!(!leaked, "an audit row carries the ticket or its hash");
}

// ─── create_upload_url ──────────────────────────────────────────────────────

async fn upl_audit_harness(tenant: &'static str) -> helpers::AccountMcpHarness {
    helpers::spin_up_account_mcp_with(helpers::AccountMcpOpts {
        admins: vec![("mcp-owner", "owner"), ("upl-member", "member")],
        tenants: vec![(tenant, Some(0))],
        files: true,
        mcp_enabled: true,
    })
    .await
}

/// The parsed reply of a successful create_upload_url call.
async fn upl_reply(h: &helpers::AccountMcpHarness, args: Value) -> Value {
    let m = mcp_call(&h.app, &h.access, &h.tid, "create_upload_url", args).await;
    assert_ne!(m["result"]["isError"], true, "create_upload_url refused");
    serde_json::from_str(m["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn create_upload_url_success_writes_one_issuance_row() {
    audit_path();
    let h = upl_audit_harness("aud-upl-ok").await;
    let o = &h.accesses[0];
    let args = json!({"tenant": "aud-upl-ok", "size": 5, "path": "a/b.txt",
        "visibility": "public", "filename": "secret-name.txt"});
    let mut plain = Vec::new();
    for _ in 0..2 {
        let r = upl_reply(&h, args.clone()).await;
        let auth = r["create"]["headers"]["Authorization"].as_str().unwrap();
        plain.push(auth.strip_prefix("Bearer ").unwrap().to_string());
    }
    let label: String = h
        .meta
        .lock()
        .await
        .query_row(
            "SELECT COALESCE(email, username) FROM admins WHERE id = ?1",
            [o.admin_id],
            |r| r.get(0),
        )
        .unwrap();
    let rows = rows_eventually(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'create_upload_url'"),
        "aud-upl-ok",
        2,
    )
    .await;
    for row in &rows {
        assert_eq!(row["status"], "ok");
        assert_eq!(row["error_code"], Value::Null);
        assert_eq!(row["auth_method"], "mcp_oauth");
        assert_eq!(row["token_hint"], "-");
        assert_eq!(row["actor_admin_id"], json!(o.admin_id));
        assert_eq!(row["actor_email_snapshot"], json!(label));
        assert_eq!(
            extra_of(row),
            json!({"grant_id": o.grant_id, "max_bytes": 5, "visibility": "public", "has_path": true})
        );
    }
    let mut scanned = rows_now("SELECT * FROM audit WHERE tenant = ?1", "aud-upl-ok");
    scanned.extend(rows_now(
        "SELECT * FROM audit WHERE tenant = '-' AND actor_admin_id = CAST(?1 AS INTEGER)",
        &o.admin_id.to_string(),
    ));
    assert!(scanned.len() >= 2);
    let kind = drust::mgmt::mcp_oauth::tokens::TokenKind::UploadTicket;
    let mut needles: Vec<String> = vec!["a/b.txt".into(), "secret-name.txt".into()];
    for p in &plain {
        needles.push(p.clone());
        needles.push(drust::mgmt::mcp_oauth::tokens::hash(kind, p));
    }
    for row in &scanned {
        let s = row.to_string();
        for (i, n) in needles.iter().enumerate() {
            assert!(!s.contains(n.as_str()), "an audit row carries needle #{i}");
        }
    }
}

#[tokio::test]
async fn create_upload_url_denials_audit_on_the_host_only() {
    audit_path();
    let h = upl_audit_harness("aud-upl-deny").await;
    let m = &h.accesses[1];
    let before = rows_now(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1"),
        "aud-upl-deny",
    )
    .len();
    // (a) a tenant the member cannot see
    let text = mcp_tool_text(
        &h.app,
        &m.access,
        "aud-upl-deny",
        "create_upload_url",
        json!({"size": 1}),
    )
    .await;
    assert!(text.contains("TENANT_NOT_FOUND"));
    let d = rows_eventually(
        &format!(
            "SELECT {COLS} FROM audit WHERE tenant = '-' AND op = 'mcp_denied' \
             AND json_extract(extra, '$.requested_tenant') = ?1"
        ),
        "aud-upl-deny",
        1,
    )
    .await;
    assert_eq!(d[0]["error_code"], "TENANT_NOT_FOUND");
    assert_eq!(d[0]["actor_admin_id"], json!(m.admin_id));
    assert_eq!(
        extra_of(&d[0]),
        json!({"surface": "upload_tool", "name": "create_upload_url",
            "requested_tenant": "aud-upl-deny", "grant_id": m.grant_id})
    );
    // (b) no tenant at all. Such a row names no tenant, so it is found as one
    // more row of its kind (others in this binary may exist), not by admin id.
    let no_tenant = "SELECT tenant, op, error_code, actor_admin_id, extra FROM audit \
         WHERE tenant = '-' AND op = 'mcp_denied' AND error_code = 'TENANT_REQUIRED' \
         AND json_extract(extra, '$.name') = ?1";
    let earlier = rows_now(no_tenant, "create_upload_url").len();
    let (st, _, msgs) = mcp_rpc(
        &h.app,
        Some(&m.access),
        tools_call("create_upload_url", json!({"size": 1})),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(msgs[0]["result"]["isError"], true);
    fence(&h, "fence-upl-deny").await;
    let r = rows_now(no_tenant, "create_upload_url");
    assert!(r.len() > earlier, "no TENANT_REQUIRED row was written");
    for row in &r {
        let x = extra_of(row);
        assert_eq!(x["surface"], "upload_tool");
        assert!(x.get("requested_tenant").is_none(), "{row}");
    }
    assert!(
        r.iter()
            .any(|row| row["actor_admin_id"] == json!(m.admin_id))
    );
    assert_eq!(
        rows_now(
            &format!("SELECT {COLS} FROM audit WHERE tenant = ?1"),
            "aud-upl-deny"
        )
        .len(),
        before
    );
    assert!(
        rows_now(
            "SELECT * FROM audit WHERE tenant = 'aud-upl-deny' AND actor_admin_id = CAST(?1 AS INTEGER)",
            &m.admin_id.to_string(),
        )
        .is_empty()
    );
}

#[tokio::test]
async fn create_upload_url_refused_after_resolve_audits_on_the_tenant() {
    audit_path();
    let h = upl_audit_harness("aud-upl-big").await;
    let o = &h.accesses[0];
    // the harness's large_upload_max_bytes is the MgmtState default 2 GiB
    let text = mcp_tool_text(
        &h.app,
        &h.access,
        "aud-upl-big",
        "create_upload_url",
        json!({"size": 2_147_483_649u64}),
    )
    .await;
    assert!(text.contains("UPLOAD_TOO_LARGE"));
    let rows = rows_eventually(
        &format!("SELECT {COLS} FROM audit WHERE tenant = ?1 AND op = 'create_upload_url'"),
        "aud-upl-big",
        1,
    )
    .await;
    assert_eq!(rows[0]["status"], "error");
    assert_eq!(rows[0]["error_code"], "UPLOAD_TOO_LARGE");
    assert_eq!(rows[0]["actor_admin_id"], json!(o.admin_id));
    // No host row names this tenant (admin ids repeat across this binary's
    // harnesses, so the tenant id is the filter).
    fence(&h, "fence-upl-big").await;
    assert!(
        rows_now(
            "SELECT * FROM audit WHERE tenant = '-' \
             AND json_extract(extra, '$.requested_tenant') = ?1",
            "aud-upl-big",
        )
        .is_empty()
    );
}

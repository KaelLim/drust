//! v1.56 M3 — MCP Prompts. `prompt_list` is pure; `render_prompt` embeds the
//! tenant's live schema, so it runs against a real `DrustMcp` (same scaffold as
//! tests/mcp_resources.rs). Prompts are service-only by MCP dispatch; these
//! tests exercise the pure builders directly.

#[path = "helpers.rs"]
mod helpers;

use drust::mcp::prompts::{prompt_list, render_prompt};
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

fn tf(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: false,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

fn args(pairs: &[(&str, &str)]) -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut m = serde_json::Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }
    Some(m)
}

fn body_of(r: &rmcp::model::GetPromptResult) -> String {
    r.messages
        .iter()
        .map(|m| match &m.content {
            rmcp::model::PromptMessageContent::Text { text } => text.clone(),
            _ => String::new(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn prompt_list_advertises_the_full_set() {
    let names: Vec<String> = prompt_list().into_iter().map(|p| p.name).collect();
    for want in [
        "bootstrap",
        "design_collection",
        "secure_collection",
        "debug_write",
        "write_edge_function",
        "review_history",
    ] {
        assert!(names.iter().any(|n| n == want), "missing prompt {want}");
    }
    assert_eq!(names.len(), 6);
}

#[tokio::test]
async fn bootstrap_embeds_the_tenant_schema() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "notes", &[tf("body", "text")])
        .await
        .unwrap();
    let r = render_prompt(&s, "bootstrap", &None).await.unwrap();
    let body = body_of(&r);
    assert!(body.contains("blog"), "names the tenant: {body}");
    assert!(
        body.contains("notes"),
        "embeds the live schema (collection name): {body}"
    );
    assert!(body.contains("dry_run"), "carries the core rules");
}

#[tokio::test]
async fn secure_collection_embeds_the_definition() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "posts", &[tf("title", "text")])
        .await
        .unwrap();
    let r = render_prompt(&s, "secure_collection", &args(&[("collection", "posts")]))
        .await
        .unwrap();
    let body = body_of(&r);
    assert!(body.contains("posts"), "names the collection: {body}");
    assert!(
        body.contains("anon_caps"),
        "embeds the definition (caps): {body}"
    );
}

#[tokio::test]
async fn design_collection_embeds_the_purpose() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let r = render_prompt(
        &s,
        "design_collection",
        &args(&[("purpose", "blog posts with tags")]),
    )
    .await
    .unwrap();
    assert!(body_of(&r).contains("blog posts with tags"));
}

#[tokio::test]
async fn write_edge_function_embeds_the_wit_contract_and_egress_gotcha() {
    // The prompt must hand an MCP client the ACTUAL guest contract — the WIT
    // (whose `http-fetch` import is the whole reason to fetch it) and the
    // deny-by-default egress gotcha — not just point at an SDK it cannot reach.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let r = render_prompt(
        &s,
        "write_edge_function",
        &args(&[("trigger", "record.created")]),
    )
    .await
    .unwrap();
    let body = body_of(&r);
    assert!(
        body.contains("record.created"),
        "carries the trigger: {body}"
    );
    // WIT embedded verbatim (include_str! of the SDK template world.wit).
    assert!(
        body.contains("http-fetch: func(origin: string"),
        "embeds the real WIT http-fetch signature: {body}"
    );
    assert!(
        body.contains("export handle: func(event-json: string)"),
        "embeds the WIT world export: {body}"
    );
    // The guest skeleton (include_str! of the SDK template src/lib.rs).
    assert!(
        body.contains("impl Guest for EdgeFn"),
        "embeds the lib.rs skeleton: {body}"
    );
    // The #1 first-run trap.
    assert!(
        body.contains("EGRESS_NOT_ALLOWLISTED"),
        "warns about the deny-by-default egress gotcha: {body}"
    );
}

/// `insert_record` / `update_record` have no `dry_run`, so it may not be
/// offered as a fix; a lost reply is checked the way the instructions say, with
/// `recent_writes`, and a failure is read from the isError result (this endpoint
/// never answers a tool failure as a JSON-RPC error).
#[tokio::test]
async fn debug_write_makes_no_dry_run_promise_and_matches_the_instructions() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let r = render_prompt(&s, "debug_write", &args(&[("collection", "posts")]))
        .await
        .unwrap();
    let body = body_of(&r);
    assert!(
        !body.contains("Re-run the write with `dry_run: true`"),
        "debug_write: {body}"
    );
    assert!(
        body.contains("check `recent_writes`"),
        "debug_write: {body}"
    );
    assert!(!body.contains("JSON-RPC error"), "debug_write: {body}");
    assert!(body.contains("isError result"), "debug_write: {body}");
    assert!(body.contains("suggested_fix"), "debug_write: {body}");
    assert!(body.contains("list_records"), "debug_write: {body}");
}

/// The recipe names no upload URL (the user uploads the .wasm), and the egress
/// step uses the MCP tools instead of a raw PUT that would replace the whole
/// allowlist.
#[tokio::test]
async fn write_edge_function_names_no_upload_url() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let r = render_prompt(
        &s,
        "write_edge_function",
        &args(&[("trigger", "record.created")]),
    )
    .await
    .unwrap();
    let body = body_of(&r);
    let fn_path = drust::base_path::base("/t/blog/functions");
    assert!(
        body.contains("Build it, then ask the user to upload the .wasm"),
        "{body}"
    );
    assert!(!body.contains(&fn_path), "must not carry {fn_path}: {body}");
    for bad in ["curl -X POST /t/", "curl -X PUT", "/egress-allowlist"] {
        assert!(!body.contains(bad), "must not contain {bad:?}: {body}");
    }
    assert!(body.contains("get_egress_allowlist"), "{body}");
    assert!(body.contains("set_egress_allowlist"), "{body}");
    assert!(body.contains("EGRESS_NOT_ALLOWLISTED"), "{body}");
}

/// M1 (T7): on MCP the caller is the service identity — nothing is
/// owner-enforced for it.
#[tokio::test]
async fn bootstrap_does_not_claim_owner_enforcement() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let r = render_prompt(&s, "bootstrap", &None).await.unwrap();
    let body = body_of(&r);
    assert!(!body.contains("owner-enforced"), "bootstrap: {body}");
    assert!(body.contains("dry_run"), "bootstrap: {body}");
}

/// M1: the type list matches `create_collection` (`type_to_sqlite`).
#[tokio::test]
async fn design_collection_lists_every_field_type() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let r = render_prompt(&s, "design_collection", &args(&[("purpose", "events")]))
        .await
        .unwrap();
    let body = body_of(&r);
    assert!(body.contains("datetime"), "design_collection: {body}");
    assert!(body.contains("json"), "design_collection: {body}");
}

#[tokio::test]
async fn missing_required_arg_is_invalid_params() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let e = render_prompt(&s, "design_collection", &None)
        .await
        .unwrap_err();
    assert_eq!(e.code.0, -32602, "missing arg → invalid_params");
}

#[tokio::test]
async fn unknown_collection_and_unknown_prompt_are_invalid_params() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let e = render_prompt(&s, "secure_collection", &args(&[("collection", "nope")]))
        .await
        .unwrap_err();
    assert_eq!(e.code.0, -32602, "unknown collection → invalid_params");

    let e2 = render_prompt(&s, "no_such_prompt", &None)
        .await
        .unwrap_err();
    assert_eq!(e2.code.0, -32602, "unknown prompt → invalid_params");
}

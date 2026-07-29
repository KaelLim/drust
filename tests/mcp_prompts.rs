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

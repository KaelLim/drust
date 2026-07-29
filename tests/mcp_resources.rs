//! v1.56 M2 — MCP Resources: the thin router projects tenant knowledge into
//! `drust://<tenant>/<path>` by calling the SAME reader fns the tools use.
//! Tests exercise the pure helpers (`parse_resource_uri` / `render_resource` /
//! `static_resource_list`) directly against a real `DrustMcp` — constructing a
//! `RequestContext` for the trait methods is impractical in a unit test.

#[path = "helpers.rs"]
mod helpers;

use drust::mcp::resources::{
    ResourceUri, parse_resource_uri, render_resource, static_resource_list,
};
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

#[tokio::test]
async fn schema_resource_renders_via_reader_fn() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "notes", &[tf("body", "text")])
        .await
        .unwrap();
    let uri = parse_resource_uri("drust://blog/schema", "blog").unwrap();
    assert_eq!(uri, ResourceUri::Schema);
    let (body, mime) = render_resource(&s, &uri).await.unwrap();
    assert_eq!(mime, "application/json");
    assert!(
        body.contains("notes"),
        "schema resource must list the collection (same output as get_schema_overview): {body}"
    );
}

#[tokio::test]
async fn static_list_advertises_all_nine_resources() {
    let list = static_resource_list("blog");
    assert_eq!(list.len(), 9, "9 static resources advertised");
    let json = serde_json::to_string(&list).unwrap();
    for path in [
        "schema",
        "schema.md",
        "collections",
        "openapi.json",
        "types.ts",
        "zod.ts",
        "functions",
        "rpcs",
        "cron",
    ] {
        assert!(
            json.contains(&format!("drust://blog/{path}")),
            "resources/list must include {path}: {json}"
        );
    }
}

#[tokio::test]
async fn all_static_resources_render_with_correct_mime() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "notes", &[tf("body", "text")])
        .await
        .unwrap();
    // Every static resource renders non-empty with the declared mime.
    for (uri, mime) in [
        ("drust://blog/schema", "application/json"),
        ("drust://blog/schema.md", "text/markdown"),
        ("drust://blog/collections", "application/json"),
        ("drust://blog/openapi.json", "application/json"),
        ("drust://blog/types.ts", "text/typescript"),
        ("drust://blog/zod.ts", "text/typescript"),
        ("drust://blog/functions", "application/json"),
        ("drust://blog/rpcs", "application/json"),
        ("drust://blog/cron", "application/json"),
    ] {
        let parsed = parse_resource_uri(uri, "blog").unwrap();
        let (body, m) = render_resource(&s, &parsed).await.unwrap();
        assert_eq!(m, mime, "mime for {uri}");
        assert!(!body.is_empty(), "empty body for {uri}");
    }
    // The schema-derived resources all mention the collection (thin-router: same
    // output as the underlying reader/codegen).
    for uri in [
        "drust://blog/schema",
        "drust://blog/schema.md",
        "drust://blog/collections",
        "drust://blog/openapi.json",
        "drust://blog/types.ts",
        "drust://blog/zod.ts",
    ] {
        let parsed = parse_resource_uri(uri, "blog").unwrap();
        let (body, _) = render_resource(&s, &parsed).await.unwrap();
        assert!(
            body.to_lowercase().contains("notes"),
            "{uri} should mention the collection: {}",
            &body[..body.len().min(160)]
        );
    }
}

#[tokio::test]
async fn cross_tenant_uri_denied_without_touching_pool() {
    // A resource URI naming another tenant is refused by the host-compare guard
    // (-32002) before any pool is opened.
    let e = parse_resource_uri("drust://other-tenant/schema", "blog").unwrap_err();
    assert_eq!(e.code.0, -32002);
}

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
async fn static_list_advertises_schema_for_this_tenant() {
    let list = static_resource_list("blog");
    let json = serde_json::to_string(&list).unwrap();
    assert!(
        json.contains("drust://blog/schema"),
        "resources/list must include the schema resource: {json}"
    );
}

#[tokio::test]
async fn cross_tenant_uri_denied_without_touching_pool() {
    // A resource URI naming another tenant is refused by the host-compare guard
    // (-32002) before any pool is opened.
    let e = parse_resource_uri("drust://other-tenant/schema", "blog").unwrap_err();
    assert_eq!(e.code.0, -32002);
}

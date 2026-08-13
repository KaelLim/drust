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
async fn static_list_advertises_all_ten_resources() {
    let list = static_resource_list("blog");
    // 9 (v1.56 M2) + the v1.64 files handbook.
    assert_eq!(list.len(), 10, "10 static resources advertised");
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
        "files-guide.md",
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
        ("drust://blog/files-guide.md", "text/markdown"),
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

// ── v1.64 (#974): the files handbook ──────────────────────────────────────
//
// The user asked for the file rules to live in a DOCUMENT rather than in an
// ever-fattening `whoami`, so what is pinned here is that the document really
// carries the model (an agent that reads it needs no other source) and that its
// live section reflects THIS tenant's registry — a handbook whose grant list is
// stale or absent would send the reader back to guessing.

/// Write one prefix rule straight through the registry kernel — the same
/// function every write face calls, so the fixture cannot drift from what a
/// real `set_file_policy` would store.
async fn grant(s: &drust::mcp::server::DrustMcp, prefix: &str, roles: &[&str]) {
    let row = drust::storage::file_policy::FilePolicyRow {
        prefix: prefix.to_string(),
        owner_scoped: false,
        public_read: true,
        select_policy: None,
        delete_policy: None,
        public_upload_roles: Some(roles.iter().map(|r| r.to_string()).collect()),
    };
    s.inner()
        .pool
        .with_writer(move |c| drust::storage::file_policy::upsert_file_policy(c, &row))
        .await
        .unwrap();
}

#[tokio::test]
async fn files_guide_carries_the_grant_model_and_no_credentials() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let uri = parse_resource_uri("drust://blog/files-guide.md", "blog").unwrap();
    assert_eq!(uri, ResourceUri::FilesGuide);
    let (body, mime) = render_resource(&s, &uri).await.unwrap();
    assert_eq!(mime, "text/markdown");

    // (a) The grant model itself: the column, both role names, the longest-prefix
    // rule, the outer cap gate, and the fact that absence denies.
    for needle in [
        "public_upload_roles",
        "\"anon\"",
        "\"user\"",
        "LONGEST",
        "upload` file cap",
        "deny-by-default",
    ] {
        assert!(
            body.contains(needle),
            "the guide must explain the grant model — missing {needle:?}"
        );
    }
    // (b) The two upload stations and the two buckets.
    for needle in [
        "multipart/form-data",
        "tus 1.0",
        "private bucket",
        "public bucket",
    ] {
        assert!(
            body.contains(needle),
            "missing upload/visibility text {needle:?}"
        );
    }
    // (c) The remediation the error code sends a reader here for, plus curl.
    assert!(
        body.contains("FILE_PUBLIC_UPLOAD_DENIED"),
        "the guide must name the error it remedies"
    );
    assert!(
        body.contains("list_file_policies") && body.contains("set_file_visibility"),
        "remediation must name the tools that fix it: {body}"
    );
    assert!(
        body.contains("curl -X PUT"),
        "curl examples must be present"
    );

    // (d) NO credentials. A resource can be auto-pulled into model context, so
    // tokens stay behind the whoami TOOL (mcp-surface rule) — the guide may only
    // name the env-var placeholder and point at whoami.
    assert!(
        body.contains("whoami"),
        "the guide must point at whoami for tokens"
    );
    assert!(
        !body.contains("drust_svc_")
            && !body.contains("drust_user_")
            && !body.contains("Bearer dr"),
        "the guide must never embed a real token: {body}"
    );
}

#[tokio::test]
async fn files_guide_lists_this_tenants_live_grants() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let uri = parse_resource_uri("drust://blog/files-guide.md", "blog").unwrap();

    // A tenant with no grant is told so explicitly, not left with an empty table
    // that reads like "the section failed to render".
    let (body, _) = render_resource(&s, &uri).await.unwrap();
    assert!(
        body.contains("No prefix grants public upload"),
        "an ungranted tenant must say so: {body}"
    );

    grant(&s, "avatars/", &["user"]).await;
    grant(&s, "drop/", &["anon", "user"]).await;
    let (body, _) = render_resource(&s, &uri).await.unwrap();
    let live = body
        .split("publish grants (live)")
        .nth(1)
        .expect("live section present");
    assert!(
        live.contains("`avatars/`") && live.contains("`drop/`"),
        "both granted prefixes must be listed: {live}"
    );
    assert!(
        live.contains("| user |") && live.contains("| anon, user |"),
        "each prefix must show WHICH roles it grants: {live}"
    );
    assert!(
        !live.contains("No prefix grants public upload"),
        "the empty-state line must not survive alongside real rows: {live}"
    );

    // Revoking is visible in the same read — the point of a live section.
    s.inner()
        .pool
        .with_writer(|c| drust::storage::file_policy::delete_file_policy(c, "avatars/").map(|_| ()))
        .await
        .unwrap();
    let (body, _) = render_resource(&s, &uri).await.unwrap();
    let live = body.split("publish grants (live)").nth(1).unwrap();
    assert!(
        !live.contains("`avatars/`") && live.contains("`drop/`"),
        "a cleared rule must leave the guide's live list: {live}"
    );
}

#[tokio::test]
async fn files_guide_reports_an_unreadable_registry_instead_of_looking_ungranted() {
    // Fail-closed is invisible in a document: "no grants" and "I could not read
    // the registry" render the same unless the render says so — and the second
    // one also means every non-service file READ is being denied.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    s.inner()
        .pool
        .with_writer(|c| c.execute_batch("DROP TABLE \"_system_file_policy\""))
        .await
        .unwrap();
    let uri = parse_resource_uri("drust://blog/files-guide.md", "blog").unwrap();
    let (body, _) = render_resource(&s, &uri).await.unwrap();
    assert!(
        body.contains("could not be read"),
        "an unreadable registry must be reported, not rendered as 'no grants': {body}"
    );
    assert!(
        !body.contains("No prefix grants public upload"),
        "…and must NOT be reported as the ungranted-but-healthy state: {body}"
    );
}

#[tokio::test]
async fn cross_tenant_uri_denied_without_touching_pool() {
    // A resource URI naming another tenant is refused by the host-compare guard
    // (-32002) before any pool is opened.
    let e = parse_resource_uri("drust://other-tenant/schema", "blog").unwrap_err();
    assert_eq!(e.code.0, -32002);
}

// ── M4 templates ──────────────────────────────────────────────────────────

#[tokio::test]
async fn collection_schema_and_records_templates_render() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "notes", &[tf("body", "text")])
        .await
        .unwrap();

    let cs = parse_resource_uri("drust://blog/collections/notes/schema", "blog").unwrap();
    let (body, mime) = render_resource(&s, &cs).await.unwrap();
    assert_eq!(mime, "application/json");
    assert!(body.contains("body"), "schema lists the field: {body}");

    let recs =
        parse_resource_uri("drust://blog/collections/notes/records?per_page=5", "blog").unwrap();
    let (body, _) = render_resource(&s, &recs).await.unwrap();
    assert!(
        body.contains("drust://blog/collections/notes/records/{id}"),
        "records body carries the top-level resource_uri_template: {body}"
    );
}

#[tokio::test]
async fn single_record_template_returns_the_row() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "notes", &[tf("body", "text")])
        .await
        .unwrap();
    // Insert one row and confirm the single-record resource returns it AND the
    // insert response carries a concrete resource_link.
    let ins = drust::mcp::tools::write::insert_record(
        &s,
        "notes",
        serde_json::json!({ "body": "hello-resource" }),
    )
    .await
    .unwrap();
    let id = ins["id"].as_i64().unwrap();
    assert_eq!(
        ins["resource_link"],
        format!("drust://blog/collections/notes/records/{id}"),
        "insert_record carries a concrete resource_link: {ins}"
    );

    let uri = format!("drust://blog/collections/notes/records/{id}");
    let parsed = parse_resource_uri(&uri, "blog").unwrap();
    let (body, mime) = render_resource(&s, &parsed).await.unwrap();
    assert_eq!(mime, "application/json");
    assert!(
        body.contains("hello-resource"),
        "single-record resource returns the row: {body}"
    );
}

#[tokio::test]
async fn single_record_missing_row_is_not_found() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "notes", &[tf("body", "text")])
        .await
        .unwrap();
    let parsed = parse_resource_uri("drust://blog/collections/notes/records/9999", "blog").unwrap();
    let e = render_resource(&s, &parsed).await.unwrap_err();
    assert_eq!(e.code.0, -32002, "absent row → -32002, not a 500");
}

#[tokio::test]
async fn collection_schema_unknown_collection_is_not_found() {
    // describe_collection returns Ok({"error_code":...}) for a missing
    // collection — the render arm must map that to -32002, not a success body.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let parsed = parse_resource_uri("drust://blog/collections/nope/schema", "blog").unwrap();
    let e = render_resource(&s, &parsed).await.unwrap_err();
    assert_eq!(e.code.0, -32002);
}

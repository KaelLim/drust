//! #950-B T6 — the MCP face of the `_system_file_policy` registry.
//!
//! Three tools (`set_file_policy` / `list_file_policies` / `clear_file_policy`)
//! over the SAME T3 core the REST face uses. What is pinned here:
//!
//! 1. **One validation kernel, one error vocabulary.** The MCP face must not
//!    re-implement the four refusals — a second copy is how two faces come to
//!    disagree about what "restricted but unspecified" means. Each code is
//!    asserted through the tool, and `bail_mcp` reads everything before the
//!    first colon as `error_code`, so `FILE_POLICY_*: <why>` is the wire shape.
//! 2. **A refused write leaves nothing behind.** Validation runs before the
//!    writer lock, so a rejected registration must not appear in `list`.
//! 3. **The clause arguments are typed, and tolerate a stringified object**
//!    (v1.58.6: a bare `serde_json::Value` arg advertises "any", which invited
//!    clients to JSON-encode the object and made every filter fail).
//!
//! MCP is service-only by dispatch (`/t/<id>/mcp` → anon `WRITE_DENIED`, user
//! `MCP_USER_DENIED`), so there is deliberately no per-tool role check to test
//! here — the REST face carries that half (`tests/files_rls_policy.rs`).
//!
//! Delegates are driven directly, as in `tests/policy_mcp.rs`; the wire-name +
//! annotation half lives in-file in `src/mcp/handler.rs` because `tool_router()`
//! has inherited visibility.

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::file_policy as fp;
use drust::storage::pool::TenantRegistry;
use serde_json::{Value, json};
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir, tenant: &str) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create(tenant).await.unwrap()
}

/// The `error_code` an MCP client would see: `bail_mcp` splits on the first
/// colon, so asserting on that prefix is asserting on the wire contract.
fn code_of(e: &anyhow::Error) -> String {
    let msg = e.to_string();
    msg.split(':').next().unwrap_or("").trim().to_string()
}

async fn policies(mcp: &DrustMcp) -> Vec<Value> {
    let v = fp::list_file_policies(mcp).await.unwrap();
    v["policies"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn set_list_clear_round_trip_and_a_second_clear_is_not_found() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcpfp-rt").await;

    // A fresh tenant DB opened directly has no seeded root (the seed lives in
    // `make_tenant_inner` / the boot migration), so the registry starts empty.
    assert!(policies(&mcp).await.is_empty());

    let v = fp::set_file_policy(&mcp, "avatars/", true, false, None, None)
        .await
        .unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["prefix"], "avatars/");

    let listed = policies(&mcp).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["prefix"], "avatars/");
    assert_eq!(listed[0]["owner_scoped"], true);
    assert_eq!(listed[0]["public_read"], false);

    // A re-register REPLACES rather than duplicating, and the stored clause
    // round-trips under its wire name (`select`, not `select_policy_json`).
    let select = json!({ "visibility": "private" });
    fp::set_file_policy(&mcp, "avatars/", true, false, Some(select.clone()), None)
        .await
        .unwrap();
    let listed = policies(&mcp).await;
    assert_eq!(listed.len(), 1, "re-register must replace, never duplicate");
    assert_eq!(listed[0]["select"], select);

    assert_eq!(
        fp::clear_file_policy(&mcp, "avatars/").await.unwrap()["ok"],
        true
    );
    assert!(policies(&mcp).await.is_empty());

    let err = fp::clear_file_policy(&mcp, "avatars/").await.unwrap_err();
    assert_eq!(
        code_of(&err),
        "FILE_POLICY_NOT_FOUND",
        "clearing a rule that was never there is a distinct fact from clearing \
         one that was: {err}"
    );
}

#[tokio::test]
async fn the_tenant_root_is_addressable_as_the_empty_prefix() {
    // `''` is a legal prefix and the only rule an unfiled (`path IS NULL`) row
    // can match — the seeded-root shape the upgrade depends on.
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcpfp-root").await;

    fp::set_file_policy(&mcp, "", false, true, None, None)
        .await
        .unwrap();
    let listed = policies(&mcp).await;
    assert_eq!(listed[0]["prefix"], "");
    assert_eq!(listed[0]["public_read"], true);

    assert_eq!(fp::clear_file_policy(&mcp, "").await.unwrap()["ok"], true);
    assert!(policies(&mcp).await.is_empty());
}

#[tokio::test]
async fn the_four_registry_refusals_travel_over_mcp_with_their_codes() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcpfp-err").await;

    // (a) clause-less: neither owner-scoped, nor filtered, nor explicitly open.
    let err = fp::set_file_policy(&mcp, "open/", false, false, None, None)
        .await
        .unwrap_err();
    assert_eq!(code_of(&err), "FILE_POLICY_OPEN_REQUIRES_FLAG");

    // A delete clause alone is not an answer to "who may READ this prefix".
    let err = fp::set_file_policy(
        &mcp,
        "open/",
        false,
        false,
        None,
        Some(json!({ "uploader": { "$auth": "id" } })),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&err), "FILE_POLICY_OPEN_REQUIRES_FLAG");

    // (b) prefix grammar: a non-empty prefix must end in '/', and no segment
    // may be a dot-segment.
    for bad in ["avatars", "a/../", "/a/", "a//"] {
        let err = fp::set_file_policy(&mcp, bad, true, false, None, None)
            .await
            .unwrap_err();
        assert_eq!(code_of(&err), "FILE_POLICY_PREFIX_INVALID", "{bad:?}");
    }

    // (c) #954 cross-storage-class operand: size_bytes is INTEGER, $auth is
    // always the TEXT user id — the two evaluators would order it differently.
    let err = fp::set_file_policy(
        &mcp,
        "x/",
        true,
        false,
        Some(json!({ "size_bytes": { "$lt": { "$auth": "id" } } })),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&err), "FILE_POLICY_OPERAND_UNSUPPORTED");

    // …and a column deliberately kept out of the synthetic file schema.
    let err = fp::set_file_policy(
        &mcp,
        "x/",
        true,
        false,
        Some(json!({ "meta_json": "x" })),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&err), "FILE_POLICY_OPERAND_UNSUPPORTED");

    // The delete clause goes through the same validator.
    let err = fp::set_file_policy(
        &mcp,
        "x/",
        true,
        false,
        None,
        Some(json!({ "size_bytes": { "$gt": { "$auth": "id" } } })),
    )
    .await
    .unwrap_err();
    assert_eq!(code_of(&err), "FILE_POLICY_OPERAND_UNSUPPORTED");

    assert!(
        policies(&mcp).await.is_empty(),
        "every refusal must leave the registry untouched — validation runs \
         before the writer lock"
    );
}

#[tokio::test]
async fn a_double_encoded_clause_string_is_accepted_like_the_object() {
    // v1.58.6: many MCP clients JSON-encode object-typed arguments. The clause
    // args route through `parse_filter_value`, which peels one string layer and
    // otherwise returns a teaching hint instead of serde's "did not match any
    // variant of untagged enum FilterAst".
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcpfp-str").await;

    let as_string = json!("{\"uploader\":{\"$auth\":\"id\"}}");
    fp::set_file_policy(&mcp, "docs/", false, false, Some(as_string), None)
        .await
        .unwrap();
    let listed = policies(&mcp).await;
    assert_eq!(
        listed[0]["select"],
        json!({ "uploader": { "$auth": "id" } }),
        "the stringified clause must store as the parsed object"
    );

    // A clause that is neither an object nor a decodable string is refused,
    // with the hint rather than an opaque serde error.
    let err = fp::set_file_policy(&mcp, "docs/", false, false, Some(json!(7)), None)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("select"),
        "the refusal must name which clause failed: {err}"
    );
}

#[tokio::test]
async fn the_clause_arguments_advertise_an_object_schema_not_any() {
    // The v1.58.6 root cause was a schema, not a parser: a bare `Value` arg
    // renders as "any", and clients then stringify it. Both clause args must
    // publish the shared FilterAst object schema.
    let schema = serde_json::to_value(schemars::schema_for!(fp::SetFilePolicyArgs)).unwrap();
    for prop in ["select", "delete"] {
        assert_eq!(
            schema["properties"][prop]["type"], "object",
            "{prop} must advertise type=object, got: {}",
            schema["properties"][prop]
        );
    }
    assert_eq!(
        schema["properties"]["prefix"]["type"], "string",
        "prefix is a plain string"
    );
}

#[tokio::test]
async fn list_files_exposes_the_logical_path() {
    // Anti-drift: `_system_files` grew a `path` column in v1.63, and the MCP
    // file object is one of the two faces that projects a file row (the REST
    // list returns the whole `FileRow`). A file object without `path` cannot be
    // reconciled with the prefix rules `list_file_policies` returns.
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcpfp-files").await;

    mcp.inner()
        .pool
        .with_writer(|c| {
            c.execute(
                "INSERT INTO _system_files \
                   (key, original_name, content_type, size_bytes, visibility, uploader, path) \
                 VALUES ('k1.png', 'me.png', 'image/png', 5, 'private', 'u-alice', \
                         'avatars/alice/me.png')",
                [],
            )?;
            c.execute(
                "INSERT INTO _system_files \
                   (key, original_name, content_type, size_bytes, visibility, uploader) \
                 VALUES ('k2.bin', 'legacy.bin', NULL, 5, 'private', 'service')",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();

    let v = drust::mcp::tools::files::list_files(
        &mcp,
        drust::mcp::tools::files::ListFilesArgs {
            visibility: None,
            limit: 50,
            offset: 0,
        },
    )
    .await
    .unwrap();
    let files = v["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    let filed = files
        .iter()
        .find(|f| f["id"] == "k1.png")
        .expect("filed row present");
    assert_eq!(filed["path"], "avatars/alice/me.png");
    let unfiled = files
        .iter()
        .find(|f| f["id"] == "k2.bin")
        .expect("unfiled row present");
    assert!(
        unfiled["path"].is_null(),
        "an unfiled row reports null, never \"\" — the two mean different \
         things to prefix matching"
    );
}

#[test]
fn the_three_file_policy_tools_are_registered() {
    // `tool_router()` is inherited-visibility, so an external test can only see
    // the count; the wire names + annotations are pinned in-file by
    // `handler.rs::annotation_tests`. 73 (v1.60) + 3 = 76.
    assert_eq!(
        drust::mcp::handler::DrustMcpService::tool_count(),
        76,
        "MCP tool count must be 76 after adding the three file-policy tools"
    );
}

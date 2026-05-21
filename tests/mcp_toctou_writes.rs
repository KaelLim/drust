//! TOCTOU regression tests for the 6 schema-mutation MCP helpers that had a
//! read-before-write existence check outside the writer closure (v1.19.x).
//!
//! v1.20 commit D folded every existence check inside the `with_writer` closure
//! so the check and the write run under the same per-tenant writer-mutex
//! acquisition.  A concurrent `drop_collection` between the old two-step
//! pattern would leave orphan rows in `_system_collection_meta`; the fold
//! closes that window.
//!
//! Test strategy: true concurrent TOCTOU races are non-deterministic, so we
//! instead verify the observable invariant — calling any of the 6 helpers on a
//! non-existent collection (a) returns the expected typed error code AND (b) does
//! not write any orphan row into `_system_collection_meta`.  If the check were
//! still outside the writer we could not guarantee (b); inside the writer it is
//! structurally guaranteed because the row read and the potential-write are
//! serialised.
//!
//! The pattern is uniform across all 6 helpers; the comments explain the
//! coverage rationale for each.

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::owner_field::set_owner_field;
use drust::storage::pool::TenantRegistry;
use drust::storage::schema::DmlVerb;
use std::sync::Arc;

// ─── shared scaffolding ──────────────────────────────────────────────────────

async fn svc(dir: &tempfile::TempDir, tenant: &str) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create(tenant).await.unwrap()
}

/// Assert that `_system_collection_meta` has no row for `coll`, i.e. no orphan
/// was written as a side-effect of a rejected helper call.
async fn assert_no_orphan_meta(mcp: &DrustMcp, coll: &str) {
    let coll = coll.to_string();
    let n: i64 = mcp
        .inner()
        .pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT COUNT(*) FROM _system_collection_meta WHERE collection_name=?1",
                rusqlite::params![coll],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "orphan _system_collection_meta row found for a collection that should not exist"
    );
}

// ─── 1: set_anon_caps on non-existent collection ────────────────────────────

#[tokio::test]
async fn set_anon_caps_collection_not_found_no_orphan() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "toctou-anon-caps").await;

    let err = drust::mcp::tools::schema::set_anon_caps(
        &mcp,
        "ghost",
        &[DmlVerb::Select],
    )
    .await
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND") || msg.contains("unknown collection"),
        "expected COLLECTION_NOT_FOUND-flavoured error, got: {msg}"
    );
    // Confirm no orphan row was written.
    assert_no_orphan_meta(&mcp, "ghost").await;
}

// ─── 2: set_realtime on non-existent collection ──────────────────────────────

#[tokio::test]
async fn set_realtime_collection_not_found_no_orphan() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "toctou-realtime").await;

    let err = drust::mcp::tools::realtime::set_realtime(&mcp, "ghost", true)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND") || msg.contains("unknown collection"),
        "expected COLLECTION_NOT_FOUND-flavoured error, got: {msg}"
    );
    assert_no_orphan_meta(&mcp, "ghost").await;
}

// ─── 3: set_owner_field on non-existent collection ──────────────────────────

#[tokio::test]
async fn set_owner_field_collection_not_found_no_orphan() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "toctou-owner-field").await;

    // Even though there is no `user_id` column, the collection-not-found check
    // fires first — we never reach the FK validation step.
    let err = set_owner_field(
        &mcp.inner().pool,
        "ghost".to_string(),
        "user_id".to_string(),
        "own".to_string(),
    )
    .await
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND"),
        "expected COLLECTION_NOT_FOUND error, got: {msg}"
    );
    assert_no_orphan_meta(&mcp, "ghost").await;
}

// ─── 4: set_collection_description on non-existent collection ───────────────

#[tokio::test]
async fn set_collection_description_not_found_no_orphan() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "toctou-coll-desc").await;

    let err = drust::mcp::tools::schema::set_collection_description(
        &mcp.inner().pool,
        "ghost",
        "some description",
    )
    .await
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND"),
        "expected COLLECTION_NOT_FOUND error, got: {msg}"
    );
    assert_no_orphan_meta(&mcp, "ghost").await;
}

// ─── 5: set_field_description — two sub-cases ────────────────────────────────
//
// 5a: collection does not exist → COLLECTION_NOT_FOUND, no orphan.
// 5b: collection exists, field does not → FIELD_NOT_FOUND, no orphan key in
//     the field_descriptions_json blob.

#[tokio::test]
async fn set_field_description_collection_not_found_no_orphan() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "toctou-field-desc-coll").await;

    let err = drust::mcp::tools::schema::set_field_description(
        &mcp.inner().pool,
        "ghost",
        "title",
        "a field desc",
    )
    .await
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND"),
        "expected COLLECTION_NOT_FOUND error, got: {msg}"
    );
    assert_no_orphan_meta(&mcp, "ghost").await;
}

#[tokio::test]
async fn set_field_description_field_not_found_no_orphan_key() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "toctou-field-desc-field").await;

    create_collection(
        &mcp,
        "posts",
        &[FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: true,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
            description: None,
        }],
    )
    .await
    .unwrap();

    let err = drust::mcp::tools::schema::set_field_description(
        &mcp.inner().pool,
        "posts",
        "no_such_field",
        "a field desc",
    )
    .await
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("FIELD_NOT_FOUND"),
        "expected FIELD_NOT_FOUND error, got: {msg}"
    );

    // Verify that the field_descriptions_json blob has no orphan key for
    // `no_such_field` — the write must not have occurred.
    let blob: Option<String> = mcp
        .inner()
        .pool
        .with_reader(|c| {
            c.query_row(
                "SELECT field_descriptions_json FROM _system_collection_meta \
                 WHERE collection_name='posts'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .ok()
        .flatten();
    let map: serde_json::Value =
        blob.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(serde_json::json!({}));
    assert!(
        map.get("no_such_field").is_none(),
        "orphan key 'no_such_field' found in field_descriptions_json: {map}"
    );
}

// ─── 6: set_index_description — two sub-cases ────────────────────────────────
//
// 6a: collection does not exist → COLLECTION_NOT_FOUND, no orphan.
// 6b: collection exists, index does not → INDEX_NOT_FOUND, no orphan key in
//     the index_descriptions_json blob.

#[tokio::test]
async fn set_index_description_collection_not_found_no_orphan() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "toctou-idx-desc-coll").await;

    let err = drust::mcp::tools::schema::set_index_description(
        &mcp.inner().pool,
        "ghost",
        "idx_ghost_foo",
        "an index desc",
    )
    .await
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND"),
        "expected COLLECTION_NOT_FOUND error, got: {msg}"
    );
    assert_no_orphan_meta(&mcp, "ghost").await;
}

#[tokio::test]
async fn set_index_description_index_not_found_no_orphan_key() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "toctou-idx-desc-idx").await;

    create_collection(
        &mcp,
        "posts",
        &[FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: true,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
            description: None,
        }],
    )
    .await
    .unwrap();

    let err = drust::mcp::tools::schema::set_index_description(
        &mcp.inner().pool,
        "posts",
        "idx_does_not_exist",
        "an index desc",
    )
    .await
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("INDEX_NOT_FOUND"),
        "expected INDEX_NOT_FOUND error, got: {msg}"
    );

    // Verify that the index_descriptions_json blob has no orphan key.
    let blob: Option<String> = mcp
        .inner()
        .pool
        .with_reader(|c| {
            c.query_row(
                "SELECT index_descriptions_json FROM _system_collection_meta \
                 WHERE collection_name='posts'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .ok()
        .flatten();
    let map: serde_json::Value =
        blob.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(serde_json::json!({}));
    assert!(
        map.get("idx_does_not_exist").is_none(),
        "orphan key 'idx_does_not_exist' found in index_descriptions_json: {map}"
    );
}

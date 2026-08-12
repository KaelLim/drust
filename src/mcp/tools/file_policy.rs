//! Files RLS (#950-B, v1.63) — the MCP face of the `_system_file_policy`
//! prefix registry: `set_file_policy` / `list_file_policies` /
//! `clear_file_policy`.
//!
//! These are thin adapters over `crate::storage::file_policy`, which is the
//! ONE validation kernel every face shares. The REST twin
//! (`crate::tenant::file_policy_routes`) calls the same four functions in the
//! same order — validate, then write — so the two faces cannot drift into two
//! different opinions about what a legal rule is. The only face-specific part
//! is how a refusal is rendered: REST maps [`FilePolicyError`] onto a status +
//! `error_code` body, and here `FilePolicyError`'s `Display` already reads
//! `CODE: why`, which is exactly the shape `handler::bail_mcp` splits on to
//! populate `error_code`.
//!
//! **Service-only by dispatch.** `/t/<id>/mcp` rejects anon (`WRITE_DENIED`)
//! and user (`MCP_USER_DENIED`) before a tool runs, so there is no per-tool
//! role check here — matching `set_policy` and the fts index tools. That is
//! also why the LIST tool needs no read gate even though the registry is the
//! tenant's file-access map: no untrusted caller can reach it.
//!
//! The clause arguments arrive as `serde_json::Value` and go through
//! [`parse_filter_value`], never a bare `serde_json::from_value` — the v1.58.6
//! lesson: a client that JSON-encodes an object argument must still be
//! understood, and a failure must return the teaching hint rather than serde's
//! "did not match any variant of untagged enum FilterAst".

use crate::mcp::server::DrustMcp;
use crate::query::vector_filter::{FilterAst, parse_filter_value};
use crate::storage::file_policy::{
    FilePolicyError, FilePolicyRow, delete_file_policy, load_file_policies, upsert_file_policy,
    validate_file_policy,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

/// `set_file_policy` arguments. Every doc comment here is published verbatim
/// as the property description in `tools/list`, so it is model-facing text.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetFilePolicyArgs {
    /// The folder prefix this rule governs, e.g. `"avatars/"`. A non-empty
    /// prefix MUST end with `/`; the empty string `""` is the tenant root and
    /// governs every file that no deeper rule claims, including files uploaded
    /// with no `path` at all. Longest matching prefix wins.
    pub prefix: String,
    /// AND-composes `uploader == <caller's user id>` onto every decision for
    /// this prefix: a logged-in user reaches only the files they uploaded.
    /// Anon and service never satisfy it (service bypasses file RLS entirely).
    #[serde(default)]
    pub owner_scoped: bool,
    /// The EXPLICIT "this prefix is not access-restricted" flag. Required when
    /// the rule is neither `owner_scoped` nor filtered by `select`, because a
    /// rule that says nothing at all DENIES every read (`FILE_POLICY_OPEN_
    /// REQUIRES_FLAG`). Cap gates (`set_file_caps`) still apply on top.
    #[serde(default)]
    pub public_read: bool,
    /// Optional read filter: a FilterAst over the file row's
    /// `path`/`uploader`/`key`/`visibility`/`content_type`/`original_name`/
    /// `size_bytes`/`uploaded_at` (plus `id`/`created_at`/`updated_at`).
    /// Operands may reference `{"$auth":"id"}` and `{"$authenticated":true}`.
    /// AND-composes with `owner_scoped`; it never replaces it. Pass as a JSON
    /// object, not a JSON-encoded string.
    #[serde(default)]
    #[schemars(schema_with = "crate::query::vector_filter::filter_arg_json_schema")]
    pub select: Option<Value>,
    /// Optional delete filter, same grammar as `select`. Omit to inherit the
    /// select semantics (readable ⇒ possibly deletable); the `delete` file cap
    /// is still required on top. Pass as a JSON object, not a JSON-encoded
    /// string.
    #[serde(default)]
    #[schemars(schema_with = "crate::query::vector_filter::filter_arg_json_schema")]
    pub delete: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClearFilePolicyArgs {
    /// The exact registered prefix to remove — `""` clears the tenant root.
    /// Removing a rule does NOT open the prefix: files it covered fall to the
    /// next-longest rule, or to the owner-scoped default when none matches.
    pub prefix: String,
}

/// Parse one optional clause (`select` / `delete`) into a `FilterAst`.
/// Routes through `parse_filter_value` for the double-encoded-string tolerance
/// and the shape hint (mirrors `tools::policy::parse_clause`).
fn parse_clause(label: &str, raw: Option<Value>) -> anyhow::Result<Option<FilterAst>> {
    match raw {
        None => Ok(None),
        Some(v) => {
            Ok(Some(parse_filter_value(v).map_err(|msg| {
                anyhow::anyhow!("invalid `{label}` filter: {msg}")
            })?))
        }
    }
}

/// Register or replace the rule for one prefix.
///
/// Validation runs BEFORE the writer lock — it is pure, and a refusal must
/// leave no row behind (`tests/mcp_file_policy.rs` pins that the registry is
/// untouched after each refusal).
pub async fn set_file_policy(
    s: &DrustMcp,
    prefix: &str,
    owner_scoped: bool,
    public_read: bool,
    select: Option<Value>,
    delete: Option<Value>,
) -> anyhow::Result<Value> {
    let row = FilePolicyRow {
        prefix: prefix.to_string(),
        owner_scoped,
        public_read,
        select_policy: parse_clause("select", select)?,
        delete_policy: parse_clause("delete", delete)?,
    };
    // `FilePolicyError: Display` is `CODE: why`, which `bail_mcp` splits into
    // `error_code` + message — the same code the REST face puts in its body.
    validate_file_policy(&row).map_err(|e| anyhow::anyhow!("{e}"))?;
    s.inner()
        .pool
        .with_writer(move |c| upsert_file_policy(c, &row))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(json!({ "ok": true, "prefix": prefix }))
}

/// Every registered rule, ordered by prefix.
///
/// A storage failure PROPAGATES rather than returning an empty list: an
/// unreadable registry is the same fact the read path turns into a refusal, and
/// an empty page here would be indistinguishable from "no rules registered".
pub async fn list_file_policies(s: &DrustMcp) -> anyhow::Result<Value> {
    let policies = s
        .inner()
        .pool
        .with_reader(load_file_policies)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(json!({ "policies": policies }))
}

/// Remove one prefix rule. Clearing a prefix that has no rule is
/// `FILE_POLICY_NOT_FOUND`, never a silent success — "I cleared it" and "it was
/// never there" are different facts to an operator tightening access.
pub async fn clear_file_policy(s: &DrustMcp, prefix: &str) -> anyhow::Result<Value> {
    let owned = prefix.to_string();
    let removed = s
        .inner()
        .pool
        .with_writer(move |c| delete_file_policy(c, &owned))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !removed {
        anyhow::bail!("{}", FilePolicyError::NotFound(prefix.to_string()));
    }
    Ok(json!({ "ok": true, "prefix": prefix }))
}

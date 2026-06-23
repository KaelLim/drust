//! RLS Phase 8 (Config) — MCP delegate fns for per-collection,
//! per-operation row-level-security policies. Mirrors the shape of
//! `realtime.rs` (`set_realtime`): validate the identifier + protected
//! prefix up front, then run the existence check + `validate_policy` INSIDE
//! the writer closure (TOCTOU-safe, same as `set_anon_caps` / `set_owner_field`
//! and the sibling REST handler `tenant::policy_routes`).
//!
//! Service-only by MCP dispatch — the whole MCP service is service-key-only
//! (anon → 403 WRITE_DENIED, user → 403 MCP_USER_DENIED), so no extra guard
//! is needed here (spec §8.3).

use crate::mcp::server::DrustMcp;
use crate::query::policy::{Policy, validate_policy};
use crate::query::vector_filter::FilterAst;
use crate::storage::schema::{
    DmlVerb, collection_exists, describe_collection, is_protected_collection, read_policies,
    write_policy,
};
use serde_json::json;

/// Map an op string to a `DmlVerb`, bailing on anything else.
fn parse_op(op: &str) -> anyhow::Result<DmlVerb> {
    match op {
        "select" => Ok(DmlVerb::Select),
        "insert" => Ok(DmlVerb::Insert),
        "update" => Ok(DmlVerb::Update),
        "delete" => Ok(DmlVerb::Delete),
        other => anyhow::bail!("invalid op {other:?}: must be select|insert|update|delete"),
    }
}

/// Parse one optional clause (`using` or `check`) JSON into a `FilterAst`.
fn parse_clause(label: &str, raw: Option<serde_json::Value>) -> anyhow::Result<Option<FilterAst>> {
    match raw {
        None => Ok(None),
        Some(v) => {
            let ast: FilterAst = serde_json::from_value(v)
                .map_err(|e| anyhow::anyhow!("invalid `{label}` filter: {e}"))?;
            Ok(Some(ast))
        }
    }
}

/// Set (replace) one op's policy on a collection.
/// `using` / `check` are the two optional FilterAst clauses as JSON.
pub async fn set_policy(
    s: &DrustMcp,
    collection: &str,
    op: &str,
    using: Option<serde_json::Value>,
    check: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    super::schema::identifier(collection)?;
    if is_protected_collection(collection) {
        anyhow::bail!(
            "refusing to set policy on system collection {collection:?} \
             (protected by _system_ prefix)"
        );
    }
    let verb = parse_op(op)?;
    let policy = Policy {
        using: parse_clause("using", using)?,
        check: parse_clause("check", check)?,
    };

    let pool = s.inner().pool.clone();
    let coll = collection.to_string();
    // Existence + validation INSIDE the writer closure (TOCTOU-safe, mirrors
    // set_anon_caps / set_owner_field / the REST policy route).
    let res = pool
        .with_writer(move |c| {
            if !collection_exists(c, &coll)? {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(format!("COLLECTION_NOT_FOUND: {coll}")),
                ));
            }
            let schema = match describe_collection(c, &coll)? {
                Some(s) => s,
                None => {
                    return Err(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(1),
                        Some(format!("COLLECTION_NOT_FOUND: {coll}")),
                    ));
                }
            };
            if let Err(e) = validate_policy(&schema, verb, &policy) {
                // Surface as Ok(Err) so the writer transaction is NOT a DB error;
                // nothing was written yet, so there is nothing to roll back.
                return Ok(Err(e.to_string()));
            }
            // (audit3 F2) Refuse to attach a policy while an anon-callable RPC
            // references this collection — call_rpc applies no RLS policy to
            // stored-RPC SQL, so the RPC would leak the rows the policy hides.
            if let Err(e) = crate::rpc::prepare::guard_policy_change_against_anon_rpcs(c, &coll) {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(e.to_string()),
                ));
            }
            write_policy(c, &coll, verb, Some(&policy))?;
            Ok(Ok(()))
        })
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("COLLECTION_NOT_FOUND") {
                anyhow::anyhow!(
                    "unknown collection: {}",
                    msg.split_once(": ").map(|x| x.1).unwrap_or(&msg)
                )
            } else {
                anyhow::anyhow!("{e}")
            }
        });

    match res? {
        Ok(()) => {}
        Err(validation_msg) => anyhow::bail!("POLICY_INVALID: {validation_msg}"),
    }
    pool.schema_cache.invalidate(collection);
    // audit3 F3 — a tightened policy must drop in-flight anon SSE subscribers,
    // which captured the old select-policy at connect time; evict so they
    // reconnect and re-gate (mirrors set_realtime).
    let tenant = s.inner().tenant_id.clone();
    s.inner().bus.evict_collection(&tenant, collection);
    Ok(json!({
        "ok": true,
        "collection": collection,
        "op": op,
    }))
}

/// Read the stored policy set for a collection. Shape mirrors the REST
/// `get_policies` handler: `{ "stored": <CollectionPolicies> }`.
pub async fn get_policies(s: &DrustMcp, collection: &str) -> anyhow::Result<serde_json::Value> {
    super::schema::identifier(collection)?;
    let pool = s.inner().pool.clone();
    let coll = collection.to_string();
    let policies = pool
        .with_reader(move |c| read_policies(c, &coll))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(json!({
        "collection": collection,
        "stored": policies,
    }))
}

/// Clear one op's policy on a collection (write NULL).
pub async fn clear_policy(
    s: &DrustMcp,
    collection: &str,
    op: &str,
) -> anyhow::Result<serde_json::Value> {
    super::schema::identifier(collection)?;
    if is_protected_collection(collection) {
        anyhow::bail!(
            "refusing to clear policy on system collection {collection:?} \
             (protected by _system_ prefix)"
        );
    }
    let verb = parse_op(op)?;
    let pool = s.inner().pool.clone();
    let coll = collection.to_string();
    pool.with_writer(move |c| write_policy(c, &coll, verb, None))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    pool.schema_cache.invalidate(collection);
    // audit3 F3 — evict in-flight anon SSE subscribers so they reconnect and
    // re-gate against the cleared policy (mirrors set_realtime).
    let tenant = s.inner().tenant_id.clone();
    s.inner().bus.evict_collection(&tenant, collection);
    Ok(json!({
        "ok": true,
        "collection": collection,
        "op": op,
    }))
}

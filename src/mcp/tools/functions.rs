//! v1.36 — MCP function tools. Service-only by MCP dispatch (transport
//! rejects anon/user before any tool runs). NO upload tool by design —
//! whoami/instructions point at the REST multipart route (file-upload
//! convention).

use crate::mcp::server::DrustMcp;
use serde_json::{Value, json};

pub async fn list_functions(s: &DrustMcp) -> anyhow::Result<Value> {
    let rows = crate::functions::schema::list_functions(&s.inner().pool).await?;
    Ok(json!({ "functions": rows }))
}

pub async fn delete_function(s: &DrustMcp, name: &str) -> anyhow::Result<Value> {
    let inner = s.inner();
    // Capture the sha BEFORE the delete so a successful delete can GC the
    // now-unreferenced `{sha}.wasm` blob — mirrors REST `delete_one`
    // (src/functions/routes.rs:264-273). The artifact dir is derived from the
    // pool's data_root (== the registry's data_root the REST surface threads),
    // so no extra field on DrustMcpInner is needed.
    let sha = crate::functions::schema::get_function(&inner.pool, name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("FN_NOT_FOUND: no function named {name}"))?
        .wasm_sha256;
    let deleted = crate::functions::schema::delete_function(&inner.pool, name).await?;
    if !deleted {
        anyhow::bail!("FN_NOT_FOUND: no function named {name}");
    }
    if let Some(f) = inner.functions.as_ref() {
        f.bindings.invalidate(&inner.tenant_id);
    }
    // GC the artifact only when no other live row references the sha. Holds the
    // store invariant ("a file exists ⟺ some live row references it",
    // src/functions/routes.rs:58-63) on the MCP delete path too.
    crate::functions::routes::gc_artifact_if_unreferenced(
        &inner.pool,
        inner.pool.data_root(),
        &inner.tenant_id,
        &sha,
    )
    .await;
    Ok(json!({ "deleted": name }))
}

pub async fn set_function_active(s: &DrustMcp, name: &str, active: bool) -> anyhow::Result<Value> {
    let inner = s.inner();
    let hit = crate::functions::schema::set_active(&inner.pool, name, active).await?;
    if !hit {
        anyhow::bail!("FN_NOT_FOUND: no function named {name}");
    }
    if let Some(f) = inner.functions.as_ref() {
        f.bindings.invalidate(&inner.tenant_id);
    }
    Ok(json!({ "name": name, "active": active }))
}

/// Service-only (by MCP dispatch) config of the caller-identity invoke ACL.
/// Grant AND revoke both flow through `set_invoke_acl` — a missing name is
/// `FN_NOT_FOUND`. Invalidates the trigger-binding cache so the new flags take
/// effect on the next dispatch decision. Mirrors REST `PATCH …/functions/<name>`
/// (which routes through the same `schema::set_invoke_acl`).
pub async fn set_function_invoke_acl(
    s: &DrustMcp,
    name: &str,
    anon: bool,
    user: bool,
) -> anyhow::Result<Value> {
    let inner = s.inner();
    let hit = crate::functions::schema::set_invoke_acl(&inner.pool, name, anon, user).await?;
    if !hit {
        anyhow::bail!("FN_NOT_FOUND: no function named {name}");
    }
    if let Some(f) = inner.functions.as_ref() {
        f.bindings.invalidate(&inner.tenant_id);
    }
    Ok(json!({ "name": name, "invoke_anon": anon, "invoke_user": user }))
}

pub async fn get_function_logs(
    s: &DrustMcp,
    name: &str,
    limit: Option<i64>,
) -> anyhow::Result<Value> {
    let rows =
        crate::functions::schema::list_logs(&s.inner().pool, name, limit.unwrap_or(50)).await?;
    Ok(json!({ "logs": rows }))
}

/// Async invoke: enqueues through the same dispatcher queue as real events;
/// returns the enqueue acknowledgement, NOT the run result. Models read the
/// outcome via get_function_logs (trigger="manual").
pub async fn invoke_function(s: &DrustMcp, name: &str, event: Value) -> anyhow::Result<Value> {
    let inner = s.inner();
    let row = crate::functions::schema::get_function(&inner.pool, name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("FN_NOT_FOUND: no function named {name}"))?;
    let Some(f) = inner.functions.as_ref() else {
        anyhow::bail!("FN_UNAVAILABLE: function dispatch not wired on this surface");
    };
    f.enqueue_manual(&inner.tenant_id, &row.name, event.to_string())
        .await;
    Ok(json!({ "enqueued": name, "note": "read result via get_function_logs (trigger=manual)" }))
}

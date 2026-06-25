//! REST surface: /t/<id>/functions[…]. Service-only via the router-level
//! require_service_layer (mounted in tenant/mod.rs, files_router pattern).

use crate::functions::FnConfig;
use crate::functions::dispatcher::FunctionDispatcher;
use crate::functions::executor::{Executor, Invocation};
use crate::functions::schema;
use crate::storage::pool::TenantRegistry;
use crate::tenant::router::TenantRef;
use axum::Extension;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use sha2::Digest;
use std::sync::Arc;

#[derive(Clone)]
pub struct FunctionsRouteState {
    pub tenants: Arc<TenantRegistry>,
    pub dispatcher: Arc<FunctionDispatcher>,
    pub executor: Arc<Executor>,
    pub cfg: FnConfig,
    pub data_root: std::path::PathBuf,
}

/// Lower-hex encode bytes. The repo has no `hex` crate dependency (the
/// `hex::encode_lower` call in `auth/bearer.rs` resolves to a private
/// in-file module); this mirrors that helper's semantics for the wasm sha.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Map a sentinel-prefixed anyhow error ("CODE: msg") to a response.
/// Bodies go through the canonical `crate::error::json_error` so the
/// service-only functions surface shares one error code path with the
/// rest of drust (`error_code` + `message` + catalog `suggested_fix`).
fn map_sentinel(e: anyhow::Error) -> Response {
    let s = e.to_string();
    let code = s.split(':').next().unwrap_or("").trim().to_string();
    let status = match code.as_str() {
        "FN_LIMIT" => StatusCode::CONFLICT,
        "FN_NAME_INVALID" | "FN_TRIGGERS_INVALID" => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    crate::error::json_error(status, &code, &s)
}

fn artifact_dir(root: &std::path::Path, tenant: &str) -> std::path::PathBuf {
    root.join("tenants").join(tenant).join("_functions")
}

/// Remove the content-addressed `{sha}.wasm` artifact iff no live
/// `_system_functions` row still references that sha. The store's invariant is
/// "a file exists ⟺ some live row references it"; this is the single primitive
/// that enforces it, shared by `create` (rejection + replace-displacement
/// paths) and `delete_one`. Best-effort: a failed unlink self-heals on the next
/// GC pass (any later delete / same-sha create re-runs the check).
pub async fn gc_artifact_if_unreferenced(
    pool: &crate::storage::pool::SharedTenantPool,
    data_root: &std::path::Path,
    tenant_id: &str,
    sha: &str,
) {
    if let Ok(false) = schema::sha_still_referenced(pool, sha).await {
        let p = artifact_dir(data_root, tenant_id).join(format!("{sha}.wasm"));
        let _ = tokio::fs::remove_file(p).await;
    }
}

/// POST /t/<id>/functions — multipart: name, wasm, triggers, description?
pub async fn create(
    State(st): State<FunctionsRouteState>,
    Extension(t): Extension<TenantRef>,
    Path(_tenant): Path<String>,
    mut mp: Multipart,
) -> Response {
    let mut name = String::new();
    let mut triggers = String::from("[]");
    let mut description = String::new();
    let mut wasm: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = mp.next_field().await {
        match field.name().unwrap_or("") {
            "name" => name = field.text().await.unwrap_or_default(),
            "triggers" => triggers = field.text().await.unwrap_or_default(),
            "description" => description = field.text().await.unwrap_or_default(),
            "wasm" => wasm = field.bytes().await.ok().map(|b| b.to_vec()),
            _ => {}
        }
    }
    let Some(wasm) = wasm else {
        return crate::error::json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_PARAMS",
            "missing wasm field",
        );
    };
    if wasm.len() > st.cfg.max_wasm_bytes {
        return crate::error::json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "FN_WASM_TOO_LARGE",
            &format!("{} bytes > cap {}", wasm.len(), st.cfg.max_wasm_bytes),
        );
    }
    if !schema::valid_name(&name) {
        return crate::error::json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "FN_NAME_INVALID",
            "bad name",
        );
    }
    if let Err(e) = crate::functions::bindings::parse_triggers(&triggers) {
        return map_sentinel(e);
    }
    // Compile gate (spec §8): 422 + suggested_fix on a non-component upload.
    if let Err(e) = crate::functions::runtime::validate_component(&wasm) {
        return crate::error::json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "WASM_COMPILE_FAILED",
            &format!("{e:#}"),
        );
    }

    // Artifact-first, NOT SQLite-first. `create_function` is an UPSERT
    // (ON CONFLICT(name) DO UPDATE — replace-in-place), so a SQLite-first
    // ordering plus compensate-delete would, on the REPLACE path, DELETE a
    // pre-existing working function AND cascade-purge its entire
    // `_system_function_logs` history on a transient artifact-write failure.
    // Writing the content-addressed `{sha}.wasm` first keeps the row untouched
    // on write failure (true no-op on error). The store's invariant — a file
    // exists iff a live row references its sha — is then held by GCing the two
    // paths that can leave an unreferenced blob: `create_function` rejecting
    // (FN_LIMIT / DB error → row unchanged) and a successful replace displacing
    // the previous sha. Both route through `gc_artifact_if_unreferenced`, the
    // same primitive `delete_one` uses.
    let sha = hex_lower(&sha2::Sha256::digest(&wasm));
    let dir = artifact_dir(&st.data_root, &t.tenant_id);
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return crate::error::json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FN_IO",
            &e.to_string(),
        );
    }
    let path = dir.join(format!("{sha}.wasm"));
    if let Err(e) = tokio::fs::write(&path, &wasm).await {
        return crate::error::json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FN_IO",
            &e.to_string(),
        );
    }

    // The sha this name currently resolves to (if any), captured before the
    // upsert so a successful replace can GC the artifact it displaces.
    let prev_sha = match schema::get_function(&t.pool, &name).await {
        Ok(Some(r)) => Some(r.wasm_sha256),
        _ => None,
    };

    match schema::create_function(
        &t.pool,
        schema::CreateFunctionParams {
            name: name.clone(),
            wasm_sha256: sha.clone(),
            size_bytes: wasm.len() as i64,
            triggers_json: triggers,
            description,
        },
        st.cfg.max_per_tenant,
    )
    .await
    {
        Ok(row) => {
            st.dispatcher.bindings.invalidate(&t.tenant_id);
            // A replace with new bytes displaced the old artifact — GC it.
            if let Some(prev) = prev_sha
                && prev != sha
            {
                gc_artifact_if_unreferenced(&t.pool, &st.data_root, &t.tenant_id, &prev).await;
            }
            audit_fn(&t, "function.create", &name);
            (StatusCode::CREATED, Json(row)).into_response()
        }
        Err(e) => {
            // Rejected (FN_LIMIT / DB error): the row is unchanged, so the blob
            // we just wrote is orphaned unless another row already references
            // the same bytes. GC it.
            gc_artifact_if_unreferenced(&t.pool, &st.data_root, &t.tenant_id, &sha).await;
            map_sentinel(e)
        }
    }
}

pub async fn list(
    State(_st): State<FunctionsRouteState>,
    Extension(t): Extension<TenantRef>,
    Path(_tenant): Path<String>,
) -> Response {
    match schema::list_functions(&t.pool).await {
        Ok(rows) => Json(serde_json::json!({ "functions": rows })).into_response(),
        Err(e) => map_sentinel(e),
    }
}

pub async fn get_one(
    State(_st): State<FunctionsRouteState>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
) -> Response {
    match schema::get_function(&t.pool, &name).await {
        Ok(Some(row)) => Json(row).into_response(),
        Ok(None) => {
            crate::error::json_error(StatusCode::NOT_FOUND, "FN_NOT_FOUND", "no such function")
        }
        Err(e) => map_sentinel(e),
    }
}

#[derive(serde::Deserialize)]
pub struct PatchBody {
    pub active: Option<bool>,
    pub triggers: Option<serde_json::Value>,
    pub description: Option<String>,
    /// Caller-identity invoke ACL (T5). Service-only by the router-level
    /// `require_service_layer` — grant AND revoke both land here. When either
    /// is `Some`, both flags are written together (the merge below preserves
    /// whichever side the caller omitted).
    pub invoke_anon: Option<bool>,
    pub invoke_user: Option<bool>,
}

pub async fn patch(
    State(st): State<FunctionsRouteState>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
    Json(body): Json<PatchBody>,
) -> Response {
    let triggers_json = match body.triggers {
        Some(v) => {
            let s = v.to_string();
            if let Err(e) = crate::functions::bindings::parse_triggers(&s) {
                return map_sentinel(e);
            }
            Some(s)
        }
        None => None,
    };
    if let Some(active) = body.active {
        match schema::set_active(&t.pool, &name, active).await {
            Ok(true) => {}
            // Row absent — 404 and stop before any further write.
            Ok(false) => {
                return crate::error::json_error(
                    StatusCode::NOT_FOUND,
                    "FN_NOT_FOUND",
                    "no such function",
                );
            }
            Err(e) => return map_sentinel(e),
        }
    }
    if triggers_json.is_some() || body.description.is_some() {
        match schema::update_meta(&t.pool, &name, triggers_json, body.description).await {
            Ok(true) => {}
            // Reaching here means no `set_active` 404 fired (that early-returns),
            // so a zero-row update can only mean the function does not exist.
            Ok(false) => {
                return crate::error::json_error(
                    StatusCode::NOT_FOUND,
                    "FN_NOT_FOUND",
                    "no such function",
                );
            }
            Err(e) => return map_sentinel(e),
        }
    }
    // Invoke ACL (T5) — service-only by `require_service_layer`. `set_invoke_acl`
    // writes both columns in one UPDATE, so merge whichever flag the caller
    // omitted with its current value (a one-sided PATCH must not clobber the
    // other). Read-then-write under the same service-only surface.
    if body.invoke_anon.is_some() || body.invoke_user.is_some() {
        let cur = match schema::get_function(&t.pool, &name).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                return crate::error::json_error(
                    StatusCode::NOT_FOUND,
                    "FN_NOT_FOUND",
                    "no such function",
                );
            }
            Err(e) => return map_sentinel(e),
        };
        let anon = body.invoke_anon.unwrap_or(cur.invoke_anon);
        let user = body.invoke_user.unwrap_or(cur.invoke_user);
        match schema::set_invoke_acl(&t.pool, &name, anon, user).await {
            Ok(true) => {}
            Ok(false) => {
                return crate::error::json_error(
                    StatusCode::NOT_FOUND,
                    "FN_NOT_FOUND",
                    "no such function",
                );
            }
            Err(e) => return map_sentinel(e),
        }
    }
    st.dispatcher.bindings.invalidate(&t.tenant_id);
    audit_fn(&t, "function.update", &name);
    match schema::get_function(&t.pool, &name).await {
        Ok(Some(row)) => Json(row).into_response(),
        _ => crate::error::json_error(StatusCode::NOT_FOUND, "FN_NOT_FOUND", "no such function"),
    }
}

/// Shared delete body for both the REST `delete_one` route and the admin
/// `ƒ _functions` page's delete button. Returns `Ok(true)` when a row was
/// removed, `Ok(false)` when the name did not exist. Invalidates the
/// trigger-match cache and GCs the content-addressed artifact (only when no
/// surviving row still references the sha) on a real delete.
pub async fn delete_impl(
    pool: &crate::storage::pool::SharedTenantPool,
    dispatcher: &FunctionDispatcher,
    data_root: &std::path::Path,
    tenant_id: &str,
    name: &str,
) -> anyhow::Result<bool> {
    let sha = match schema::get_function(pool, name).await? {
        Some(r) => r.wasm_sha256,
        None => return Ok(false),
    };
    if schema::delete_function(pool, name).await? {
        dispatcher.bindings.invalidate(tenant_id);
        gc_artifact_if_unreferenced(pool, data_root, tenant_id, &sha).await;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn delete_one(
    State(st): State<FunctionsRouteState>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
) -> Response {
    match delete_impl(&t.pool, &st.dispatcher, &st.data_root, &t.tenant_id, &name).await {
        Ok(true) => {
            audit_fn(&t, "function.delete", &name);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => {
            crate::error::json_error(StatusCode::NOT_FOUND, "FN_NOT_FOUND", "no such function")
        }
        Err(e) => map_sentinel(e),
    }
}

#[derive(serde::Deserialize)]
pub struct InvokeBody {
    pub event: serde_json::Value,
}

/// POST /t/<id>/functions/<name>/invoke — synchronous test-invoke.
pub async fn invoke(
    State(st): State<FunctionsRouteState>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
    Json(body): Json<InvokeBody>,
) -> Response {
    match schema::get_function(&t.pool, &name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return crate::error::json_error(
                StatusCode::NOT_FOUND,
                "FN_NOT_FOUND",
                "no such function",
            );
        }
        Err(e) => return map_sentinel(e),
    }
    let started = std::time::Instant::now();
    let out = st
        .executor
        .run_one(Invocation {
            tenant_id: t.tenant_id.clone(),
            function_name: name,
            trigger: "manual".into(),
            event_json: body.event.to_string(),
            // Service-only route (require_service_layer) → god-mode, unchanged.
            caller: crate::functions::caller::CallerCtx::Privileged,
        })
        .await;
    Json(serde_json::json!({
        "status": out.status.as_str(),
        "result": out.result,
        "logs": out.log_text,
        "duration_ms": started.elapsed().as_millis() as u64,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct LogsQs {
    pub limit: Option<i64>,
}

pub async fn logs(
    State(_st): State<FunctionsRouteState>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, name)): Path<(String, String)>,
    Query(qs): Query<LogsQs>,
) -> Response {
    match schema::list_logs(&t.pool, &name, qs.limit.unwrap_or(50)).await {
        Ok(rows) => Json(serde_json::json!({ "logs": rows })).into_response(),
        Err(e) => map_sentinel(e),
    }
}

fn audit_fn(t: &TenantRef, op: &str, name: &str) {
    crate::safety::audit_db::try_send(&crate::safety::audit::AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        tenant: t.tenant_id.clone(),
        token_hint: t.token_hint.clone(),
        op: op.to_string(),
        status: "ok".to_string(),
        duration_ms: 0,
        collection: Some(name.to_string()),
        sql_hash: None,
        record_id: None,
        error_code: None,
        error_message: None,
        auth_method: None,
        oauth_email: None,
        oauth_error_code: None,
        actor_admin_id: None,
        actor_email_snapshot: None,
        extra: Default::default(),
    });
}

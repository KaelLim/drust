use crate::mcp::server::DrustMcp;
use crate::storage::schema::{
    describe_collection as describe_inner, list_collections as list_inner,
};
use serde_json::json;

pub async fn list_collections(s: &DrustMcp) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let list = pool.with_reader(list_inner).await?;
    Ok(json!({ "collections": list }))
}

pub async fn describe_collection(s: &DrustMcp, name: &str) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let name_owned = name.to_string();
    let out = pool
        .with_reader(move |c| describe_inner(c, &name_owned))
        .await?;
    match out {
        Some(schema) => Ok(serde_json::to_value(schema)?),
        None => Ok(json!({ "error_code": "COLLECTION_NOT_FOUND" })),
    }
}

/// Return the calling tenant's identity, both bearer tokens (plaintext),
/// the relative REST/MCP endpoint paths, and the upload size limit.
///
/// MCP is service-only at the auth layer, so the caller already holds
/// the service token; surfacing it here lets a model that's wired only
/// to MCP construct curl/HTTP requests for non-MCP-exposed surfaces
/// (chiefly the multipart file upload endpoint, which deliberately has
/// no MCP tool).
///
/// Tokens minted before v1.1c stored only the hash; the corresponding
/// `plaintext` field is `null` and the operator must reroll via the
/// admin UI to recover it.
pub async fn whoami(s: &DrustMcp) -> anyhow::Result<serde_json::Value> {
    let inner = s.inner();
    let tenant_id = inner.tenant_id.clone();
    let max_upload_bytes = inner.max_upload_bytes;
    let Some(meta) = inner.meta.as_ref() else {
        anyhow::bail!("META_UNAVAILABLE: this drust process was started without a meta connection");
    };

    let conn = meta.lock().await;
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT name, created_at FROM tenants \
             WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![&tenant_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let (tenant_name, tenant_created_at) = match row {
        Some(t) => t,
        None => anyhow::bail!("tenant {tenant_id} not found in meta.sqlite"),
    };

    let read_token = |role: &str| -> Option<serde_json::Value> {
        let r: Option<(i64, String, Option<String>)> = conn
            .query_row(
                "SELECT id, created_at, plaintext FROM tokens \
                 WHERE tenant_id = ?1 AND role = ?2 AND revoked_at IS NULL \
                 ORDER BY created_at DESC LIMIT 1",
                rusqlite::params![&tenant_id, role],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok();
        r.map(|(id, created_at, plaintext)| {
            json!({
                "id": id,
                "created_at": created_at,
                "plaintext": plaintext,
            })
        })
    };
    let anon = read_token("anon");
    let service = read_token("service");
    drop(conn);

    let rest_base = format!("/drust/t/{tenant_id}/");
    let mcp_path = format!("/drust/t/{tenant_id}/mcp");
    let files_upload = format!("/drust/t/{tenant_id}/files");
    let files_upload_resumable = format!("/drust/t/{tenant_id}/uploads");
    let rpc_pattern = format!("/drust/t/{tenant_id}/rpc/<name>");
    // v1.31 — broadcast room surfaces. realtime_ws expects WS upgrade; pass
    // the service or anon token via `?token=<...>` (browsers can't set
    // Authorization on WebSocket). rooms_publish_rest is service-only.
    let realtime_ws = format!("/drust/t/{tenant_id}/realtime?token=<bearer>");
    let rooms_publish_rest = format!("/drust/t/{tenant_id}/rooms/<room>");
    let rooms_cfg = &inner.rooms_cfg;

    Ok(json!({
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "tenant_created_at": tenant_created_at,
        "tokens": {
            "anon": anon,
            "service": service,
        },
        "endpoints": {
            "rest_base": rest_base,
            "mcp": mcp_path,
            "files_upload": files_upload,
            "files_upload_resumable": files_upload_resumable,
            "rpc": rpc_pattern,
            "realtime_ws": realtime_ws,
            "rooms_publish_rest": rooms_publish_rest,
        },
        "limits": {
            "max_upload_bytes": max_upload_bytes,
            "broadcast_payload_max_bytes": rooms_cfg.payload_max_bytes,
            "broadcast_publish_qps": rooms_cfg.publish_qps,
            "broadcast_room_subscriber_max": rooms_cfg.room_subscriber_max,
            "broadcast_client_room_max": rooms_cfg.client_room_max,
        },
        "broadcast": {
            "note": "v1.31: publish via MCP tool `broadcast` or REST POST rooms_publish_rest \
                     (service-only). Subscribe via WS upgrade at realtime_ws + send \
                     {\"op\":\"subscribe\",\"room\":\"<name>\"} on the multiplex socket.",
        },
    }))
}

/// MCP impl: one-shot schema bootstrap. Returns every collection's
/// full schema (incl. fields, indices, descriptions, anon_caps,
/// realtime_enabled, etc.) plus every RPC's metadata (name,
/// description, params, anon_callable, sql).
///
/// Service-key only (enforced at dispatch). LLM-friendly for
/// connect-time "show me the data model" calls.
pub async fn get_schema_overview(s: &DrustMcp) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let collections = pool
        .with_reader(|c| {
            let names = crate::storage::schema::list_collections(c)?;
            let mut out = Vec::with_capacity(names.len());
            for col in names {
                if let Some(cs) = crate::storage::schema::describe_collection(c, &col.name)? {
                    out.push(cs);
                }
            }
            Ok::<_, rusqlite::Error>(out)
        })
        .await?;
    // `collections` was fetched above as Vec<CollectionSchema>.
    // Normalize each so owner_field/read_scope/vector_fields are ALWAYS present.
    // CollectionSchema uses #[serde(skip_serializing_if=...)] on those, so they
    // vanish when None/empty and the model can't tell "no owner field" from
    // "key omitted". Override for the OVERVIEW surface only — the REST handler +
    // codegen keep the lean shape (CollectionSchema serde attrs are NOT changed).
    let collections_enriched: Vec<serde_json::Value> = collections
        .iter()
        .map(|cs| {
            let mut v = serde_json::to_value(cs).expect("CollectionSchema serialises");
            if let Some(obj) = v.as_object_mut() {
                obj.entry("owner_field").or_insert(serde_json::Value::Null);
                obj.entry("read_scope").or_insert(serde_json::Value::Null);
                obj.entry("vector_fields")
                    .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            }
            v
        })
        .collect();

    let rpcs = pool
        .with_reader(|c| {
            crate::rpc::registry::list(c).map_err(|e| {
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
            })
        })
        .await?;
    // Enrich each RPC with a derived `user_id_autobound` flag so the model
    // doesn't have to know the `user_id`-param naming convention. Mirrors the
    // auto-bind predicate in src/rpc/handler.rs (params.iter().any(|p| p.name == "user_id")).
    let rpcs_enriched: Vec<serde_json::Value> = rpcs
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).expect("StoredRpc serialises");
            let autobound = r.params.iter().any(|p| p.name == "user_id");
            if let Some(obj) = v.as_object_mut() {
                obj.insert("user_id_autobound".to_string(), serde_json::Value::Bool(autobound));
            }
            v
        })
        .collect();

    let tenant_id = s.inner().tenant_id.clone();
    Ok(serde_json::json!({
        "tenant": tenant_id,
        "collections": collections_enriched,
        "rpcs": rpcs_enriched,
    }))
}

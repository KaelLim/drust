use crate::mcp::server::DrustMcp;
use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::executor::execute_read_query;
use crate::query::filter::build_count_sql;
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

pub async fn sample_rows(s: &DrustMcp, name: &str, n: usize) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql = format!(
        "SELECT * FROM \"{}\" ORDER BY id LIMIT {}",
        name.replace('"', "\"\""),
        n.min(500)
    );
    let out = pool
        .with_reader(move |c| {
            execute_read_query(c, &sql, 500, 16_384).map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .await?;
    Ok(serde_json::to_value(out)?)
}

pub async fn count_rows(
    s: &DrustMcp,
    name: &str,
    where_clause: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql = build_count_sql(name, where_clause, None);
    let n: i64 = pool
        .with_reader(move |c| {
            attach_readonly_authorizer(c);
            let r = c.query_row(&sql, [], |r| r.get(0));
            detach_authorizer(c);
            r
        })
        .await?;
    Ok(json!({ "count": n }))
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
    let rpc_pattern = format!("/drust/t/{tenant_id}/rpc/<name>");

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
            "rpc": rpc_pattern,
        },
        "limits": {
            "max_upload_bytes": max_upload_bytes,
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
    let rpcs = pool
        .with_reader(|c| {
            crate::rpc::registry::list(c).map_err(|e| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(e.to_string()),
                )
            })
        })
        .await?;
    let tenant_id = s.inner().tenant_id.clone();
    Ok(serde_json::json!({
        "tenant": tenant_id,
        "collections": collections,
        "rpcs": rpcs,
    }))
}

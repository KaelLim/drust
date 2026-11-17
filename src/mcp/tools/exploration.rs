use crate::mcp::server::DrustMcp;
use crate::storage::schema::{
    describe_collection as describe_inner, list_collections as list_inner,
};
use serde_json::json;

pub async fn list_collections(s: &DrustMcp) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let list = pool.with_reader(|c| list_inner(c)).await?;
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
        None => Ok(json!({
            "error_code": "COLLECTION_NOT_FOUND",
            "message": format!("no such collection: {name}"),
        })),
    }
}

/// What `whoami` may reveal to its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WhoamiView {
    /// What the per-tenant service-key endpoint returns: both bearer tokens in
    /// plaintext.
    Full,
    /// An account-level caller: the service key is never read in plaintext,
    /// only its id, creation time and where an admin can copy it.
    Account {
        mcp_url: String,
        api_keys_url: String,
        grant_id: i64,
    },
}

/// The account view's service-token lookup. It deliberately does not select
/// `plaintext`, so the key never leaves meta on that path. Same WHERE and
/// ORDER BY as the full view's lookup, so both pick the same row.
const ACCOUNT_SERVICE_TOKEN_SQL: &str = "SELECT id, created_at FROM tokens \
     WHERE tenant_id = ?1 AND role = 'service' AND revoked_at IS NULL \
     ORDER BY created_at DESC LIMIT 1";

/// Return the calling tenant's identity, its bearer tokens as the view allows,
/// the relative REST/MCP endpoint paths, and the upload size limit.
///
/// In the `Full` view (the per-tenant endpoint), MCP is service-only at the
/// auth layer, so the caller already holds the service token; surfacing it
/// here lets a model that's wired only to MCP construct curl/HTTP requests
/// for non-MCP-exposed surfaces (chiefly the multipart file upload endpoint,
/// which deliberately has no MCP tool).
///
/// The `Account` view never returns the service key: an account-level caller
/// signs in with a short-lived OAuth token, and handing it the never-expiring
/// service key would turn that sign-in into a permanent credential. It gets
/// the key's id, creation time and the admin page where it can be copied, the
/// account-level MCP URL, and a `caller` block naming its OAuth grant.
///
/// Tokens minted before v1.1c stored only the hash; the corresponding
/// `plaintext` field is `null` and the operator must reroll via the
/// admin UI to recover it.
///
/// v1.64 (#974) adds a deliberately SMALL `file_upload` block: the URI of the
/// `files-guide.md` resource plus this tenant's live publish grants. It is a
/// signpost, not a manual — the rules live in the guide, which is one read away
/// and cannot go stale against this string. `granted_prefixes` is `null` (never
/// `[]`) when the registry could not be read: "nobody may publish" and "I could
/// not find out" are different facts, and the second one also means every
/// non-service file READ is currently denied.
pub async fn whoami(s: &DrustMcp, view: WhoamiView) -> anyhow::Result<serde_json::Value> {
    let inner = s.inner();
    let tenant_id = inner.tenant_id.clone();
    let max_upload_bytes = inner.max_upload_bytes;
    let Some(meta) = inner.meta.as_ref() else {
        anyhow::bail!("META_UNAVAILABLE: this drust process was started without a meta connection");
    };

    // Scoped so the meta guard AND the closure that borrows it are both gone
    // before the tenant-pool read below: the `#[tool]` wrapper requires a `Send`
    // future, and a live `rusqlite::Connection` borrow held across an `.await`
    // is what breaks that (a bare `drop(conn)` is not enough — the closure is
    // still in scope).
    let (tenant_name, tenant_created_at, anon, service) = {
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
        let service = match &view {
            WhoamiView::Full => read_token("service"),
            WhoamiView::Account { api_keys_url, .. } => conn
                .query_row(
                    ACCOUNT_SERVICE_TOKEN_SQL,
                    rusqlite::params![&tenant_id],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .ok()
                .map(|(id, created_at)| {
                    json!({
                        "redacted": true,
                        "id": id,
                        "created_at": created_at,
                        "how_to_get": api_keys_url,
                    })
                }),
        };
        (tenant_name, tenant_created_at, anon, service)
    };

    let rest_base = crate::base_path::base(&format!("/t/{tenant_id}/"));
    let mcp_path = crate::base_path::base(&format!("/t/{tenant_id}/mcp"));
    let files_upload = crate::base_path::base(&format!("/t/{tenant_id}/files"));
    let files_upload_resumable = crate::base_path::base(&format!("/t/{tenant_id}/uploads"));
    let rpc_pattern = crate::base_path::base(&format!("/t/{tenant_id}/rpc/<name>"));
    // v1.31 — broadcast room surfaces. realtime_ws expects WS upgrade; pass
    // the service or anon token via `?token=<...>` (browsers can't set
    // Authorization on WebSocket). rooms_publish_rest is service-only.
    let realtime_ws = crate::base_path::base(&format!("/t/{tenant_id}/realtime?token=<bearer>"));
    let rooms_publish_rest = crate::base_path::base(&format!("/t/{tenant_id}/rooms/<room>"));
    let rooms_cfg = &inner.rooms_cfg;

    // Outside the meta scope above: this is a TENANT-pool read and must not run
    // while the process-wide meta mutex is held.
    let files_guide_resource = crate::mcp::resources::files_guide_uri(&tenant_id);
    let granted_prefixes = match crate::mcp::tools::file_policy::public_upload_grants(s).await {
        Ok(grants) => serde_json::Value::Array(
            grants
                .into_iter()
                .map(|(prefix, roles)| json!({ "prefix": prefix, "roles": roles }))
                .collect(),
        ),
        Err(_) => serde_json::Value::Null,
    };

    let mut out = json!({
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
        "file_upload": {
            "guide_resource": files_guide_resource,
            "granted_prefixes": granted_prefixes,
        },
        "broadcast": {
            "note": "v1.31: publish via MCP tool `broadcast` or REST POST rooms_publish_rest \
                     (service-only). Subscribe via WS upgrade at realtime_ws + send \
                     {\"op\":\"subscribe\",\"room\":\"<name>\"} on the multiplex socket.",
        },
    });
    if let WhoamiView::Account {
        mcp_url, grant_id, ..
    } = view
    {
        out["endpoints"]["mcp"] = serde_json::Value::String(mcp_url);
        if let Some(o) = out.as_object_mut() {
            o.insert(
                "caller".into(),
                json!({"kind": "oauth", "grant_id": grant_id}),
            );
        }
    }
    Ok(out)
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
                // RLS (v1.38): CollectionPolicies is #[serde(skip_serializing_if=
                // is_empty)] so the key vanishes for the common no-policy case.
                // Force it present (as {}) on the OVERVIEW surface so the model
                // can tell "no policy" from "key omitted" — same posture as
                // owner_field/read_scope above.
                obj.entry("policies")
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
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
                obj.insert(
                    "user_id_autobound".to_string(),
                    serde_json::Value::Bool(autobound),
                );
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

#[cfg(test)]
mod whoami_account_sql_tests {
    use super::ACCOUNT_SERVICE_TOKEN_SQL;

    // The account view never reads the service plaintext out of meta, so it
    // cannot leak it later through a log or a refactor.
    #[test]
    fn account_service_token_sql_never_selects_plaintext() {
        assert_eq!(
            ACCOUNT_SERVICE_TOKEN_SQL,
            "SELECT id, created_at FROM tokens WHERE tenant_id = ?1 AND role = 'service' \
             AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"
        );
        assert!(!ACCOUNT_SERVICE_TOKEN_SQL.contains("plaintext"));
    }

    // The plaintext-reading query runs for the service role exactly once (the
    // Full arm), and the account arm uses the constant. Comments are skipped;
    // the needles are assembled at runtime.
    #[test]
    fn whoami_reads_the_service_plaintext_only_in_the_full_view() {
        let src = include_str!("exploration.rs");
        let prod = src.split(&format!("#[cfg({})]", "test")).next().unwrap();
        let code: String = prod
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let full_read = format!("read_token(\"{}\")", "service");
        assert_eq!(code.matches(full_read.as_str()).count(), 1, "{full_read}");
        let constant = format!("{}_SERVICE_TOKEN_SQL", "ACCOUNT");
        assert_eq!(
            code.matches(constant.as_str()).count(),
            2,
            "declared once, used once"
        );
    }
}

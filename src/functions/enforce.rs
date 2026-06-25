//! Reusable, transport-agnostic enforcement core (v-fn-caller-invoke, Task 2).
//!
//! These fns reproduce the per-op authorization decision order that lives inline
//! in the REST handlers (`src/tenant/records.rs`, `src/tenant/records_list.rs`,
//! `src/tenant/file_caps.rs`) EXACTLY, keyed on the caller's [`AuthCtx`], then
//! delegate the actual SQL / Garage I/O to the existing
//! `crate::mcp::tools::{write,read}` writers (which already fan out to SSE +
//! webhooks). The function host calls this core for any non-`Privileged`
//! `CallerCtx`; `Privileged` keeps the god-mode path. The REST handlers are NOT
//! refactored onto this core in this task — they remain the regression oracle,
//! so the existing `tests/` suite proves the decisions here match REST.
//!
//! Security: there is no fallthrough that yields service power. The cap-gate
//! (`has_dml_cap`), the anon-owner-scoped deny, the owner stamp/filter
//! (`compute_owner_*`), the explicit-policy USING pre-flight, and the in-tx
//! policy CHECK are each applied on EVERY op for `Anon` / `User`. A `Service`
//! ctx (the `Privileged` mapping) bypasses by the same rules the REST handlers
//! use — never by a missing branch.

use crate::auth::middleware::AuthCtx;
use crate::mcp::server::DrustMcp;
use crate::mcp::tools::write::PolicyCheck;
use crate::query::list_builder::{ListRequest, build_structured_list_sql};
use crate::storage::schema::{DmlVerb, FileVerb, has_dml_cap, is_protected_collection};
use crate::tenant::file_caps::{FileCapGate, TenantFileCaps, check_file_cap};
use crate::tenant::router::TokenRole;

/// Map an `AuthCtx` to the `TokenRole` the cap-gate keys on. Mirrors the
/// `AuthCtx`/`TokenRole` correspondence asserted in `records_list.rs`.
fn role_of(ctx: &AuthCtx) -> TokenRole {
    match ctx {
        AuthCtx::Service { .. } => TokenRole::Service,
        AuthCtx::Anon => TokenRole::Anon,
        AuthCtx::User { .. } => TokenRole::User,
    }
}

/// Resolve the cached schema for `coll`, applying the same protected-table 404
/// the REST handlers raise. Returns the schema for cap/owner/policy decisions.
async fn load_schema(
    mcp: &DrustMcp,
    coll: &str,
) -> anyhow::Result<std::sync::Arc<crate::storage::schema::CollectionSchema>> {
    if is_protected_collection(coll) {
        anyhow::bail!("NOT_FOUND: no such collection: {coll}");
    }
    let pool = mcp.inner().pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.to_string();
    pool.with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await?
        .ok_or_else(|| anyhow::anyhow!("NOT_FOUND: no such collection: {coll}"))
}

/// INSERT under the caller's identity. Decision order mirrors
/// `records.rs::create_handler`:
/// 1. protected-table 404 + schema load,
/// 2. anon-on-owner-scoped → `ANON_FORBIDDEN_OWNER_SCOPED`,
/// 3. cap gate (`has_dml_cap`),
/// 4. owner stamp (User overwrites owner_field with its id) / owner-required
///    409 (Service must supply owner_field on an owner-scoped collection),
/// 5. delegate to `insert_record_checked` with the insert-policy CHECK threaded
///    into the writer tx (rollback on fail).
pub async fn enforced_insert(
    mcp: &DrustMcp,
    ctx: &AuthCtx,
    coll: &str,
    mut data: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let schema = load_schema(mcp, coll).await?;
    let role = role_of(ctx);

    // Anon on an owner-scoped collection is refused before the cap gate.
    if matches!(ctx, AuthCtx::Anon) && schema.owner_field.is_some() {
        anyhow::bail!(
            "ANON_FORBIDDEN_OWNER_SCOPED: anon tokens may not write to owner-scoped collections"
        );
    }
    if !has_dml_cap(role, DmlVerb::Insert, &schema) {
        anyhow::bail!(cap_deny_msg(role, DmlVerb::Insert, coll));
    }

    if let Some(owner_field) = schema.owner_field.as_deref() {
        match ctx {
            AuthCtx::Service { .. } => {
                let supplied = data
                    .as_object()
                    .and_then(|o| o.get(owner_field))
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                if !supplied {
                    anyhow::bail!(
                        "OWNER_FIELD_REQUIRED: service token must supply '{owner_field}' on owner-scoped collection"
                    );
                }
            }
            AuthCtx::User { user_id, .. } => {
                // Overwrite whatever the caller sent — a user cannot forge
                // another user's id (same as create_handler).
                if let Some(o) = data.as_object_mut() {
                    o.insert(
                        owner_field.to_string(),
                        serde_json::Value::String(user_id.clone()),
                    );
                }
            }
            AuthCtx::Anon => unreachable!("anon refused above"),
        }
    }

    let policy_check = crate::query::policy::effective_policy_check(ctx, &schema, DmlVerb::Insert)
        .map(|ast| PolicyCheck {
            ast: ast.clone(),
            auth_id: ctx.user_id().map(|s| s.to_string()),
        });

    crate::mcp::tools::write::insert_record_checked(mcp, coll, data, policy_check).await
}

/// UPDATE under the caller's identity. Decision order mirrors
/// `records.rs::update_handler`: cap gate, owner write-filter (User: own rows
/// only, regardless of read_scope), strip client-supplied owner_field, explicit
/// USING pre-flight + in-tx CHECK. A foreign / policy-hidden row → not-found.
pub async fn enforced_update(
    mcp: &DrustMcp,
    ctx: &AuthCtx,
    coll: &str,
    id: i64,
    mut data: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let schema = load_schema(mcp, coll).await?;
    let role = role_of(ctx);

    if matches!(ctx, AuthCtx::Anon) && schema.owner_field.is_some() {
        anyhow::bail!(
            "ANON_FORBIDDEN_OWNER_SCOPED: anon tokens may not write to owner-scoped collections"
        );
    }
    if !has_dml_cap(role, DmlVerb::Update, &schema) {
        anyhow::bail!(cap_deny_msg(role, DmlVerb::Update, coll));
    }

    let owner_filter = crate::tenant::records::compute_owner_write_filter(ctx, &schema);

    // Strip a client-supplied owner_field on the User-owner-scoped path so a
    // user cannot transfer ownership of their row (same as update_handler).
    if let (AuthCtx::User { .. }, Some(field)) = (ctx, schema.owner_field.as_deref())
        && let Some(o) = data.as_object_mut()
    {
        o.remove(field);
    }

    // The owner clause is a WHERE-AND pre-flight (a user updating a foreign row
    // must see not-found). The MCP `update_record_checked` only filters by id,
    // so enforce ownership here: if an owner filter applies and the target row
    // is not owned by the caller, return not-found WITHOUT mutating.
    let using_sql = crate::query::policy::policy_using_sql(ctx, &schema, DmlVerb::Update)?;
    if (owner_filter.is_some() || using_sql.is_some())
        && !is_writable_target(mcp, coll, id, &owner_filter, &using_sql).await?
    {
        anyhow::bail!("RECORD_NOT_FOUND: no such record");
    }

    let policy_check = crate::query::policy::effective_policy_check(ctx, &schema, DmlVerb::Update)
        .map(|ast| PolicyCheck {
            ast: ast.clone(),
            auth_id: ctx.user_id().map(|s| s.to_string()),
        });

    crate::mcp::tools::write::update_record_checked(mcp, coll, id, data, policy_check).await
}

/// DELETE under the caller's identity. Decision order mirrors
/// `records.rs::delete_handler`: cap gate, owner write-filter, explicit USING
/// pre-flight — all AND-ed inside the delete tx (`delete_record_filtered`).
pub async fn enforced_delete(
    mcp: &DrustMcp,
    ctx: &AuthCtx,
    coll: &str,
    id: i64,
) -> anyhow::Result<serde_json::Value> {
    let schema = load_schema(mcp, coll).await?;
    let role = role_of(ctx);

    if matches!(ctx, AuthCtx::Anon) && schema.owner_field.is_some() {
        anyhow::bail!(
            "ANON_FORBIDDEN_OWNER_SCOPED: anon tokens may not write to owner-scoped collections"
        );
    }
    if !has_dml_cap(role, DmlVerb::Delete, &schema) {
        anyhow::bail!(cap_deny_msg(role, DmlVerb::Delete, coll));
    }

    let owner_filter = crate::tenant::records::compute_owner_write_filter(ctx, &schema);
    let using_sql = crate::query::policy::policy_using_sql(ctx, &schema, DmlVerb::Delete)?;

    crate::mcp::tools::write::delete_record_filtered(mcp, coll, id, owner_filter, using_sql).await
}

/// Pre-flight: is `id` a writable TARGET for this caller (owner clause + policy
/// USING)? Runs under the read-only authorizer (read lane). Mirrors the REST
/// update/delete pre-flight SELECT.
async fn is_writable_target(
    mcp: &DrustMcp,
    coll: &str,
    id: i64,
    owner: &Option<(String, String)>,
    using: &Option<(String, Vec<rusqlite::types::Value>)>,
) -> anyhow::Result<bool> {
    use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
    use rusqlite::OptionalExtension;
    use rusqlite::types::Value;
    let pool = mcp.inner().pool.clone();
    let coll = coll.to_string();
    let owner = owner.clone();
    let using = using.clone();
    Ok(pool
        .with_reader(move |c| -> rusqlite::Result<bool> {
            attach_readonly_authorizer(c);
            let mut sql = format!(
                "SELECT 1 FROM \"{}\" WHERE id = ?1",
                coll.replace('"', "\"\"")
            );
            let mut pp: Vec<Value> = vec![Value::Integer(id)];
            if let Some((field, user_id)) = &owner {
                sql.push_str(&format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                ));
            }
            if let Some((frag, pbinds)) = &using {
                sql.push_str(&format!(" AND ({frag})"));
                pp.extend(pbinds.iter().cloned());
            }
            let refs: Vec<&dyn rusqlite::ToSql> =
                pp.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let found = c
                .query_row(&sql, &refs[..], |_| Ok(()))
                .optional()?
                .is_some();
            detach_authorizer(c);
            Ok(found)
        })
        .await?)
}

/// Structured list under the caller's identity. Ports the `records_list.rs`
/// `post_list` auth matrix EXACTLY (anon-owner deny, anon_caps/user_caps select
/// gate, owner_pair for User read_scope="own"), threads owner + select-policy
/// USING into `build_structured_list_sql`, and runs the `?`-bound SELECT under
/// the read-only authorizer.
pub async fn enforced_list(
    mcp: &DrustMcp,
    ctx: &AuthCtx,
    coll: &str,
    req: ListRequest,
) -> anyhow::Result<serde_json::Value> {
    use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
    let schema = load_schema(mcp, coll).await?;

    // ── Auth matrix (lockstep with records_list.rs::post_list) ──────────
    let owner_pair: Option<(String, String)> = match (
        ctx,
        schema.owner_field.as_deref(),
        schema.read_scope.as_deref(),
    ) {
        (AuthCtx::Service { .. }, _, _) => None,
        (AuthCtx::Anon, Some(_), _) => {
            anyhow::bail!(
                "ANON_FORBIDDEN_OWNER_SCOPED: anon cannot read owner-scoped collection — register a user"
            );
        }
        (AuthCtx::Anon, None, _) => {
            if !schema.anon_caps.contains(&DmlVerb::Select) {
                anyhow::bail!("ANON_CAP_DENIED: anon role lacks 'select' on collection '{coll}'");
            }
            None
        }
        (AuthCtx::User { user_id, .. }, Some(field), Some("own")) => {
            Some((field.to_string(), user_id.clone()))
        }
        (AuthCtx::User { .. }, Some(_), Some(_)) => {
            if !schema.user_caps.contains(&DmlVerb::Select) {
                anyhow::bail!(
                    "ANON_CAP_DENIED: user role lacks 'select' on collection '{coll}' (grant it via user_caps)"
                );
            }
            None
        }
        (AuthCtx::User { .. }, _, _) => {
            if !schema.user_caps.contains(&DmlVerb::Select) {
                anyhow::bail!(
                    "ANON_CAP_DENIED: user role lacks 'select' on collection '{coll}' (grant it via user_caps)"
                );
            }
            None
        }
    };

    let policy_clause = crate::query::policy::policy_using_sql(ctx, &schema, DmlVerb::Select)?;

    let owner_ref = owner_pair.as_ref().map(|(f, v)| (f.as_str(), v.as_str()));
    let (list_sql, count_sql, binds) =
        build_structured_list_sql(&schema, &req, owner_ref, policy_clause)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let vector_names: std::collections::HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    let pool = mcp.inner().pool.clone();
    let list_sql_owned = list_sql.clone();
    let binds_list = binds.clone();
    let rows: Vec<serde_json::Value> = pool
        .with_reader(move |c| -> rusqlite::Result<Vec<serde_json::Value>> {
            attach_readonly_authorizer(c);
            let r = run_list_rows(c, &list_sql_owned, &binds_list);
            detach_authorizer(c);
            r
        })
        .await?;
    let records_out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            if let serde_json::Value::Object(mut m) = row {
                m.retain(|k, _| !vector_names.contains(k));
                serde_json::Value::Object(m)
            } else {
                row
            }
        })
        .collect();

    let count_sql_owned = count_sql.clone();
    let binds_count = binds.clone();
    let total: i64 = pool
        .with_reader(move |c| -> rusqlite::Result<i64> {
            attach_readonly_authorizer(c);
            let r = (|| -> rusqlite::Result<i64> {
                let mut stmt = c.prepare(&count_sql_owned)?;
                let refs: Vec<&dyn rusqlite::ToSql> = binds_count
                    .iter()
                    .map(|v| v as &dyn rusqlite::ToSql)
                    .collect();
                stmt.query_row(rusqlite::params_from_iter(refs), |r| r.get(0))
            })();
            detach_authorizer(c);
            r
        })
        .await
        .unwrap_or(0);

    let per_page = req.per_page.unwrap_or(20);
    let page = req.page.unwrap_or(1);
    Ok(serde_json::json!({
        "records": records_out,
        "total": total,
        "page": page,
        "perPage": per_page,
    }))
}

/// Run a `?`-bound SELECT and materialise each row as a JSON object. Plain
/// `prepare` (the projection is schema-derived but recompiling per call keeps it
/// in lockstep; the SQL text already changes on DDL so caching would self-heal
/// — plain prepare is the conservative choice).
fn run_list_rows(
    conn: &rusqlite::Connection,
    sql: &str,
    binds: &[rusqlite::types::Value],
) -> rusqlite::Result<Vec<serde_json::Value>> {
    use rusqlite::types::ValueRef;
    let mut stmt = conn.prepare(sql)?;
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let mut rows_iter = stmt.query(rusqlite::params_from_iter(refs))?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    while let Some(r) = rows_iter.next()? {
        let mut obj = serde_json::Map::new();
        for (i, name) in col_names.iter().enumerate() {
            let v = r.get_ref(i)?;
            obj.insert(
                name.clone(),
                match v {
                    ValueRef::Null => serde_json::Value::Null,
                    ValueRef::Integer(n) => serde_json::json!(n),
                    ValueRef::Real(f) => serde_json::json!(f),
                    ValueRef::Text(t) => {
                        serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
                    }
                    ValueRef::Blob(b) => serde_json::json!({ "__blob_bytes": b.len() }),
                },
            );
        }
        out.push(serde_json::Value::Object(obj));
    }
    Ok(out)
}

// ───────────────────────── files ─────────────────────────

/// `get-file-bytes` raw path (no cap gate) — the byte-for-byte body lifted from
/// the runtime host so `Privileged` and the cap-gated entry share one impl.
pub async fn get_file_bytes_raw(
    mcp: &DrustMcp,
    key: &str,
    file_read_max: u64,
) -> Result<Vec<u8>, String> {
    let inner = mcp.inner();
    let garage = inner
        .garage
        .as_ref()
        .ok_or("STORAGE_UNAVAILABLE: storage not configured")?;
    let pool = inner.pool.clone();
    let key2 = key.to_string();
    let row: Option<(String, i64)> = pool
        .with_reader(move |c| {
            match c.query_row(
                "SELECT visibility, size_bytes FROM _system_files WHERE key = ?1",
                rusqlite::params![key2],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            ) {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
        .map_err(|e| format!("DB_ERROR: {e}"))?;
    let (visibility, size) = row.ok_or("FILE_NOT_FOUND: no such key")?;
    if size as u64 > file_read_max {
        return Err(format!(
            "FN_FILE_TOO_LARGE: {size} bytes exceeds get-file-bytes cap {file_read_max}"
        ));
    }
    let bucket = crate::storage::files::bucket_for(vis_from_str(&visibility));
    let object_key = format!("{}/{}", inner.tenant_id, key);
    garage
        .get_object_bytes_in(bucket, &object_key)
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("GARAGE_GET_FAILED: {e:#}"))
}

/// `put-file` raw path (no cap gate) — body lifted from the runtime host so
/// `Privileged` and the cap-gated entry share one impl.
pub async fn put_file_raw(
    mcp: &DrustMcp,
    key: &str,
    bytes: Vec<u8>,
    content_type: &str,
    visibility: &str,
    disk_min_free_pct: u8,
) -> Result<String, String> {
    if !matches!(visibility, "public" | "private") {
        return Err("INVALID_VISIBILITY: visibility must be public|private".into());
    }
    let inner = mcp.inner();
    let garage = inner
        .garage
        .as_ref()
        .ok_or("STORAGE_UNAVAILABLE: storage not configured")?;
    if bytes.len() > inner.max_upload_bytes {
        return Err(format!(
            "FN_PUT_TOO_LARGE: {} bytes exceeds upload limit {}",
            bytes.len(),
            inner.max_upload_bytes
        ));
    }
    match crate::storage::disk::disk_stats(crate::storage::disk::disk_check_root()) {
        Ok(stats) if (stats.free_pct as u8) < disk_min_free_pct => {
            return Err(format!(
                "DISK_FULL: {:.1}% free, minimum {}% required",
                stats.free_pct, disk_min_free_pct
            ));
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "disk_stats for the disk-check root failed — skipping disk check");
        }
    }
    let pool = inner.pool.clone();
    let size = bytes.len() as i64;
    let cc = put_file_cache_control(visibility);
    let key_w = key.to_string();
    let ct_w = content_type.to_string();
    let vis_w = visibility.to_string();
    let cc_w = cc.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_files
             (key, original_name, content_type, size_bytes, content_disposition,
              visibility, cache_control, meta_json, uploader)
             VALUES (?1, ?2, ?3, ?4, 'inline', ?5, ?6, NULL, 'function')",
            rusqlite::params![key_w, key_w, ct_w, size, vis_w, cc_w],
        )
        .map(|_| ())
    })
    .await
    .map_err(|e| format!("DB_INSERT_FAILED: {e}"))?;

    let bucket = crate::storage::files::bucket_for(vis_from_str(visibility));
    let object_key = format!("{}/{}", inner.tenant_id, key);
    if let Err(e) = garage
        .put_object_in(
            bucket,
            &object_key,
            bytes.into(),
            Some(content_type),
            "inline",
            key,
            Some(cc),
            None,
        )
        .await
    {
        let key_c = key.to_string();
        let _ = pool
            .with_writer(move |c| {
                c.execute(
                    "DELETE FROM _system_files WHERE key = ?1",
                    rusqlite::params![key_c],
                )
                .map(|_| ())
            })
            .await;
        return Err(format!("GARAGE_PUT_FAILED: {e:#}"));
    }
    Ok(serde_json::json!({"key": key, "size_bytes": size}).to_string())
}

fn vis_from_str(visibility: &str) -> crate::storage::files::Visibility {
    match visibility {
        "public" => crate::storage::files::Visibility::Public,
        _ => crate::storage::files::Visibility::Private,
    }
}

fn put_file_cache_control(visibility: &str) -> &'static str {
    crate::storage::files::default_cache_control(
        vis_from_str(visibility),
        crate::storage::files::Disposition::Inline,
    )
}

/// `get-file-bytes` under the caller's identity: file `read` cap gate, then the
/// raw path. Service bypasses (Privileged maps to `TokenRole::Service`).
pub async fn enforced_get_file_bytes(
    mcp: &DrustMcp,
    role: TokenRole,
    caps: &TenantFileCaps,
    key: &str,
    file_read_max: u64,
) -> Result<Vec<u8>, String> {
    if !matches!(
        check_file_cap(role, caps, FileVerb::Read),
        FileCapGate::Allow
    ) {
        return Err("FILE_READ_DENIED: bearer lacks file.read capability".into());
    }
    get_file_bytes_raw(mcp, key, file_read_max).await
}

/// `put-file` under the caller's identity: file `upload` cap gate, then the raw
/// path. Service bypasses.
pub async fn enforced_put_file(
    mcp: &DrustMcp,
    role: TokenRole,
    caps: &TenantFileCaps,
    key: &str,
    bytes: Vec<u8>,
    content_type: &str,
    visibility: &str,
    disk_min_free_pct: u8,
) -> Result<String, String> {
    if !matches!(
        check_file_cap(role, caps, FileVerb::Upload),
        FileCapGate::Allow
    ) {
        return Err("FILE_UPLOAD_DENIED: bearer lacks file.upload capability".into());
    }
    put_file_raw(mcp, key, bytes, content_type, visibility, disk_min_free_pct).await
}

/// The role-aware cap-deny message, mirroring `records.rs::require_write_cap`.
fn cap_deny_msg(role: TokenRole, verb: DmlVerb, coll: &str) -> String {
    if matches!(role, TokenRole::User) {
        format!(
            "ANON_CAP_DENIED: user role lacks '{}' on collection '{}' (grant it via user_caps)",
            verb.as_str(),
            coll
        )
    } else {
        format!(
            "ANON_CAP_DENIED: anon role lacks '{}' on collection '{}'",
            verb.as_str(),
            coll
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::tools::schema::{FieldSpec, create_collection, set_anon_caps, set_user_caps};
    use crate::storage::files::Visibility;
    use crate::storage::schema::DmlVerb;
    use std::sync::Arc;

    fn field(name: &str, ty: &str) -> FieldSpec {
        FieldSpec {
            name: name.into(),
            sql_type: ty.into(),
            nullable: true,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
            description: None,
            ..Default::default()
        }
    }

    /// Build a fully-wired DrustMcp (with an in-memory Garage) over a fresh
    /// tenant pool — the enforcement core needs a real pool + schema cache.
    /// Pattern lifted from runtime.rs::build_store_with_garage.
    async fn mcp_with_garage(tenant_id: &str) -> (DrustMcp, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let tenants = Arc::new(crate::storage::pool::TenantRegistry::new(
            tmp.path().to_path_buf(),
            2,
        ));
        let _pool = tenants.get_or_open(tenant_id).unwrap();
        let garage = Arc::new(crate::storage::garage::GarageClient::from_store(
            Arc::new(object_store::memory::InMemory::new()),
            "unused",
        ));
        let rooms_cfg = crate::tenant::rooms::RoomsConfig::test_defaults();
        let bucket = rooms_cfg.bucket();
        let mcp = DrustMcp::new(
            tenant_id,
            tenants.get_or_open(tenant_id).unwrap(),
            crate::tenant::events::EventBus::new(),
            crate::tenant::WebhookDispatcher::new(tenants.clone(), None),
            Some(garage),
            String::new(),
            Arc::new([0u8; 32]),
            None,
            52_428_800,
            1_000_000,
            Arc::new(tokio::sync::Mutex::new(
                crate::safety::audit_db::open_audit_db_memory().unwrap(),
            )),
            crate::tenant::rooms::RoomBus::new(),
            bucket,
            rooms_cfg,
            None,
            None,
        );
        (mcp, tmp)
    }

    fn anon() -> AuthCtx {
        AuthCtx::Anon
    }
    fn user(id: &str) -> AuthCtx {
        AuthCtx::User {
            user_id: id.into(),
            token_hash: String::new(),
        }
    }
    fn service() -> AuthCtx {
        AuthCtx::Service { admin_id: None }
    }

    /// Create an owner-scoped collection whose owner column is a real FK to
    /// `_system_users(id)` (the FK shape `set_owner_field` requires), then set
    /// `owner_field` + `read_scope` via the low-level schema fn and invalidate
    /// the cache. Raw-SQL table creation mirrors `tests/audit3_readscope_all_caps`.
    async fn make_owner_scoped(mcp: &DrustMcp, coll: &str, read_scope: &str) {
        let coll_c = coll.to_string();
        let scope_c = read_scope.to_string();
        let coll_q = coll.replace('"', "\"\"");
        mcp.inner()
            .pool
            .with_writer(move |c| {
                c.execute_batch(&format!(
                    "PRAGMA foreign_keys = ON;
                     CREATE TABLE \"{coll_q}\" (
                         id         INTEGER PRIMARY KEY AUTOINCREMENT,
                         owner      TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                         title      TEXT,
                         created_at TEXT DEFAULT (datetime('now')),
                         updated_at TEXT DEFAULT (datetime('now'))
                     );"
                ))?;
                crate::storage::schema::set_owner_field(c, &coll_c, Some("owner"), Some(&scope_c))
            })
            .await
            .unwrap();
        mcp.inner().pool.schema_cache.invalidate(coll);
    }

    /// Seed a `_system_users` row so an owner FK can reference it.
    async fn seed_user(mcp: &DrustMcp, id: &str) {
        let id = id.to_string();
        mcp.inner()
            .pool
            .with_writer(move |c| {
                c.execute(
                    "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
                     VALUES (?1, ?1, 'x', datetime('now'), datetime('now'))",
                    rusqlite::params![id],
                )
                .map(|_| ())
            })
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn anon_insert_denied_without_cap() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        create_collection(&mcp, "notes", &[field("body", "text")])
            .await
            .unwrap();
        // default anon_caps = [select] → no insert cap.
        let r = enforced_insert(&mcp, &anon(), "notes", serde_json::json!({"body": "x"})).await;
        let e = r.unwrap_err().to_string();
        assert!(e.contains("ANON_CAP_DENIED"), "got: {e}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn anon_insert_allowed_with_cap() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        create_collection(&mcp, "notes", &[field("body", "text")])
            .await
            .unwrap();
        set_anon_caps(&mcp, "notes", &[DmlVerb::Select, DmlVerb::Insert])
            .await
            .unwrap();
        let v = enforced_insert(&mcp, &anon(), "notes", serde_json::json!({"body": "x"}))
            .await
            .unwrap();
        assert!(v.get("id").is_some(), "inserted: {v}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn user_owner_stamped_on_insert() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        make_owner_scoped(&mcp, "todos", "own").await;
        seed_user(&mcp, "u-1").await;
        // user_caps owner-scoped insert is open (owner stamp is the control).
        let v = enforced_insert(
            &mcp,
            &user("u-1"),
            "todos",
            // try to forge another user's id — must be overwritten.
            serde_json::json!({"title": "t", "owner": "u-evil"}),
        )
        .await
        .unwrap();
        assert_eq!(v["record"]["owner"], "u-1", "owner must be stamped: {v}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn user_update_foreign_row_not_found() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        make_owner_scoped(&mcp, "todos", "own").await;
        seed_user(&mcp, "u-1").await;
        seed_user(&mcp, "u-2").await;
        // u-1 owns row 1.
        let v = enforced_insert(
            &mcp,
            &user("u-1"),
            "todos",
            serde_json::json!({"title": "a"}),
        )
        .await
        .unwrap();
        let id = v["id"].as_i64().unwrap();
        // u-2 may not update u-1's row → not-found.
        let r = enforced_update(
            &mcp,
            &user("u-2"),
            "todos",
            id,
            serde_json::json!({"title": "hacked"}),
        )
        .await;
        let e = r.unwrap_err().to_string();
        assert!(
            e.contains("RECORD_NOT_FOUND") || e.contains("no such record"),
            "got: {e}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn policy_check_fail_rolls_back() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        create_collection(&mcp, "items", &[field("n", "integer")])
            .await
            .unwrap();
        set_anon_caps(&mcp, "items", &[DmlVerb::Select, DmlVerb::Insert])
            .await
            .unwrap();
        // insert policy CHECK: n > 10
        crate::mcp::tools::policy::set_policy(
            &mcp,
            "items",
            "insert",
            None,
            Some(serde_json::json!({ "n": { "gt": 10 } })),
        )
        .await
        .unwrap();
        // fails CHECK → rolled back.
        let r = enforced_insert(&mcp, &anon(), "items", serde_json::json!({"n": 5})).await;
        assert!(
            r.unwrap_err().to_string().contains("POLICY_CHECK_FAILED"),
            "expected policy rollback"
        );
        // table is empty (rolled back) — count via a service list.
        let listed = enforced_list(&mcp, &service(), "items", ListRequest::default())
            .await
            .unwrap();
        assert_eq!(listed["total"], 0, "insert must have rolled back: {listed}");
        // a passing row is accepted.
        let ok = enforced_insert(&mcp, &anon(), "items", serde_json::json!({"n": 20})).await;
        assert!(ok.is_ok(), "n=20 passes the CHECK");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_scope_all_user_gated_by_user_caps() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        make_owner_scoped(&mcp, "pub", "all").await;
        // user_caps default = [select]? It defaults to [select]; revoke to [].
        set_user_caps(&mcp, "pub", &[]).await.unwrap();
        // read_scope=all → no owner filter → must be gated by user_caps[select].
        let r = enforced_list(&mcp, &user("u-1"), "pub", ListRequest::default()).await;
        let e = r.unwrap_err().to_string();
        assert!(e.contains("ANON_CAP_DENIED"), "got: {e}");
        // grant select → allowed.
        set_user_caps(&mcp, "pub", &[DmlVerb::Select])
            .await
            .unwrap();
        let ok = enforced_list(&mcp, &user("u-1"), "pub", ListRequest::default()).await;
        assert!(ok.is_ok(), "select cap granted → listable");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn service_bypasses_all() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        create_collection(&mcp, "notes", &[field("body", "text")])
            .await
            .unwrap();
        // no caps granted; service still inserts + lists.
        let v = enforced_insert(&mcp, &service(), "notes", serde_json::json!({"body": "s"}))
            .await
            .unwrap();
        assert!(v.get("id").is_some());
        let listed = enforced_list(&mcp, &service(), "notes", ListRequest::default())
            .await
            .unwrap();
        assert_eq!(listed["total"], 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_file_bytes_denied_without_read_cap() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        // seed a file via the service raw put.
        put_file_raw(
            &mcp,
            "f.bin",
            b"hi".to_vec(),
            "application/octet-stream",
            "private",
            0,
        )
        .await
        .unwrap();
        let caps = TenantFileCaps::default(); // no anon read cap
        let r =
            enforced_get_file_bytes(&mcp, TokenRole::Anon, &caps, "f.bin", 4 * 1024 * 1024).await;
        assert!(r.unwrap_err().contains("FILE_READ_DENIED"));
        // grant read → allowed.
        let mut caps2 = TenantFileCaps::default();
        caps2.anon.insert(FileVerb::Read);
        let ok =
            enforced_get_file_bytes(&mcp, TokenRole::Anon, &caps2, "f.bin", 4 * 1024 * 1024).await;
        assert_eq!(ok.unwrap(), b"hi");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_file_denied_without_upload_cap() {
        let (mcp, _t) = mcp_with_garage("t1").await;
        let caps = TenantFileCaps::default();
        let r = enforced_put_file(
            &mcp,
            TokenRole::User,
            &caps,
            "u.bin",
            b"x".to_vec(),
            "application/octet-stream",
            "private",
            0,
        )
        .await;
        assert!(r.unwrap_err().contains("FILE_UPLOAD_DENIED"));
        // grant upload → allowed.
        let mut caps2 = TenantFileCaps::default();
        caps2.user.insert(FileVerb::Upload);
        let ok = enforced_put_file(
            &mcp,
            TokenRole::User,
            &caps2,
            "u.bin",
            b"x".to_vec(),
            "application/octet-stream",
            "private",
            0,
        )
        .await;
        assert!(ok.is_ok());
        let _ = Visibility::Private; // keep import used
    }
}

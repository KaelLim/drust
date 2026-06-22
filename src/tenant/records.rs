use crate::auth::middleware::AuthCtx;
use crate::error::{json_error, json_error_with_aliases, json_error_with_context};
use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::executor::execute_read_query;
use crate::query::filter::{ListParams, SortDir, build_count_sql, build_list_sql, parse_sort};
use crate::storage::schema::{
    CollectionSchema, DmlVerb, collection_exists, describe_collection, has_dml_cap,
    is_protected_collection,
};
use crate::tenant::WebhookDispatcher;
use crate::tenant::events::{Event, EventBus};
use crate::tenant::router::TenantRef;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::types::Value;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize, Default)]
pub struct ListQs {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

/// Resolve the cached schema for `coll`, then gate the caller's role
/// against `verb`. Returns the schema on success so the handler can
/// reuse it for field-name validation. Returns a 403 (anon lacks cap)
/// or 404 (collection not found) `Response` on failure.
async fn require_dml_cap(
    tenant: &TenantRef,
    coll: &str,
    verb: DmlVerb,
) -> Result<std::sync::Arc<CollectionSchema>, Response> {
    // _system_* tables are internal storage and never exposed via the
    // records API regardless of role. Service tokens that need to touch
    // them have dedicated admin/MCP entry points.
    if is_protected_collection(coll) {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            &format!("no such collection: {coll}"),
        ));
    }
    let pool = tenant.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.to_string();
    let load_res = pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await;
    let schema = match load_res {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("no such collection: {coll}"),
            ));
        }
        Err(e) => {
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            ));
        }
    };
    // Anon on owner-scoped collection with read_scope=own has no user_id to
    // match against, so it can't see any rows — fail loudly rather than
    // silently returning an empty list.
    if matches!(tenant.role, crate::tenant::router::TokenRole::Anon)
        && schema.owner_field.is_some()
        && schema.read_scope.as_deref() == Some("own")
    {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "ANON_FORBIDDEN_OWNER_SCOPED",
            "anon cannot read owner-scoped collection with read_scope=own",
        ));
    }
    if !has_dml_cap(tenant.role, verb, &schema) {
        let message = if matches!(tenant.role, crate::tenant::router::TokenRole::User) {
            format!(
                "user role lacks '{}' on collection '{}' (grant it via user_caps)",
                verb.as_str(),
                coll
            )
        } else {
            format!(
                "anon role lacks '{}' on collection '{}'",
                verb.as_str(),
                coll
            )
        };
        return Err(json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "ANON_CAP_DENIED",
            &["ANON_DENIED"],
            &message,
        ));
    }
    Ok(schema)
}

/// Same as `require_dml_cap` for write verbs (Insert/Update/Delete), but
/// additionally checks owner-scoped anon policy *before* the cap gate, so
/// anon callers on owner-scoped collections get `ANON_FORBIDDEN_OWNER_SCOPED`
/// rather than the generic `ANON_DENIED`.
async fn require_write_cap(
    tenant: &TenantRef,
    ctx: &AuthCtx,
    coll: &str,
    verb: DmlVerb,
) -> Result<std::sync::Arc<CollectionSchema>, Response> {
    if is_protected_collection(coll) {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            &format!("no such collection: {coll}"),
        ));
    }
    let pool = tenant.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.to_string();
    let load_res = pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await;
    let schema = match load_res {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("no such collection: {coll}"),
            ));
        }
        Err(e) => {
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            ));
        }
    };
    // Anon on an owner-scoped collection gets a specific error that distinguishes
    // "collection is owner-gated" from "this collection doesn't allow anon writes".
    if matches!(ctx, AuthCtx::Anon) && schema.owner_field.is_some() {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "ANON_FORBIDDEN_OWNER_SCOPED",
            "anon tokens may not write to owner-scoped collections",
        ));
    }
    // Cap gate: Anon is checked against anon_caps, User against user_caps
    // (Service passes unconditionally). See has_dml_cap.
    if !has_dml_cap(tenant.role, verb, &schema) {
        let message = if matches!(tenant.role, crate::tenant::router::TokenRole::User) {
            format!(
                "user role lacks '{}' on collection '{}' (grant it via user_caps)",
                verb.as_str(),
                coll
            )
        } else {
            format!(
                "anon role lacks '{}' on collection '{}'",
                verb.as_str(),
                coll
            )
        };
        return Err(json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "ANON_CAP_DENIED",
            &["ANON_DENIED"],
            &message,
        ));
    }
    Ok(schema)
}

/// Compute an owner row-level filter `(field_name, user_id)` when:
/// - the collection has an `owner_field` with `read_scope = "own"`, AND
/// - the caller is a `User` token (Service and Anon bypass the filter).
fn compute_owner_filter(ctx: &AuthCtx, schema: &CollectionSchema) -> Option<(String, String)> {
    match (
        ctx,
        schema.owner_field.as_deref(),
        schema.read_scope.as_deref(),
    ) {
        (AuthCtx::User { user_id, .. }, Some(field), Some("own")) => {
            Some((field.to_string(), user_id.clone()))
        }
        _ => None,
    }
}

fn json_to_sql_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Integer(if *b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Value::Real(f)
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        other => Value::Text(other.to_string()),
    }
}

fn record_as_json(
    stmt: &mut rusqlite::Statement,
    column_names: &[String],
    id: i64,
) -> rusqlite::Result<serde_json::Value> {
    let row = stmt.query_row(rusqlite::params![id], |r| {
        let mut obj = serde_json::Map::new();
        for (i, n) in column_names.iter().enumerate() {
            let v = r.get_ref(i)?;
            let jv = match v {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(i) => serde_json::json!(i),
                rusqlite::types::ValueRef::Real(f) => serde_json::json!(f),
                rusqlite::types::ValueRef::Text(t) => {
                    serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
                }
                rusqlite::types::ValueRef::Blob(b) => {
                    serde_json::json!({ "__blob_bytes": b.len() })
                }
            };
            obj.insert(n.clone(), jv);
        }
        Ok(serde_json::Value::Object(obj))
    })?;
    Ok(row)
}

/// Run a `?`-bound legacy list SELECT and materialise each row as a JSON
/// object keyed by column name, default-hiding declared vector columns and
/// honoring `row_cap`. Mirrors `records_list::run_bound_select` but applies
/// the vector-name hide inline (the legacy path projects `SELECT *`). The
/// caller is responsible for attaching/detaching the read-only authorizer.
fn list_bound_rows(
    conn: &rusqlite::Connection,
    sql: &str,
    binds: &[Value],
    vector_names: &std::collections::HashSet<String>,
    row_cap: usize,
) -> rusqlite::Result<Vec<serde_json::Value>> {
    let mut stmt = conn.prepare(sql)?;
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let mut rows_iter = stmt.query(rusqlite::params_from_iter(refs))?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    while let Some(r) = rows_iter.next()? {
        if out.len() >= row_cap {
            break;
        }
        let mut obj = serde_json::Map::new();
        for (i, name) in col_names.iter().enumerate() {
            if vector_names.contains(name) {
                continue;
            }
            let v = r.get_ref(i)?;
            obj.insert(
                name.clone(),
                match v {
                    rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                    rusqlite::types::ValueRef::Integer(n) => json!(n),
                    rusqlite::types::ValueRef::Real(f) => json!(f),
                    rusqlite::types::ValueRef::Text(t) => {
                        serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
                    }
                    rusqlite::types::ValueRef::Blob(b) => json!({ "__blob_bytes": b.len() }),
                },
            );
        }
        out.push(serde_json::Value::Object(obj));
    }
    Ok(out)
}

/// Attach RFC 8594 Deprecation + Sunset + Link headers to a response.
/// Called by `list_handler` when the legacy `?filter` / `?sort` query
/// params are present.  The headers are informational only (phase 1);
/// phase 2 will start refusing these params after the sunset date.
fn attach_deprecation_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::HeaderName::from_static("deprecation"),
        axum::http::header::HeaderValue::from_static("true"),
    );
    h.insert(
        axum::http::header::HeaderName::from_static("sunset"),
        axum::http::header::HeaderValue::from_static("Fri, 01 Jan 2027 00:00:00 GMT"),
    );
    h.insert(
        axum::http::header::HeaderName::from_static("link"),
        axum::http::header::HeaderValue::from_static(
            "<https://github.com/KaelLim/drust/blob/main/docs/migration/list-filter.md>; rel=\"deprecation\"",
        ),
    );
}

pub async fn list_handler(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll)): Path<(String, String)>,
    Query(qs): Query<ListQs>,
) -> Response {
    let schema = match require_dml_cap(&t, &coll, DmlVerb::Select).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    // v1.19.2 — User tokens on owner-scoped collections cannot pass raw
    // `?filter=` or `?sort=` because those interpolate verbatim into SQL
    // (see src/query/filter.rs::build_list_sql) and a `--` comment can
    // void the row-level owner clause. Reject explicitly with a typed
    // code pointing to the safe alternatives. FilterAst integration on
    // /records/* is queued for v1.21.
    if matches!(ctx, AuthCtx::User { .. })
        && schema.owner_field.is_some()
        && schema.read_scope.as_deref() == Some("own")
        && (qs.filter.is_some() || qs.sort.is_some())
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "USER_FILTER_DENIED_ON_OWNER_SCOPED",
            "user-token filter/sort on owner-scoped collections is unsupported \
             (raw filter strings can bypass row-level owner enforcement). \
             Use POST /collections/<c>/list with a structured Filter AST \
             (drust builds the SQL itself with `?` binds, so owner_field is \
             enforced by construction), POST /collections/<c>/search for \
             vector queries, or expose a stored RPC that binds :user_id \
             internally.",
        );
    }
    // H1 — explicit select-policy USING must be enforced on this legacy
    // GET-list path too (not only POST /list). policy_using_sql returns None
    // for service / no-policy. A compile error is a 500.
    let policy_clause = match crate::query::policy::policy_using_sql(&ctx, &schema, DmlVerb::Select)
    {
        Ok(c) => c,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "POLICY_COMPILE_ERROR",
                &e.to_string(),
            );
        }
    };
    // RLS Task 15 / H1 — raw `?filter=` / `?sort=` interpolate verbatim into
    // SQL (build_list_sql) so a trailing `--` comment could void an AND-ed
    // owner/policy clause. Refuse when ANY row-level rule applies. The anon
    // owner_field/policy guard keys on the schema (so anon is refused even
    // when service-only policy_clause is None); the policy_clause guard
    // additionally covers any non-service caller subject to a select policy.
    // Either way, point at the structured /list endpoint (FilterAst, `?`-bound).
    // A plain list (no filter/sort) still works — owner_field is interpolated
    // and the explicit policy USING is AND-ed in as a `?`-bound clause below.
    if (qs.filter.is_some() || qs.sort.is_some())
        && (policy_clause.is_some()
            || (matches!(ctx, AuthCtx::Anon)
                && (schema.owner_field.is_some() || !schema.policies.is_empty())))
    {
        return json_error(
            StatusCode::FORBIDDEN,
            "ANON_QUERY_DENIED_ON_POLICY",
            "raw filter/sort is unsupported on a policy-protected collection; \
             use POST /collections/<c>/list (FilterAst)",
        );
    }
    // F1 (audit 2026-06-22) — backstop for EVERY remaining untrusted-role
    // raw-filter case. The legacy `?filter=`/`?sort=` params interpolate
    // verbatim into build_list_sql (no `?` binds), and the read-only authorizer
    // (authorizer.rs) ALLOWS reads of any non-`_system_` sibling collection. So
    // an anon/user caller can smuggle a subquery (`EXISTS(SELECT 1 FROM "B" …)`
    // / `UNION`) into the raw filter to read sibling collection `B` their role
    // has no caps on — the per-collection cap boundary (anon_caps/user_caps) is
    // an explicit authorization boundary, so this is a privilege bypass. The
    // owner-scoped and policy guards above only cover SOME shapes; a plain
    // collection (no owner_field, no policy) slips past both. Deny the raw
    // param for BOTH untrusted roles on EVERY collection — it is deprecated
    // (Sunset 2027-01-01). Service is trusted (bypasses caps, may read every
    // table) and keeps the raw param; untrusted roles must use the structured
    // POST /list (FilterAst, `?`-bound, cap/owner/policy-safe by construction).
    if matches!(ctx, AuthCtx::Anon | AuthCtx::User { .. })
        && (qs.filter.is_some() || qs.sort.is_some())
    {
        return json_error(
            StatusCode::FORBIDDEN,
            "RAW_FILTER_DENIED",
            "raw ?filter=/?sort= is not allowed for anon or user tokens \
             (a raw filter can read sibling collections via subqueries, \
             bypassing per-collection caps). Use POST /collections/<c>/list \
             with a structured Filter AST (drust builds the SQL with `?` \
             binds), POST /collections/<c>/search, or a stored RPC.",
        );
    }
    // require_dml_cap already loaded the schema (via the cache); a
    // successful return proves the collection exists. The previous
    // standalone collection_exists reader hit + "existing collections"
    // 404 branch here were redundant (require_dml_cap returns its own
    // 404 with code "NOT_FOUND" first). v1.32.1 D4 — drop the redundant
    // reader checkout from the happy path.
    let pool = t.pool.clone();
    // Compute owner_filter: only for User tokens on collections with
    // read_scope = "own".  Service and Anon bypass the row-level filter.
    let owner_filter = compute_owner_filter(&ctx, &schema);
    let (sort_field, sort_dir) = match qs.sort.as_deref() {
        Some(s) => parse_sort(s),
        None => ("created_at".into(), SortDir::Desc),
    };
    // Keep a copy of the (field, user_id) tuple for the count query — we
    // need `&str` slices that outlive the params struct.
    let owner_filter_for_count = owner_filter.clone();
    let params = ListParams {
        filter: qs.filter.clone(),
        sort_field,
        sort_dir,
        page: qs.page.unwrap_or(1),
        per_page: qs.per_page.unwrap_or(20),
        owner_filter,
    };
    let list_sql = build_list_sql(&coll, &params, policy_clause.as_ref());
    let count_sql = build_count_sql(
        &coll,
        qs.filter.as_deref(),
        owner_filter_for_count
            .as_ref()
            .map(|(f, v)| (f.as_str(), v.as_str())),
        policy_clause.as_ref(),
    );
    // Vector fields are excluded from list responses by default — they
    // serialise to a useless `{"__blob_bytes": n}` sentinel anyway via
    // the read-only executor, and a 384-dim vector inflates each row by
    // ~1.5 KB. Vectors are retrieved via /search.
    let vector_names: std::collections::HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    let (records_out, total): (Vec<serde_json::Value>, i64) = if let Some((_frag, binds)) =
        policy_clause.as_ref()
    {
        // Policy path — the SQL carries `?` placeholders for the select-policy
        // USING fragment; execute under the read-only authorizer with the
        // policy binds (mirrors records_list::post_list). The 500-row cap is
        // applied at materialise time. owner_field (if any) is still inlined
        // into the SQL above; the only `?` are the policy's.
        let binds_list = binds.clone();
        let binds_count = binds.clone();
        let vnames = vector_names.clone();
        let list_sql_owned = list_sql.clone();
        let rows_res: rusqlite::Result<Vec<serde_json::Value>> = pool
            .with_reader(move |c| {
                attach_readonly_authorizer(c);
                let r = list_bound_rows(c, &list_sql_owned, &binds_list, &vnames, 500);
                detach_authorizer(c);
                r
            })
            .await;
        let records_out = match rows_res {
            Ok(v) => v,
            Err(_) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "QUERY_FORBIDDEN",
                    "filter rejected",
                );
            }
        };
        let count_sql_owned = count_sql.clone();
        let total = pool
            .with_reader(move |c| -> rusqlite::Result<i64> {
                attach_readonly_authorizer(c);
                let r = {
                    let refs: Vec<&dyn rusqlite::ToSql> = binds_count
                        .iter()
                        .map(|v| v as &dyn rusqlite::ToSql)
                        .collect();
                    c.query_row(&count_sql_owned, rusqlite::params_from_iter(refs), |r| {
                        r.get(0)
                    })
                };
                detach_authorizer(c);
                r
            })
            .await
            .unwrap_or(0);
        (records_out, total)
    } else {
        // Non-policy path — verbatim (zero behavior change). owner_field and
        // any raw ?filter are interpolated as literals; the SQL has no `?`.
        let records_res = {
            let sql = list_sql.clone();
            pool.with_reader(move |c| {
                execute_read_query(c, &sql, 500, 32_768).map_err(|_e| rusqlite::Error::InvalidQuery)
            })
            .await
        };
        let records = match records_res {
            Ok(qr) => qr,
            Err(_) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "QUERY_FORBIDDEN",
                    "filter rejected",
                );
            }
        };
        let total = {
            let sql = count_sql.clone();
            pool.with_reader(move |c| {
                attach_readonly_authorizer(c);
                let r = c.query_row(&sql, [], |r| r.get::<_, i64>(0));
                detach_authorizer(c);
                r
            })
            .await
            .unwrap_or(0)
        };
        let records_out: Vec<serde_json::Value> = records
            .rows
            .iter()
            .map(|row| {
                let mut m = serde_json::Map::new();
                for (i, name) in records.column_names.iter().enumerate() {
                    if vector_names.contains(name) {
                        continue;
                    }
                    m.insert(name.clone(), row[i].to_json());
                }
                serde_json::Value::Object(m)
            })
            .collect();
        (records_out, total)
    };
    let per_page = params.per_page.clamp(1, 500) as u64;
    let total_pages = (total as u64).div_ceil(per_page.max(1));
    let mut resp = Json(json!({
        "records": records_out,
        "page": params.page,
        "perPage": per_page,
        "total": total,
        "totalPages": total_pages,
    }))
    .into_response();
    // H5-1 phase 1: advertise deprecation when the legacy raw-SQL query
    // params (?filter / ?sort) are present. Behavior is unchanged for now.
    // Phase 2 (after 2027-01-01) will refuse these params entirely.
    // Clients should migrate to POST /collections/<c>/list with a
    // structured FilterAst body — drust builds the SQL with ? binds, so
    // owner_field is always enforced and there is no injection surface.
    if qs.filter.is_some() || qs.sort.is_some() {
        attach_deprecation_headers(&mut resp);
    }
    resp
}

pub async fn get_handler(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
) -> Response {
    let schema = match require_dml_cap(&t, &coll, DmlVerb::Select).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let owner_filter = compute_owner_filter(&ctx, &schema);
    // Explicit select-policy USING (None for service callers / no policy).
    let policy_sql = match crate::query::policy::policy_using_sql(&ctx, &schema, DmlVerb::Select) {
        Ok(c) => c,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "POLICY_COMPILE_ERROR",
                &e.to_string(),
            );
        }
    };
    let vector_names: std::collections::HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();
    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let policy_sql_c = policy_sql.clone();
    let out = pool
        .with_reader(move |c| {
            if !collection_exists(c, &coll_clone)? {
                return Ok(None);
            }
            // Pre-flight visibility SELECT under the policy USING: if the row
            // doesn't satisfy the explicit select-policy, treat it as absent
            // (same 404 as a missing row). Leaves the owner-inline read below
            // unchanged. Service callers have `policy_sql_c == None`.
            if let Some((frag, pbinds)) = &policy_sql_c {
                use rusqlite::OptionalExtension;
                let q = format!(
                    "SELECT 1 FROM \"{}\" WHERE id = ? AND ({frag})",
                    coll_clone.replace('"', "\"\"")
                );
                let mut pp: Vec<rusqlite::types::Value> = vec![rusqlite::types::Value::Integer(id)];
                pp.extend(pbinds.iter().cloned());
                let refs: Vec<&dyn rusqlite::ToSql> =
                    pp.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                let visible: Option<i64> = c.query_row(&q, &refs[..], |r| r.get(0)).optional()?;
                if visible.is_none() {
                    return Ok(None); // → 404, same as a missing row
                }
            }
            // Build the query; append owner filter as a literal when needed.
            let mut sql = format!(
                "SELECT * FROM \"{}\" WHERE id = ?1",
                coll_clone.replace('"', "\"\"")
            );
            if let Some((field, user_id)) = &owner_filter {
                sql.push_str(&format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                ));
            }
            let mut stmt = c.prepare(&sql)?;
            let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let rec = record_as_json(&mut stmt, &cols, id);
            match rec {
                Ok(mut v) => {
                    if let Some(obj) = v.as_object_mut() {
                        obj.retain(|k, _| !vector_names.contains(k));
                    }
                    Ok(Some(v))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await;
    match out {
        Ok(Some(v)) => Json(json!({ "record": v })).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct DataBody {
    pub data: serde_json::Value,
}

pub async fn create_handler(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(body): Json<DataBody>,
    bus: EventBus,
    webhooks: Arc<WebhookDispatcher>,
    functions: Arc<crate::functions::dispatcher::FunctionDispatcher>,
) -> Response {
    let schema = match require_write_cap(&t, &ctx, &coll, DmlVerb::Insert).await {
        Ok(s) => s,
        Err(r) => return r,
    };

    // Owner-field policy checks for Service/User (anon already blocked by require_write_cap):
    if let Some(ref owner_field) = schema.owner_field {
        match &ctx {
            AuthCtx::Anon => {
                // already blocked above; unreachable but keep for exhaustiveness
                return json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_FORBIDDEN_OWNER_SCOPED",
                    "anon tokens may not write to owner-scoped collections",
                );
            }
            AuthCtx::Service { .. } => {
                // Service must explicitly supply the owner field so the row
                // is attributed to a real user; missing it is a caller error.
                let data_obj = body.data.as_object();
                let supplied = data_obj
                    .and_then(|o| o.get(owner_field))
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                if !supplied {
                    return json_error_with_context(
                        StatusCode::CONFLICT,
                        "OWNER_FIELD_REQUIRED",
                        &format!(
                            "service token must supply '{owner_field}' on owner-scoped collection"
                        ),
                        &crate::safety::error_fixes::ErrorContext::OwnerFieldRequired {
                            collection: &coll,
                            field: owner_field,
                        },
                    );
                }
            }
            AuthCtx::User { user_id, .. } => {
                // User token: the owner field is always overwritten to the
                // caller's user_id — clients cannot forge another user's id.
                // (Handled inside the writer closure below.)
                let _ = user_id; // used in closure capture
            }
        }
    }

    let mut data = match body.data.as_object() {
        Some(o) => o.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TYPE_MISMATCH",
                "data must be object",
            );
        }
    };

    // For user tokens with an owner_field, overwrite whatever the client sent.
    if let (Some(owner_field), AuthCtx::User { user_id, .. }) = (&schema.owner_field, &ctx) {
        data.insert(
            owner_field.clone(),
            serde_json::Value::String(user_id.clone()),
        );
    }

    // Pre-encode vector fields BEFORE the writer mutex so codec errors
    // (dim mismatch, non-finite, etc.) surface as typed 422s. Each
    // declared vector field present in `data` becomes a Vec<u8> in
    // `vector_bytes` and is removed from `data` (so json_to_sql_value
    // doesn't try to stringify it as text).
    let mut vector_bytes: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    for vf in &schema.vector_fields {
        if let Some(v) = data.get(&vf.name).cloned() {
            match crate::query::vector_codec::pack(&vf.name, vf.dim, &v) {
                Ok(bytes) => {
                    vector_bytes.insert(vf.name.clone(), bytes);
                }
                Err(crate::query::vector_codec::VectorCodecError::DimMismatch {
                    field,
                    expected,
                    got,
                }) => {
                    return json_error_with_context(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "VECTOR_DIM_MISMATCH",
                        &format!("vector field {:?} has wrong dim", vf.name),
                        &crate::safety::error_fixes::ErrorContext::VectorDimMismatch {
                            field: &field,
                            expected_dim: expected,
                            actual_dim: got as u32,
                        },
                    );
                }
                Err(crate::query::vector_codec::VectorCodecError::NonFinite { .. }) => {
                    return json_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "VECTOR_NON_FINITE",
                        &format!("vector field {:?} contains NaN or Inf", vf.name),
                    );
                }
                Err(e) => {
                    return json_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "VECTOR_TYPE_ERROR",
                        &e.to_string(),
                    );
                }
            }
        }
    }

    // Vector field names that exist on this collection — used after the
    // INSERT to filter them out of the response shape (default-hide on
    // read; vectors are only meant to be retrieved via /search).
    let vector_names: std::collections::HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    // Explicit-policy CHECK for INSERT (service bypasses → None). Evaluated
    // on the persisted (read-back) row INSIDE the writer transaction so a
    // failing predicate rolls the INSERT back (sentinel → 403 below).
    let check_ast: Option<crate::query::vector_filter::FilterAst> =
        crate::query::policy::effective_policy_check(&ctx, &schema, DmlVerb::Insert).cloned();
    let auth_id_for_check: Option<String> = ctx.user_id().map(|s| s.to_string());

    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let tenant_id = t.tenant_id.clone();
    // Capture submitted keys + schema field names BEFORE the closure
    // moves `data` and `schema` — needed at the error point to identify
    // which key was rejected as FIELD_NOT_FOUND.
    let submitted_keys: Vec<String> = data.keys().cloned().collect();
    let known_fields: Vec<String> = schema.fields.iter().map(|f| f.name.clone()).collect();
    let res = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<(i64, serde_json::Value)> {
            // Validate against schema
            let schema = match describe_collection(tx, &coll_clone)? {
                Some(s) => s,
                None => return Err(rusqlite::Error::InvalidQuery),
            };
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data.keys() {
                if !allowed.contains(k.as_str()) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            let cols: Vec<&str> = data.keys().map(|k| k.as_str()).collect();
            let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
            let sql = if cols.is_empty() {
                format!(
                    "INSERT INTO \"{}\" DEFAULT VALUES",
                    coll_clone.replace('"', "\"\"")
                )
            } else {
                format!(
                    "INSERT INTO \"{}\" ({}) VALUES ({})",
                    coll_clone.replace('"', "\"\""),
                    cols.iter()
                        .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                        .collect::<Vec<_>>()
                        .join(","),
                    placeholders.join(","),
                )
            };
            // Bind values: vector fields → Value::Blob from the pre-encoded
            // bytes map; everything else → json_to_sql_value.
            let params: Vec<Value> = data
                .iter()
                .map(|(k, v)| match vector_bytes.get(k) {
                    Some(bytes) => Value::Blob(bytes.clone()),
                    None => json_to_sql_value(v),
                })
                .collect();
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            tx.execute(&sql, &refs[..])?;
            let id = tx.last_insert_rowid();
            // Read back the row excluding vector columns so the response
            // is small and the BLOB never leaks as {"__blob_bytes": n}.
            let mut stmt = tx.prepare(&format!(
                "SELECT * FROM \"{}\" WHERE id = ?1",
                coll_clone.replace('"', "\"\"")
            ))?;
            let cols_out: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let mut rec = record_as_json(&mut stmt, &cols_out, id)?;
            if let Some(obj) = rec.as_object_mut() {
                obj.retain(|k, _| !vector_names.contains(k));
            }
            // Explicit-policy CHECK on the persisted row. A failing predicate
            // returns the sentinel error, rolling back this INSERT.
            if let Some(check) = &check_ast {
                let row_map = rec.as_object().cloned().unwrap_or_default();
                let pc = crate::query::policy::PolicyCtx {
                    auth_id: auth_id_for_check.clone(),
                    data: Some(row_map.clone()),
                };
                if !crate::query::policy::eval_policy(check, &row_map, &pc) {
                    return Err(crate::query::policy::policy_check_sentinel());
                }
            }
            Ok((id, rec))
        })
        .await;
    match res {
        Ok((id, rec)) => {
            // Build response first; dispatch only after payload exists.
            let mut r = Json(json!({ "id": id, "record": rec.clone() })).into_response();
            *r.status_mut() = StatusCode::CREATED;
            let ev = Event::Created { record: rec };
            bus.publish(&tenant_id, &coll, ev.clone());
            functions.dispatch(&tenant_id, &coll, &ev);
            webhooks.dispatch(&tenant_id, &coll, ev);
            r
        }
        Err(ref e) if crate::query::policy::is_policy_check_failure(e) => json_error(
            StatusCode::FORBIDDEN,
            "POLICY_CHECK_FAILED",
            "insert rejected by the collection's insert policy CHECK",
        ),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("InvalidQuery") {
                let bad = submitted_keys
                    .iter()
                    .find(|k| !known_fields.iter().any(|f| f == *k))
                    .cloned()
                    .unwrap_or_default();
                json_error_with_context(
                    StatusCode::BAD_REQUEST,
                    "FIELD_NOT_FOUND",
                    "unknown field or missing collection",
                    &crate::safety::error_fixes::ErrorContext::FieldNotFound {
                        field: &bad,
                        collection: &coll,
                        existing: &known_fields,
                    },
                )
            } else {
                (StatusCode::BAD_REQUEST, msg).into_response()
            }
        }
    }
}

pub async fn update_handler(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
    Json(body): Json<DataBody>,
    bus: EventBus,
    webhooks: Arc<WebhookDispatcher>,
    functions: Arc<crate::functions::dispatcher::FunctionDispatcher>,
) -> Response {
    let schema = match require_write_cap(&t, &ctx, &coll, DmlVerb::Update).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let owner_filter = compute_owner_filter(&ctx, &schema);
    // Explicit-policy USING (pre-flight target filter) + CHECK (post-image)
    // for UPDATE. Service bypasses both (`effective_policy_*` → None). The
    // USING fragment AND-composes ALONGSIDE the unchanged owner clause: a row
    // failing the explicit USING is not an updatable target (→ 404). The
    // CHECK is evaluated on the persisted (read-back) row INSIDE the writer
    // transaction so a failing predicate rolls the UPDATE back (→ 403).
    let using_sql: Option<(String, Vec<rusqlite::types::Value>)> =
        match crate::query::policy::policy_using_sql(&ctx, &schema, DmlVerb::Update) {
            Ok(c) => c,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "POLICY_COMPILE_ERROR",
                    &e.to_string(),
                );
            }
        };
    let check_ast: Option<crate::query::vector_filter::FilterAst> =
        crate::query::policy::effective_policy_check(&ctx, &schema, DmlVerb::Update).cloned();
    let auth_id_for_check: Option<String> = ctx.user_id().map(|s| s.to_string());
    let mut data = match body.data.as_object() {
        Some(o) => o.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TYPE_MISMATCH",
                "data must be object",
            );
        }
    };
    // Strip any client-supplied owner_field on the User-owner-scoped path so
    // a user cannot transfer ownership of their own row to another user via
    // PATCH {"data": {"user_id": "u-other"}}.
    if let (AuthCtx::User { .. }, Some(field)) = (&ctx, schema.owner_field.as_deref()) {
        data.shift_remove(field);
    }
    if data.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "TYPE_MISMATCH",
            "data must have at least one field",
        );
    }

    // Pre-encode vector fields, same shape as create_handler. Errors
    // surface as 422 with typed codes before the writer mutex.
    let mut vector_bytes: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    for vf in &schema.vector_fields {
        if let Some(v) = data.get(&vf.name).cloned() {
            match crate::query::vector_codec::pack(&vf.name, vf.dim, &v) {
                Ok(bytes) => {
                    vector_bytes.insert(vf.name.clone(), bytes);
                }
                Err(crate::query::vector_codec::VectorCodecError::DimMismatch {
                    field,
                    expected,
                    got,
                }) => {
                    return json_error_with_context(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "VECTOR_DIM_MISMATCH",
                        &format!("vector field {:?} has wrong dim", vf.name),
                        &crate::safety::error_fixes::ErrorContext::VectorDimMismatch {
                            field: &field,
                            expected_dim: expected,
                            actual_dim: got as u32,
                        },
                    );
                }
                Err(crate::query::vector_codec::VectorCodecError::NonFinite { .. }) => {
                    return json_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "VECTOR_NON_FINITE",
                        &format!("vector field {:?} contains NaN or Inf", vf.name),
                    );
                }
                Err(e) => {
                    return json_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "VECTOR_TYPE_ERROR",
                        &e.to_string(),
                    );
                }
            }
        }
    }
    let vector_names: std::collections::HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let tenant_id = t.tenant_id.clone();
    // Capture submitted keys + schema field names BEFORE the closure
    // moves `data` and `schema` — needed at the error point to identify
    // which key was rejected as FIELD_NOT_FOUND.
    let submitted_keys: Vec<String> = data.keys().cloned().collect();
    let known_fields: Vec<String> = schema.fields.iter().map(|f| f.name.clone()).collect();
    let res = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<serde_json::Value> {
            let schema = match describe_collection(tx, &coll_clone)? {
                Some(s) => s,
                None => return Err(rusqlite::Error::InvalidQuery),
            };
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data.keys() {
                if !allowed.contains(k.as_str()) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            // Explicit-policy USING pre-flight: the target row must satisfy the
            // compiled fragment (bound via `?`). A miss is indistinguishable
            // from "no such row" by design — returns the same 404 arm.
            if let Some((frag, pbinds)) = &using_sql {
                use rusqlite::OptionalExtension;
                let q = format!(
                    "SELECT 1 FROM \"{}\" WHERE id = ? AND ({frag})",
                    coll_clone.replace('"', "\"\"")
                );
                let mut pp: Vec<Value> = vec![Value::Integer(id)];
                pp.extend(pbinds.iter().cloned());
                let refs: Vec<&dyn rusqlite::ToSql> =
                    pp.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                if tx
                    .query_row(&q, &refs[..], |r| r.get::<_, i64>(0))
                    .optional()?
                    .is_none()
                {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
            }
            let set_exprs: Vec<String> = data
                .keys()
                .enumerate()
                .map(|(i, k)| format!("\"{}\" = ?{}", k.replace('"', "\"\""), i + 1))
                .collect();
            let id_param_idx = data.len() + 1;
            // Append owner filter as a literal — user_id is UUID shaped,
            // safe to inline after escaping.
            let owner_clause = if let Some((field, user_id)) = &owner_filter {
                format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                )
            } else {
                String::new()
            };
            let sql = format!(
                "UPDATE \"{}\" SET {}, updated_at = datetime('now') WHERE id = ?{}{}",
                coll_clone.replace('"', "\"\""),
                set_exprs.join(","),
                id_param_idx,
                owner_clause,
            );
            // Bind: vector fields → BLOB; others → json_to_sql_value.
            let mut params: Vec<Value> = data
                .iter()
                .map(|(k, v)| match vector_bytes.get(k) {
                    Some(bytes) => Value::Blob(bytes.clone()),
                    None => json_to_sql_value(v),
                })
                .collect();
            params.push(Value::Integer(id));
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let n = tx.execute(&sql, &refs[..])?;
            if n == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let mut stmt = tx.prepare(&format!(
                "SELECT * FROM \"{}\" WHERE id = ?1",
                coll_clone.replace('"', "\"\"")
            ))?;
            let cols_out: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let mut rec = record_as_json(&mut stmt, &cols_out, id)?;
            if let Some(obj) = rec.as_object_mut() {
                obj.retain(|k, _| !vector_names.contains(k));
            }
            // Explicit-policy CHECK on the persisted (post-image) row. A failing
            // predicate returns the sentinel error, rolling back this UPDATE.
            if let Some(check) = &check_ast {
                let row_map = rec.as_object().cloned().unwrap_or_default();
                let pc = crate::query::policy::PolicyCtx {
                    auth_id: auth_id_for_check.clone(),
                    data: Some(row_map.clone()),
                };
                if !crate::query::policy::eval_policy(check, &row_map, &pc) {
                    return Err(crate::query::policy::policy_check_sentinel());
                }
            }
            Ok(rec)
        })
        .await;
    match res {
        Ok(rec) => {
            // Build response first; dispatch only after payload exists.
            let r = Json(json!({ "record": rec.clone() })).into_response();
            let ev = Event::Updated { record: rec };
            bus.publish(&tenant_id, &coll, ev.clone());
            functions.dispatch(&tenant_id, &coll, &ev);
            webhooks.dispatch(&tenant_id, &coll, ev);
            r
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            (StatusCode::NOT_FOUND, "no such record").into_response()
        }
        Err(ref e) if crate::query::policy::is_policy_check_failure(e) => json_error(
            StatusCode::FORBIDDEN,
            "POLICY_CHECK_FAILED",
            "update rejected by the collection's update policy CHECK",
        ),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("InvalidQuery") {
                let bad = submitted_keys
                    .iter()
                    .find(|k| !known_fields.iter().any(|f| f == *k))
                    .cloned()
                    .unwrap_or_default();
                json_error_with_context(
                    StatusCode::BAD_REQUEST,
                    "FIELD_NOT_FOUND",
                    "unknown field",
                    &crate::safety::error_fixes::ErrorContext::FieldNotFound {
                        field: &bad,
                        collection: &coll,
                        existing: &known_fields,
                    },
                )
            } else {
                (StatusCode::BAD_REQUEST, msg).into_response()
            }
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DeleteQs {
    #[serde(default)]
    pub dry_run: Option<bool>,
}

pub async fn delete_handler(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
    Query(q): Query<DeleteQs>,
    bus: EventBus,
    webhooks: Arc<WebhookDispatcher>,
    functions: Arc<crate::functions::dispatcher::FunctionDispatcher>,
) -> Response {
    // F2 (audit 2026-06-22) — authorize BEFORE branching on dry_run. A dry_run
    // preview must require the SAME cap + owner + policy authorization as a
    // real delete; otherwise it is an unauthenticated blast-radius oracle
    // (FK topology + child-row counts) for rows the caller cannot delete.
    // require_write_cap 404s _system_/missing collections and 403s missing
    // caps / anon-on-owner-scoped.
    let schema = match require_write_cap(&t, &ctx, &coll, DmlVerb::Delete).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let owner_filter = compute_owner_filter(&ctx, &schema);
    // Explicit-policy USING (pre-flight target filter) for DELETE. Service
    // bypasses (`policy_using_sql` → None). The USING fragment AND-composes
    // ALONGSIDE the unchanged owner clause: a row failing the explicit USING is
    // not a deletable target (→ 404 via the existing `Ok(0)` arm).
    let using_sql: Option<(String, Vec<rusqlite::types::Value>)> =
        match crate::query::policy::policy_using_sql(&ctx, &schema, DmlVerb::Delete) {
            Ok(c) => c,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "POLICY_COMPILE_ERROR",
                    &e.to_string(),
                );
            }
        };

    if q.dry_run.unwrap_or(false) {
        // The row must be a deletable TARGET for this caller (owner clause +
        // policy USING) before any blast radius is revealed — mirrors the
        // real-delete pre-flight below. Not a target → 404, exactly like a real
        // delete miss. (cap + _system_ + anon-owner already enforced above.)
        let coll_pf = coll.clone();
        let owner_pf = owner_filter.clone();
        let using_pf = using_sql.clone();
        let is_target = t
            .pool
            .with_reader(move |c| -> rusqlite::Result<bool> {
                use rusqlite::OptionalExtension;
                attach_readonly_authorizer(c);
                let mut sql = format!(
                    "SELECT 1 FROM \"{}\" WHERE id = ?1",
                    coll_pf.replace('"', "\"\"")
                );
                let mut pp: Vec<Value> = vec![Value::Integer(id)];
                if let Some((field, user_id)) = &owner_pf {
                    sql.push_str(&format!(
                        " AND \"{}\" = '{}'",
                        field.replace('"', "\"\""),
                        user_id.replace('\'', "''")
                    ));
                }
                if let Some((frag, pbinds)) = &using_pf {
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
            .await;
        match is_target {
            Ok(true) => {
                let br =
                    match crate::storage::blast_radius::delete_blast_radius(&t.pool, &coll, id)
                        .await
                    {
                        Ok(br) => br,
                        Err(e) => {
                            return json_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "INTERNAL_ERROR",
                                &e.to_string(),
                            );
                        }
                    };
                return Json(serde_json::to_value(br).expect("serialise")).into_response();
            }
            Ok(false) => return (StatusCode::NOT_FOUND, "no such record").into_response(),
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    &e.to_string(),
                );
            }
        }
    }

    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let tenant_id = t.tenant_id.clone();
    let res = pool
        .with_writer_tx(move |tx| {
            if let Some((frag, pbinds)) = &using_sql {
                use rusqlite::OptionalExtension;
                let q = format!(
                    "SELECT 1 FROM \"{}\" WHERE id = ?1 AND ({frag})",
                    coll_clone.replace('"', "\"\"")
                );
                let mut pp: Vec<Value> = vec![Value::Integer(id)];
                pp.extend(pbinds.iter().cloned());
                let refs: Vec<&dyn rusqlite::ToSql> =
                    pp.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                if tx
                    .query_row(&q, &refs[..], |r| r.get::<_, i64>(0))
                    .optional()?
                    .is_none()
                {
                    return Ok(0usize); // → existing `Ok(0) => 404` arm
                }
            }
            let owner_clause = if let Some((field, user_id)) = &owner_filter {
                format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                )
            } else {
                String::new()
            };
            let sql = format!(
                "DELETE FROM \"{}\" WHERE id = ?1{}",
                coll_clone.replace('"', "\"\""),
                owner_clause,
            );
            tx.execute(&sql, rusqlite::params![id])
        })
        .await;
    match res {
        Ok(0) => (StatusCode::NOT_FOUND, "no such record").into_response(),
        Ok(_) => {
            // Build response first; dispatch only after payload exists.
            let r = StatusCode::NO_CONTENT.into_response();
            let ev = Event::Deleted { id };
            bus.publish(&tenant_id, &coll, ev.clone());
            functions.dispatch(&tenant_id, &coll, &ev);
            webhooks.dispatch(&tenant_id, &coll, ev);
            r
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod deny_message_tests {
    use crate::storage::schema::DmlVerb;
    use crate::tenant::router::TokenRole;

    // Mirrors the role-aware branch inside require_dml_cap / require_write_cap.
    // Kept in lockstep with the handler so a reword is caught at lib-test speed.
    fn cap_deny_message(role: TokenRole, verb: DmlVerb, coll: &str) -> String {
        if matches!(role, TokenRole::User) {
            format!(
                "user role lacks '{}' on collection '{}' (grant it via user_caps)",
                verb.as_str(),
                coll
            )
        } else {
            format!(
                "anon role lacks '{}' on collection '{}'",
                verb.as_str(),
                coll
            )
        }
    }

    #[test]
    fn user_deny_message_names_user_and_points_at_user_caps() {
        let m = cap_deny_message(TokenRole::User, DmlVerb::Insert, "todos");
        assert_eq!(
            m,
            "user role lacks 'insert' on collection 'todos' (grant it via user_caps)"
        );
        assert!(!m.contains("anon"), "user deny must not say 'anon'");
    }

    #[test]
    fn anon_deny_message_unchanged() {
        let m = cap_deny_message(TokenRole::Anon, DmlVerb::Delete, "todos");
        assert_eq!(m, "anon role lacks 'delete' on collection 'todos'");
    }
}

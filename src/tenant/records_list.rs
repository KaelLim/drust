//! `POST /t/<id>/collections/<c>/list` — structured list endpoint.
//!
//! Mirrors the [`vector_search::search_handler`] shape: caller posts a
//! JSON body, drust compiles SQL itself from a `FilterAst` + sort + page
//! + select, runs it under the read-only authorizer with `?`-bound
//! parameters. owner_field enforcement is by construction — user tokens
//! get an auto-appended `"<field>" = ?` clause and the corresponding
//! bind, with no path for user input to skip it.
//!
//! See spec: `docs/superpowers/specs/2026-05-22-drust-v121-design.md` §2.

use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::query::authorizer::{attach_search_readonly_authorizer, detach_authorizer};
use crate::query::list_builder::{
    AggregateRequest, ListError, ListRequest, build_aggregate_sql, build_structured_list_sql,
};
use crate::query::vector_filter::FilterError;
use crate::storage::schema::{CollectionSchema, DmlVerb, is_protected_collection};
use crate::tenant::router::{TenantRef, TokenRole};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::types::{Value, ValueRef};
use serde_json::json;

/// Shared read-authorization for `/list` and `/aggregate`. Given the caller and
/// the collection schema, returns `(owner_pair, policy_clause)` — the owner
/// row-filter clause (when one applies) and the explicit-policy USING clause —
/// making the SAME cap/owner/policy decision for both faces so their row
/// authorization is in lockstep by construction. Returns `Err(Response)` on a
/// typed deny (403) or a policy compile error (500).
///
/// LOCKSTEP: the User cap checks consult `user_caps` (NOT `anon_caps`),
/// mirroring the User arm of `crate::storage::schema::has_dml_cap`. The
/// `read_scope="all"` branch deliberately keeps its own select-cap requirement
/// despite `owner_field` (it does NOT use has_dml_cap's owner short-circuit) —
/// see spec §5.3. Any change to the cap source MUST be made in BOTH places.
///
/// Does NOT run the ctx/role sanity `debug_assert` — that stays in the callers
/// where `TenantRef::role` is in scope (see [`debug_assert_ctx_role`]).
pub(crate) fn compute_read_auth(
    ctx: &AuthCtx,
    schema: &CollectionSchema,
    coll: &str,
) -> Result<(Option<(String, String)>, Option<(String, Vec<Value>)>), Response> {
    let owner_pair: Option<(String, String)> = match (
        ctx,
        schema.owner_field.as_deref(),
        schema.read_scope.as_deref(),
    ) {
        // Service — bypass everything.
        (AuthCtx::Service { .. }, _, _) => None,

        // Anon on owner-scoped → typed deny.
        (AuthCtx::Anon, Some(_), _) => {
            return Err(json_error(
                StatusCode::FORBIDDEN,
                "ANON_FORBIDDEN_OWNER_SCOPED",
                "anon cannot read owner-scoped collection — register a user",
            ));
        }
        // Anon on non-owner-scoped → needs select cap.
        (AuthCtx::Anon, None, _) => {
            if !schema.anon_caps.contains(&DmlVerb::Select) {
                return Err(json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_CAP_DENIED",
                    &format!("anon role lacks 'select' on collection '{coll}'"),
                ));
            }
            None
        }
        // User on owner-scoped + read_scope=own → auto-append owner clause.
        (AuthCtx::User { user_id, .. }, Some(field), Some("own")) => {
            Some((field.to_string(), user_id.clone()))
        }
        // User on owner-scoped + read_scope=all → no row filter, but still gate
        // via user_caps (no escalation; keeps parity with /search). This branch
        // keeps its own cap check despite owner_field — see the LOCKSTEP note.
        (AuthCtx::User { .. }, Some(_), Some(_)) => {
            if !schema.user_caps.contains(&DmlVerb::Select) {
                return Err(json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_CAP_DENIED",
                    &format!(
                        "user role lacks 'select' on collection '{coll}' (grant it via user_caps)"
                    ),
                ));
            }
            None
        }
        // User on non-owner-scoped → gate via user_caps (no escalation).
        (AuthCtx::User { .. }, _, _) => {
            if !schema.user_caps.contains(&DmlVerb::Select) {
                return Err(json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_CAP_DENIED",
                    &format!(
                        "user role lacks 'select' on collection '{coll}' (grant it via user_caps)"
                    ),
                ));
            }
            None
        }
    };

    // Explicit-policy USING (AND-ed alongside the owner clause). Service → None
    // (bypass). A compile error → 500 with a typed code.
    let policy_clause = match crate::query::policy::policy_using_sql(ctx, schema, DmlVerb::Select) {
        Ok(c) => c,
        Err(e) => {
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "POLICY_COMPILE_ERROR",
                &e.to_string(),
            ));
        }
    };

    Ok((owner_pair, policy_clause))
}

/// Debug sanity check that the `AuthCtx` and `TokenRole` extensions stayed in
/// sync (set together in `bearer_auth_layer`). A future refactor that splits
/// them surfaces here during tests. No-op in release builds.
#[inline]
fn debug_assert_ctx_role(ctx: &AuthCtx, role: TokenRole) {
    debug_assert!(
        matches!(
            (ctx, role),
            (AuthCtx::Anon, TokenRole::Anon)
                | (AuthCtx::Service { .. }, TokenRole::Service)
                | (AuthCtx::User { .. }, TokenRole::User)
        ),
        "AuthCtx/TokenRole mismatch (ctx={ctx:?} role={role:?})",
    );
}

/// `POST /t/<id>/collections/<c>/list`
pub async fn post_list(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(req): Json<ListRequest>,
) -> Response {
    if is_protected_collection(&coll) {
        return json_error(
            StatusCode::NOT_FOUND,
            "COLLECTION_NOT_FOUND",
            &format!("no such collection: {coll}"),
        );
    }
    let pool = t.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.clone();
    let schema = match pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "COLLECTION_NOT_FOUND",
                &format!("no such collection: {coll}"),
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    // Row-authorization (owner clause + explicit-policy USING), computed by the
    // shared `compute_read_auth` so `/list` and `/aggregate` stay in lockstep by
    // construction. The full cap/owner/policy matrix (incl. the read_scope="all"
    // note) lives there.
    let (owner_pair, policy_clause) = match compute_read_auth(&ctx, &schema, &coll) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    debug_assert_ctx_role(&ctx, t.role);

    // ── Compile SQL ──────────────────────────────────────────────────
    let owner_ref = owner_pair.as_ref().map(|(f, v)| (f.as_str(), v.as_str()));
    let (list_sql, count_sql, binds) =
        match build_structured_list_sql(&schema, &req, owner_ref, policy_clause) {
            Ok(x) => x,
            Err(e) => return map_list_error(e),
        };

    // Vector field names — server-side default-hide on the response
    // (matches GET /records behaviour). For `/list`, we already excluded
    // them in the projection, but a caller-supplied `select` that's
    // empty after vector-filter falls back to `id`, so this is a no-op.
    let vector_names: std::collections::HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    // ── Execute list ─────────────────────────────────────────────────
    let pool_list = t.pool.clone();
    let list_sql_owned = list_sql.clone();
    let binds_for_list = binds.clone();
    let records_res: rusqlite::Result<(Vec<String>, Vec<serde_json::Value>)> = pool_list
        .with_reader(move |c| {
            attach_search_readonly_authorizer(c);
            let r = run_bound_select(c, &list_sql_owned, &binds_for_list);
            detach_authorizer(c);
            r
        })
        .await;
    let (col_names, rows) = match records_res {
        Ok(v) => v,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    // Default-hide vector columns from the row objects too (defense in
    // depth; projection already excludes them).
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
    let _ = col_names; // column names are encoded into the row objects.

    // ── Execute count ─────────────────────────────────────────────────
    let pool_count = t.pool.clone();
    let count_sql_owned = count_sql.clone();
    let binds_for_count = binds.clone();
    let count_res: rusqlite::Result<i64> = pool_count
        .with_reader(move |c| -> rusqlite::Result<i64> {
            attach_search_readonly_authorizer(c);
            let r = (|| -> rusqlite::Result<i64> {
                let mut stmt = c.prepare_cached(&count_sql_owned)?;
                let refs: Vec<&dyn rusqlite::ToSql> = binds_for_count
                    .iter()
                    .map(|v| v as &dyn rusqlite::ToSql)
                    .collect();
                stmt.query_row(rusqlite::params_from_iter(refs), |r| r.get(0))
            })();
            detach_authorizer(c);
            r
        })
        .await;
    let total: i64 = match count_res {
        Ok(n) => n,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    let per_page = req.per_page.unwrap_or(20);
    let page = req.page.unwrap_or(1);
    Json(json!({
        "records": records_out,
        "total": total,
        "page": page,
        "perPage": per_page,
    }))
    .into_response()
}

/// `POST /t/<id>/collections/<c>/aggregate` (M1)
///
/// Aggregate metrics (count/sum/avg/min/max) with an optional `group_by`, under
/// the SAME row-authorization as `/list`: the shared [`compute_read_auth`] plus
/// `build_aggregate_sql`'s reuse of `build_where_clause` guarantee a User only
/// aggregates rows they may read and anon obeys `anon_caps`/policy by
/// construction. Read-only connection + read-only authorizer; service bypasses.
pub async fn post_aggregate(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(req): Json<AggregateRequest>,
) -> Response {
    if is_protected_collection(&coll) {
        return json_error(
            StatusCode::NOT_FOUND,
            "COLLECTION_NOT_FOUND",
            &format!("no such collection: {coll}"),
        );
    }
    let pool = t.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.clone();
    let schema = match pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "COLLECTION_NOT_FOUND",
                &format!("no such collection: {coll}"),
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    // Same owner/policy authorization as /list — in lockstep by construction.
    let (owner_pair, policy_clause) = match compute_read_auth(&ctx, &schema, &coll) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    debug_assert_ctx_role(&ctx, t.role);

    let owner_ref = owner_pair.as_ref().map(|(f, v)| (f.as_str(), v.as_str()));
    let (sql, binds) = match build_aggregate_sql(&schema, &req, owner_ref, policy_clause) {
        Ok(x) => x,
        Err(e) => return map_list_error(e),
    };

    let pool_run = t.pool.clone();
    let sql_owned = sql.clone();
    let binds_owned = binds.clone();
    let rows_res: rusqlite::Result<(Vec<String>, Vec<serde_json::Value>)> = pool_run
        .with_reader(move |c| {
            attach_search_readonly_authorizer(c);
            let r = run_bound_select(c, &sql_owned, &binds_owned);
            detach_authorizer(c);
            r
        })
        .await;
    let (_col_names, rows) = match rows_res {
        Ok(v) => v,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    let per_page = req.per_page.unwrap_or(20);
    let page = req.page.unwrap_or(1);
    Json(json!({
        "rows": rows,
        "page": page,
        "perPage": per_page,
    }))
    .into_response()
}

/// `POST /t/<id>/collections/<c>/list/explain`
///
/// Service-only. Returns `{"plan": ["...","..."]}` derived from
/// `EXPLAIN QUERY PLAN <list_sql>`. Anon/user → 403 `EXPLAIN_REQUIRES_SERVICE`.
pub async fn post_list_explain(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(req): Json<ListRequest>,
) -> Response {
    if !matches!(ctx, AuthCtx::Service { .. }) {
        return json_error(
            StatusCode::FORBIDDEN,
            "EXPLAIN_REQUIRES_SERVICE",
            "explain requires the service token",
        );
    }
    if is_protected_collection(&coll) {
        return json_error(
            StatusCode::NOT_FOUND,
            "COLLECTION_NOT_FOUND",
            &format!("no such collection: {coll}"),
        );
    }
    let pool = t.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.clone();
    let schema = match pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "COLLECTION_NOT_FOUND",
                &format!("no such collection: {coll}"),
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    let (list_sql, _count, binds) = match build_structured_list_sql(&schema, &req, None, None) {
        Ok(x) => x,
        Err(e) => return map_list_error(e),
    };

    let plan_sql = format!("EXPLAIN QUERY PLAN {list_sql}");
    let plan: Vec<String> = pool
        .with_reader(move |c| -> rusqlite::Result<Vec<String>> {
            attach_search_readonly_authorizer(c);
            let r = (|| -> rusqlite::Result<Vec<String>> {
                let mut stmt = c.prepare(&plan_sql)?;
                let refs: Vec<&dyn rusqlite::ToSql> =
                    binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                let rows =
                    stmt.query_map(rusqlite::params_from_iter(refs), |r| r.get::<_, String>(3))?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row?);
                }
                Ok(out)
            })();
            detach_authorizer(c);
            r
        })
        .await
        .unwrap_or_default();

    Json(json!({ "plan": plan })).into_response()
}

/// Map a `ListError` to an HTTP response per spec §3.
fn map_list_error(e: ListError) -> Response {
    match e {
        ListError::Filter(FilterError::Parse(msg)) => {
            json_error(StatusCode::BAD_REQUEST, "FILTER_PARSE_ERROR", &msg)
        }
        ListError::Filter(FilterError::UnknownField(f)) => json_error(
            StatusCode::BAD_REQUEST,
            "FILTER_UNKNOWN_FIELD",
            &format!("unknown field in filter: {f:?}"),
        ),
        ListError::Filter(FilterError::VectorField(f)) => json_error(
            StatusCode::BAD_REQUEST,
            "FILTER_VECTOR_FIELD",
            &format!("filter cannot target vector field: {f:?}"),
        ),
        ListError::Filter(FilterError::TooDeep) => json_error(
            StatusCode::BAD_REQUEST,
            "FILTER_TOO_DEEP",
            "filter nesting exceeds max depth",
        ),
        ListError::Filter(FilterError::Fts { code, message }) => {
            json_error(StatusCode::BAD_REQUEST, code, &message)
        }
        ListError::Filter(other) => json_error(
            StatusCode::BAD_REQUEST,
            "FILTER_PARSE_ERROR",
            &other.to_string(),
        ),
        ListError::SortFieldUnknown(f) => json_error(
            StatusCode::BAD_REQUEST,
            "SORT_FIELD_UNKNOWN",
            &format!("unknown sort field: {f:?}"),
        ),
        ListError::SortVectorField(f) => json_error(
            StatusCode::BAD_REQUEST,
            "SORT_VECTOR_FIELD",
            &format!("sort field is a vector column: {f:?}"),
        ),
        ListError::SortDirInvalid => json_error(
            StatusCode::BAD_REQUEST,
            "SORT_DIR_INVALID",
            "sort.dir must be 'asc' or 'desc'",
        ),
        ListError::SelectFieldUnknown(f) => json_error(
            StatusCode::BAD_REQUEST,
            "SELECT_FIELD_UNKNOWN",
            &format!("unknown select field: {f:?}"),
        ),
        ListError::PageRangeInvalid => json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PAGE_RANGE_INVALID",
            "per_page must be 1..=500 and page must be >= 1",
        ),
        // ── aggregate (M1) — all client input errors → 400 ──
        ListError::NoMetrics => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_NO_METRICS",
            "aggregate needs at least one metric",
        ),
        ListError::MetricOpInvalid(op) => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_OP_INVALID",
            &format!("aggregate op must be count|sum|avg|min|max: {op:?}"),
        ),
        ListError::MetricFieldRequired(op) => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_FIELD_REQUIRED",
            &format!("aggregate op {op:?} requires a field"),
        ),
        ListError::MetricFieldUnknown(f) => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_FIELD_UNKNOWN",
            &format!("unknown aggregate field: {f:?}"),
        ),
        ListError::MetricVectorField(f) => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_FIELD_VECTOR",
            &format!("aggregate field is a vector column: {f:?}"),
        ),
        ListError::GroupFieldUnknown(f) => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_GROUP_UNKNOWN",
            &format!("unknown group_by field: {f:?}"),
        ),
        ListError::GroupVectorField(f) => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_GROUP_VECTOR",
            &format!("group_by field is a vector column: {f:?}"),
        ),
        ListError::AliasInvalid(a) => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_ALIAS_INVALID",
            &format!("aggregate alias must be an identifier: {a:?}"),
        ),
        ListError::AliasDuplicate(a) => json_error(
            StatusCode::BAD_REQUEST,
            "AGG_ALIAS_DUPLICATE",
            &format!("aggregate output column name is duplicated: {a:?}"),
        ),
    }
}

/// Run `sql` with `?`-bound `binds` and materialise each row as a JSON
/// object keyed by column name. The caller is responsible for attaching
/// the read-only authorizer beforehand and detaching after.
fn run_bound_select(
    conn: &rusqlite::Connection,
    sql: &str,
    binds: &[Value],
) -> rusqlite::Result<(Vec<String>, Vec<serde_json::Value>)> {
    // prepare_cached: the structured /list SQL is stable per (collection, shape)
    // and re-issued on every page fetch, so the per-connection statement cache
    // hits. No correctness change — same SQL, same `?` binds.
    let mut stmt = conn.prepare_cached(sql)?;
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
                    ValueRef::Integer(n) => json!(n),
                    ValueRef::Real(f) => json!(f),
                    ValueRef::Text(t) => {
                        serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
                    }
                    ValueRef::Blob(b) => json!({ "__blob_bytes": b.len() }),
                },
            );
        }
        out.push(serde_json::Value::Object(obj));
    }
    Ok((col_names, out))
}

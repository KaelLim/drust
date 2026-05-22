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
use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::list_builder::{
    ListError, ListRequest, build_structured_list_sql,
};
use crate::query::vector_filter::FilterError;
use crate::storage::schema::{DmlVerb, is_protected_collection};
use crate::tenant::router::{TenantRef, TokenRole};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::types::{Value, ValueRef};
use serde_json::json;

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

    // ── Auth matrix per spec §2.2 ────────────────────────────────────
    let owner_pair: Option<(String, String)> = match (
        &ctx,
        schema.owner_field.as_deref(),
        schema.read_scope.as_deref(),
    ) {
        // Service — bypass everything.
        (AuthCtx::Service, _, _) => None,

        // Anon on owner-scoped → typed deny.
        (AuthCtx::Anon, Some(_), _) => {
            return json_error(
                StatusCode::FORBIDDEN,
                "OWNER_SCOPED_ANON_DENIED",
                "anon cannot read owner-scoped collection — register a user",
            );
        }
        // Anon on non-owner-scoped → needs select cap.
        (AuthCtx::Anon, None, _) => {
            if !schema.anon_caps.contains(&DmlVerb::Select) {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_CAP_DENIED",
                    &format!(
                        "anon role lacks 'select' on collection '{coll}'"
                    ),
                );
            }
            None
        }
        // User on owner-scoped + read_scope=own → auto-append owner clause.
        (
            AuthCtx::User { user_id, .. },
            Some(field),
            Some("own"),
        ) => Some((field.to_string(), user_id.clone())),

        // User on owner-scoped + read_scope=all → no row filter but caller
        // is owner-scope-aware. Treat as non-owner-scoped for caps (no
        // escalation): fall through to anon_caps check.
        (AuthCtx::User { .. }, Some(_), Some(_)) => {
            // read_scope = "all" — owner-scope is informational; the user
            // sees everyone's rows. Still gate via anon_caps to keep parity
            // with /search.
            if !schema.anon_caps.contains(&DmlVerb::Select) {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_CAP_DENIED",
                    &format!(
                        "user role inherits anon caps; 'select' not allowed on '{coll}'"
                    ),
                );
            }
            None
        }
        // User on non-owner-scoped → fall through to anon_caps (no escalation).
        (AuthCtx::User { .. }, _, _) => {
            if !schema.anon_caps.contains(&DmlVerb::Select) {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_CAP_DENIED",
                    &format!(
                        "user role inherits anon caps; 'select' not allowed on '{coll}'"
                    ),
                );
            }
            None
        }
    };

    // Use TokenRole as a sanity check that the AuthCtx wiring stayed
    // in sync with the bearer_auth_layer extension setup. If a future
    // refactor splits them, this debug_assert surfaces during tests.
    debug_assert!(
        match (&ctx, t.role) {
            (AuthCtx::Anon, TokenRole::Anon)
            | (AuthCtx::Service, TokenRole::Service)
            | (AuthCtx::User { .. }, TokenRole::User) => true,
            _ => false,
        },
        "AuthCtx/TokenRole mismatch (ctx={:?} role={:?})",
        ctx,
        t.role,
    );

    // ── Compile SQL ──────────────────────────────────────────────────
    let owner_ref = owner_pair.as_ref().map(|(f, v)| (f.as_str(), v.as_str()));
    let (list_sql, count_sql, binds) =
        match build_structured_list_sql(&schema, &req, owner_ref) {
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
            attach_readonly_authorizer(c);
            let r = run_bound_select(c, &list_sql_owned, &binds_for_list);
            detach_authorizer(c);
            r
        })
        .await;
    let (col_names, rows) = match records_res {
        Ok(v) => v,
        Err(_e) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "QUERY_FORBIDDEN",
                "list rejected",
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
    let total: i64 = pool_count
        .with_reader(move |c| -> rusqlite::Result<i64> {
            attach_readonly_authorizer(c);
            let r = (|| -> rusqlite::Result<i64> {
                let mut stmt = c.prepare(&count_sql_owned)?;
                let refs: Vec<&dyn rusqlite::ToSql> = binds_for_count
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
    Json(json!({
        "records": records_out,
        "total": total,
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
    if !matches!(ctx, AuthCtx::Service) {
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

    let (list_sql, _count, binds) =
        match build_structured_list_sql(&schema, &req, None) {
            Ok(x) => x,
            Err(e) => return map_list_error(e),
        };

    let plan_sql = format!("EXPLAIN QUERY PLAN {list_sql}");
    let plan: Vec<String> = pool
        .with_reader(move |c| -> rusqlite::Result<Vec<String>> {
            attach_readonly_authorizer(c);
            let r = (|| -> rusqlite::Result<Vec<String>> {
                let mut stmt = c.prepare(&plan_sql)?;
                let refs: Vec<&dyn rusqlite::ToSql> = binds
                    .iter()
                    .map(|v| v as &dyn rusqlite::ToSql)
                    .collect();
                let rows = stmt.query_map(
                    rusqlite::params_from_iter(refs),
                    |r| r.get::<_, String>(3),
                )?;
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
        ListError::Filter(FilterError::Parse(msg)) => json_error(
            StatusCode::BAD_REQUEST,
            "FILTER_PARSE_ERROR",
            &msg,
        ),
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
    let mut stmt = conn.prepare(sql)?;
    let col_names: Vec<String> =
        stmt.column_names().iter().map(|s| s.to_string()).collect();
    let refs: Vec<&dyn rusqlite::ToSql> =
        binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
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
                    ValueRef::Text(t) => serde_json::Value::String(
                        String::from_utf8_lossy(t).into_owned(),
                    ),
                    ValueRef::Blob(b) => json!({ "__blob_bytes": b.len() }),
                },
            );
        }
        out.push(serde_json::Value::Object(obj));
    }
    Ok((col_names, out))
}

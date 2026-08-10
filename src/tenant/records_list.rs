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
use crate::query::vector_filter::{FilterAst, FilterError};
use crate::storage::schema::{CollectionSchema, DmlVerb, is_protected_collection};
use crate::tenant::router::{TenantRef, TokenRole};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::types::{Value, ValueRef};
use serde_json::json;

/// Which cap regime [`compute_read_auth_inner`] applies.
///
/// **Module-private on purpose, and it must stay that way.** A public
/// escalating value is the v1.57 defect shape: an outside caller that picks the
/// wrong variant silently grants itself more than it should. The only way to
/// reach [`CapMode::RpcGrant`] from elsewhere in the crate is the dedicated
/// `*_rpc_grant` wrapper, which names its intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapMode {
    /// The collection's own `anon_caps` / `user_caps` gate the read. Every
    /// pre-existing caller (`/list`, `/aggregate`) is in this mode and its
    /// behaviour is unchanged.
    Collection,
    /// The caller reached this read through a stored `kind='query'` RPC whose
    /// `anon_callable` flag is the grant (#950). A cap check is skipped ONLY
    /// where an independent row gate (owner clause, RLS policy, or the RPC's own
    /// fixed template) protects the rows; where the cap IS the row gate it is
    /// kept — see the per-arm table in the spec's §授權語意.
    RpcGrant,
}

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
    compute_read_auth_inner(CapMode::Collection, ctx, schema, coll)
}

/// The RPC-as-grant cap regime (#950) has **no wrapper of its own here on
/// purpose**: [`run_structured_list_rpc_grant`] is the single door to
/// [`CapMode::RpcGrant`]. A bare `compute_read_auth_rpc_grant` would be a
/// cap-relaxing entry point reachable WITHOUT the rest of the pipeline the
/// relaxation assumes (the protected-collection gate, the FTS probe, the query
/// deadline) — the same "an outside caller can pick the wrong value" shape
/// [`CapMode`] is private to avoid. The lib tests below drive
/// `compute_read_auth_inner` directly, so both regimes stay pinned per arm.
fn compute_read_auth_inner(
    cap: CapMode,
    ctx: &AuthCtx,
    schema: &CollectionSchema,
    coll: &str,
) -> Result<(Option<(String, String)>, Option<(String, Vec<Value>)>), Response> {
    let rpc_grant = matches!(cap, CapMode::RpcGrant);
    let owner_pair: Option<(String, String)> = match (
        ctx,
        schema.owner_field.as_deref(),
        schema.read_scope.as_deref(),
    ) {
        // Service — bypass everything.
        (AuthCtx::Service { .. }, _, _) => None,

        // Anon on owner-scoped → typed deny. NEVER relaxed by RpcGrant: there
        // is no row gate for an anon caller on an owner-scoped collection (a
        // policy-only anon arm is a later phase, not this one).
        (AuthCtx::Anon, Some(_), _) => {
            return Err(json_error(
                StatusCode::FORBIDDEN,
                "ANON_FORBIDDEN_OWNER_SCOPED",
                "anon cannot read owner-scoped collection — register a user",
            ));
        }
        // Anon on non-owner-scoped → needs select cap. Under RpcGrant the cap
        // is a blanket door the RPC's own `anon_callable` grant replaces; the
        // policy clause below still applies.
        (AuthCtx::Anon, None, _) => {
            if !rpc_grant && !schema.anon_caps.contains(&DmlVerb::Select) {
                return Err(json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_CAP_DENIED",
                    &format!("anon role lacks 'select' on collection '{coll}'"),
                ));
            }
            None
        }
        // User on owner-scoped + read_scope=own → auto-append owner clause.
        // No cap check in either mode: the owner clause IS the row gate.
        (AuthCtx::User { user_id, .. }, Some(field), Some("own")) => {
            Some((field.to_string(), user_id.clone()))
        }
        // User on owner-scoped + read_scope=all → no row filter, but still gate
        // via user_caps (no escalation; keeps parity with /search). This branch
        // keeps its own cap check despite owner_field — see the LOCKSTEP note.
        // RpcGrant deliberately does NOT skip it: with no row filter the cap is
        // the row gate, so skipping it would hand any user token the whole
        // table (audit3 F1; `tests/audit3_readscope_all_caps.rs`).
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
        // Catch-all for the User role: either owner_field=None (non-owner-scoped
        // — blanket cap, skipped under RpcGrant), or the legacy owner_field=Some
        // with a NULL read_scope, which is ALSO unfiltered and therefore keeps
        // its cap in both modes for the same reason as the "all" arm above.
        (AuthCtx::User { .. }, owner, _) => {
            if (!rpc_grant || owner.is_some()) && !schema.user_caps.contains(&DmlVerb::Select) {
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
    // (bypass). A compile error → 500 with a typed code. Never mode-dependent:
    // RpcGrant relaxes caps only, and the policy is precisely the row gate that
    // makes relaxing them safe.
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

/// One page of structured-list results, as produced by
/// [`run_structured_list`] and rendered by `/list` into its
/// `{records,total,page,perPage}` envelope.
pub(crate) struct ListPage {
    pub records: Vec<serde_json::Value>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
}

/// Failure modes of [`run_structured_list`], kept as data so each caller face
/// maps them to its own wire contract. `Http` carries an already-typed response
/// (the auth denies and the FTS probe) through unchanged.
pub(crate) enum ListCoreError {
    NoSuchCollection,
    Build(crate::query::list_builder::ListError),
    Http(Response),
    Db(rusqlite::Error),
}

/// The `/list` pipeline, minus the HTTP envelope: schema load →
/// row-authorization → SQL build → FTS pre-probe → list + count execution.
/// Shared verbatim by `POST /list` and (from #950) the stored `kind='query'`
/// RPC arm, so the two cannot drift.
pub(crate) async fn run_structured_list(
    pool: &crate::storage::pool::SharedTenantPool,
    ctx: &AuthCtx,
    coll: &str,
    req: ListRequest,
) -> Result<ListPage, ListCoreError> {
    run_structured_list_inner(CapMode::Collection, pool, ctx, coll, req).await
}

/// [`run_structured_list`] under the RPC-as-grant cap regime (#950) — the ONLY
/// door to [`CapMode::RpcGrant`], and the reason there is no bare
/// `compute_read_auth_rpc_grant`. See [`compute_read_auth_inner`]'s per-arm
/// table for exactly which cap checks that relaxes; everything else (owner
/// clause, RLS policy, protected-collection gate, FTS probe, deadline,
/// authorizer) is identical. Called from `crate::rpc::exec_query`.
pub(crate) async fn run_structured_list_rpc_grant(
    pool: &crate::storage::pool::SharedTenantPool,
    ctx: &AuthCtx,
    coll: &str,
    req: ListRequest,
) -> Result<ListPage, ListCoreError> {
    run_structured_list_inner(CapMode::RpcGrant, pool, ctx, coll, req).await
}

async fn run_structured_list_inner(
    cap: CapMode,
    pool: &crate::storage::pool::SharedTenantPool,
    ctx: &AuthCtx,
    coll: &str,
    req: ListRequest,
) -> Result<ListPage, ListCoreError> {
    // The core carries its own protected-collection gate rather than trusting
    // every caller to pre-check: `post_list` keeps its early check (a double
    // door is fine), while the query-RPC arm's only other gate is a save-time
    // template validation, which a later schema change could outrun.
    if is_protected_collection(coll) {
        return Err(ListCoreError::NoSuchCollection);
    }
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.to_string();
    let schema = match pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return Err(ListCoreError::NoSuchCollection),
        Err(e) => return Err(ListCoreError::Db(e)),
    };

    // Row-authorization (owner clause + explicit-policy USING), computed by the
    // shared `compute_read_auth_inner` so `/list` and `/aggregate` stay in
    // lockstep by construction. The full cap/owner/policy matrix (incl. the
    // read_scope="all" note and the per-mode cap rules) lives there.
    let (owner_pair, policy_clause) = match compute_read_auth_inner(cap, ctx, &schema, coll) {
        Ok(v) => v,
        Err(resp) => return Err(ListCoreError::Http(resp)),
    };

    // ── Compile SQL ──────────────────────────────────────────────────
    let owner_ref = owner_pair.as_ref().map(|(f, v)| (f.as_str(), v.as_str()));
    let (list_sql, count_sql, binds) =
        match build_structured_list_sql(&schema, &req, owner_ref, policy_clause) {
            Ok(x) => x,
            Err(e) => return Err(ListCoreError::Build(e)),
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

    // ── FTS_QUERY_INVALID structural pre-probe ───────────────────────
    // A malformed fts5 MATCH would otherwise surface as a generic 500 from the
    // list/count statement failing mid-scan; probe the isolated MATCH first so it
    // maps to 400 FTS_QUERY_INVALID. No-op unless the filter carries a MATCH-path
    // `$fts` operand.
    if let Err(resp) = fts_probe_guard(pool, &schema, req.filter.as_ref()).await {
        return Err(ListCoreError::Http(resp));
    }

    // ── Execute list ─────────────────────────────────────────────────
    let pool_list = pool.clone();
    let list_sql_owned = list_sql.clone();
    let binds_for_list = binds.clone();
    let records_res: rusqlite::Result<(Vec<String>, Vec<serde_json::Value>)> = pool_list
        .with_reader(move |c| {
            let _deadline = crate::query::executor::DeadlineGuard::arm(
                c,
                crate::query::executor::query_deadline(),
            );
            attach_search_readonly_authorizer(c);
            let r = run_bound_select(c, &list_sql_owned, &binds_for_list);
            detach_authorizer(c);
            r
        })
        .await;
    let (col_names, rows) = match records_res {
        Ok(v) => v,
        Err(e) => return Err(ListCoreError::Db(e)),
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
    let pool_count = pool.clone();
    let count_sql_owned = count_sql.clone();
    let binds_for_count = binds.clone();
    let count_res: rusqlite::Result<i64> = pool_count
        .with_reader(move |c| -> rusqlite::Result<i64> {
            let _deadline = crate::query::executor::DeadlineGuard::arm(
                c,
                crate::query::executor::query_deadline(),
            );
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
        Err(e) => return Err(ListCoreError::Db(e)),
    };

    Ok(ListPage {
        records: records_out,
        total,
        page: req.page.unwrap_or(1),
        per_page: req.per_page.unwrap_or(20),
    })
}

/// `POST /t/<id>/collections/<c>/list`
pub async fn post_list(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(req): Json<ListRequest>,
) -> Response {
    debug_assert_ctx_role(&ctx, t.role);
    if is_protected_collection(&coll) {
        return json_error(
            StatusCode::NOT_FOUND,
            "COLLECTION_NOT_FOUND",
            &format!("no such collection: {coll}"),
        );
    }

    let page = match run_structured_list(&t.pool, &ctx, &coll, req).await {
        Ok(p) => p,
        Err(ListCoreError::NoSuchCollection) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "COLLECTION_NOT_FOUND",
                &format!("no such collection: {coll}"),
            );
        }
        Err(ListCoreError::Build(e)) => return map_list_error(e),
        Err(ListCoreError::Http(resp)) => return resp,
        Err(ListCoreError::Db(e)) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    Json(json!({
        "records": page.records,
        "total": page.total,
        "page": page.page,
        "perPage": page.per_page,
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

    // Same structural FTS_QUERY_INVALID pre-probe as /list — /aggregate shares
    // the FilterAst → `$fts` compile path.
    if let Err(resp) = fts_probe_guard(&pool, &schema, req.filter.as_ref()).await {
        return resp;
    }

    let pool_run = t.pool.clone();
    let sql_owned = sql.clone();
    let binds_owned = binds.clone();
    let rows_res: rusqlite::Result<(Vec<String>, Vec<serde_json::Value>)> = pool_run
        .with_reader(move |c| {
            let _deadline = crate::query::executor::DeadlineGuard::arm(
                c,
                crate::query::executor::query_deadline(),
            );
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
///
/// `pub(crate)` so the query-RPC arm (`crate::rpc::exec_query`) can reuse the
/// one case where a template failure is still the CALLER's fault —
/// `PageRangeInvalid`, which comes from the caller's `?page=/?per_page=` — and
/// therefore keeps `/list`'s 422 rather than becoming a template 409.
pub(crate) fn map_list_error(e: ListError) -> Response {
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

/// Run the structural `FTS_QUERY_INVALID` pre-probe for every `$fts` MATCH
/// operand in `filter` on a reader, mapping the outcome to a `Response`. `Ok(())`
/// when there is nothing to probe or every MATCH is well-formed; a `400
/// FTS_QUERY_INVALID` when a MATCH is malformed; `500 DB_ERROR` only on a genuine
/// reader failure. Shared verbatim by `/list` and `/aggregate` (and reused by
/// `/search` via `probe_fts_queries`) so the mapping is written once.
pub(crate) async fn fts_probe_guard(
    pool: &crate::storage::pool::SharedTenantPool,
    schema: &CollectionSchema,
    filter: Option<&FilterAst>,
) -> Result<(), Response> {
    match crate::query::vector_filter::probe_fts_queries(pool, schema, filter).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(msg)) => Err(json_error(
            StatusCode::BAD_REQUEST,
            "FTS_QUERY_INVALID",
            &msg,
        )),
        Err(e) => Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        )),
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

/// Cap-mode matrix pins (#950 T3).
///
/// Every test asserts BOTH modes: `CapMode::Collection` must be byte-identical
/// to the pre-split `/list` behaviour, and `CapMode::RpcGrant` must follow the
/// spec's per-arm table (`docs/superpowers/specs/2026-08-10-rpc-rls-readmode-design.md`
/// §授權語意). The rule these encode: **RpcGrant skips a cap check ONLY where an
/// independent row gate protects the rows.** Where the cap IS the row gate — the
/// User × owner-scoped × `read_scope="all"` arm and its legacy NULL-read_scope
/// sibling, both of which apply NO row filter — the cap is never skipped, in any
/// mode.
#[cfg(test)]
mod cap_mode_tests {
    use super::*;
    use crate::query::policy::{CollectionPolicies, Policy};
    use crate::storage::schema::Field;
    use std::collections::BTreeSet;

    fn field(name: &str) -> Field {
        Field {
            name: name.to_string(),
            sql_type: "TEXT".into(),
            nullable: true,
            pk: false,
            default_value: None,
            foreign_key: None,
            description: None,
            ..Default::default()
        }
    }

    fn schema_for(
        anon: &[DmlVerb],
        user: &[DmlVerb],
        owner_field: Option<&str>,
        read_scope: Option<&str>,
    ) -> CollectionSchema {
        CollectionSchema {
            name: "posts".into(),
            fields: vec![field("author"), field("status")],
            indices: vec![],
            row_count: 0,
            anon_caps: anon.iter().copied().collect::<BTreeSet<_>>(),
            user_caps: user.iter().copied().collect::<BTreeSet<_>>(),
            owner_field: owner_field.map(|s| s.to_string()),
            read_scope: read_scope.map(|s| s.to_string()),
            vector_fields: vec![],
            fts_indexes: vec![],
            realtime_enabled: true,
            audit_enabled: true,
            description: None,
            policies: CollectionPolicies::default(),
        }
    }

    fn user_ctx() -> AuthCtx {
        AuthCtx::User {
            user_id: "u1".into(),
            token_hash: "hash".into(),
        }
    }

    /// What `compute_read_auth_inner` returns: `(owner_pair, policy_clause)`
    /// or a typed response.
    type ReadAuth = Result<(Option<(String, String)>, Option<(String, Vec<Value>)>), Response>;

    /// `compute_read_auth_inner` under both modes, so every pin states the
    /// Collection expectation (zero-change) next to the RpcGrant one.
    fn both(ctx: &AuthCtx, schema: &CollectionSchema) -> (ReadAuth, ReadAuth) {
        (
            compute_read_auth_inner(CapMode::Collection, ctx, schema, "posts"),
            compute_read_auth_inner(CapMode::RpcGrant, ctx, schema, "posts"),
        )
    }

    fn assert_denied(r: ReadAuth) {
        match r {
            Ok(v) => panic!("expected a typed deny, got Ok({v:?})"),
            Err(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
        }
    }

    fn assert_no_owner_clause(r: ReadAuth) {
        match r {
            Ok((owner, _policy)) => assert_eq!(owner, None),
            Err(resp) => panic!("expected Ok, got {}", resp.status()),
        }
    }

    // ── Anon ────────────────────────────────────────────────────────────

    #[test]
    fn rpc_grant_anon_owner_scoped_still_403() {
        // Anon × owner-scoped is 403 in EVERY mode — RPC-as-grant never relaxes
        // it (the policy-only anon arm is a later phase, not this one).
        for read_scope in [Some("own"), Some("all"), None] {
            let s = schema_for(
                &[DmlVerb::Select],
                &[DmlVerb::Select],
                Some("author"),
                read_scope,
            );
            let (coll, grant) = both(&AuthCtx::Anon, &s);
            assert_denied(coll);
            assert_denied(grant);
        }
    }

    #[test]
    fn rpc_grant_anon_skips_anon_caps() {
        // Non-owner-scoped: the cap is a blanket door, and the RPC's own
        // `anon_callable` flag replaces it. Policy (if any) still applies.
        let s = schema_for(&[], &[DmlVerb::Select], None, None);
        let (coll, grant) = both(&AuthCtx::Anon, &s);
        assert_denied(coll);
        assert_no_owner_clause(grant);
    }

    // ── User ────────────────────────────────────────────────────────────

    #[test]
    fn rpc_grant_user_readscope_all_keeps_cap() {
        // read_scope="all" applies NO row filter, so `user_caps[select]` IS the
        // row gate here. Skipping it would let any user token read the whole
        // table through an anon-callable query RPC. Kept in BOTH modes.
        let denied = schema_for(&[DmlVerb::Select], &[], Some("author"), Some("all"));
        let (coll, grant) = both(&user_ctx(), &denied);
        assert_denied(coll);
        assert_denied(grant);

        // With the cap granted, both modes agree: allowed, and still unfiltered.
        let allowed = schema_for(
            &[DmlVerb::Select],
            &[DmlVerb::Select],
            Some("author"),
            Some("all"),
        );
        let (coll, grant) = both(&user_ctx(), &allowed);
        assert_no_owner_clause(coll);
        assert_no_owner_clause(grant);
    }

    #[test]
    fn rpc_grant_user_legacy_null_scope_keeps_cap() {
        // Legacy rows: owner_field set but read_scope NULL. Same shape as
        // "all" — unfiltered — so the cap stays the row gate in BOTH modes.
        let denied = schema_for(&[DmlVerb::Select], &[], Some("author"), None);
        let (coll, grant) = both(&user_ctx(), &denied);
        assert_denied(coll);
        assert_denied(grant);

        let allowed = schema_for(&[DmlVerb::Select], &[DmlVerb::Select], Some("author"), None);
        let (coll, grant) = both(&user_ctx(), &allowed);
        assert_no_owner_clause(coll);
        assert_no_owner_clause(grant);
    }

    #[test]
    fn rpc_grant_user_own_gets_owner_clause() {
        // read_scope="own" has no cap check in either mode — the owner clause
        // is the row gate, and it must be emitted identically.
        let s = schema_for(&[], &[], Some("author"), Some("own"));
        let (coll, grant) = both(&user_ctx(), &s);
        let want = Some(("author".to_string(), "u1".to_string()));
        assert_eq!(coll.map(|(o, _)| o).ok(), Some(want.clone()));
        assert_eq!(grant.map(|(o, _)| o).ok(), Some(want));
    }

    #[test]
    fn rpc_grant_user_no_owner_skips_user_caps() {
        // Non-owner-scoped: blanket cap, replaced by the RPC grant.
        let s = schema_for(&[DmlVerb::Select], &[], None, None);
        let (coll, grant) = both(&user_ctx(), &s);
        assert_denied(coll);
        assert_no_owner_clause(grant);
    }

    // ── Service + policy ────────────────────────────────────────────────

    #[test]
    fn rpc_grant_service_bypasses() {
        let s = schema_for(&[], &[], Some("author"), Some("all"));
        let ctx = AuthCtx::Service { admin_id: None };
        let (coll, grant) = both(&ctx, &s);
        for r in [coll, grant] {
            match r {
                Ok((owner, policy)) => {
                    assert_eq!(owner, None);
                    assert_eq!(policy, None);
                }
                Err(resp) => panic!("service must bypass, got {}", resp.status()),
            }
        }
    }

    // ── The core's own protected-collection gate ────────────────────────

    #[tokio::test]
    async fn core_refuses_a_protected_collection_that_actually_exists() {
        // Defense in depth: `run_structured_list*` must refuse `_system_*`
        // itself, not lean on each caller's pre-check. The probe table is a
        // REAL `_system_`-prefixed table, so deleting the core's gate would let
        // the schema load succeed and the read proceed — this pin would then
        // see a different error instead of `NoSuchCollection`. A gate tested
        // only against a collection that does not exist tests nothing.
        let tmp = tempfile::tempdir().unwrap();
        let tenants = crate::storage::pool::TenantRegistry::new(tmp.path().to_path_buf(), 1);
        let pool = tenants.get_or_create("t1").unwrap();
        pool.with_writer(|c| {
            c.execute_batch("CREATE TABLE IF NOT EXISTS _system_probe (id TEXT PRIMARY KEY)")
        })
        .await
        .unwrap();

        let svc = AuthCtx::Service { admin_id: None };
        let outcomes = [
            run_structured_list(&pool, &svc, "_system_probe", ListRequest::default()).await,
            run_structured_list_rpc_grant(&pool, &svc, "_system_probe", ListRequest::default())
                .await,
        ];
        for r in outcomes {
            assert!(
                matches!(r, Err(ListCoreError::NoSuchCollection)),
                "the core must gate protected collections itself"
            );
        }
    }

    #[test]
    fn rpc_grant_policy_clause_is_mode_independent() {
        // The explicit-policy USING clause is never mode-dependent: RpcGrant
        // relaxes caps only, and policy is the row gate that makes that safe.
        let mut s = schema_for(&[DmlVerb::Select], &[DmlVerb::Select], None, None);
        s.policies = CollectionPolicies {
            select: Some(Policy {
                using: Some(
                    serde_json::from_str::<FilterAst>(r#"{"status":{"$eq":"published"}}"#).unwrap(),
                ),
                check: None,
            }),
            ..Default::default()
        };

        for ctx in [AuthCtx::Anon, user_ctx()] {
            let (coll, grant) = both(&ctx, &s);
            let coll_clause = coll.expect("collection mode allowed").1;
            let grant_clause = grant.expect("rpc-grant mode allowed").1;
            assert!(
                coll_clause.is_some(),
                "the select policy must compile to a USING clause"
            );
            assert_eq!(coll_clause, grant_clause);
        }
    }
}

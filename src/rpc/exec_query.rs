//! Execution arm for `kind='query'` stored RPCs (#950 Phase 1).
//!
//! A query-kind RPC is a curated `FilterAst` **template**, not SQL. Executing
//! one is: substitute the caller's arguments into the template at the JSON
//! level, parse the result as a `FilterAst`, and run it through the UNCHANGED
//! `/list` pipeline under the CALLER's identity — so `owner_field`, RLS
//! policies and the cap-retention rules apply by construction, and the SQL is
//! 100% builder-generated with every operand `?`-bound.
//!
//! This is the SINGLE executor: REST (`crate::rpc::handler`), MCP `call_rpc`
//! and the admin playground all call [`run_query_rpc`] rather than growing
//! parallel copies (the sql arm's `exec_write::run_write_rpc` precedent).
//!
//! Spec: `docs/superpowers/specs/2026-08-10-rpc-rls-readmode-design.md`
//! §呼叫路徑 / §授權語意 / §錯誤目錄.

use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::query::list_builder::{ListError, ListRequest};
use crate::rpc::params::ParamError;
use crate::rpc::query_template::{self, TemplateError};
use crate::rpc::registry::StoredRpc;
use crate::storage::pool::SharedTenantPool;
use crate::tenant::records_list::{ListCoreError, ListPage, map_list_error};
use axum::http::StatusCode;
use axum::response::Response;

/// Run one query-kind RPC and return the `/list` page it produced.
///
/// `body_map` is the caller's argument map (the same body the sql arm feeds to
/// `validate_and_bind`); `page` / `per_page` come from the QUERY STRING, kept
/// out of the argument map so a template can declare a param called `page`
/// without colliding with the wire contract.
///
/// > The sql read arm's `:user_id` auto-bind is deliberately NOT ported.
/// > Identity inside a template is `{"$auth":"id"}` and nothing else: it is
/// > substituted from the `AuthCtx` here, is null for every caller without an
/// > end-user identity (anon, service, admin, cron), and — unlike a declared
/// > `:user_id` param — cannot be supplied, shadowed or spoofed through the
/// > body. Adding an auto-bind would create a second identity channel whose
/// > two halves could disagree.
pub(crate) async fn run_query_rpc(
    pool: &SharedTenantPool,
    ctx: &AuthCtx,
    stored: &StoredRpc,
    body_map: serde_json::Map<String, serde_json::Value>,
    page: Option<u32>,
    per_page: Option<u32>,
) -> Result<ListPage, Response> {
    // A kind='query' row without a template is only reachable by hand-editing
    // the DB (`registry::check_kind_rules` refuses to write one), so treat it
    // as the stale-template case rather than a 500.
    let tpl = query_template::parse_template(stored.query_json.as_deref().unwrap_or(""))
        .map_err(|e| json_error(StatusCode::CONFLICT, "RPC_QUERY_STALE", &e.to_string()))?;

    // `resolve_args` is the ONE argument entry point: it fuses the shape/type
    // checks with default resolution, in that order — a declared default must
    // land BEFORE substitution, or an omitted optional param silently filters
    // on NULL. `substitute_to_filter_ast` is likewise the ONLY path to a
    // `FilterAst`: it welds substitution to the STRICT `from_value` parse, so a
    // scalar string argument can never be re-parsed back into operator
    // structure (that is the second half of the AST-injection gate).
    let args = query_template::resolve_args(&stored.params, &body_map).map_err(map_template_err)?;
    let auth_id = match ctx {
        AuthCtx::User { user_id, .. } => Some(user_id.as_str()),
        AuthCtx::Anon | AuthCtx::Service { .. } => None,
    };
    let filter = match &tpl.filter {
        Some(f) => Some(
            query_template::substitute_to_filter_ast(f, &args, auth_id)
                .map_err(map_template_err)?,
        ),
        None => None,
    };

    let req = ListRequest {
        filter,
        sort: tpl.sort.clone(),
        page,
        per_page,
        select: tpl.select.clone(),
    };

    match crate::tenant::records_list::run_structured_list_rpc_grant(
        pool,
        ctx,
        &tpl.collection,
        req,
    )
    .await
    {
        Ok(p) => Ok(p),
        // The collection was dropped (or renamed) after the template was
        // saved — the same class as a dropped column below.
        Err(ListCoreError::NoSuchCollection) => Err(json_error(
            StatusCode::CONFLICT,
            "RPC_QUERY_STALE",
            "collection no longer exists",
        )),
        // The one build failure the CALLER caused rather than the template:
        // page/per_page arrive on the query string. Keep `/list`'s 422.
        Err(ListCoreError::Build(ListError::PageRangeInvalid)) => {
            Err(map_list_error(ListError::PageRangeInvalid))
        }
        // Every other build failure means the stored template no longer
        // matches the live schema (dropped field, sort target gone, …). It
        // passed `validate_template` at save time, so this is drift.
        Err(ListCoreError::Build(e)) => Err(json_error(
            StatusCode::CONFLICT,
            "RPC_QUERY_STALE",
            &e.to_string(),
        )),
        // Already-typed responses: the auth denies (403) and the FTS probe.
        Err(ListCoreError::Http(r)) => Err(r),
        Err(ListCoreError::Db(e)) => Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        )),
    }
}

/// Argument/template failures → the wire.
///
/// The `Arg(_)` arm mirrors the sql read arm's `RpcOutcome::Param` mapping
/// CODE-FOR-CODE (`src/rpc/handler.rs`), because a caller cannot tell which
/// kind of RPC they are calling from the error alone and the two arms share
/// `params::coerce`. Everything else is template drift: it validated at save
/// time, so seeing it at call time means the schema moved underneath.
fn map_template_err(e: TemplateError) -> Response {
    match e {
        TemplateError::NotScalar(p) => json_error(
            StatusCode::BAD_REQUEST,
            "RPC_PARAM_NOT_SCALAR",
            &format!(
                "param '{p}' must be a JSON scalar (string, number, boolean or null) — \
                 an object or array argument could inject filter structure"
            ),
        ),
        TemplateError::Arg(pe) => match pe {
            ParamError::Missing(_) => {
                json_error(StatusCode::BAD_REQUEST, "PARAM_MISSING", &pe.to_string())
            }
            ParamError::TypeMismatch { .. } => json_error(
                StatusCode::BAD_REQUEST,
                "PARAM_TYPE_MISMATCH",
                &pe.to_string(),
            ),
            ParamError::Unknown(_) => {
                json_error(StatusCode::BAD_REQUEST, "PARAM_UNKNOWN", &pe.to_string())
            }
            ParamError::BadParamsJson(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PARAM_BAD_STORED",
                &pe.to_string(),
            ),
        },
        other => json_error(StatusCode::CONFLICT, "RPC_QUERY_STALE", &other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::params::ParamType;

    fn code_of(resp: &Response) -> StatusCode {
        resp.status()
    }

    #[test]
    fn not_scalar_is_a_400_not_a_stale_409() {
        // The AST-injection refusal must read as a CALLER error, never as
        // template drift — the caller can fix it by sending a scalar.
        let r = map_template_err(TemplateError::NotScalar("who".into()));
        assert_eq!(code_of(&r), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn arg_errors_keep_the_sql_arms_statuses() {
        let cases = [
            (
                TemplateError::Arg(ParamError::Unknown("nope".into())),
                StatusCode::BAD_REQUEST,
            ),
            (
                TemplateError::Arg(ParamError::Missing("who".into())),
                StatusCode::BAD_REQUEST,
            ),
            (
                TemplateError::Arg(ParamError::TypeMismatch {
                    name: "n".into(),
                    expected: ParamType::Integer,
                    got: "string".into(),
                }),
                StatusCode::BAD_REQUEST,
            ),
            (
                TemplateError::Arg(ParamError::BadParamsJson("x".into())),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (e, want) in cases {
            assert_eq!(code_of(&map_template_err(e)), want);
        }
    }

    #[test]
    fn drift_shapes_are_409() {
        for e in [
            TemplateError::BadShape("nope".into()),
            TemplateError::UndeclaredParam("who".into()),
            TemplateError::UnusedParam("who".into()),
            TemplateError::BadAuthKey("\"email\"".into()),
        ] {
            assert_eq!(code_of(&map_template_err(e)), StatusCode::CONFLICT);
        }
    }
}

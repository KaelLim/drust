use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::query::executor::{ExecError, execute_read_query};
use crate::tenant::router::TenantRef;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct QueryBody {
    pub sql: String,
}

/// audit3 D1 — `/query` and `/query/explain` execute raw, un-rewritable SQL, so
/// none of drust's row-access controls (owner_field, RLS policies, anon_caps)
/// can be enforced on them. They are therefore SERVICE-ONLY: any non-Service
/// caller is denied. User keeps its specific `QUERY_USER_DENIED` code; Anon —
/// previously allowed unless the tenant had adopted a policy/owner_field — is
/// now denied unconditionally (`QUERY_ANON_DENIED`, with the prior
/// `ANON_QUERY_DENIED_ON_POLICY` retained as an alias). Returns the deny
/// response for User/Anon, or `None` for Service.
fn deny_non_service_query(ctx: &AuthCtx, path: &str) -> Option<Response> {
    match ctx {
        AuthCtx::Service { .. } => None,
        AuthCtx::User { .. } => Some(json_error(
            StatusCode::FORBIDDEN,
            "QUERY_USER_DENIED",
            &format!("user token cannot use {path}"),
        )),
        AuthCtx::Anon => Some(crate::error::json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "QUERY_ANON_DENIED",
            &["ANON_QUERY_DENIED_ON_POLICY"],
            &format!(
                "{path} is service-only — anon reads via POST /collections/<c>/list or /search"
            ),
        )),
    }
}

pub async fn query_handler(
    Extension(ctx): Extension<AuthCtx>,
    Extension(t): Extension<TenantRef>,
    Json(body): Json<QueryBody>,
) -> Response {
    if let Some(resp) = deny_non_service_query(&ctx, "/query") {
        return resp;
    }
    const ROW_CAP: usize = 10_000;
    const MAX_SQL: usize = 16_384;
    let pool = t.pool.clone();
    let sql = body.sql.clone();
    let out = pool
        .with_reader(move |c| {
            execute_read_query(c, &sql, ROW_CAP, MAX_SQL).map_err(|e| {
                let tag = match &e {
                    ExecError::TooLarge { .. } => "too_large",
                    ExecError::Forbidden(_) => "forbidden",
                    ExecError::Timeout(_) => "timeout",
                    ExecError::Sql(_) => "sql_error",
                };
                rusqlite::Error::SqlInputError {
                    error: rusqlite::ffi::Error::new(1),
                    msg: tag.into(),
                    sql: "".into(),
                    offset: 0,
                }
            })
        })
        .await;
    match out {
        Ok(qr) => Json(serde_json::to_value(qr).unwrap()).into_response(),
        Err(e) => {
            let m = e.to_string();
            if m.contains("too_large") {
                json_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "QUERY_TOO_LARGE",
                    "sql too large",
                )
            } else if m.contains("forbidden") {
                json_error(
                    StatusCode::FORBIDDEN,
                    "QUERY_FORBIDDEN",
                    "denied by authorizer",
                )
            } else if m.contains("timeout") {
                json_error(StatusCode::REQUEST_TIMEOUT, "QUERY_TIMEOUT", "timed out")
            } else {
                json_error(StatusCode::BAD_REQUEST, "INTERNAL", &m)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExplainBody {
    pub sql: String,
}

pub async fn explain_handler(
    Extension(ctx): Extension<AuthCtx>,
    Extension(t): Extension<TenantRef>,
    Json(body): Json<ExplainBody>,
) -> Response {
    if let Some(resp) = deny_non_service_query(&ctx, "/query/explain") {
        return resp;
    }
    match crate::mcp::tools::index::explain_select(&t.pool, &body.sql).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let (status, code) = if msg.contains("not authorized")
                || msg.contains("authorizer")
                || msg.contains("prohibited")
            {
                (StatusCode::BAD_REQUEST, "SQL_NOT_ALLOWED")
            } else if msg.contains("syntax") || msg.contains("near") {
                (StatusCode::BAD_REQUEST, "SQL_PARSE_ERROR")
            } else {
                (StatusCode::BAD_REQUEST, "SQL_ERROR")
            };
            let body = json!({ "error_code": code, "message": msg });
            let mut r = Json(body).into_response();
            *r.status_mut() = status;
            r
        }
    }
}

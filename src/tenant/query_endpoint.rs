use crate::query::authorizer::attach_readonly_authorizer;
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

pub async fn query_handler(
    Extension(t): Extension<TenantRef>,
    Json(body): Json<QueryBody>,
) -> Response {
    const ROW_CAP: usize = 10_000;
    const MAX_SQL: usize = 16_384;
    let pool = t.pool.clone();
    let sql = body.sql.clone();
    let out = pool
        .with_reader(move |c| {
            attach_readonly_authorizer(c);
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
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json_err("QUERY_TOO_LARGE", "sql too large"),
                )
                    .into_response()
            } else if m.contains("forbidden") {
                (
                    StatusCode::FORBIDDEN,
                    json_err("QUERY_FORBIDDEN", "denied by authorizer"),
                )
                    .into_response()
            } else if m.contains("timeout") {
                (
                    StatusCode::REQUEST_TIMEOUT,
                    json_err("QUERY_TIMEOUT", "timed out"),
                )
                    .into_response()
            } else {
                (StatusCode::BAD_REQUEST, json_err("INTERNAL", &m)).into_response()
            }
        }
    }
}

fn json_err(code: &str, msg: &str) -> Json<serde_json::Value> {
    Json(json!({ "error_code": code, "message": msg }))
}

//! REST handler for `POST /t/{tenant}/rpc/{name}`.
//!
//! Looks up a stored RPC, gates it against the caller's role
//! (anon vs service), validates the JSON body against the RPC's
//! declared param schema, and executes the bound SQL through the
//! read-only authorizer. On success, increments the per-role call
//! counter and `last_called_at` on `_system_rpc` — fire-and-forget
//! so the response isn't blocked on the writer mutex.

use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::query::executor::{
    ExecError, QueryResult, execute_read_query_with_named,
};
use crate::rpc::params::{ParamError, validate_and_bind};
use crate::rpc::registry::{self, RegistryError};
use crate::tenant::router::TenantRef;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::json;

const MAX_ROWS: usize = 1_000;
const MAX_BYTES: usize = 1_048_576;

/// All possible outcomes of a single RPC dispatch. The closure passed
/// to `with_reader` returns one of these wrapped in `Ok`, so true
/// `rusqlite::Error`s only surface for connection-level problems.
enum RpcOutcome {
    Ok(QueryResult),
    NotFound,
    AnonDenied,
    Param(ParamError),
    Exec(ExecError),
    Registry(RegistryError),
}

pub async fn call_rpc(
    Extension(t): Extension<TenantRef>,
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, name)): Path<(String, String)>,
    // Accept missing or empty bodies gracefully. Axum's `Json<T>` extractor
    // rejects an empty body outright; using `Option<Json<...>>` would force
    // the Content-Type header check on every caller. We deserialise into a
    // raw `serde_json::Value` and require it to be a JSON object (or null /
    // missing → empty).
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let raw_body = match body {
        Some(Json(v)) => v,
        None => serde_json::Value::Null,
    };
    let body_map = match raw_body {
        serde_json::Value::Null => serde_json::Map::new(),
        serde_json::Value::Object(m) => m,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "BAD_BODY",
                "request body must be a JSON object",
            );
        }
    };

    let pool = t.pool.clone();
    let name_for_closure = name.clone();
    let ctx_for_closure = ctx.clone();
    let outcome_res = pool
        .with_reader(move |conn| {
            // 1. Look up the RPC by name.
            let stored = match registry::lookup(conn, &name_for_closure) {
                Ok(Some(s)) => s,
                Ok(None) => return Ok(RpcOutcome::NotFound),
                Err(e) => return Ok(RpcOutcome::Registry(e)),
            };

            // 2. Role allow-list check.
            //    Service: always allowed.
            //    Anon / User: allowed only when anon_callable = true.
            let allowed = match &ctx_for_closure {
                AuthCtx::Service => true,
                AuthCtx::Anon | AuthCtx::User { .. } => stored.anon_callable,
            };
            if !allowed {
                return Ok(RpcOutcome::AnonDenied);
            }

            // 2b. Auto-bind :user_id from AuthCtx when:
            //     (a) the RPC declares a param named "user_id",
            //     (b) the caller is a User token, and
            //     (c) the body did not supply user_id.
            let mut body_map = body_map;
            if let AuthCtx::User { user_id, .. } = &ctx_for_closure {
                let declares_user_id = stored.params.iter().any(|p| p.name == "user_id");
                if declares_user_id && !body_map.contains_key("user_id") {
                    body_map.insert(
                        "user_id".into(),
                        serde_json::Value::String(user_id.clone()),
                    );
                }
            }

            // 3. Validate + bind params.
            let bound = match validate_and_bind(&stored.params, &body_map) {
                Ok(b) => b,
                Err(e) => return Ok(RpcOutcome::Param(e)),
            };

            // 4. Execute through the read-only authorizer.
            match execute_read_query_with_named(
                conn,
                &stored.sql,
                &bound,
                MAX_ROWS,
                MAX_BYTES,
            ) {
                Ok(qr) => Ok(RpcOutcome::Ok(qr)),
                Err(e) => Ok(RpcOutcome::Exec(e)),
            }
        })
        .await;

    let outcome = match outcome_res {
        Ok(o) => o,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };

    match outcome {
        RpcOutcome::Ok(qr) => {
            // Fire-and-forget counter bump on the writer mutex. Failed
            // calls (any non-Ok arm above) do not increment.
            let pool_for_counter = t.pool.clone();
            let role_for_counter = t.role;
            let name_for_counter = name.clone();
            tokio::spawn(async move {
                let res = pool_for_counter
                    .with_writer(move |c| {
                        registry::increment(c, &name_for_counter, role_for_counter)
                    })
                    .await;
                if let Err(e) = res {
                    tracing::warn!(error = %e, "rpc counter bump failed");
                }
            });
            let row_count = qr.rows.len();
            Json(json!({
                "column_names": qr.column_names,
                "rows": qr.rows,
                "row_count": row_count,
                "truncated": qr.truncated,
            }))
            .into_response()
        }
        RpcOutcome::NotFound => json_error(
            StatusCode::NOT_FOUND,
            "RPC_NOT_FOUND",
            &format!("no such rpc: {name}"),
        ),
        RpcOutcome::AnonDenied => json_error(
            StatusCode::FORBIDDEN,
            "ANON_DENIED",
            &format!("anon role cannot call rpc '{name}'"),
        ),
        RpcOutcome::Param(e) => match e {
            ParamError::Missing(_) => {
                json_error(StatusCode::BAD_REQUEST, "PARAM_MISSING", &e.to_string())
            }
            ParamError::TypeMismatch { .. } => json_error(
                StatusCode::BAD_REQUEST,
                "PARAM_TYPE_MISMATCH",
                &e.to_string(),
            ),
            ParamError::Unknown(_) => {
                json_error(StatusCode::BAD_REQUEST, "PARAM_UNKNOWN", &e.to_string())
            }
            ParamError::BadParamsJson(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PARAM_BAD_STORED",
                &e.to_string(),
            ),
        },
        RpcOutcome::Exec(e) => match &e {
            ExecError::TooLarge { .. } => json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "QUERY_TOO_LARGE",
                &e.to_string(),
            ),
            ExecError::Forbidden(_) => json_error(
                StatusCode::FORBIDDEN,
                "QUERY_FORBIDDEN",
                &e.to_string(),
            ),
            ExecError::Timeout(_) => json_error(
                StatusCode::REQUEST_TIMEOUT,
                "QUERY_TIMEOUT",
                &e.to_string(),
            ),
            ExecError::Sql(_) => {
                json_error(StatusCode::BAD_REQUEST, "SQL_ERROR", &e.to_string())
            }
        },
        RpcOutcome::Registry(e) => match e {
            RegistryError::NotFound(_) => json_error(
                StatusCode::NOT_FOUND,
                "RPC_NOT_FOUND",
                &e.to_string(),
            ),
            RegistryError::BadParams(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PARAM_BAD_STORED",
                &e.to_string(),
            ),
            RegistryError::AlreadyExists(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            ),
            RegistryError::Sqlite(_) => {
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string())
            }
        },
    }
}


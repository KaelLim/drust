use crate::auth::middleware::AuthCtx;
use crate::error::json_error;
use crate::tenant::router::TenantRef;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct SetOwnerFieldBody {
    pub field: String,
    #[serde(default = "default_read_scope")]
    pub read_scope: String,
}

fn default_read_scope() -> String {
    "own".into()
}

pub async fn set_owner_field_handler(
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
    Extension(t): Extension<TenantRef>,
    Json(body): Json<SetOwnerFieldBody>,
) -> Response {
    if !matches!(ctx, AuthCtx::Service) {
        return json_error(
            StatusCode::FORBIDDEN,
            "SERVICE_ONLY",
            "service key required",
        );
    }
    if body.read_scope != "own" && body.read_scope != "all" {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_READ_SCOPE",
            "read_scope must be 'own' or 'all'",
        );
    }
    let collection = match params.get("coll") {
        Some(c) => c.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing collection"),
    };
    let pool = t.pool.clone();
    let coll_for_val = collection.clone();
    let field_for_val = body.field.clone();
    let validation = pool
        .with_reader(move |c| validate_owner_column(c, &coll_for_val, &field_for_val))
        .await;
    match validation {
        Ok(Ok(())) => {}
        Ok(Err(code)) => return json_error(StatusCode::CONFLICT, code, ""),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    }
    let coll_for_set = collection.clone();
    let field_for_set = body.field.clone();
    let scope_for_set = body.read_scope.clone();
    let res = pool
        .with_writer(move |c| {
            crate::storage::schema::set_owner_field(
                c,
                &coll_for_set,
                Some(&field_for_set),
                Some(&scope_for_set),
            )
        })
        .await;
    if res.is_err() {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "WRITE_FAILED", "");
    }
    pool.schema_cache.invalidate(&collection);
    (
        StatusCode::OK,
        Json(json!({
            "owner_field": body.field,
            "read_scope":  body.read_scope,
        })),
    )
        .into_response()
}

pub async fn clear_owner_field_handler(
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
    Extension(t): Extension<TenantRef>,
) -> Response {
    if !matches!(ctx, AuthCtx::Service) {
        return json_error(
            StatusCode::FORBIDDEN,
            "SERVICE_ONLY",
            "service key required",
        );
    }
    let collection = match params.get("coll") {
        Some(c) => c.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing collection"),
    };
    let pool = t.pool.clone();
    let coll_for_clear = collection.clone();
    let res = pool
        .with_writer(move |c| {
            crate::storage::schema::set_owner_field(c, &coll_for_clear, None, None)
        })
        .await;
    if res.is_err() {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "WRITE_FAILED", "");
    }
    pool.schema_cache.invalidate(&collection);
    (StatusCode::OK, Json(json!({"cleared": true}))).into_response()
}

/// Validate that `field` exists in `table` and is a FK to `_system_users(id)`.
fn validate_owner_column(
    conn: &Connection,
    table: &str,
    field: &str,
) -> rusqlite::Result<Result<(), &'static str>> {
    // 1) Column exists?
    let cols: Vec<String> = conn
        .prepare(&format!(
            "PRAGMA table_info(\"{}\")",
            table.replace('"', "\"\"")
        ))?
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(Result::ok)
        .collect();
    if !cols.iter().any(|c| c == field) {
        return Ok(Err("OWNER_FIELD_INVALID_COLUMN"));
    }
    // 2) FK to _system_users(id)?
    // PRAGMA foreign_key_list columns: id(0), seq(1), table(2), from(3), to(4), ...
    let fks: Vec<(String, String, String)> = conn
        .prepare(&format!(
            "PRAGMA foreign_key_list(\"{}\")",
            table.replace('"', "\"\"")
        ))?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(2)?, // referenced table
                r.get::<_, String>(3)?, // from column (in this table)
                r.get::<_, String>(4)?, // to column (in referenced table)
            ))
        })?
        .filter_map(Result::ok)
        .collect();
    let ok = fks
        .iter()
        .any(|(ref_t, from, to)| ref_t == "_system_users" && from == field && to == "id");
    if !ok {
        return Ok(Err("OWNER_FIELD_NOT_FK"));
    }
    Ok(Ok(()))
}


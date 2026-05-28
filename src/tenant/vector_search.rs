//! POST /t/{tenant}/collections/{coll}/search
//!
//! Structured similarity search over a vector field. Builds the SQL
//! itself from the body (no raw SQL from the caller) so anon and user
//! tokens can safely call it — see CLAUDE.md "User tokens denied on
//! /query but allowed on /search" for rationale.

use crate::auth::middleware::AuthCtx;
use crate::error::{json_error, json_error_with_aliases};
use crate::query::vector_codec;
use crate::query::vector_filter::{self, FilterAst, FilterError};
use crate::storage::schema::DmlVerb;
use crate::tenant::router::{TenantRef, TokenRole};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::types::{Value, ValueRef};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct SearchBody {
    pub field: String,
    pub vector: serde_json::Value,
    pub k: u32,
    #[serde(default = "default_metric")]
    pub metric: String,
    #[serde(default)]
    pub r#where: Option<FilterAst>,
    #[serde(default)]
    pub select: Option<Vec<String>>,
}

fn default_metric() -> String {
    "cosine".to_string()
}

pub async fn search_handler(
    Extension(ctx): Extension<AuthCtx>,
    Extension(tenant): Extension<TenantRef>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(body): Json<SearchBody>,
) -> Response {
    if !(1..=1000).contains(&body.k) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "K_OUT_OF_RANGE",
            "k must be between 1 and 1000",
        );
    }
    let distance_fn = match body.metric.as_str() {
        "cosine" => "vec_distance_cosine",
        "l2" => "vec_distance_l2",
        "l1" => "vec_distance_l1",
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "INVALID_METRIC",
                "metric must be one of: cosine, l2, l1",
            );
        }
    };

    let pool = tenant.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.clone();
    let schema_res = pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await;
    let schema = match schema_res {
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

    if matches!(tenant.role, TokenRole::Anon)
        && schema.owner_field.is_some()
        && schema.read_scope.as_deref() == Some("own")
    {
        return json_error(
            StatusCode::FORBIDDEN,
            "ANON_FORBIDDEN_OWNER_SCOPED",
            "anon cannot search owner-scoped collection with read_scope=own",
        );
    }
    if !crate::storage::schema::has_dml_cap(tenant.role, DmlVerb::Select, &schema) {
        return json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "ANON_CAP_DENIED",
            &["ANON_DENIED"],
            &format!("role lacks 'select' on collection '{coll}'"),
        );
    }

    let vf = match schema.vector_fields.iter().find(|v| v.name == body.field) {
        Some(v) => v.clone(),
        None => {
            return json_error(
                StatusCode::NOT_FOUND,
                "VECTOR_FIELD_NOT_FOUND",
                &format!("no vector field {:?} on collection {:?}", body.field, coll),
            );
        }
    };

    let qvec = match vector_codec::pack(&vf.name, vf.dim, &body.vector) {
        Ok(v) => v,
        Err(vector_codec::VectorCodecError::DimMismatch { .. }) => {
            return json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VECTOR_DIM_MISMATCH",
                &format!("query vector dim != {}", vf.dim),
            );
        }
        Err(vector_codec::VectorCodecError::NonFinite { .. }) => {
            return json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VECTOR_NON_FINITE",
                "query vector contains NaN or Inf",
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VECTOR_TYPE_ERROR",
                &e.to_string(),
            );
        }
    };

    let (where_sql, mut where_binds): (String, Vec<Value>) = match &body.r#where {
        None => ("1=1".to_string(), vec![]),
        Some(ast) => match vector_filter::compile(&schema, ast) {
            Ok(t) => t,
            Err(FilterError::UnknownField(f)) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "FILTER_UNKNOWN_FIELD",
                    &format!("unknown field in filter: {f:?}"),
                );
            }
            Err(FilterError::VectorField(f)) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "FILTER_VECTOR_FIELD",
                    &format!("filter cannot target vector field: {f:?}"),
                );
            }
            Err(FilterError::TooDeep) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "FILTER_TOO_DEEP",
                    &format!(
                        "filter nesting exceeds max depth ({})",
                        vector_filter::MAX_FILTER_DEPTH
                    ),
                );
            }
            Err(e) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "FILTER_PARSE_ERROR",
                    &e.to_string(),
                );
            }
        },
    };

    // User token + owner_field=own → auto-append the row filter.
    let mut owner_clause = String::new();
    if let (TokenRole::User, Some(of), Some(scope)) = (
        tenant.role,
        schema.owner_field.as_deref(),
        schema.read_scope.as_deref(),
    ) {
        if scope == "own" {
            if let AuthCtx::User { user_id, .. } = &ctx {
                owner_clause = format!(" AND \"{}\" = ?", of.replace('"', "\"\""));
                where_binds.push(Value::Text(user_id.clone()));
            }
        }
    }

    // Default select: all non-vector fields.
    let select_cols: Vec<String> = match &body.select {
        Some(req) => req
            .iter()
            .filter(|n| !schema.vector_fields.iter().any(|v| v.name == **n))
            .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
            .collect(),
        None => schema
            .fields
            .iter()
            .filter(|f| !schema.vector_fields.iter().any(|v| v.name == f.name))
            .map(|f| format!("\"{}\"", f.name.replace('"', "\"\"")))
            .collect(),
    };
    let select_list = if select_cols.is_empty() {
        "id".to_string()
    } else {
        select_cols.join(", ")
    };

    let sql = format!(
        "SELECT {select_list}, {distance_fn}(\"{}\", ?) AS _distance \
         FROM \"{}\" WHERE {where_sql}{owner_clause} \
         ORDER BY _distance LIMIT ?",
        vf.name.replace('"', "\"\""),
        coll.replace('"', "\"\""),
    );

    let mut binds: Vec<Value> = Vec::with_capacity(2 + where_binds.len());
    binds.push(Value::Blob(qvec));
    binds.extend(where_binds);
    binds.push(Value::Integer(body.k as i64));

    let metric_owned = body.metric.clone();
    let k_owned = body.k;
    let exec_res: rusqlite::Result<Vec<serde_json::Value>> = pool
        .with_reader(move |c| {
            let mut stmt = c.prepare(&sql)?;
            let col_names: Vec<String> =
                stmt.column_names().iter().map(|s| s.to_string()).collect();
            let mut rows_iter = stmt.query(rusqlite::params_from_iter(binds.iter()))?;
            let mut out = Vec::new();
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
            Ok(out)
        })
        .await;

    match exec_res {
        Ok(rows) => Json(json!({
            "rows": rows,
            "k": k_owned,
            "metric": metric_owned,
            "truncated": false,
        }))
        .into_response(),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

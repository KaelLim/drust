use crate::storage::schema::{describe_collection, list_collections};
use crate::tenant::router::{TenantAuthState, TenantRef, require_service};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};

pub async fn list_handler(Extension(t): Extension<TenantRef>) -> Response {
    let pool = t.pool.clone();
    let out = pool.with_reader(list_collections).await;
    match out {
        Ok(list) => Json(serde_json::json!({ "collections": list })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn describe_handler(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll)): Path<(String, String)>,
) -> Response {
    let pool = t.pool.clone();
    let out = pool
        .with_reader(move |c| describe_collection(c, &coll))
        .await;
    match out {
        Ok(Some(schema)) => Json(serde_json::to_value(schema).unwrap()).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "collection not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Index REST handlers ───────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct CreateIndexBody {
    pub fields: Vec<String>,
    #[serde(default)]
    pub unique: Option<bool>,
    #[serde(default)]
    pub force: Option<bool>,
}

pub async fn create_index_handler(
    State(state): State<TenantAuthState>,
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(body): Json<CreateIndexBody>,
) -> Response {
    if let Err(r) = require_service(&t) {
        return r;
    }
    match crate::mcp::tools::index::create_index_with_threshold(
        &t.pool,
        &coll,
        &body.fields,
        body.unique.unwrap_or(false),
        body.force.unwrap_or(false),
        state.index_large_table_rows,
    )
    .await
    {
        Ok(v) => {
            let extras = serde_json::json!({
                "index_name":   v["name"].clone(),
                "index_fields": &body.fields,
                "row_count":    v["row_count_at_build"].clone(),
                "force_used":   body.force.unwrap_or(false),
            });
            let mut r = (StatusCode::CREATED, axum::Json(v)).into_response();
            r.extensions_mut()
                .insert(crate::safety::audit::AuditExtra(extras));
            r
        }
        Err(e) => map_index_error(e),
    }
}

pub async fn drop_index_handler(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, _coll, name)): Path<(String, String, String)>,
) -> Response {
    if let Err(r) = require_service(&t) {
        return r;
    }
    // REST drop is name-only; field-based resolution is MCP-only.
    match crate::mcp::tools::index::drop_index(&t.pool, &_coll, Some(&name), None).await {
        Ok(v) => {
            let extras = serde_json::json!({ "index_name": &name });
            let mut r = axum::Json(v).into_response();
            r.extensions_mut()
                .insert(crate::safety::audit::AuditExtra(extras));
            r
        }
        Err(e) => map_index_error(e),
    }
}

fn map_index_error(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let (status, code) = if msg.contains("no such collection") || msg.contains("no such index") {
        (StatusCode::NOT_FOUND, "NOT_FOUND")
    } else if msg.contains("not found on collection") {
        (StatusCode::NOT_FOUND, "FIELD_NOT_FOUND")
    } else if msg.contains("LARGE_TABLE") {
        (StatusCode::CONFLICT, "LARGE_TABLE")
    } else if msg.contains("already exists") {
        (StatusCode::CONFLICT, "INDEX_EXISTS")
    } else if msg.contains("UNIQUE") || msg.contains("unique") {
        (StatusCode::CONFLICT, "UNIQUE_VIOLATION")
    } else if msg.contains("INVALID_PARAMS")
        || msg.contains("must be non-empty")
        || msg.contains("non-empty")
        || msg.contains("duplicate")
    {
        (StatusCode::BAD_REQUEST, "INVALID_PARAMS")
    } else if msg.contains("invalid identifier") {
        (StatusCode::BAD_REQUEST, "INVALID_IDENTIFIER")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
    };
    let body = serde_json::json!({ "error_code": code, "message": msg });
    let mut r = Json(body).into_response();
    *r.status_mut() = status;
    r
}

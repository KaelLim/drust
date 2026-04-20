use crate::storage::schema::{describe_collection, list_collections};
use crate::tenant::router::TenantRef;
use axum::extract::Path;
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
    let out = pool.with_reader(move |c| describe_collection(c, &coll)).await;
    match out {
        Ok(Some(schema)) => Json(serde_json::to_value(schema).unwrap()).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "collection not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

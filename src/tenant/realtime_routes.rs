//! v1.16 — service-only endpoint to toggle SSE realtime broadcast on
//! a single collection. Cache-invalidates and evicts the broadcast
//! channel so the toggle takes effect immediately.

use crate::error::json_error;
use crate::storage::schema::{
    collection_exists, is_protected_collection, write_realtime_enabled,
};
use crate::tenant::events::EventBus;
use crate::tenant::router::{TenantRef, TokenRole};
use axum::Extension;
use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct PutRealtimeBody {
    pub enabled: bool,
}

/// PUT `/t/{tenant}/collections/{coll}/realtime`. Service-only.
pub async fn put_realtime_handler(
    Extension(t): Extension<TenantRef>,
    Path((tenant, coll)): Path<(String, String)>,
    Json(body): Json<PutRealtimeBody>,
    bus: EventBus,
) -> Response {
    // 1. service-only.
    if !matches!(t.role, TokenRole::Service) {
        return json_error(
            StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            "service token required",
        )
        .into_response();
    }
    // 2. protected.
    if is_protected_collection(&coll) {
        return json_error(
            StatusCode::FORBIDDEN,
            "PROTECTED_COLLECTION",
            "cannot toggle realtime on _system_ collection",
        )
        .into_response();
    }
    // 3. existence check.
    let pool = t.pool.clone();
    let coll_check = coll.clone();
    let exists = pool
        .with_reader(move |c| collection_exists(c, &coll_check))
        .await;
    match exists {
        Ok(true) => {}
        Ok(false) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "UNKNOWN_COLLECTION",
                "no such collection",
            )
            .into_response();
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            )
            .into_response();
        }
    }
    // 4. write through the writer mutex.
    let coll_for_writer = coll.clone();
    let enabled = body.enabled;
    if let Err(e) = pool
        .with_writer(move |c| write_realtime_enabled(c, &coll_for_writer, enabled))
        .await
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        )
        .into_response();
    }
    // 5. invalidate cache BEFORE evicting bus channel — so any subscriber
    //    that races in between will fail-fast on the cache reload.
    pool.schema_cache.invalidate(&coll);
    if !enabled {
        bus.evict_collection(&tenant, &coll);
    }
    Json(json!({
        "ok": true,
        "collection": coll,
        "realtime_enabled": enabled,
    }))
    .into_response()
}

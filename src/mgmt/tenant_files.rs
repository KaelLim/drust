//! Tenant-side file handlers (private bytes proxy in this task; upload/list/get/delete in task 19;
//! sign in task 18).
//!
//! Routes mount under /drust/t/<tenant>/files/* behind tenant bearer auth.
//! The handlers open the per-tenant data.sqlite directly to fetch the
//! _system_files row, then stream bytes from the right Garage bucket.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use std::sync::Arc;

use crate::storage::{
    files::{Owner, Visibility, bucket_for_upload, map_file_row},
    garage::GarageClient,
};

#[derive(Clone)]
pub struct TenantFilesState {
    pub garage: Option<Arc<GarageClient>>,
    pub data_root: std::path::PathBuf,
    pub disk_min_free_pct: u8,
    pub max_upload_bytes: usize,
    pub public_base_url: String,
}

/// GET /drust/t/<tenant>/files/<key>/bytes
/// Streams the file body. Auth via bearer_auth_layer (must be a service token
/// for the tenant — anon tokens will be 403 by the dispatch layer for any
/// non-list operation).
pub async fn stream_bytes(
    State(state): State<TenantFilesState>,
    Path((tenant_id, key)): Path<(String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let garage = state.garage.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage not configured".into(),
        )
    })?;

    let conn = crate::storage::tenant_db::open_read(&state.data_root, &tenant_id)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("tenant: {e}")))?;

    let row = conn
        .query_row(
            "SELECT * FROM _system_files WHERE key = ?1",
            rusqlite::params![key],
            map_file_row,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => (StatusCode::NOT_FOUND, "not found".into()),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    let visibility = if row.visibility == "public" {
        Visibility::Public
    } else {
        Visibility::Private
    };
    let bucket = bucket_for_upload(&Owner::Tenant(tenant_id.clone()), visibility);

    let stream = garage
        .get_object_stream_in(&bucket, &key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("get: {e}")))?;

    let body = Body::from_stream(stream);
    let ct = row
        .content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    let disp_mode = row.content_disposition.as_deref().unwrap_or("inline");
    let ascii = crate::storage::garage::ascii_fallback_filename(&row.original_name);
    let pct = urlencoding::encode(&row.original_name);
    let cd = format!("{disp_mode}; filename=\"{ascii}\"; filename*=UTF-8''{pct}");
    let cc = row.cache_control.as_deref().unwrap_or("private, no-store");

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, ct.parse().unwrap());
    headers.insert(header::CONTENT_DISPOSITION, cd.parse().unwrap());
    headers.insert(header::CACHE_CONTROL, cc.parse().unwrap());

    Ok((headers, body).into_response())
}

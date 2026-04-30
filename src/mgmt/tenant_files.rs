//! Tenant-side file handlers (private bytes proxy, upload/list/get/delete, sign).
//!
//! Routes mount under /drust/t/<tenant>/files/* behind tenant bearer auth.
//! The handlers open the per-tenant data.sqlite directly to fetch the
//! _system_files row, then stream bytes from the right Garage bucket.

use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use serde::Serialize;
use std::sync::Arc;

use crate::storage::{
    files::{FileRow, Owner, Visibility, build_public_url, map_file_row},
    garage::GarageClient,
};

#[derive(serde::Deserialize, Default)]
pub struct SignRequest {
    pub expires_in: Option<u64>,
    pub download: Option<bool>,
}

#[derive(Debug, serde::Serialize)]
pub struct SignResponse {
    pub url: String,
    pub expires_at: Option<String>,
}

#[derive(Clone)]
pub struct TenantFilesState {
    pub garage: Option<Arc<GarageClient>>,
    pub data_root: std::path::PathBuf,
    pub disk_min_free_pct: u8,
    pub max_upload_bytes: usize,
    pub public_base_url: String,
    /// HMAC secret for mint-and-verify of drust-served signed URLs.
    pub url_sign_secret: Arc<[u8; 32]>,
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
    let bucket = crate::storage::files::bucket_for(visibility);
    let object_key = crate::storage::files::compose_key(&Owner::Tenant(tenant_id.clone()), &key);

    let stream = garage
        .get_object_stream_in(bucket, &object_key)
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

/// POST /drust/t/<tenant>/files/<key>/sign
pub async fn sign_url(
    State(state): State<TenantFilesState>,
    Path((tenant_id, key)): Path<(String, String)>,
    axum::Json(req): axum::Json<SignRequest>,
) -> Result<axum::Json<SignResponse>, (StatusCode, String)> {
    let expires_in = req.expires_in.unwrap_or(3600);
    if expires_in == 0 || expires_in > 604_800 {
        return Err((
            StatusCode::BAD_REQUEST,
            "expires_in must be 1–604800 seconds (7 days)".into(),
        ));
    }

    let conn = crate::storage::tenant_db::open_read(&state.data_root, &tenant_id)
        .map_err(|e| (StatusCode::NOT_FOUND, format!("tenant: {e}")))?;
    let row = conn
        .query_row(
            "SELECT * FROM _system_files WHERE key = ?1",
            rusqlite::params![key],
            crate::storage::files::map_file_row,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => (StatusCode::NOT_FOUND, "not found".into()),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    if row.visibility == "public" {
        let url = crate::storage::files::build_public_url(
            &state.public_base_url,
            &crate::storage::files::Owner::Tenant(tenant_id.clone()),
            crate::storage::files::Visibility::Public,
            &row.key,
        );
        return Ok(axum::Json(SignResponse {
            url,
            expires_at: None,
        }));
    }

    // Private: mint a drust-HMAC-signed URL pointing at our public origin.
    let _ = state.garage.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage not configured".to_string(),
        )
    })?;
    let download = req.download.unwrap_or(false);
    let expires_ts = chrono::Utc::now().timestamp() + expires_in as i64;
    let owner = crate::storage::signed_url::Owner::Tenant(tenant_id);
    let token = crate::storage::signed_url::mint(
        &*state.url_sign_secret,
        &owner,
        &row.key,
        expires_ts,
        download,
    );
    let url = crate::storage::signed_url::build_url(
        &state.public_base_url,
        &owner,
        &row.key,
        expires_ts,
        download,
        &token,
    );
    let expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64)).to_rfc3339();
    Ok(axum::Json(SignResponse {
        url,
        expires_at: Some(expires_at),
    }))
}

// ─── Task 19: upload / list / get_one / delete_one ───────────────────────────

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub id: String,
    pub key: String,
    pub url: String,
    pub bytes: i64,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub files: Vec<FileRow>,
    pub file_count: usize,
    pub used_bytes: i64,
}

/// POST /drust/t/<tenant>/files
/// Multipart upload (same field shape as admin route): file, visibility,
/// disposition, cache_control, meta.  Resolves bucket via visibility, INSERTs
/// into the per-tenant _system_files, PUTs to Garage.  Content-Length pre-check
/// and best-effort disk check mirror the admin handler (Task 15).
pub async fn upload(
    State(state): State<TenantFilesState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    multipart: Multipart,
) -> axum::response::Response {
    use crate::mgmt::public_files::{UploadFields, parse_upload_fields};
    use crate::storage::files::{Disposition, default_cache_control};

    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

    // Disk check — best-effort; skip if path absent (mirrors Task 15).
    match crate::storage::disk::disk_stats(std::path::Path::new("/var/lib/garage")) {
        Ok(stats) => {
            if (stats.free_pct as u8) < state.disk_min_free_pct {
                return (
                    StatusCode::INSUFFICIENT_STORAGE,
                    format!(
                        "disk too full: {:.1}% free, minimum {}% required",
                        stats.free_pct, state.disk_min_free_pct
                    ),
                )
                    .into_response();
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "disk_stats for /var/lib/garage failed — skipping disk check");
        }
    }

    // Content-Length pre-check.
    if let Some(cl) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        && cl as usize > state.max_upload_bytes
    {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "upload exceeds {} MB limit ({} bytes provided)",
                state.max_upload_bytes / (1024 * 1024),
                cl
            ),
        )
            .into_response();
    }

    // Parse multipart — reuse Task 15's helper.
    let fields = match parse_upload_fields(multipart).await {
        Ok(f) => f,
        Err(e) if e.starts_with("__413__") => {
            return (StatusCode::PAYLOAD_TOO_LARGE, e[7..].to_string()).into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let UploadFields {
        original_name,
        explicit_ct,
        body,
        visibility,
        disposition,
        cache_control_override,
        meta_json,
    } = fields;

    let size = body.len() as i64;

    // Resolve content-type.
    let sniffed_ct = explicit_ct
        .filter(|ct| ct != "application/octet-stream")
        .or_else(|| {
            mime_guess::from_path(&original_name)
                .first_raw()
                .map(|s| s.to_string())
        });

    // Build cache_control.
    let cache_control = cache_control_override
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_cache_control(visibility, disposition).to_string());

    let disp_mode = match disposition {
        Disposition::Inline => "inline",
        Disposition::Attachment => "attachment",
    };
    let vis_str = match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
    };
    let bucket = crate::storage::files::bucket_for(visibility);

    // DB stores the bare key (`<uuid>.<ext>`); Garage uses `<tenant>/<key>`
    // so a single bucket holds everyone.
    let ext = std::path::Path::new(&original_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("bin");
    let key = format!("{}.{}", uuid::Uuid::new_v4(), ext);
    let object_key = crate::storage::files::compose_key(&Owner::Tenant(tenant_id.clone()), &key);

    // SQLite-first INSERT into tenant DB.
    {
        let conn =
            crate::storage::tenant_db::open_write(&state.data_root, &tenant_id).map_err(|e| {
                tracing::error!(error = %e, "tenant db open failed");
                e
            });
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("tenant db: {e}"))
                    .into_response();
            }
        };
        if let Err(e) = conn.execute(
            "INSERT INTO _system_files
             (key, original_name, content_type, size_bytes, content_disposition,
              visibility, cache_control, meta_json, uploader)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                &key,
                &original_name,
                &sniffed_ct,
                size,
                disp_mode,
                vis_str,
                &cache_control,
                &meta_json,
                "service",
            ],
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("db insert: {e}")).into_response();
        }
    }

    // PUT to Garage — compensate on failure.
    if let Err(e) = garage
        .put_object_in(
            bucket,
            &object_key,
            body,
            sniffed_ct.as_deref(),
            disp_mode,
            &original_name,
            Some(&cache_control),
            meta_json.as_deref(),
        )
        .await
    {
        tracing::error!(
            object_key = %object_key,
            bucket = %bucket,
            error = format!("{e:#}"),
            "garage put_object_in failed — rolling back metadata row"
        );
        // Compensating delete.
        if let Ok(conn) = crate::storage::tenant_db::open_write(&state.data_root, &tenant_id) {
            let _ = conn.execute(
                "DELETE FROM _system_files WHERE key = ?1",
                rusqlite::params![&key],
            );
        }
        return (StatusCode::BAD_GATEWAY, format!("garage put: {e:#}")).into_response();
    }

    let url = build_public_url(
        &state.public_base_url,
        &Owner::Tenant(tenant_id),
        visibility,
        &key,
    );
    axum::Json(UploadResponse {
        id: key.clone(),
        key,
        url,
        bytes: size,
    })
    .into_response()
}

/// GET /drust/t/<tenant>/files
/// Returns all rows in _system_files for this tenant, ordered by uploaded_at DESC.
pub async fn list(
    State(state): State<TenantFilesState>,
    Path(tenant_id): Path<String>,
) -> axum::response::Response {
    let conn = match crate::storage::tenant_db::open_read(&state.data_root, &tenant_id) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::NOT_FOUND, format!("tenant: {e}")).into_response();
        }
    };

    let mut stmt = match conn.prepare("SELECT * FROM _system_files ORDER BY uploaded_at DESC") {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("db prepare: {e}"),
            )
                .into_response();
        }
    };

    let rows: Vec<FileRow> = match stmt.query_map([], map_file_row) {
        Ok(it) => it.filter_map(|r| r.ok()).collect(),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("db query: {e}")).into_response();
        }
    };

    let used_bytes: i64 = rows.iter().map(|r| r.size_bytes).sum();
    let file_count = rows.len();

    axum::Json(ListResponse {
        files: rows,
        file_count,
        used_bytes,
    })
    .into_response()
}

/// GET /drust/t/<tenant>/files/<key>
/// Returns the _system_files row for a single key, or 404.
pub async fn get_one(
    State(state): State<TenantFilesState>,
    Path((tenant_id, key)): Path<(String, String)>,
) -> axum::response::Response {
    let conn = match crate::storage::tenant_db::open_read(&state.data_root, &tenant_id) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::NOT_FOUND, format!("tenant: {e}")).into_response();
        }
    };

    match conn.query_row(
        "SELECT * FROM _system_files WHERE key = ?1",
        rusqlite::params![key],
        map_file_row,
    ) {
        Ok(row) => axum::Json(row).into_response(),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// DELETE /drust/t/<tenant>/files/<key>
/// Removes the Garage object (idempotent on 404) then deletes the DB row.
/// Returns 204 NO_CONTENT on success, 404 if the row doesn't exist.
pub async fn delete_one(
    State(state): State<TenantFilesState>,
    Path((tenant_id, key)): Path<(String, String)>,
) -> axum::response::Response {
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

    // Look up the row to find bucket (visibility-dependent).
    let (visibility_str, bucket) = {
        let conn = match crate::storage::tenant_db::open_read(&state.data_root, &tenant_id) {
            Ok(c) => c,
            Err(e) => {
                return (StatusCode::NOT_FOUND, format!("tenant: {e}")).into_response();
            }
        };
        let vis: String = match conn.query_row(
            "SELECT visibility FROM _system_files WHERE key = ?1",
            rusqlite::params![key],
            |r| r.get(0),
        ) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return (StatusCode::NOT_FOUND, "not found").into_response();
            }
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        };
        let visibility = if vis == "public" {
            Visibility::Public
        } else {
            Visibility::Private
        };
        let bucket = crate::storage::files::bucket_for(visibility);
        (vis, bucket.to_string())
    };

    // Garage object key is the tenant-prefixed form.
    let object_key = crate::storage::files::compose_key(&Owner::Tenant(tenant_id.clone()), &key);
    // Delete from Garage — idempotent per Task 8.
    if let Err(e) = garage.delete_object_in(&bucket, &object_key).await {
        tracing::error!(
            key = %key,
            bucket = %bucket,
            visibility = %visibility_str,
            error = format!("{e:#}"),
            "garage delete_object_in failed"
        );
        return (StatusCode::BAD_GATEWAY, format!("garage delete: {e:#}")).into_response();
    }

    // Delete the DB row.
    let conn = match crate::storage::tenant_db::open_write(&state.data_root, &tenant_id) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("db open: {e}")).into_response();
        }
    };
    if let Err(e) = conn.execute(
        "DELETE FROM _system_files WHERE key = ?1",
        rusqlite::params![key],
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("db delete: {e}")).into_response();
    }

    StatusCode::NO_CONTENT.into_response()
}

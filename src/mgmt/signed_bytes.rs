//! Public (unauth) GET handlers that serve a drust-signed download URL.
//!
//! Routes mount outside the admin-session / bearer-auth layers. Auth is
//! the HMAC-SHA256 token in the `t` query param. See
//! `crate::storage::signed_url` for the mint/verify helpers.
//!
//! Two endpoints:
//!   `GET /drust/s/admin/{key}?e=<unix>&t=<token>&d=0|1`  (admin buckets)
//!   `GET /drust/s/t/{tenant}/{key}?e=<unix>&t=<token>&d=0|1` (tenant buckets)

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use rusqlite::Connection;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::storage::files::{self, FileRow, map_file_row};
use crate::storage::garage::GarageClient;
use crate::storage::signed_url::{self, Owner as SignOwner};

#[derive(Clone)]
pub struct SignedBytesState {
    pub meta: Arc<Mutex<Connection>>,
    pub data_root: std::path::PathBuf,
    pub garage: Option<Arc<GarageClient>>,
    pub url_sign_secret: Arc<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
pub struct SigQs {
    pub e: i64,
    pub t: String,
    #[serde(default)]
    pub d: Option<String>,
}

fn is_download(qs: &SigQs) -> bool {
    matches!(qs.d.as_deref(), Some("1"))
}

fn respond<S>(row: &FileRow, stream: S, download: bool) -> axum::response::Response
where
    S: futures::Stream<Item = Result<bytes::Bytes, anyhow::Error>> + Send + 'static,
{
    // P0-1 (2026-07-29 audit) / redesigned 2026-07-30 — the signed-URL
    // responder lives on the same origin as the admin UI; a script-executing
    // type is served under `Content-Security-Policy: sandbox` instead of
    // being downgraded — see `files::content_security_policy_for`.
    let ct = row
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let disp_mode = if download {
        "attachment"
    } else {
        row.content_disposition.as_deref().unwrap_or("inline")
    };
    let ascii = crate::storage::garage::ascii_fallback_filename(&row.original_name);
    let pct = urlencoding::encode(&row.original_name);
    let cd = format!("{disp_mode}; filename=\"{ascii}\"; filename*=UTF-8''{pct}");
    let cc = row.cache_control.as_deref().unwrap_or("private, no-store");
    // Stored values are unvalidated caller input — never `.unwrap()` them.
    use crate::storage::files::safe_header_value;
    let mut headers = axum::http::HeaderMap::new();
    // Content-Type, nosniff, and the conditional sandbox CSP are one shared
    // function across all three drust byte responders — see
    // `files::insert_content_type_headers`.
    crate::storage::files::insert_content_type_headers(&mut headers, &ct);
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        safe_header_value(&cd, "attachment"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        safe_header_value(cc, "private, no-store"),
    );
    (headers, axum::body::Body::from_stream(stream)).into_response()
}

/// GET /drust/s/admin/{key}?e=<expires>&t=<token>&d=<0|1>
pub async fn admin_signed_bytes(
    State(state): State<SignedBytesState>,
    Path(key): Path<String>,
    Query(qs): Query<SigQs>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let download = is_download(&qs);
    if !signed_url::verify(
        &*state.url_sign_secret,
        &SignOwner::Admin,
        &key,
        qs.e,
        download,
        &qs.t,
    ) {
        return Err((StatusCode::FORBIDDEN, "invalid or expired token".into()));
    }

    let garage = state.garage.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage not configured".into(),
        )
    })?;

    let conn = state.meta.lock().await;
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
    drop(conn);

    let visibility = if row.visibility == "public" {
        files::Visibility::Public
    } else {
        files::Visibility::Private
    };
    let bucket = files::bucket_for(visibility);

    let stream = garage
        .get_object_stream_in(bucket, &key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("get: {e}")))?;

    Ok(respond(&row, stream, download))
}

/// GET /drust/s/t/{tenant}/{key}?e=<expires>&t=<token>&d=<0|1>
pub async fn tenant_signed_bytes(
    State(state): State<SignedBytesState>,
    Path((tenant_id, key)): Path<(String, String)>,
    Query(qs): Query<SigQs>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let download = is_download(&qs);
    if !signed_url::verify(
        &*state.url_sign_secret,
        &SignOwner::Tenant(tenant_id.clone()),
        &key,
        qs.e,
        download,
        &qs.t,
    ) {
        return Err((StatusCode::FORBIDDEN, "invalid or expired token".into()));
    }

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
    drop(conn);

    let visibility = if row.visibility == "public" {
        files::Visibility::Public
    } else {
        files::Visibility::Private
    };
    let bucket = files::bucket_for(visibility);
    let object_key = files::compose_key(&files::Owner::Tenant(tenant_id), &key);

    let stream = garage
        .get_object_stream_in(bucket, &object_key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("get: {e}")))?;

    Ok(respond(&row, stream, download))
}

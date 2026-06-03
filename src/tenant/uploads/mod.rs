//! v1.33 — Mode B large-file upload: tus 1.0 server + spool-to-Garage.
pub mod session;

use crate::error::{json_error, json_error_with_aliases};
use crate::mgmt::tenant_files::TenantFilesState;
use crate::tenant::router::{TenantRef, TokenRole};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header::HeaderName};
use axum::response::{IntoResponse, Response};
use std::path::PathBuf;

const TUS_VERSION: &str = "1.0.0";

fn hname(s: &'static str) -> HeaderName { HeaderName::from_static(s) }

fn require_service(t: &TenantRef) -> Result<(), Response> {
    if matches!(t.role, TokenRole::Anon | TokenRole::User) {
        return Err(json_error_with_aliases(
            StatusCode::FORBIDDEN, "WRITE_DENIED", &["SERVICE_REQUIRED"],
            "large upload requires a service key",
        ));
    }
    Ok(())
}

/// Spool path for a session: `<data_root>/tenants/<tid>/_uploads/<token>.part`.
fn spool_path(state: &TenantFilesState, tid: &str, token: &str) -> PathBuf {
    crate::storage::tenant_db::tenant_dir(&state.data_root, tid)
        .join("_uploads")
        .join(format!("{token}.part"))
}

/// OPTIONS /t/{tenant}/uploads — tus capability discovery.
pub async fn options(
    State(state): State<TenantFilesState>,
    axum::Extension(t): axum::Extension<TenantRef>,
    Path(_tenant): Path<String>,
) -> Response {
    if let Err(e) = require_service(&t) { return e; }
    let mut h = HeaderMap::new();
    h.insert(hname("tus-resumable"), TUS_VERSION.parse().unwrap());
    h.insert(hname("tus-version"), TUS_VERSION.parse().unwrap());
    h.insert(hname("tus-extension"), "creation,termination,expiration".parse().unwrap());
    h.insert(hname("tus-max-size"),
        state.large_upload_max_bytes.to_string().parse().unwrap());
    (StatusCode::NO_CONTENT, h).into_response()
}

/// POST /t/{tenant}/uploads — tus creation. Creates the session row + empty
/// spool file; returns 201 + Location (browser-facing, /drust-prefixed).
pub async fn create(
    State(state): State<TenantFilesState>,
    axum::Extension(t): axum::Extension<TenantRef>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Response {
    use session::{NewSession, derive_key, insert_session, parse_upload_metadata, count_in_flight};
    if let Err(e) = require_service(&t) { return e; }
    // No garage check here: creation only writes a session row + empty spool
    // file (Garage is touched only at finalize), and the /uploads routes mount
    // only when Garage is configured (main.rs gates files_router on it). The
    // create tests deliberately run with `garage: None`.

    // Upload-Length (required).
    let total_length = match headers.get("upload-length")
        .and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<i64>().ok())
    {
        Some(n) if n >= 0 => n,
        _ => return json_error(StatusCode::BAD_REQUEST, "UPLOAD_LENGTH_REQUIRED",
            "Upload-Length header required (non-negative integer)"),
    };
    if total_length as u64 > state.large_upload_max_bytes as u64 {
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "UPLOAD_TOO_LARGE",
            &format!("Upload-Length {total_length} exceeds limit {}", state.large_upload_max_bytes));
    }

    // Per-tenant concurrent-session cap.
    match count_in_flight(&t.pool).await {
        Ok(n) if n >= state.large_upload_max_sessions_per_tenant as i64 =>
            return json_error(StatusCode::TOO_MANY_REQUESTS, "TOO_MANY_UPLOADS",
                "too many in-flight uploads; finish or delete one first"),
        Ok(_) => {}
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string()),
    }

    // Metadata (filename / filetype / visibility).
    let meta = headers.get("upload-metadata")
        .and_then(|v| v.to_str().ok()).map(parse_upload_metadata).unwrap_or_default();
    let original_name = meta.get("filename").cloned().unwrap_or_else(|| "upload.bin".to_string());
    let visibility = match meta.get("visibility").map(|s| s.as_str()) {
        Some("public") => "public",
        _ => "private",
    };
    let content_type = meta.get("filetype").cloned().or_else(|| {
        mime_guess::from_path(&original_name).first_raw().map(|s| s.to_string())
    });

    let token = uuid::Uuid::new_v4().to_string();
    let key = derive_key(&original_name);
    let ttl = state.large_upload_session_ttl_secs as i64;
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(ttl)).to_rfc3339();

    // Create the empty spool file (and its dir) before the DB row, so a
    // crash leaves at most an orphan file (janitor-swept), never a row
    // without a spool.
    let spool = spool_path(&state, &tenant, &token);
    if let Some(parent) = spool.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "SPOOL_ERROR", &e.to_string());
        }
    }
    if let Err(e) = tokio::fs::File::create(&spool).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "SPOOL_ERROR", &e.to_string());
    }

    let row = NewSession {
        upload_token: token.clone(),
        tenant_id: tenant.clone(),
        key,
        visibility: visibility.to_string(),
        original_name,
        content_type,
        total_length,
        expires_at: expires_at.clone(),
    };
    if let Err(e) = insert_session(&t.pool, row).await {
        let _ = tokio::fs::remove_file(&spool).await; // compensate
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string());
    }

    let mut h = HeaderMap::new();
    h.insert(hname("tus-resumable"), TUS_VERSION.parse().unwrap());
    // Browser-facing path: Caddy strips /drust, so re-prepend it here.
    h.insert(axum::http::header::LOCATION,
        format!("/drust/t/{tenant}/uploads/{token}").parse().unwrap());
    h.insert(hname("upload-expires"), expires_at.parse().unwrap());
    (StatusCode::CREATED, h).into_response()
}

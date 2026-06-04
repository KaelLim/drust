//! v1.33 — Mode B large-file upload: tus 1.0 server + spool-to-Garage.
pub mod session;

use crate::error::{json_error, json_error_with_aliases};
use crate::mgmt::tenant_files::TenantFilesState;
use crate::storage::files::{Owner, Visibility, bucket_for, compose_key};
use crate::tenant::router::{TenantRef, TokenRole};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header::HeaderName};
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

/// Per-token append lock — serializes concurrent PATCHes to one spool file.
/// Keyed by the globally-unique upload token, so no cross-tenant collision.
fn token_locks() -> &'static DashMap<String, Arc<Mutex<()>>> {
    static LOCKS: OnceLock<DashMap<String, Arc<Mutex<()>>>> = OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}
fn token_lock(token: &str) -> Arc<Mutex<()>> {
    token_locks().entry(token.to_string()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
}

fn tus_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(hname("tus-resumable"), TUS_VERSION.parse().unwrap());
    h
}

pub(crate) const TUS_VERSION: &str = "1.0.0";
/// tus extensions this server implements — advertised by both the
/// `options` handler and the CORS-bypass capability layer in
/// `crate::tenant::inject_tus_capabilities` (kept here so the two can't drift).
pub(crate) const TUS_EXTENSION: &str = "creation,termination,expiration";

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
    h.insert(hname("tus-extension"), TUS_EXTENSION.parse().unwrap());
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

    // Disk guard on the spool filesystem (data_root).
    if let Ok(stats) = crate::storage::disk::disk_stats(&state.data_root) {
        if (stats.free_pct as u8) < state.disk_min_free_pct {
            return json_error(StatusCode::INSUFFICIENT_STORAGE, "DISK_FULL",
                "insufficient free disk for upload");
        }
    }

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

/// HEAD /t/{tenant}/uploads/{token} — resume probe.
pub async fn head(
    State(state): State<TenantFilesState>,
    axum::Extension(t): axum::Extension<TenantRef>,
    Path((tenant, token)): Path<(String, String)>,
) -> Response {
    if let Err(e) = require_service(&t) { return e; }
    if !session::is_valid_token(&token) {
        return (StatusCode::NOT_FOUND, tus_headers()).into_response();
    }
    let sess = match session::get_session(&t.pool, &token).await {
        Ok(Some(s)) if s.tenant_id == tenant => s,
        Ok(_) => return (StatusCode::NOT_FOUND, tus_headers()).into_response(),
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string()),
    };
    let offset = spool_len(&state, &tenant, &token).await;
    let mut h = tus_headers();
    h.insert(hname("upload-offset"), offset.to_string().parse().unwrap());
    h.insert(hname("upload-length"), sess.total_length.to_string().parse().unwrap());
    h.insert(axum::http::header::CACHE_CONTROL, "no-store".parse().unwrap());
    (StatusCode::OK, h).into_response()
}

/// Current durable offset = spool file size (0 if missing).
async fn spool_len(state: &TenantFilesState, tid: &str, token: &str) -> i64 {
    match tokio::fs::metadata(spool_path(state, tid, token)).await {
        Ok(m) => m.len() as i64,
        Err(_) => 0,
    }
}

/// PATCH /t/{tenant}/uploads/{token} — append a chunk; finalize on completion.
pub async fn patch(
    State(state): State<TenantFilesState>,
    axum::Extension(t): axum::Extension<TenantRef>,
    Path((tenant, token)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    use tokio::io::AsyncWriteExt;
    if let Err(e) = require_service(&t) { return e; }
    if !session::is_valid_token(&token) {
        return (StatusCode::NOT_FOUND, tus_headers()).into_response();
    }
    let sess = match session::get_session(&t.pool, &token).await {
        Ok(Some(s)) if s.tenant_id == tenant => s,
        Ok(_) => return (StatusCode::NOT_FOUND, tus_headers()).into_response(),
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string()),
    };
    let want_offset = headers.get("upload-offset")
        .and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<i64>().ok());

    let lock = token_lock(&token);
    let _guard = lock.lock().await;

    let spool = spool_path(&state, &tenant, &token);
    let cur = spool_len(&state, &tenant, &token).await;
    if want_offset != Some(cur) {
        let mut h = tus_headers();
        h.insert(hname("upload-offset"), cur.to_string().parse().unwrap());
        return (StatusCode::CONFLICT, h).into_response();
    }

    // Already complete → idempotent finalize retry (ignore any body).
    if cur == sess.total_length {
        return finalize_and_respond(&state, &t, &tenant, &token, &sess, cur).await;
    }
    if cur + body.len() as i64 > sess.total_length {
        return json_error(StatusCode::BAD_REQUEST, "UPLOAD_OVERFLOW",
            "chunk would exceed declared Upload-Length");
    }

    // Disk guard on the spool filesystem (data_root).
    if let Ok(stats) = crate::storage::disk::disk_stats(&state.data_root) {
        if (stats.free_pct as u8) < state.disk_min_free_pct {
            return (StatusCode::INSUFFICIENT_STORAGE, tus_headers()).into_response();
        }
    }

    // Append.
    let mut f = match tokio::fs::OpenOptions::new().append(true).open(&spool).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::NOT_FOUND, tus_headers()).into_response(),
    };
    if let Err(e) = f.write_all(&body).await {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "SPOOL_ERROR", &e.to_string());
    }
    let new_off = cur + body.len() as i64;

    if new_off == sess.total_length {
        return finalize_and_respond(&state, &t, &tenant, &token, &sess, new_off).await;
    }
    let mut h = tus_headers();
    h.insert(hname("upload-offset"), new_off.to_string().parse().unwrap());
    (StatusCode::NO_CONTENT, h).into_response()
}

/// SQLite-first, idempotent finalize. INSERT OR IGNORE the _system_files row,
/// stream spool→Garage, then delete spool + session. A Garage failure leaves
/// everything intact so the client's retried final PATCH re-runs this.
async fn finalize_and_respond(
    state: &TenantFilesState, t: &TenantRef, tenant: &str, token: &str,
    sess: &session::Session, offset: i64,
) -> Response {
    let Some(garage) = state.garage.clone() else {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "STORAGE_UNCONFIGURED", "storage not configured");
    };
    let visibility = if sess.visibility == "public" { Visibility::Public } else { Visibility::Private };
    let bucket = bucket_for(visibility);
    let object_key = compose_key(&Owner::Tenant(tenant.to_string()), &sess.key);
    let cache_control = crate::storage::files::default_cache_control(
        visibility, crate::storage::files::Disposition::Inline).to_string();
    let disp_mode = "inline";

    // 1. SQLite-first: INSERT OR IGNORE (idempotent across retries).
    {
        let key = sess.key.clone();
        let on = sess.original_name.clone();
        let ct = sess.content_type.clone();
        let cc = cache_control.clone();
        let vis = sess.visibility.clone();
        let total = sess.total_length;
        if let Err(e) = t.pool.with_writer(move |c| {
            c.execute(
                "INSERT OR IGNORE INTO _system_files
                   (key, original_name, content_type, size_bytes, content_disposition,
                    visibility, cache_control, meta_json, uploader)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, 'service')",
                rusqlite::params![key, on, ct, total, disp_mode, vis, cc],
            ).map(|_| ())
        }).await {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string());
        }
    }

    // 2. Stream spool → Garage.
    let spool = spool_path(state, tenant, token);
    if let Err(e) = garage.put_file_in(
        bucket, &object_key, &spool, sess.content_type.as_deref(),
        disp_mode, &sess.original_name, Some(&cache_control),
    ).await {
        tracing::error!(object_key = %object_key, error = format!("{e:#}"),
            "Mode B finalize put_file_in failed — session retained for retry");
        return json_error(StatusCode::BAD_GATEWAY, "GARAGE_PUT_FAILED",
            "object store write failed; retry the final PATCH to finalize");
    }

    // 3. Success → clean up.
    let _ = tokio::fs::remove_file(&spool).await;
    let _ = session::delete_session(&t.pool, token).await;
    token_locks().remove(token);

    let mut h = tus_headers();
    h.insert(hname("upload-offset"), offset.to_string().parse().unwrap());
    (StatusCode::NO_CONTENT, h).into_response()
}

/// GET /t/{tenant}/uploads — service-only list of in-flight sessions.
pub async fn list_sessions(
    State(_state): State<TenantFilesState>,
    axum::Extension(t): axum::Extension<TenantRef>,
    Path(_tenant): Path<String>,
) -> Response {
    if let Err(e) = require_service(&t) { return e; }
    match session::list_sessions(&t.pool).await {
        Ok(rows) => {
            let arr: Vec<_> = rows.into_iter().map(|s| serde_json::json!({
                "upload_token": s.upload_token,
                "key": s.key,
                "original_name": s.original_name,
                "total_length": s.total_length,
                "expires_at": s.expires_at,
            })).collect();
            axum::Json(serde_json::json!({ "sessions": arr })).into_response()
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string()),
    }
}

/// DELETE /t/{tenant}/uploads/{token} — tus termination (= manual discard).
pub async fn terminate(
    State(state): State<TenantFilesState>,
    axum::Extension(t): axum::Extension<TenantRef>,
    Path((tenant, token)): Path<(String, String)>,
) -> Response {
    if let Err(e) = require_service(&t) { return e; }
    if !session::is_valid_token(&token) {
        return (StatusCode::NOT_FOUND, tus_headers()).into_response();
    }
    match session::get_session(&t.pool, &token).await {
        Ok(Some(s)) if s.tenant_id == tenant => {}
        Ok(_) => return (StatusCode::NOT_FOUND, tus_headers()).into_response(),
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", &e.to_string()),
    }
    let _ = tokio::fs::remove_file(spool_path(&state, &tenant, &token)).await;
    let _ = session::delete_session(&t.pool, &token).await;
    token_locks().remove(&token);
    (StatusCode::NO_CONTENT, tus_headers()).into_response()
}

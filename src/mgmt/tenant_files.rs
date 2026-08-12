//! Tenant-side file handlers (private bytes proxy, upload/list/get/delete, sign).
//!
//! Routes mount under /drust/t/<tenant>/files/* behind tenant bearer auth.
//! The handlers open the per-tenant data.sqlite directly to fetch the
//! _system_files row, then stream bytes from the right Garage bucket.

use axum::{
    body::Body,
    extract::{FromRequestParts, Multipart, Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::middleware::AuthCtx;
use crate::storage::{
    files::{FileRow, Owner, Visibility, build_public_url, map_file_row},
    garage::GarageClient,
};

/// v1.63 (#950-B) — the caller a file verb runs as.
///
/// Three of the Mode-A verbs (upload / stream / delete) are mounted TWICE: on
/// the data plane behind `bearer_auth_layer`, and under `/admin` behind an
/// admin session cookie. The admin mount has no bearer, so it has no
/// `AuthCtx` — and "extension absent ⇒ treat as service" would be fail-OPEN
/// the moment a read gate reads it (T4 does). The two mounts are therefore
/// SEPARATE handlers over a shared `_inner`, and this enum is what they differ
/// by: the admin twin names `AdminPlane` explicitly, and the data-plane
/// handler cannot be reached at all without an identity (see
/// [`RequiredAuthCtx`]).
pub enum FileCaller {
    /// Admin session (`/admin/tenants/{id}/files/*`) — management face, full
    /// visibility, stamps uploads as `service` exactly as before the split.
    AdminPlane,
    /// Tenant bearer, resolved by `bearer_auth_layer`.
    DataPlane(AuthCtx),
}

impl FileCaller {
    /// Whether this caller has service power: the admin plane always, and a
    /// data-plane `AuthCtx::Service` (shared service token, admin PAT, or
    /// OAuth-issued token — all three are service-equivalent).
    pub fn is_service(&self) -> bool {
        match self {
            FileCaller::AdminPlane => true,
            FileCaller::DataPlane(ctx) => matches!(ctx, AuthCtx::Service { .. }),
        }
    }

    /// The `uploader` stamp for a row this caller creates: `service` /
    /// `anon` / the bare `u-…` user id. Same string shape tus has recorded
    /// since v1.42, so both stations' rows compare against `$auth` identically.
    pub fn uploader(&self) -> String {
        match self {
            FileCaller::AdminPlane => "service".to_string(),
            FileCaller::DataPlane(ctx) => crate::tenant::uploads::session_identity(ctx),
        }
    }
}

/// v1.63 (#950-B) — the per-file RLS gate for a single-file read or delete.
///
/// The INNER of the two gates: `file_caps_layer` has already decided the caller
/// may perform this VERB at all, and this decides whether it may perform it on
/// THIS ROW. Service (and the admin plane, which is the management face) bypass
/// — the same bypass every other RLS surface gives a service key.
///
/// `conn` is the connection the handler ALREADY opened for the row: the policy
/// read rides it rather than opening a second one (spec §連線紀律 — no
/// `get_or_create` on a read path, since that resurrects a soft-deleted tenant,
/// and no read-only authorizer, which would deny the `_system_*` read this
/// needs).
///
/// Every failure is a refusal. A registry that cannot be read, or a row that
/// cannot be serialized, must not be the reason a file becomes visible.
fn file_access_allowed(
    caller: &FileCaller,
    conn: &rusqlite::Connection,
    row: &FileRow,
    access: crate::storage::file_policy::FileAccess,
) -> bool {
    let ctx = match caller {
        FileCaller::AdminPlane => return true,
        FileCaller::DataPlane(ctx) => ctx,
    };
    if matches!(ctx, AuthCtx::Service { .. }) {
        return true;
    }
    let policies = match crate::storage::file_policy::load_file_policies(conn) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "file policy read failed — refusing the request");
            return false;
        }
    };
    let Some(row_map) = serde_json::to_value(row)
        .ok()
        .and_then(|v| v.as_object().cloned())
    else {
        tracing::error!(key = %row.key, "file row would not serialize — refusing the request");
        return false;
    };
    crate::storage::file_policy::authorize_file(&policies, &row_map, ctx, access)
}

/// A REQUIRED `AuthCtx` extractor: a data-plane file handler that cannot see
/// who is calling refuses the request instead of guessing.
///
/// `Extension<AuthCtx>` would already reject, but with axum's generic 500 and
/// no error code. This exists so the refusal is (a) typed
/// (`AUTH_CTX_MISSING`), and (b) impossible to "fix" by relaxing it to an
/// `Option` — the whole point of the v1.63 route split is that the data-plane
/// handlers fail CLOSED on a missing identity, matching the polarity of
/// `file_caps_layer` and `require_service_layer`.
pub struct RequiredAuthCtx(pub AuthCtx);

impl<S: Send + Sync> FromRequestParts<S> for RequiredAuthCtx {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthCtx>() {
            Some(ctx) => Ok(RequiredAuthCtx(ctx.clone())),
            None => Err(crate::error::json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AUTH_CTX_MISSING",
                "no authenticated identity on a data-plane file route; \
                 refusing rather than assuming service",
            )),
        }
    }
}

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
    /// v1.20 — per-tenant pool registry so admin file writes go through
    /// the writer mutex.
    pub tenants: std::sync::Arc<crate::storage::pool::TenantRegistry>,
    /// v1.33 — Mode B per-file ceiling (bytes).
    pub large_upload_max_bytes: usize,
    /// v1.33 — Mode B per-chunk body limit (bytes).
    pub large_upload_chunk_max_bytes: usize,
    /// v1.33 — max concurrent in-flight Mode B sessions per tenant.
    pub large_upload_max_sessions_per_tenant: u32,
    /// v1.33 — abandoned Mode B session TTL (seconds).
    pub large_upload_session_ttl_secs: u64,
    /// v1.36 — file.uploaded function dispatch (Mode A + Mode B completion).
    pub functions: std::sync::Arc<crate::functions::dispatcher::FunctionDispatcher>,
    /// v1.50 (Spec B, Task 4) — meta.sqlite handle for the low-frequency
    /// `quota::read_tier` lookup on the file-upload choke points (Mode A + tus).
    /// `None` in test ctors → the quota tier falls back to 1 (10 GiB); every
    /// prod construction site threads the real meta so upgraded tenants get
    /// their higher cap. Same fail-safe-to-1 shape as the MCP write core.
    pub meta: Option<std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>>,
}

/// Test-only constructor available in debug builds.
///
/// Defaults:
/// - `disk_min_free_pct`: 20
/// - `max_upload_bytes`: 52 428 800 (50 MiB, matches integration-test default)
/// - `public_base_url`: `"http://localhost"`
/// - `url_sign_secret`: `[0u8; 32]` (zeros — acceptable for tests, never used in prod)
///
/// Pass `garage: None` for handlers that short-circuit before the S3 call,
/// or `garage: Some(Arc::new(mock_garage))` for tests that need a Garage client.
#[cfg(any(test, debug_assertions))]
impl TenantFilesState {
    pub fn test_default(
        garage: Option<std::sync::Arc<GarageClient>>,
        data_root: std::path::PathBuf,
        tenants: std::sync::Arc<crate::storage::pool::TenantRegistry>,
    ) -> Self {
        let (functions, _exec, _cfg) = crate::functions::test_stack_parts(tenants.clone());
        Self {
            garage,
            data_root,
            disk_min_free_pct: 20,
            max_upload_bytes: 52_428_800,
            public_base_url: "http://localhost".into(),
            url_sign_secret: std::sync::Arc::new([0u8; 32]),
            tenants,
            large_upload_max_bytes: 2_147_483_648,
            large_upload_chunk_max_bytes: 67_108_864,
            large_upload_max_sessions_per_tenant: 5,
            large_upload_session_ttl_secs: 86_400,
            functions,
            // Tests exercise the tier-1 (10 GiB) default; prod threads real meta.
            meta: None,
        }
    }
}

/// v1.50 (Spec B, Task 4) — resolve the tenant's quota tier for the file-upload
/// choke points. `meta` present → `quota::read_tier` (single low-freq meta
/// lock, fail-safe to 1); absent (test ctors) → 1. Kept here so Mode A + the
/// tus handlers resolve the tier identically.
pub(crate) async fn resolve_quota_tier(state: &TenantFilesState, tenant_id: &str) -> i64 {
    match state.meta.as_ref() {
        Some(m) => crate::storage::quota::read_tier(m, tenant_id).await,
        None => 1,
    }
}

/// GET /drust/admin/tenants/<id>/files (legacy alias).
/// v1.32.7 renamed the admin page URL to `/_files` so it lines up with
/// the other virtual sidebar entries (`_overview`, `_api_keys`, etc.);
/// this redirect keeps any existing bookmark or browser history entry
/// working. Sub-routes under `/files/...` (upload, key, sign, bytes)
/// are unchanged.
pub async fn redirect_legacy_files_page(
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Redirect};
    Redirect::permanent(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/_files"
    )))
    .into_response()
}

/// GET /drust/t/<tenant>/files/<key>/bytes — data-plane twin.
/// Streams the file body. The per-verb `read` cap is enforced by
/// `file_caps_layer`; the identity is required here so the per-file RLS gate
/// (T4) has one, and so a missing one is a refusal rather than an assumption.
pub async fn stream_bytes(
    State(state): State<TenantFilesState>,
    RequiredAuthCtx(ctx): RequiredAuthCtx,
    Path((tenant_id, key)): Path<(String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    stream_bytes_inner(state, FileCaller::DataPlane(ctx), tenant_id, key).await
}

/// GET /drust/admin/tenants/<id>/files/<key>/bytes — admin twin (no bearer,
/// hence no `AuthCtx`; the admin session + ownership guard are the auth).
pub async fn admin_tfiles_stream(
    State(state): State<TenantFilesState>,
    Path((tenant_id, key)): Path<(String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    stream_bytes_inner(state, FileCaller::AdminPlane, tenant_id, key).await
}

async fn stream_bytes_inner(
    state: TenantFilesState,
    caller: FileCaller,
    tenant_id: String,
    key: String,
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

    // v1.63 — the per-file gate, on the connection already open above. A file
    // the caller may not read is reported as ABSENT: `not found` here is
    // byte-identical to the no-such-key arm, so the response cannot be used to
    // probe which keys exist.
    if !file_access_allowed(
        &caller,
        &conn,
        &row,
        crate::storage::file_policy::FileAccess::Read,
    ) {
        return Err((StatusCode::NOT_FOUND, "not found".into()));
    }

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
    // P0-1 (2026-07-29 audit) / redesigned 2026-07-30 — this route is
    // same-origin with the admin UI (it is also mounted under `/admin`), so a
    // script-executing type is served under `Content-Security-Policy: sandbox`
    // instead of being downgraded — see `files::content_security_policy_for`.
    let ct = row
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let disp_mode = row.content_disposition.as_deref().unwrap_or("inline");
    let ascii = crate::storage::garage::ascii_fallback_filename(&row.original_name);
    let pct = urlencoding::encode(&row.original_name);
    let cd = format!("{disp_mode}; filename=\"{ascii}\"; filename*=UTF-8''{pct}");
    let cc = row.cache_control.as_deref().unwrap_or("private, no-store");

    // Stored values are unvalidated caller input (tus `Upload-Metadata`,
    // multipart `cache_control`) — never `.unwrap()` them into a header.
    use crate::storage::files::safe_header_value;
    let mut headers = HeaderMap::new();
    // Content-Type, nosniff, and the conditional sandbox CSP are one shared
    // function across all three drust byte responders — see
    // `files::insert_content_type_headers`.
    crate::storage::files::insert_content_type_headers(&mut headers, &ct);
    headers.insert(
        header::CONTENT_DISPOSITION,
        safe_header_value(&cd, "attachment"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        safe_header_value(cc, "private, no-store"),
    );

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

/// POST /drust/t/<tenant>/files — data-plane twin.
/// Multipart upload (same field shape as the admin route): file, visibility,
/// disposition, cache_control, meta, and (v1.63) the optional logical `path`.
/// Resolves bucket via visibility, INSERTs into the per-tenant _system_files,
/// PUTs to Garage.  Content-Length pre-check and best-effort disk check mirror
/// the admin handler (Task 15).
///
/// v1.63 (#950-B): the row is stamped with the CALLER, and only a service
/// caller may publish — see `upload_inner`.
pub async fn upload(
    State(state): State<TenantFilesState>,
    RequiredAuthCtx(ctx): RequiredAuthCtx,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    multipart: Multipart,
) -> axum::response::Response {
    upload_inner(
        state,
        FileCaller::DataPlane(ctx),
        tenant_id,
        headers,
        multipart,
    )
    .await
}

/// POST /drust/admin/tenants/<id>/files/upload — admin twin. Stamps `service`
/// and keeps the historical `public`-by-default, exactly as the single
/// pre-v1.63 handler did for every caller.
pub async fn admin_tfiles_upload(
    State(state): State<TenantFilesState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    multipart: Multipart,
) -> axum::response::Response {
    upload_inner(state, FileCaller::AdminPlane, tenant_id, headers, multipart).await
}

async fn upload_inner(
    state: TenantFilesState,
    caller: FileCaller,
    tenant_id: String,
    headers: HeaderMap,
    multipart: Multipart,
) -> axum::response::Response {
    use crate::mgmt::public_files::{UploadFields, parse_upload_fields};
    use crate::storage::files::{Disposition, default_cache_control};

    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

    // Disk check — best-effort; skip if path absent (mirrors Task 15).
    match crate::storage::disk::disk_stats(crate::storage::disk::disk_check_root()) {
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
            tracing::warn!(error = %e, "disk_stats for the disk-check root failed — skipping disk check");
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
        // An illegal `path` is the one parse failure with its own code — the
        // rest stay plain-text 400s, as they have been since Task 15.
        Err(e) if e.starts_with(crate::storage::file_path::FILE_PATH_INVALID) => {
            return crate::error::json_error(
                StatusCode::BAD_REQUEST,
                crate::storage::file_path::FILE_PATH_INVALID,
                &e,
            );
        }
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let UploadFields {
        original_name,
        explicit_ct,
        body,
        visibility,
        visibility_explicit,
        disposition,
        cache_control_override,
        meta_json,
        path,
    } = fields;

    // v1.63 (#950-B) — publishing is a service decision (see
    // `files::enforce_upload_visibility`). Mode-A's service default stays
    // `public`; a non-service caller gets `private` and is refused if it asked
    // for `public`. Decided BEFORE the bucket/cache-control derivation below,
    // so every later use sees the enforced value.
    let requested = visibility_explicit.then_some(visibility);
    let visibility = match crate::storage::files::enforce_upload_visibility(
        caller.is_service(),
        requested,
        Visibility::Public,
    ) {
        Ok(v) => v,
        Err(_) => {
            return crate::error::json_error(
                StatusCode::FORBIDDEN,
                crate::storage::files::FILE_VISIBILITY_SERVICE_ONLY,
                "only a service key may upload a public file; omit `visibility` \
                 (or send `private`) and ask a service key to publish it",
            );
        }
    };
    let uploader = caller.uploader();

    let size = body.len() as i64;

    // Resolve content-type. The essence casing is normalized to lowercase
    // (see `files::normalize_content_type_case`) so the Caddy `/public/*`
    // response-header matcher — case-sensitive, unlike `is_unsafe_inline_type`
    // — only ever needs to match one canonical case.
    let sniffed_ct = explicit_ct
        .filter(|ct| ct != "application/octet-stream")
        .or_else(|| {
            mime_guess::from_path(&original_name)
                .first_raw()
                .map(|s| s.to_string())
        })
        .map(|ct| crate::storage::files::normalize_content_type_case(&ct));

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
    // P0-1 (2026-07-29 audit) / redesigned 2026-07-30 — ingest no longer
    // downgrades a script-executing type; see
    // `files::content_security_policy_for` for where the safety decision now
    // lives (serve time + the Caddy `/public/*` response-header matcher).
    let bucket = crate::storage::files::bucket_for(visibility);

    // DB stores the bare key (`<uuid>.<ext>`); Garage uses `<tenant>/<key>`
    // so a single bucket holds everyone.
    let ext = std::path::Path::new(&original_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("bin");
    let key = format!("{}.{}", uuid::Uuid::new_v4(), ext);
    let object_key = crate::storage::files::compose_key(&Owner::Tenant(tenant_id.clone()), &key);

    // SQLite-first INSERT into tenant DB — through the writer mutex.
    let pool = match state.tenants.get_or_create(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "tenant pool open failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("tenant db: {e}")).into_response();
        }
    };
    // v1.50 (Spec B §5.3) — per-tenant hard quota tier (default 1 → 10 GiB).
    // Read once before the writer tx; the in-tx `usage_on_conn` probe below is
    // what actually gates, measured on the same writer conn as the INSERT
    // (single-writer invariant, no TOCTOU).
    let quota_tier = resolve_quota_tier(&state, &tenant_id).await;
    {
        let key_w = key.clone();
        let original_name_w = original_name.clone();
        let sniffed_ct_w = sniffed_ct.clone();
        let cache_control_w = cache_control.clone();
        let meta_json_w = meta_json.clone();
        let disp_mode_w = disp_mode;
        let vis_str_w = vis_str;
        let uploader_w = uploader.clone();
        let path_w = path.clone();
        if let Err(e) = pool
            .with_writer(move |c| {
                // Reject when this upload's `size` bytes would push the tenant
                // over its cap. Sentinel error → 507 in the match below.
                crate::storage::quota::check_tenant_quota(
                    crate::storage::quota::usage_on_conn(c)?,
                    size as u64,
                    quota_tier,
                )
                .map_err(crate::error::quota_exceeded_error)?;
                c.execute(
                    "INSERT INTO _system_files
                     (key, original_name, content_type, size_bytes, content_disposition,
                      visibility, cache_control, meta_json, uploader, path)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    rusqlite::params![
                        &key_w,
                        &original_name_w,
                        &sniffed_ct_w,
                        size,
                        disp_mode_w,
                        vis_str_w,
                        &cache_control_w,
                        &meta_json_w,
                        &uploader_w,
                        &path_w,
                    ],
                )
                .map(|_| ())
            })
            .await
        {
            if crate::error::is_quota_exceeded(&e) {
                return crate::error::json_error(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "TENANT_QUOTA_EXCEEDED",
                    &e.to_string(),
                );
            }
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
        // Compensating delete — through the writer mutex.
        let key_comp = key.clone();
        if let Ok(pool_comp) = state.tenants.get_or_create(&tenant_id) {
            let _ = pool_comp
                .with_writer(move |c| {
                    c.execute(
                        "DELETE FROM _system_files WHERE key = ?1",
                        rusqlite::params![&key_comp],
                    )
                    .map(|_| ())
                })
                .await;
        }
        return (StatusCode::BAD_GATEWAY, format!("garage put: {e:#}")).into_response();
    }

    // v1.36 — file.uploaded function trigger (fire-and-forget).
    state.functions.dispatch_file(
        &tenant_id,
        &key,
        size,
        vis_str,
        sniffed_ct.as_deref().unwrap_or("application/octet-stream"),
    );

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
///
/// Data-plane only (unlike its three dual-mounted siblings), so the identity is
/// taken directly and is REQUIRED — a metadata row carries `path`, `uploader`
/// and `original_name`, so reading it is a read.
pub async fn get_one(
    State(state): State<TenantFilesState>,
    RequiredAuthCtx(ctx): RequiredAuthCtx,
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
        Ok(row) => {
            // Same 404 shape as the no-such-key arm below — a hidden file is
            // indistinguishable from an absent one.
            if !file_access_allowed(
                &FileCaller::DataPlane(ctx),
                &conn,
                &row,
                crate::storage::file_policy::FileAccess::Read,
            ) {
                return (StatusCode::NOT_FOUND, "not found").into_response();
            }
            axum::Json(row).into_response()
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// DELETE /drust/t/<tenant>/files/<key> — data-plane twin.
/// Removes the Garage object (idempotent on 404) then deletes the DB row.
/// Returns 204 NO_CONTENT on success, 404 if the row doesn't exist.
pub async fn delete_one(
    State(state): State<TenantFilesState>,
    RequiredAuthCtx(ctx): RequiredAuthCtx,
    Path((tenant_id, key)): Path<(String, String)>,
) -> axum::response::Response {
    delete_one_inner(state, FileCaller::DataPlane(ctx), tenant_id, key).await
}

/// DELETE /drust/admin/tenants/<id>/files/<key> — admin twin.
pub async fn admin_tfiles_delete(
    State(state): State<TenantFilesState>,
    Path((tenant_id, key)): Path<(String, String)>,
) -> axum::response::Response {
    delete_one_inner(state, FileCaller::AdminPlane, tenant_id, key).await
}

async fn delete_one_inner(
    state: TenantFilesState,
    caller: FileCaller,
    tenant_id: String,
    key: String,
) -> axum::response::Response {
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

    // Look up the row to find bucket (visibility-dependent) AND to run the
    // delete gate — the whole row, because a delete policy may reference any
    // policy-visible column, not just the two this handler used to need.
    let (visibility_str, bucket) = {
        let conn = match crate::storage::tenant_db::open_read(&state.data_root, &tenant_id) {
            Ok(c) => c,
            Err(e) => {
                return (StatusCode::NOT_FOUND, format!("tenant: {e}")).into_response();
            }
        };
        let row = match conn.query_row(
            "SELECT * FROM _system_files WHERE key = ?1",
            rusqlite::params![key],
            map_file_row,
        ) {
            Ok(r) => r,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return (StatusCode::NOT_FOUND, "not found").into_response();
            }
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        };
        // BEFORE the Garage call below: a refused delete must not have already
        // destroyed the object. Same 404 as a missing key.
        if !file_access_allowed(
            &caller,
            &conn,
            &row,
            crate::storage::file_policy::FileAccess::Delete,
        ) {
            return (StatusCode::NOT_FOUND, "not found").into_response();
        }
        let vis = row.visibility.clone();
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

    // Delete the DB row — through the writer mutex.
    let pool = match state.tenants.get_or_create(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("db open: {e}")).into_response();
        }
    };
    if let Err(e) = pool
        .with_writer(move |c| {
            c.execute(
                "DELETE FROM _system_files WHERE key = ?1",
                rusqlite::params![key],
            )
            .map(|_| ())
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("db delete: {e}")).into_response();
    }

    StatusCode::NO_CONTENT.into_response()
}

#[derive(serde::Deserialize)]
pub struct SetVisibilityBody {
    pub visibility: String,
}

/// PATCH /drust/t/<tenant>/files/<key>
/// Toggle a file between `public` and `private`. Service-key-only. Moves the
/// Garage object to the target bucket and updates the row (see
/// `crate::storage::visibility::change_visibility`).
pub async fn set_visibility(
    State(state): State<TenantFilesState>,
    axum::Extension(t): axum::Extension<crate::tenant::router::TenantRef>,
    Path((tenant_id, key)): Path<(String, String)>,
    axum::Json(body): axum::Json<SetVisibilityBody>,
) -> axum::response::Response {
    // Service-key-only — anon/user are rejected before any work.
    if let Err(r) = crate::tenant::router::require_service(&t) {
        return r;
    }
    let target = match body.visibility.as_str() {
        "public" => Visibility::Public,
        "private" => Visibility::Private,
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(serde_json::json!({
                    "error_code": "INVALID_VISIBILITY",
                    "message": "visibility must be 'public' or 'private'"
                })),
            )
                .into_response();
        }
    };
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };
    let pool = match state.tenants.get_or_create(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("db open: {e}")).into_response();
        }
    };
    use crate::storage::visibility::{VisibilityOutcome, change_visibility};
    match change_visibility(&garage, &pool, &tenant_id, &key, target).await {
        Ok(VisibilityOutcome::Changed { from, to }) => {
            axum::Json(serde_json::json!({ "ok": true, "from": from, "to": to })).into_response()
        }
        Ok(VisibilityOutcome::NoOp) => {
            axum::Json(serde_json::json!({ "ok": true, "noop": true })).into_response()
        }
        Ok(VisibilityOutcome::NotFound) => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "error_code": "NOT_FOUND" })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("visibility change: {e:#}")).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct AdminVisibilityForm {
    pub visibility: String,
}

/// POST /drust/admin/tenants/<id>/files/<key>/visibility
/// Admin-session-authed visibility toggle (no bearer / TenantRef — the admin
/// router sits behind admin_session_layer). Calls the same core mover, then
/// redirects back to the tenant files page.
pub async fn set_visibility_admin(
    State(state): State<TenantFilesState>,
    Path((tenant_id, key)): Path<(String, String)>,
    axum::Form(form): axum::Form<AdminVisibilityForm>,
) -> axum::response::Response {
    let target = match form.visibility.as_str() {
        "public" => Visibility::Public,
        "private" => Visibility::Private,
        _ => return (StatusCode::UNPROCESSABLE_ENTITY, "invalid visibility").into_response(),
    };
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };
    let pool = match state.tenants.get_or_create(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("db open: {e}")).into_response();
        }
    };
    match crate::storage::visibility::change_visibility(&garage, &pool, &tenant_id, &key, target)
        .await
    {
        Ok(_) => axum::response::Redirect::to(&crate::base_path::base(&format!(
            "/admin/tenants/{tenant_id}/_files"
        )))
        .into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("visibility change: {e:#}")).into_response(),
    }
}

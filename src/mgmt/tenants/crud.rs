//! Tenant CRUD / lifecycle (group B): list page, create/delete, self-register
//! toggle, publish-policy, cmdk JSON. Relocated from `tenants.rs` by Finding #4.

use super::{
    CreateTenantForm, CreateTenantJson, CreatedResp, InitialTokens, TenantInfo, TenantsState,
};
use crate::auth::bearer::{generate_token, hash_token};
use crate::mgmt::format::humanize_bytes;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::storage::tenant_db::{open_write, tenant_dir, validate_tenant_id};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use chrono::Utc;
use serde::Serialize;
use serde_json::json;

#[derive(Template)]
#[template(path = "tenants_list.html")]
struct TenantsListPage {
    tenants: Vec<TenantRow>,
    version: &'static str,
    disk: crate::mgmt::public_files::DiskView,
    /// Sampler refresh interval, displayed in the footer as "refresh every N min".
    stats_interval_min: u64,
    /// Human "N min ago" for the most recently re-sampled row in this batch
    /// (sampler iterates ORDER BY id, so `tenants[0]` is the most recent).
    /// Empty when no sampler tick has run yet on this boot.
    stats_age_display: String,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

struct TenantRow {
    id: String,
    /// Short display of id (e.g. first 8 chars + "…" + last 4) for UI cells.
    id_short: String,
    name: String,
    /// First grapheme of name, uppercased — used as the avatar glyph.
    initial: String,
    created_at: String,
    /// Humanised data.sqlite size (e.g. "1.3 MB", "742 KB").
    db_display: String,
    /// Formatted string like "1.3 MB" or "0.0 MB" — _system_files SUM(size_bytes).
    files_display: String,
    /// Humanised db + files combined — at-a-glance "who's eating disk" signal.
    total_display: String,
}

fn short_id(id: &str) -> String {
    if id.len() <= 12 {
        return id.to_string();
    }
    format!("{}…{}", &id[..8], &id[id.len() - 4..])
}

pub async fn list_page_axum(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
) -> Response {
    // v1.15.0 — reads denormalized stats columns. Zero per-tenant SQLite
    // opens on the request path; the background sampler keeps them fresh.
    let mut latest_sample: Option<String> = None;
    let rows: Vec<TenantRow> = {
        let conn = state.session.meta.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, created_at, db_bytes, files_bytes, stats_updated_at \
                 FROM tenants WHERE deleted_at IS NULL ORDER BY id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })
        .unwrap()
        .filter_map(Result::ok)
        .map(|(id, name, created_at, db_bytes, files_bytes, stats_at)| {
            // Track the freshest sample timestamp across the batch for the
            // footer; sampler updates each row at slightly different instants.
            if let Some(ref s) = stats_at
                && latest_sample.as_deref().is_none_or(|cur| s.as_str() > cur)
            {
                latest_sample = Some(s.clone());
            }
            let initial = name
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "?".to_string());
            let db = db_bytes.max(0) as u64;
            let files = files_bytes.max(0) as u64;
            TenantRow {
                id_short: short_id(&id),
                id,
                initial,
                name,
                created_at,
                db_display: humanize_bytes(db),
                files_display: humanize_bytes(files),
                total_display: humanize_bytes(db + files),
            }
        })
        .collect()
    };
    let disk = crate::mgmt::public_files::build_disk_view();
    let stats_interval_min: u64 = std::env::var("DRUST_STATS_SAMPLE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
        / 60;
    let stats_age_display = humanize_age(latest_sample.as_deref());
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantsListPage {
            tenants: rows,
            version: env!("CARGO_PKG_VERSION"),
            disk,
            stats_interval_min,
            stats_age_display,
            t: Translator::new(locale),
            admin,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Render an ISO-8601 timestamp as a coarse "N units ago" string for UI
/// footers. Returns empty string when input is `None` or unparseable.
fn humanize_age(iso: Option<&str>) -> String {
    let Some(s) = iso else {
        return String::new();
    };
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(s) else {
        return String::new();
    };
    let secs = (chrono::Utc::now() - then.with_timezone(&chrono::Utc))
        .num_seconds()
        .max(0);
    match secs {
        0..=59 => format!("{}s ago", secs),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

fn make_tenant_inner(
    conn: &mut rusqlite::Connection,
    data_dir: &std::path::Path,
    id: &str,
    name: &str,
    quota_mb: i64,
    quota_rows: i64,
) -> anyhow::Result<CreatedResp> {
    if let Err(e) = validate_tenant_id(id) {
        anyhow::bail!("invalid tenant id: {e}");
    }
    // A prior tenant with the same id may be soft-deleted. Treat the id as
    // free and hard-purge the old row + its tokens + on-disk data before
    // inserting. If the existing row is still active (deleted_at IS NULL),
    // reject with a clear error.
    let existing: Option<Option<String>> = conn
        .query_row(
            "SELECT deleted_at FROM tenants WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .ok();
    if let Some(deleted_at) = existing {
        if deleted_at.is_none() {
            anyhow::bail!("tenant '{id}' already exists");
        }
        tracing::info!(tenant_id = %id, "recycling id from soft-deleted tenant");
        conn.execute(
            "DELETE FROM tokens WHERE tenant_id = ?1",
            rusqlite::params![id],
        )?;
        conn.execute("DELETE FROM tenants WHERE id = ?1", rusqlite::params![id])?;
        let dir = tenant_dir(data_dir, id);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Clear any matching _trash/<id>-<ts> subdirs left from soft-delete.
        if let Ok(entries) = std::fs::read_dir(data_dir.join("_trash")) {
            let prefix = format!("{id}-");
            for entry in entries.flatten() {
                if let Some(n) = entry.file_name().to_str()
                    && n.starts_with(&prefix)
                {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
    }
    conn.execute(
        "INSERT INTO tenants (id, name, quota_db_mb, quota_rows) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, name, quota_mb, quota_rows],
    )?;
    // Create directory + data.sqlite file
    let _ = open_write(data_dir, id)?;
    std::fs::write(
        tenant_dir(data_dir, id).join("meta.json"),
        serde_json::to_vec_pretty(&json!({
            "name": name,
            "created_at": Utc::now().to_rfc3339(),
            "quota_db_mb": quota_mb,
            "quota_rows": quota_rows,
        }))?,
    )?;
    // Issue both an anon and a service key on creation. Shown once.
    let service_token = generate_token();
    let anon_token = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, plaintext, label, role) \
         VALUES (?1, ?2, ?3, 'initial-service', 'service')",
        rusqlite::params![id, hash_token(&service_token), service_token],
    )?;
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, plaintext, label, role) \
         VALUES (?1, ?2, ?3, 'initial-anon', 'anon')",
        rusqlite::params![id, hash_token(&anon_token), anon_token],
    )?;
    Ok(CreatedResp {
        tenant: TenantInfo {
            id: id.to_string(),
            name: name.to_string(),
            created_at: Utc::now().to_rfc3339(),
            quota_db_mb: quota_mb,
            quota_rows,
        },
        initial_tokens: InitialTokens {
            anon: anon_token,
            service: service_token.clone(),
        },
        initial_token: service_token,
    })
}

/// Roll back everything `make_tenant_inner` did for `id`: delete token rows,
/// the tenant row, and the on-disk directory. Used when Garage provisioning
/// fails after local state has already been written.
pub async fn create_tenant_json(
    State(state): State<TenantsState>,
    Json(form): Json<CreateTenantJson>,
) -> Response {
    let mb = form.quota_db_mb.unwrap_or(500);
    let rows = form.quota_rows.unwrap_or(1_000_000);
    let id = form
        .id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let mut conn = state.session.meta.lock().await;
    let resp = match make_tenant_inner(&mut conn, &state.data_dir, &id, &form.name, mb, rows) {
        Ok(resp) => resp,
        Err(e) => {
            let msg = e.to_string();
            return if msg.contains("invalid tenant id") || msg.contains("UNIQUE") {
                (StatusCode::BAD_REQUEST, msg).into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            };
        }
    };
    drop(conn);

    // v1.35 hook 4 — if this create recycled a soft-deleted tenant's id,
    // make_tenant_inner hard-DELETEd the old tokens/row; drop any cached
    // grant for that id so no stale entry survives the incarnation boundary.
    state.auth_cache.clear_tenant(&id);

    // v1.15.0 — immediate stats sample so the new row renders with real
    // numbers on the next dashboard load, without waiting for a sampler tick.
    crate::mgmt::stats::sample_one(&state.session.meta, &state.tenants, &id).await;

    // Storage is fully shared (two buckets host-wide: `public` + `private`);
    // per-tenant bucket provisioning is no longer needed. The new tenant's
    // files will live under `<tenant-id>/<key>` inside those buckets.
    (StatusCode::CREATED, Json(resp)).into_response()
}

pub async fn create_tenant_form(
    State(state): State<TenantsState>,
    Form(form): Form<CreateTenantForm>,
) -> Response {
    // UUID v4 — user never types a slug. Display name is the human label.
    let id = uuid::Uuid::new_v4().to_string();
    let mut conn = state.session.meta.lock().await;
    let created = make_tenant_inner(&mut conn, &state.data_dir, &id, &form.name, 500, 1_000_000);
    drop(conn);

    match created {
        Ok(_) => {
            // v1.15.0 immediate sample so the new row renders with stats next load.
            crate::mgmt::stats::sample_one(&state.session.meta, &state.tenants, &id).await;
            Redirect::to("/drust/admin/tenants").into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn soft_delete_tenant(
    State(state): State<TenantsState>,
    Path(id): Path<String>,
) -> Response {
    // Delete the tenant's objects from shared Garage buckets first (outside
    // the meta lock). Iterate _system_files and DELETE each object. Admin
    // keeps its files — they live at the root of the shared buckets, not
    // under this tenant's prefix.
    if let Some(ref garage) = state.garage {
        let rows: Vec<(String, String)> =
            match crate::storage::tenant_db::open_read(&state.data_dir, &id) {
                Ok(conn) => {
                    match conn.prepare("SELECT key, visibility FROM _system_files") {
                        Ok(mut stmt) => stmt
                            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                            .map(|it| it.filter_map(Result::ok).collect())
                            .unwrap_or_default(),
                        Err(_) => vec![], // table missing = no files to clean
                    }
                }
                Err(_) => vec![],
            };
        for (key, vis) in rows {
            let visibility = if vis == "public" {
                crate::storage::files::Visibility::Public
            } else {
                crate::storage::files::Visibility::Private
            };
            let bucket = crate::storage::files::bucket_for(visibility);
            let object_key = crate::storage::files::compose_key(
                &crate::storage::files::Owner::Tenant(id.clone()),
                &key,
            );
            if let Err(e) = garage.delete_object_in(bucket, &object_key).await {
                tracing::warn!(tenant = %id, key = %object_key, error = %e,
                    "soft-delete: object delete failed (ignored)");
            }
        }
    }

    // Now the synchronous SQLite + fs work — hold lock only over sync ops.
    {
        let conn = state.session.meta.lock().await;
        let affected = conn
            .execute(
                "UPDATE tenants SET deleted_at = datetime('now') WHERE id = ?1 AND deleted_at IS NULL",
                rusqlite::params![id],
            )
            .unwrap_or(0);
        if affected == 0 {
            return (StatusCode::NOT_FOUND, "no such tenant").into_response();
        }
        let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let src = tenant_dir(&state.data_dir, &id);
        let dst = state.data_dir.join("_trash").join(format!("{id}-{ts}"));
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if src.exists() {
            let _ = std::fs::rename(&src, &dst);
        }
    }
    // Eviction order matters: pools first (release rusqlite Connection FDs
    // on the rename target so the inode + disk space release immediately),
    // then MCP cache (drops its Arc<TenantPool> clones + session state),
    // then SSE channels (subscribers receive Closed on next recv).
    state.tenants.evict(&id);
    state.mcp.evict(&id);
    state.bus.evict_tenant(&id);
    state.bus_rooms.evict_tenant(&id);
    // v1.35 hook 3 — drop every cached Bearer + User bound to this
    // tenant so no stale grant survives the soft-delete.
    state.auth_cache.clear_tenant(&id);
    StatusCode::NO_CONTENT.into_response()
}

pub async fn soft_delete_tenant_form(
    State(state): State<TenantsState>,
    Path(id): Path<String>,
) -> Response {
    let _ = soft_delete_tenant(State(state), Path(id)).await;
    Redirect::to("/drust/admin/tenants").into_response()
}

// ─── T28: allow_self_register toggle ─────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ToggleSelfRegisterBody {
    pub enabled: bool,
}

/// `POST /admin/tenants/{id}/allow-self-register`
///
/// Flips `tenants.allow_self_register` for the given tenant. Body must be
/// `{"enabled": true|false}`. Returns `{"enabled": <bool>}` on success.
/// Requires an active admin session (enforced by `admin_session_layer`).
pub async fn toggle_self_register(
    State(state): State<TenantsState>,
    Path(tid): Path<String>,
    axum::Extension(_admin): axum::Extension<crate::auth::middleware::AdminId>,
    axum::Json(body): axum::Json<ToggleSelfRegisterBody>,
) -> Response {
    let conn = state.session.meta.lock().await;
    let v = if body.enabled { 1i64 } else { 0i64 };
    match conn.execute(
        "UPDATE tenants SET allow_self_register = ?1 WHERE id = ?2 AND deleted_at IS NULL",
        rusqlite::params![v, tid],
    ) {
        Ok(0) => (StatusCode::NOT_FOUND, "no such tenant").into_response(),
        Ok(_) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({"enabled": body.enabled})),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ─── v1.32.5: publish-policy toggle (allow_user_publish / allow_anon_publish) ─

#[derive(serde::Deserialize)]
pub struct PublishPolicyPatch {
    pub allow_user_publish: Option<bool>,
    pub allow_anon_publish: Option<bool>,
}

#[derive(serde::Serialize)]
pub struct PublishPolicyView {
    pub allow_user_publish: bool,
    pub allow_anon_publish: bool,
}

/// `PATCH /admin/tenants/{id}/publish-policy`
///
/// Partial-update of the two opt-in publish flags on `tenants`. Either
/// field may be omitted to leave it unchanged. Returns the current state
/// of both flags after the update.
///
/// MCP `broadcast` is service-only by MCP dispatch and is NOT affected
/// by these flags.
pub async fn patch_publish_policy(
    State(state): State<TenantsState>,
    Path(tid): Path<String>,
    axum::Extension(_admin): axum::Extension<crate::auth::middleware::AdminId>,
    axum::Json(body): axum::Json<PublishPolicyPatch>,
) -> Response {
    let conn = state.session.meta.lock().await;
    if let Some(v) = body.allow_user_publish
        && let Err(e) = conn.execute(
            "UPDATE tenants SET allow_user_publish = ?1 \
             WHERE id = ?2 AND deleted_at IS NULL",
            rusqlite::params![v as i64, tid],
        )
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Some(v) = body.allow_anon_publish
        && let Err(e) = conn.execute(
            "UPDATE tenants SET allow_anon_publish = ?1 \
             WHERE id = ?2 AND deleted_at IS NULL",
            rusqlite::params![v as i64, tid],
        )
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    match conn.query_row(
        "SELECT COALESCE(allow_user_publish, 0), COALESCE(allow_anon_publish, 0) \
         FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tid],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    ) {
        Ok((u, a)) => {
            // v1.35 hook 11 — drop cached Bearers for this tenant so the new
            // publish flags are re-read on the next request.
            state.auth_cache.clear_tenant(&tid);
            (
                StatusCode::OK,
                axum::Json(PublishPolicyView {
                    allow_user_publish: u != 0,
                    allow_anon_publish: a != 0,
                }),
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    }
}

/// `GET /admin/tenants/{id}/publish-policy` — read-only view of the
/// current flag state. Used by the admin UI to render the checkboxes
/// without requiring the wider tenant overview API.
pub async fn get_publish_policy(
    State(state): State<TenantsState>,
    Path(tid): Path<String>,
    axum::Extension(_admin): axum::Extension<crate::auth::middleware::AdminId>,
) -> Response {
    let conn = state.session.meta.lock().await;
    let row: rusqlite::Result<(i64, i64)> = conn.query_row(
        "SELECT COALESCE(allow_user_publish, 0), COALESCE(allow_anon_publish, 0) \
         FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    );
    match row {
        Ok((u, a)) => (
            StatusCode::OK,
            axum::Json(PublishPolicyView {
                allow_user_publish: u != 0,
                allow_anon_publish: a != 0,
            }),
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    }
}

// ===== Cmd-K palette JSON endpoint (v1.14) =====
// Lightweight tenant list for the global ⌘K palette. Service-only? No —
// admin-session gated (same as the rest of /admin/*). Returns 0 rows
// rather than an error when no tenants exist so the palette renders
// "no matches" gracefully.

#[derive(Serialize)]
struct CmdkTenant {
    id: String,
    name: String,
}

/// `GET /admin/api/cmdk/tenants` — JSON `[{id, name}, ...]` used by the
/// cmd-K overlay to populate the tenant picker. Sorted by name (case-
/// insensitive). Excludes soft-deleted tenants.
pub async fn cmdk_tenants_json(State(state): State<TenantsState>) -> Response {
    let conn = state.session.meta.lock().await;
    let mut out: Vec<CmdkTenant> = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, name FROM tenants WHERE deleted_at IS NULL \
         ORDER BY name COLLATE NOCASE",
    ) && let Ok(rows) = stmt.query_map([], |r| {
        Ok(CmdkTenant {
            id: r.get(0)?,
            name: r.get(1)?,
        })
    }) {
        out.extend(rows.flatten());
    }
    drop(conn);
    Json(out).into_response()
}

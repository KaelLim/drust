//! v1.46 — per-tenant Settings backend (spec §5.6): display-name rename +
//! `audit_default` flip via one `PATCH /admin/tenants/{id}`, plus the
//! "apply audit default to all existing collections" bulk action, plus the
//! `⚙ _settings` page render (spec §5.7 — rename form, audit section with a
//! read-only retention display, and links to the pages that already host
//! related settings; nothing is relocated).
//!
//! All handlers mount inside the `admin_session_layer`-gated admin router
//! (cookie-or-PAT), same group as the other `/admin/tenants/{id}/...` mgmt
//! routes. Rename needs no cache invalidation — the display name is re-read
//! from meta at render time (`audit.rs::resolve_tenant_name`, `rpc_admin.rs`)
//! and the auth cache keys on tokens, not names. Apply-all DOES clear the
//! tenant's schema cache: `audit_enabled` rides the cached `CollectionSchema`
//! the write choke points read.

use askama::Template;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use rusqlite::OptionalExtension;
use serde_json::json;

use crate::error::json_error;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::tenants::TenantsState;
use crate::mgmt::theme::{ResolvedPalette, ThemeHint, ThemeRenderCtx};

/// Body for `PATCH /admin/tenants/{id}` — one-sided merge: an absent field
/// leaves the stored value untouched.
#[derive(serde::Deserialize)]
pub struct TenantSettingsPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub audit_default: Option<bool>,
}

/// Validate + normalize a tenant display name: trimmed, non-empty, ≤ 200
/// bytes, no NUL / control characters. Returns the trimmed string to store.
pub fn validate_display_name(raw: &str) -> Result<String, &'static str> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("name must not be empty");
    }
    if name.len() > 200 {
        return Err("name must be at most 200 bytes");
    }
    if name.chars().any(char::is_control) {
        return Err("name must not contain NUL or control characters");
    }
    Ok(name.to_string())
}

/// `PATCH /admin/tenants/{id}` body `{"name"?: string, "audit_default"?: bool}`
///
/// Partial-update of the tenant's display name and/or audit default. Either
/// field may be omitted to leave it unchanged (one-sided merge — mirrors
/// `patch_publish_policy`). Invalid names → `400 INVALID_NAME`. Returns the
/// post-update state of both fields.
pub async fn patch_tenant_settings(
    State(state): State<TenantsState>,
    Path(tid): Path<String>,
    axum::Extension(_admin): axum::Extension<crate::auth::middleware::AdminId>,
    axum::Json(body): axum::Json<TenantSettingsPatch>,
) -> Response {
    // Validate BEFORE taking the meta lock — reject bad input cheaply.
    let name = match body.name.as_deref().map(validate_display_name).transpose() {
        Ok(n) => n,
        Err(msg) => return json_error(StatusCode::BAD_REQUEST, "INVALID_NAME", msg),
    };

    // Single UPDATE with a dynamic column list over the supplied fields.
    // Binds are owned `rusqlite::types::Value`s (not `Box<dyn ToSql>`) so the
    // handler future stays `Send` across the meta-lock await point.
    let mut sets: Vec<&'static str> = Vec::new();
    let mut binds: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(n) = name {
        sets.push("name = ?");
        binds.push(rusqlite::types::Value::Text(n));
    }
    if let Some(d) = body.audit_default {
        sets.push("audit_default = ?");
        binds.push(rusqlite::types::Value::Integer(d as i64));
    }

    let conn = state.session.meta.lock().await;
    if !sets.is_empty() {
        binds.push(rusqlite::types::Value::Text(tid.clone()));
        let sql = format!(
            "UPDATE tenants SET {} WHERE id = ? AND deleted_at IS NULL",
            sets.join(", ")
        );
        match conn.execute(&sql, rusqlite::params_from_iter(binds.iter())) {
            Ok(0) => {
                return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", "no such tenant");
            }
            Ok(_) => {}
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                );
            }
        }
    }
    // Echo the post-update state (also the 404 path for a no-op `{}` PATCH).
    match conn.query_row(
        "SELECT name, COALESCE(audit_default, 1) FROM tenants \
         WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tid],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
    ) {
        Ok((n, d)) => Json(json!({
            "id": tid,
            "name": n,
            "audit_default": d != 0,
        }))
        .into_response(),
        Err(_) => json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", "no such tenant"),
    }
}

/// `POST /admin/tenants/{id}/audit/apply-all`
///
/// Pushes the tenant's CURRENT `audit_default` onto every existing
/// collection's `_system_collection_meta.audit_enabled` in one bulk UPDATE
/// (spec §5.2 — flipping the default never magically inherits; this is the
/// explicit propagation action). Returns
/// `{"ok": true, "audit_enabled": <bool>, "updated": <n>}` where `n` counts
/// the meta rows written. NO SSE evict — audit does not gate realtime
/// (mirrors `put_audit_handler`).
pub async fn apply_audit_default_all(
    State(state): State<TenantsState>,
    Path(tid): Path<String>,
    axum::Extension(_admin): axum::Extension<crate::auth::middleware::AdminId>,
) -> Response {
    // 1. Read the default off meta (doubles as the tenant existence check);
    //    drop the meta lock BEFORE touching the tenant pool.
    let target: bool = {
        let conn = state.session.meta.lock().await;
        match conn
            .query_row(
                "SELECT COALESCE(audit_default, 1) FROM tenants \
                 WHERE id = ?1 AND deleted_at IS NULL",
                rusqlite::params![tid],
                |r| r.get::<_, i64>(0),
            )
            .optional()
        {
            Ok(Some(v)) => v != 0,
            Ok(None) => {
                return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", "no such tenant");
            }
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                );
            }
        }
    };
    // 2. Bulk-apply on the tenant db through the serialized writer.
    let pool = match state.tenants.get_or_open(&tid) {
        Ok(p) => p,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };
    let v = target as i64;
    let updated = match pool
        .with_writer(move |c| {
            c.execute(
                "UPDATE _system_collection_meta \
                 SET audit_enabled = ?1, updated_at = datetime('now')",
                rusqlite::params![v],
            )
        })
        .await
    {
        Ok(n) => n,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
    };
    // 3. Every cached CollectionSchema carries audit_enabled — clear them all
    //    so the write choke points re-read fresh flags on the next call.
    pool.schema_cache.clear();
    Json(json!({
        "ok": true,
        "audit_enabled": target,
        "updated": updated,
    }))
    .into_response()
}

/// The `⚙ _settings` virtual page (spec §5.7). Three sections: Rename
/// (→ `PATCH /admin/tenants/{id}`), Audit (tenant-default toggle + read-only
/// retention-days display + apply-to-all), Related settings (links only —
/// publish policy / self-register stay on `_api_keys`, OAuth on
/// `_oauth_providers`, etc.; D8 says link, don't relocate).
#[derive(Template)]
#[template(path = "tenant_settings.html")]
struct TenantSettingsPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    /// Current `tenants.audit_default` — seeds the toggle state.
    audit_default: bool,
    /// `DRUST_AUDIT_HISTORY_RETENTION_DAYS` resolved at render time;
    /// `0` renders as "keep forever". Display-only — the env var is the
    /// sole config surface for retention.
    retention_days: u64,
    /// Driver list for `_collection_sidebar.html`.
    collections: Vec<crate::storage::schema::Collection>,
    /// Always `"_settings"` here — sidebar `.on` matching.
    active_coll: String,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

/// `GET /admin/tenants/{id}/_settings`
pub async fn tenant_settings_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
) -> Response {
    // Name + audit_default in one meta read; 404 when missing/soft-deleted.
    let row: Option<(String, i64)> = {
        let conn = state.session.meta.lock().await;
        conn.query_row(
            "SELECT name, COALESCE(audit_default, 1) FROM tenants \
             WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()
        .unwrap_or(None)
    };
    let (tenant_name, audit_default) = match row {
        Some((n, d)) => (n, d != 0),
        None => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };

    // Collections list for the sidebar. Failure (fresh tenant without
    // data.sqlite yet) is non-fatal — the sidebar still renders the
    // virtual entries.
    let collections = crate::storage::tenant_db::open_read(&state.data_dir, &tenant_id)
        .ok()
        .and_then(|c| crate::storage::schema::list_collections(&c).ok())
        .unwrap_or_default();

    let trc = ThemeRenderCtx::build(theme);
    let page = TenantSettingsPage {
        version: env!("CARGO_PKG_VERSION"),
        tenant_id,
        tenant_name,
        audit_default,
        retention_days: crate::storage::record_history::retention_days_from_env(),
        collections,
        active_coll: "_settings".to_string(),
        t: Translator::new(locale),
        admin,
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_display_name;

    #[test]
    fn validate_display_name_trims_and_accepts() {
        assert_eq!(validate_display_name("  Prod 環境  ").unwrap(), "Prod 環境");
    }

    #[test]
    fn validate_display_name_rejects_bad_input() {
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name("a\u{0}b").is_err());
        assert!(validate_display_name("a\tb").is_err());
        assert!(validate_display_name(&"x".repeat(201)).is_err());
        // Exactly 200 bytes is the inclusive boundary.
        assert!(validate_display_name(&"x".repeat(200)).is_ok());
    }
}

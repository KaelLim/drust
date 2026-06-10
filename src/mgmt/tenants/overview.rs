//! Tenant overview admin page (group C). Relocated from `tenants.rs` by Finding #4.

use super::TenantsState;
use crate::mgmt::format::humanize_bytes;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::storage::tenant_db::{open_read, tenant_dir, validate_tenant_id};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use chrono::Utc;

// ===== Overview page (v1.14, virtual sidebar entry `⌂ _overview`) =====

#[derive(Template)]
#[template(path = "tenant_overview.html")]
struct TenantOverviewPage {
    tenant_id: String,
    tenant_name: String,
    created_at: String,
    version: &'static str,
    collections: Vec<crate::storage::schema::Collection>,
    active_coll: String,
    collection_count: usize,
    total_records: i64,
    db_size_display: String,
    user_count: i64,
    rpc_count: i64,
    webhook_active_count: i64,
    webhook_total_count: i64,
    oauth_count: i64,
    token_count: i64,
    webhook_failures: Vec<WebhookFailureRow>,
    recent_audit: Vec<RecentAuditRow>,
    /// v1.31 — live count of broadcast rooms with at least one active
    /// subscriber for this tenant. Snapshot at page-render time.
    broadcast_room_count: usize,
    /// v1.31 — sum of WS subscribers across all rooms for this tenant.
    /// Snapshot at page-render time.
    broadcast_subscriber_count: usize,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

struct WebhookFailureRow {
    collection: String,
    url: String,
    events: String,
    last_failure_at: String,
    last_failure_reason: String,
}

struct RecentAuditRow {
    /// "3m ago" / "Just now" / "14:32" — formatted for human reading.
    /// Raw ISO `ts` is dropped; we render the same row in the audit log
    /// page with the full timestamp, this is just the overview card.
    time_display: String,
    /// HTTP verb extracted from `op` ("POST /records/foo" → "POST").
    /// Empty when the op doesn't follow that shape.
    method: String,
    /// Path part of `op` minus the leading slash ("records/foo").
    path_display: String,
    status: String,
    /// Empty when status is `ok`; otherwise the canonical error code so
    /// the chip renders the failure mode rather than the generic word
    /// "error".
    error_code: String,
    /// "service" / "anon" / "user" — read from `extra.auth_kind`.
    /// Token-hint hashes are dropped (not human readable).
    auth_kind: String,
    duration_ms: u64,
}

fn humanize_audit_ts(ts: &str) -> String {
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(ts) else {
        return ts.to_string();
    };
    let secs = (Utc::now() - then.with_timezone(&Utc)).num_seconds().max(0);
    match secs {
        0..=10 => "just now".to_string(),
        11..=59 => format!("{}s ago", secs),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => then.format("%Y-%m-%d %H:%M").to_string(),
    }
}

/// `GET /admin/tenants/{id}/_overview` — virtual sidebar entry that summarises
/// the tenant's data plane: collection counts, storage size, end-users,
/// stored RPCs, OAuth providers, recent audit, and webhook failures within
/// the last 24h. New landing page (the legacy redirect target
/// `/_api_keys` is still reachable but no longer the default).
pub async fn tenant_overview_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
) -> Response {
    if validate_tenant_id(&tenant_id).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid tenant id").into_response();
    }

    // Tenant metadata + active-token count from meta.sqlite.
    let (tenant_name, created_at, token_count) = {
        let conn = state.session.meta.lock().await;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT name, created_at FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
                rusqlite::params![tenant_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let (name, created_at) = match row {
            Some(t) => t,
            None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        };
        let token_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tokens WHERE tenant_id = ?1 AND revoked_at IS NULL",
                rusqlite::params![tenant_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        (name, created_at, token_count)
    };

    // data.sqlite file size.
    let db_path = tenant_dir(&state.data_dir, &tenant_id).join("data.sqlite");
    let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    let db_size_display = humanize_bytes(db_size);

    // Tenant data-plane queries. A failure to open the data db (fresh
    // tenant pre-write, or trashed) yields zeroes — the page still renders
    // with the meta info above.
    let mut collections: Vec<crate::storage::schema::Collection> = Vec::new();
    let mut total_records: i64 = 0;
    let mut user_count: i64 = 0;
    let mut rpc_count: i64 = 0;
    let mut webhook_active_count: i64 = 0;
    let mut webhook_total_count: i64 = 0;
    let mut oauth_count: i64 = 0;
    let mut webhook_failures: Vec<WebhookFailureRow> = Vec::new();

    if let Ok(conn) = open_read(&state.data_dir, &tenant_id) {
        collections = crate::storage::schema::list_collections(&conn).unwrap_or_default();
        total_records = collections.iter().map(|c| c.row_count).sum();
        user_count = conn
            .query_row("SELECT COUNT(*) FROM _system_users", [], |r| r.get(0))
            .unwrap_or(0);
        rpc_count = conn
            .query_row("SELECT COUNT(*) FROM _system_rpc", [], |r| r.get(0))
            .unwrap_or(0);
        webhook_active_count = conn
            .query_row(
                "SELECT COUNT(*) FROM _system_webhooks WHERE active = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        webhook_total_count = conn
            .query_row("SELECT COUNT(*) FROM _system_webhooks", [], |r| r.get(0))
            .unwrap_or(0);
        oauth_count = conn
            .query_row("SELECT COUNT(*) FROM _system_oauth_providers", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);

        // Recent webhook failures (last 24h). Best-effort: any column-shape
        // mismatch on older tenants is suppressed and the card stays hidden.
        let cutoff_str = (Utc::now() - chrono::Duration::hours(24))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT collection, url, events, last_failure_at, \
                COALESCE(last_failure_reason, '') \
             FROM _system_webhooks \
             WHERE last_failure_at IS NOT NULL AND last_failure_at >= ?1 \
             ORDER BY last_failure_at DESC LIMIT 5",
        ) && let Ok(rows) = stmt.query_map(rusqlite::params![cutoff_str], |r| {
            Ok(WebhookFailureRow {
                collection: r.get(0)?,
                url: r.get(1)?,
                events: r.get(2)?,
                last_failure_at: r.get(3)?,
                last_failure_reason: r.get(4)?,
            })
        }) {
            webhook_failures.extend(rows.flatten());
        }
    }

    // Recent audit entries for this tenant (last 24h, newest first, capped 10).
    let scan = crate::mgmt::audit::scan_window(
        &state.log_dir,
        crate::mgmt::audit::Window::H24,
        Utc::now(),
    );
    let mut recent_audit: Vec<RecentAuditRow> = scan
        .entries
        .into_iter()
        .filter(|e| e.tenant == tenant_id)
        .map(|e| {
            let (method, path_display) = match e.op.split_once(' ') {
                Some((m, p)) => (m.to_string(), p.trim_start_matches('/').to_string()),
                None => (String::new(), e.op.clone()),
            };
            let auth_kind = e
                .extra
                .get("auth_kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            RecentAuditRow {
                time_display: humanize_audit_ts(&e.ts),
                method,
                path_display,
                status: e.status,
                error_code: e.error_code.unwrap_or_default(),
                auth_kind,
                duration_ms: e.duration_ms,
            }
        })
        .collect();
    recent_audit.reverse();
    recent_audit.truncate(10);

    let collection_count = collections.len();
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantOverviewPage {
            tenant_id: tenant_id.clone(),
            tenant_name,
            created_at,
            version: env!("CARGO_PKG_VERSION"),
            collections,
            active_coll: "_overview".to_string(),
            collection_count,
            total_records,
            db_size_display,
            user_count,
            rpc_count,
            webhook_active_count,
            webhook_total_count,
            oauth_count,
            token_count,
            webhook_failures,
            recent_audit,
            broadcast_room_count: state.bus_rooms.tenant_channel_count(&tenant_id),
            broadcast_subscriber_count: state.bus_rooms.tenant_subscriber_count(&tenant_id),
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

//! Owner-only OAuth client management — list + revoke + rendered HTML page.
//!
//! Routes wired in `src/mgmt/routes.rs`:
//!   GET  /admin/oauth/clients         → list_or_render (HTML or JSON by Accept)
//!   DELETE /admin/oauth/clients/{id}  → revoke_client
//!
//! Revoke = soft-mark `_oauth_clients.revoked_at + revoked_by_admin_id` +
//! hard-delete all that client's tokens (access + refresh + auth codes), all
//! inside a single transaction. Audit op: `admin.oauth.client_revoke`.
//!
//! v1.29.0 — Task 19.

use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Response};
use rusqlite::params;

use crate::auth::middleware::AdminId;
use crate::error::json_error;
use crate::mgmt::admin_profile::AdminProfileExt;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::routes::MgmtState;
use crate::mgmt::theme::ThemeHint;
use crate::safety::audit::AuditEntry;

// ─── wire shapes ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ClientRow {
    pub client_id: String,
    pub client_name: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub active_tokens: i64,
}

// ─── template ────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "admin_oauth_clients.html")]
struct OauthClientsPage {
    version: &'static str,
    t: Translator,
    admin: AdminProfileExt,
    clients: Vec<ClientRow>,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

// ─── SQL helper ──────────────────────────────────────────────────────────────

const LIST_SQL: &str = "
    SELECT c.id, c.client_name, c.created_at, c.revoked_at,
           (SELECT COUNT(*) FROM _oauth_access_tokens t
            WHERE t.client_id = c.id AND t.expires_at > datetime('now')) AS active_tokens
    FROM _oauth_clients c ORDER BY c.created_at DESC
";

// ─── handlers ────────────────────────────────────────────────────────────────

/// `GET /admin/oauth/clients` — dispatches to HTML or JSON based on `Accept`.
///
/// Browsers (text/html, no application/json) get the Askama page.
/// API/test callers (no Accept, or application/json) get JSON.
pub async fn list_or_render(
    state: State<MgmtState>,
    locale_hint: LocaleHint,
    theme_hint: ThemeHint,
    admin_ext: axum::Extension<AdminProfileExt>,
    headers: axum::http::HeaderMap,
) -> Response {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if accept.contains("text/html") && !accept.contains("application/json") {
        clients_page(state, locale_hint, theme_hint, admin_ext).await
    } else {
        list_clients_json(state, admin_ext).await
    }
}

/// JSON list (API / test path).
async fn list_clients_json(
    State(s): State<MgmtState>,
    axum::Extension(admin): axum::Extension<AdminProfileExt>,
) -> Response {
    if !admin.is_owner {
        return json_error(StatusCode::FORBIDDEN, "NOT_OWNER", "owner required");
    }
    let rows: Vec<serde_json::Value> = {
        let conn = s.meta.lock().await;
        let mut stmt = match conn.prepare(LIST_SQL) {
            Ok(s) => s,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                )
            }
        };
        stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "client_id":     r.get::<_, String>(0)?,
                "client_name":   r.get::<_, String>(1)?,
                "created_at":    r.get::<_, String>(2)?,
                "revoked_at":    r.get::<_, Option<String>>(3)?,
                "active_tokens": r.get::<_, i64>(4)?,
            }))
        })
        .and_then(Iterator::collect)
        .unwrap_or_default()
    };
    Json(serde_json::json!({ "clients": rows })).into_response()
}

/// HTML page (browser path).
async fn clients_page(
    State(s): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    axum::Extension(admin): axum::Extension<AdminProfileExt>,
) -> Response {
    if !admin.is_owner {
        return json_error(StatusCode::FORBIDDEN, "NOT_OWNER", "owner required");
    }
    let clients: Vec<ClientRow> = {
        let conn = s.meta.lock().await;
        let mut stmt = match conn.prepare(LIST_SQL) {
            Ok(s) => s,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    "select failed",
                )
            }
        };
        stmt.query_map([], |r| {
            Ok(ClientRow {
                client_id: r.get(0)?,
                client_name: r.get(1)?,
                created_at: r.get(2)?,
                revoked_at: r.get(3)?,
                active_tokens: r.get(4)?,
            })
        })
        .and_then(Iterator::collect)
        .unwrap_or_default()
    };
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        OauthClientsPage {
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            admin,
            clients,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap_or_default(),
    )
    .into_response()
}

/// `DELETE /admin/oauth/clients/{id}` — revoke a client (Owner-only).
///
/// Soft-marks `_oauth_clients.revoked_at` and hard-deletes all associated
/// tokens (access + refresh + auth codes) inside a single transaction.
pub async fn revoke_client(
    State(s): State<MgmtState>,
    axum::Extension(admin): axum::Extension<AdminProfileExt>,
    axum::Extension(AdminId(actor_id)): axum::Extension<AdminId>,
    Path(client_id): Path<String>,
) -> Response {
    if !admin.is_owner {
        return json_error(StatusCode::FORBIDDEN, "NOT_OWNER", "owner required");
    }

    // All DB work inside a single sync block before any .await.
    let db_result: Result<String, Response> = {
        let mut conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                )
            }
        };

        // Fetch name (also confirms the client exists).
        let name: Option<String> = tx
            .query_row(
                "SELECT client_name FROM _oauth_clients WHERE id = ?1",
                params![&client_id],
                |r| r.get(0),
            )
            .ok();
        let name = match name {
            Some(n) => n,
            None => {
                return json_error(
                    StatusCode::NOT_FOUND,
                    "INVALID_CLIENT",
                    "no such client",
                )
            }
        };

        // Soft-revoke the client row.
        if let Err(e) = tx.execute(
            "UPDATE _oauth_clients SET revoked_at = datetime('now'), revoked_by_admin_id = ?1 WHERE id = ?2",
            params![actor_id, &client_id],
        ) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }

        // Hard-delete all token types for this client.
        // (CASCADE on DELETE from _oauth_clients doesn't fire on a soft-revoke UPDATE.)
        let _ = tx.execute(
            "DELETE FROM _oauth_access_tokens WHERE client_id = ?1",
            params![&client_id],
        );
        let _ = tx.execute(
            "DELETE FROM _oauth_refresh_tokens WHERE client_id = ?1",
            params![&client_id],
        );
        let _ = tx.execute(
            "DELETE FROM _oauth_authorization_codes WHERE client_id = ?1",
            params![&client_id],
        );

        if let Err(e) = tx.commit() {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }

        Ok(name)
        // conn guard drops here — before any .await
    };

    let name = match db_result {
        Ok(n) => n,
        Err(r) => return r,
    };

    // Emit audit (async — safe; lock already released).
    let entry = AuditEntry::success("-", "-", "admin.oauth.client_revoke", 0).with_extra(
        serde_json::json!({
            "client_id":   &client_id,
            "client_name": &name,
            "by_admin_id": actor_id,
        }),
    );
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    Json(serde_json::json!({ "client_id": client_id, "revoked": true })).into_response()
}

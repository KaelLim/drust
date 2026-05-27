//! Per-admin PAT mint/list/revoke. Self-service: admins manage only their own tokens.
//!
//! Audit ops: admin.token.mint, admin.token.revoke.
//! Plaintext token returned ONCE at mint; hash-only stored.
//!
//! v1.29.0.

use askama::Template;
use axum::Extension;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::auth::admin_token::{generate_token, hash_token};
use crate::auth::middleware::AdminId;
use crate::error::json_error;
use crate::mgmt::admin_profile::AdminProfileExt;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::routes::MgmtState;
use crate::safety::audit::AuditEntry;

// ─── wire shapes ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MintBody {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

// ─── HTML page struct ─────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "admin_tokens.html")]
struct AdminTokensPage {
    version: &'static str,
    t: Translator,
    admin: AdminProfileExt,
    tokens: Vec<TokenRow>,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

// ─── handlers ─────────────────────────────────────────────────────────────────

/// `GET /admin/settings/tokens` — dispatches to HTML or JSON based on Accept.
pub async fn tokens_page_or_json(
    state: State<MgmtState>,
    locale_hint: LocaleHint,
    theme_hint: crate::mgmt::theme::ThemeHint,
    admin_ext: axum::Extension<AdminProfileExt>,
    admin_id: axum::Extension<AdminId>,
    headers: axum::http::HeaderMap,
) -> Response {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if accept.contains("text/html") && !accept.contains("application/json") {
        tokens_page(state, locale_hint, theme_hint, admin_ext, admin_id).await
    } else {
        list_self(state, admin_id).await
    }
}

/// Render the HTML tokens page.
async fn tokens_page(
    State(s): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<AdminProfileExt>,
    axum::Extension(AdminId(caller_id)): axum::Extension<AdminId>,
) -> Response {
    let tokens: Vec<TokenRow> = {
        let conn = s.meta.lock().await;
        let mut stmt = match conn.prepare(
            "SELECT id, name, created_at, last_used_at \
             FROM _admin_tokens WHERE admin_id = ?1 ORDER BY id",
        ) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
            }
        };
        stmt.query_map(params![caller_id], |r| {
            Ok(TokenRow {
                id: r.get(0)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
                last_used_at: r.get(3)?,
            })
        })
        .and_then(|iter| iter.collect::<rusqlite::Result<Vec<_>>>())
        .unwrap_or_default()
    };
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        AdminTokensPage {
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            admin,
            tokens,
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

/// `GET /admin/settings/tokens` (JSON) — list caller's own tokens (no plaintext).
pub async fn list_self(
    State(s): State<MgmtState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
) -> Response {
    let result: Result<Vec<TokenRow>, String> = {
        let conn = s.meta.lock().await;
        let mut stmt = match conn.prepare(
            "SELECT id, name, created_at, last_used_at \
             FROM _admin_tokens WHERE admin_id = ?1 ORDER BY id",
        ) {
            Ok(s) => s,
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
            )
                .into_response(),
        };
        stmt.query_map(params![caller_id], |r| {
            Ok(TokenRow {
                id: r.get(0)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
                last_used_at: r.get(3)?,
            })
        })
        .and_then(|iter| iter.collect())
        .map_err(|e| e.to_string())
    };

    match result {
        Ok(tokens) => Json(serde_json::json!({ "tokens": tokens })).into_response(),
        Err(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error_code": "INTERNAL", "message": msg })),
        )
            .into_response(),
    }
}

/// `POST /admin/settings/tokens` — mint a new PAT (plaintext returned ONCE).
pub async fn mint(
    State(s): State<MgmtState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
    Json(body): Json<MintBody>,
) -> Response {
    // Validate name: 1–64 chars, no NULs.
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_TOKEN_NAME",
            "token name must be 1–64 characters",
        );
    }
    if name.contains('\0') {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_TOKEN_NAME",
            "token name must not contain NUL bytes",
        );
    }

    let plaintext = generate_token();
    let hash = hash_token(&plaintext);

    // All DB work in a scoped block; drop the lock before any .await.
    let db_result: Result<(i64, Option<String>), Response> = {
        let conn = s.meta.lock().await;

        let insert_result = conn.execute(
            "INSERT INTO _admin_tokens (admin_id, name, token_hash) VALUES (?1, ?2, ?3)",
            params![caller_id, name, hash],
        );

        let new_id = match insert_result {
            Ok(_) => conn.last_insert_rowid(),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE") {
                    return json_error(
                        StatusCode::CONFLICT,
                        "TOKEN_NAME_TAKEN",
                        "a token with that name already exists",
                    );
                }
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": msg })),
                )
                    .into_response();
            }
        };

        // Fetch caller email for audit attribution.
        let caller_email: Option<String> = conn
            .query_row(
                "SELECT email FROM admins WHERE id = ?1",
                params![caller_id],
                |r| r.get(0),
            )
            .ok();

        Ok((new_id, caller_email))
        // conn guard drops here — before any .await
    };

    let (new_id, caller_email) = match db_result {
        Ok(v) => v,
        Err(r) => return r,
    };

    // Emit audit (async — safe; lock already released).
    let mut entry = AuditEntry::success("-", "-", "admin.token.mint", 0);
    entry.actor_admin_id = Some(caller_id);
    entry.actor_email_snapshot = caller_email;
    entry = entry.with_extra(serde_json::json!({
        "token_id": new_id,
        "name": name,
    }));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    let mut resp = Json(serde_json::json!({
        "id": new_id,
        "name": name,
        "plaintext_token": plaintext,
    }))
    .into_response();
    *resp.status_mut() = StatusCode::CREATED;
    resp
}

/// `DELETE /admin/settings/tokens/{id}` — revoke a PAT (self-owned only).
///
/// Returns 404 (not 403) when the token doesn't exist or belongs to another
/// admin — avoids leaking token-id enumeration to attackers.
pub async fn revoke_self(
    State(s): State<MgmtState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
    Path(token_id): Path<i64>,
) -> Response {
    // All DB work in a scoped block; drop the lock before any .await.
    let db_result: Result<(usize, String, Option<String>), Response> = {
        let conn = s.meta.lock().await;

        // Fetch token name for audit (must be caller's token).
        let token_name: Option<String> = conn
            .query_row(
                "SELECT name FROM _admin_tokens WHERE id = ?1 AND admin_id = ?2",
                params![token_id, caller_id],
                |r| r.get(0),
            )
            .ok();

        let token_name = match token_name {
            Some(n) => n,
            None => {
                return json_error(
                    StatusCode::NOT_FOUND,
                    "TOKEN_NOT_FOUND",
                    "token not found",
                );
            }
        };

        let affected = match conn.execute(
            "DELETE FROM _admin_tokens WHERE id = ?1 AND admin_id = ?2",
            params![token_id, caller_id],
        ) {
            Ok(n) => n,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
            }
        };

        if affected == 0 {
            return json_error(
                StatusCode::NOT_FOUND,
                "TOKEN_NOT_FOUND",
                "token not found",
            );
        }

        // Fetch caller email for audit attribution.
        let caller_email: Option<String> = conn
            .query_row(
                "SELECT email FROM admins WHERE id = ?1",
                params![caller_id],
                |r| r.get(0),
            )
            .ok();

        Ok((affected, token_name, caller_email))
        // conn guard drops here — before any .await
    };

    let (_, token_name, caller_email) = match db_result {
        Ok(v) => v,
        Err(r) => return r,
    };

    // Emit audit (async — safe; lock already released).
    let mut entry = AuditEntry::success("-", "-", "admin.token.revoke", 0);
    entry.actor_admin_id = Some(caller_id);
    entry.actor_email_snapshot = caller_email;
    entry = entry.with_extra(serde_json::json!({
        "token_id": token_id,
        "name": token_name,
    }));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    Json(serde_json::json!({ "revoked": true })).into_response()
}

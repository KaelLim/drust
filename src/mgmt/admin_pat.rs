//! v1.29.3 S2c — single per-admin PAT reroll endpoint.
//!
//! POST /drust/admin/settings/token/reroll
//!   → soft-revoke the caller's active PAT, mint a new one with
//!     plaintext stored, return the plaintext in the response body.
//!
//! Atomic via unchecked_transaction so the partial unique index
//! `uniq_admin_tokens_active` is always satisfied.
//!
//! Audit ops emitted (in order): admin.token.revoke + admin.token.mint,
//! both with `actor_admin_id = Some(caller_id)`.

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::auth::admin_token::{generate_token, hash_token};
use crate::auth::middleware::AdminId;
use crate::error::json_error;
use crate::mgmt::routes::MgmtState;
use crate::safety::audit::AuditEntry;

#[derive(Debug, Serialize)]
pub struct RerollResponse {
    pub plaintext: String,
}

/// `POST /drust/admin/settings/token/reroll`
pub async fn reroll(
    State(s): State<MgmtState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
) -> Response {
    let plaintext_new = generate_token();
    let hash_new = hash_token(&plaintext_new);

    // All DB work in a scoped block; lock dropped before any .await.
    let outcome: Result<(), Response> = {
        let conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL",
                    &e.to_string(),
                );
            }
        };

        if let Err(e) = tx.execute(
            // v1.44 (T4) — scope to the unlabeled UI PAT so the reroll never nukes
            // the admin's labeled CLI PATs (which live outside the relaxed
            // uniq_admin_tokens_active index). The INSERT below mints unlabeled.
            "UPDATE _admin_tokens SET revoked_at = datetime('now') \
             WHERE admin_id = ?1 AND revoked_at IS NULL AND label IS NULL",
            params![caller_id],
        ) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                &e.to_string(),
            );
        }

        if let Err(e) = tx.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (?1, ?2, ?3)",
            params![caller_id, hash_new, plaintext_new],
        ) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                &e.to_string(),
            );
        }

        if let Err(e) = tx.commit() {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                &e.to_string(),
            );
        }

        Ok(())
        // conn guard drops here — before any .await
    };

    if let Err(resp) = outcome {
        return resp;
    }

    // v1.35 hook 2 — the bulk reroll soft-revoked every active PAT for this
    // admin; the handler holds only the NEW hash. Scan-clear all cached
    // Bearer entries whose role is AdminPat { admin_id == caller_id }.
    s.auth_cache.clear_admin_pat(caller_id);

    emit_audit_revoke(caller_id);
    emit_audit_mint(caller_id);

    let mut resp = Json(RerollResponse {
        plaintext: plaintext_new,
    })
    .into_response();
    resp.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-drust-sensitive"),
        axum::http::header::HeaderValue::from_static("true"),
    );
    resp
}

// ─── CLI-PAT lifecycle (T6, public router, self-authenticating) ───────────────

/// The authenticating CLI/UI PAT row resolved from the request bearer.
/// `label.is_none()` == the single unlabeled UI PAT (refused by refresh/logout).
struct CliCaller {
    token_id: i64,
    admin_id: i64,
    email: Option<String>,
    label: Option<String>,
}

/// Self-authenticate a `/auth/cli/*` request against its `Authorization: Bearer`
/// PAT. JSON 401 on a missing / non-`drust_pat_` / unknown / expired / revoked
/// token — NEVER a 302 (these are CLI APIs on the public router, not browser
/// routes). Returns the resolving row incl. its `label`, which the admin-plane
/// `lookup` does not surface but refresh/logout need to fence off the UI PAT.
/// Best-effort bumps `last_used_at` so T7's settings list is meaningful for CLI
/// PATs (the data-plane `bearer_auth_layer` does this for tenant routes).
async fn resolve_cli_caller(
    meta: &Arc<Mutex<Connection>>,
    headers: &HeaderMap,
) -> Result<CliCaller, Response> {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|t| t.starts_with(crate::auth::admin_token::TOKEN_PREFIX))
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "CLI_AUTH_REQUIRED",
                "CLI personal access token required",
            )
        })?;
    let h = hash_token(bearer);
    let conn = meta.lock().await;
    let row = conn
        .query_row(
            "SELECT t.id, t.admin_id, t.label, a.email FROM _admin_tokens t \
             JOIN admins a ON a.id = t.admin_id \
             WHERE t.token_hash = ?1 AND t.revoked_at IS NULL \
               AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))",
            params![h],
            |r| {
                Ok(CliCaller {
                    token_id: r.get(0)?,
                    admin_id: r.get(1)?,
                    label: r.get(2)?,
                    email: r.get(3)?,
                })
            },
        )
        .ok();
    let caller = row.ok_or_else(|| {
        json_error(
            StatusCode::UNAUTHORIZED,
            "CLI_AUTH_REQUIRED",
            "CLI personal access token required or expired",
        )
    })?;
    let _ = conn.execute(
        "UPDATE _admin_tokens SET last_used_at = datetime('now') WHERE id = ?1",
        params![caller.token_id],
    );
    Ok(caller)
}

#[derive(Serialize)]
struct Console {
    id: &'static str,
    name: String,
    host: String,
}

#[derive(Serialize)]
struct WhoamiResponse {
    admin: serde_json::Value,
    consoles: Vec<Console>,
    tenants_endpoint: &'static str,
}

/// `GET /auth/cli/whoami` — self-authenticate, then return the admin identity +
/// the single OSS console (cardinality 1, synthesized from `public_url`) + the
/// tenants-list endpoint the CLI hydrates its command palette from.
pub async fn cli_whoami(State(s): State<MgmtState>, headers: HeaderMap) -> Response {
    let caller = match resolve_cli_caller(&s.meta, &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let host = s.public_url.clone();
    let name = host
        .split("://")
        .nth(1)
        .unwrap_or(&host)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    let name = if name.is_empty() {
        "default".to_string()
    } else {
        name
    };
    Json(WhoamiResponse {
        admin: serde_json::json!({ "id": caller.admin_id, "email": caller.email }),
        consoles: vec![Console {
            id: "default",
            name,
            host,
        }],
        tenants_endpoint: "/admin/api/cmdk/tenants",
    })
    .into_response()
}

// ─── internal helpers ─────────────────────────────────────────────────────────

fn emit_audit_mint(caller_id: i64) {
    let mut entry = AuditEntry::success("-", "-", "admin.token.mint", 0);
    entry.actor_admin_id = Some(caller_id);
    crate::safety::audit_db::try_send(&entry);
}

fn emit_audit_revoke(caller_id: i64) {
    let mut entry = AuditEntry::success("-", "-", "admin.token.revoke", 0);
    entry.actor_admin_id = Some(caller_id);
    crate::safety::audit_db::try_send(&entry);
}

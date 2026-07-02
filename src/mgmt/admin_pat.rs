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
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
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

/// CLI-PAT lifetime in seconds (`DRUST_CLI_PAT_TTL_SECS`, default 24h, D-10).
fn cli_pat_ttl_secs() -> i64 {
    std::env::var("DRUST_CLI_PAT_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(86_400)
}

/// `POST /auth/cli/token/refresh` — re-mint a fresh labeled CLI PAT and
/// soft-revoke the old one (D-15: refresh = re-mint + revoke, no long-lived
/// refresh token). Refuses the unlabeled UI PAT (`403 NOT_A_CLI_TOKEN`) — it is
/// rerolled via `/admin/settings/token/reroll`, never here. The INSERT + revoke
/// run in one `unchecked_transaction` so the unique index is never transiently
/// violated; the relaxed T4 index does not constrain labeled rows, so old+new
/// active inside the tx is legal.
pub async fn cli_token_refresh(State(s): State<MgmtState>, headers: HeaderMap) -> Response {
    let caller = match resolve_cli_caller(&s.meta, &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    if caller.label.is_none() {
        return json_error(
            StatusCode::FORBIDDEN,
            "NOT_A_CLI_TOKEN",
            "only labeled CLI tokens can be refreshed; reroll the UI token at /admin/settings",
        );
    }
    let plaintext_new = crate::auth::admin_token::generate_cli_token();
    let hash_new = hash_token(&plaintext_new);
    let label = caller.label.clone();
    let ttl_mod = format!("+{} seconds", cli_pat_ttl_secs());
    let expires_at: Result<String, Response> = {
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
        // v1.45.1 (F2) — revoke the old row FIRST, conditional on it still being
        // active, and require exactly one row. A concurrent/replayed refresh of
        // the same token loses this race (0 rows) → abort WITHOUT minting a
        // second successor. resolve_cli_caller ran outside this tx, so the row
        // may already be revoked by a racing refresh.
        let revoked = match tx.execute(
            "UPDATE _admin_tokens SET revoked_at = datetime('now') \
             WHERE id = ?1 AND revoked_at IS NULL",
            params![caller.token_id],
        ) {
            Ok(n) => n,
            Err(e) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
            }
        };
        if revoked != 1 {
            // tx drops → rollback; nothing minted.
            return json_error(
                StatusCode::CONFLICT,
                "CLI_TOKEN_ALREADY_ROTATED",
                "this CLI token was already rotated or revoked; log in again",
            );
        }
        if let Err(e) = tx.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext, label, expires_at) \
             VALUES (?1, ?2, ?3, ?4, datetime('now', ?5))",
            params![caller.admin_id, hash_new, plaintext_new, label, ttl_mod],
        ) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
        }
        let exp: String = match tx.query_row(
            "SELECT expires_at FROM _admin_tokens WHERE token_hash = ?1",
            params![hash_new],
            |r| r.get(0),
        ) {
            Ok(v) => v,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL",
                    &e.to_string(),
                );
            }
        };
        if let Err(e) = tx.commit() {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                &e.to_string(),
            );
        }
        Ok(exp)
        // conn guard drops here — before any .await
    };
    let expires_at = match expires_at {
        Ok(v) => v,
        Err(e) => return e,
    };
    // hook (same class as reroll hook 2) — the old CLI PAT is soft-revoked.
    s.auth_cache.clear_admin_pat(caller.admin_id);
    emit_audit_revoke(caller.admin_id);
    emit_audit_mint(caller.admin_id);

    let mut resp = Json(serde_json::json!({
        "access_token": plaintext_new,
        "expires_at": expires_at,
        "admin": { "id": caller.admin_id, "email": caller.email },
    }))
    .into_response();
    resp.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-drust-sensitive"),
        axum::http::header::HeaderValue::from_static("true"),
    );
    resp
}

/// `DELETE /auth/cli/token` — logout self-revoke. Soft-revokes the
/// authenticating CLI PAT, scoped to `id AND admin_id AND label IS NOT NULL`
/// (the `label IS NOT NULL` predicate is a no-op safety net fencing the UI PAT
/// off from the CLI lifecycle — DiD with the resolver's own label check).
pub async fn cli_token_logout(State(s): State<MgmtState>, headers: HeaderMap) -> Response {
    let caller = match resolve_cli_caller(&s.meta, &headers).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let n = {
        let conn = s.meta.lock().await;
        match conn.execute(
            "UPDATE _admin_tokens SET revoked_at = datetime('now') \
             WHERE id = ?1 AND admin_id = ?2 AND label IS NOT NULL AND revoked_at IS NULL",
            params![caller.token_id, caller.admin_id],
        ) {
            Ok(n) => n,
            Err(e) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
            }
        }
    };
    if n > 0 {
        s.auth_cache.clear_admin_pat(caller.admin_id);
        emit_audit_revoke(caller.admin_id);
    }
    Json(serde_json::json!({ "revoked": n > 0 })).into_response()
}

/// `POST /admin/settings/cli-tokens/{id}/revoke` — admin-UI per-row revoke of a
/// labeled CLI PAT (cookie-gated via `admin_session_layer` → `AdminId`). The
/// UPDATE is scoped `id AND admin_id AND label IS NOT NULL AND revoked_at IS
/// NULL` so a guessed id belonging to another admin, the unlabeled UI PAT, or
/// an already-revoked row all yield `changes()==0` → `404` (fail-closed, no
/// cross-admin revoke).
pub async fn cli_token_revoke(
    State(s): State<MgmtState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
    Path(token_id): Path<i64>,
) -> Response {
    let changed = {
        let conn = s.meta.lock().await;
        conn.execute(
            "UPDATE _admin_tokens SET revoked_at = datetime('now') \
             WHERE id = ?1 AND admin_id = ?2 AND label IS NOT NULL AND revoked_at IS NULL",
            params![token_id, caller_id],
        )
        .unwrap_or(0)
    };
    if changed == 0 {
        return json_error(
            StatusCode::NOT_FOUND,
            "CLI_TOKEN_NOT_FOUND",
            "no active CLI token with that id for this admin",
        );
    }
    s.auth_cache.clear_admin_pat(caller_id);
    emit_audit_revoke(caller_id);
    Redirect::to(&crate::base_path::base("/admin/settings")).into_response()
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

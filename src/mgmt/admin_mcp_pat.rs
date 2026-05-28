//! v1.29.2 S3b — per-admin auto-MCP PAT.
//!
//! Two endpoints:
//!   POST /drust/admin/me/mcp-pat/ensure  → ensure an active auto_mcp PAT
//!                                          exists; mint if not, return
//!                                          plaintext only on the mint.
//!   POST /drust/admin/me/mcp-pat/remint  → revoke the active auto_mcp PAT
//!                                          and mint a new one; always
//!                                          return plaintext.
//!
//! Hash-only storage: plaintext appears in the HTTP response on the mint
//! only. Subsequent ensure() calls return null + an 8-char hash fingerprint
//! so the UI can confirm "you have a PAT" without re-exposing the secret.
//!
//! The partial unique index `uniq_admin_tokens_auto_mcp` enforces
//! at-most-one-active-row-per-admin at the storage layer; remint
//! interleaves the soft-revoke (UPDATE revoked_at) and the new INSERT
//! in a single unchecked_transaction so concurrent calls can't double-mint.

use axum::Extension;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::params;
use serde::Serialize;

use crate::auth::admin_token::{generate_token, hash_token};
use crate::auth::middleware::AdminId;
use crate::error::json_error;
use crate::mgmt::routes::MgmtState;
use crate::safety::audit::AuditEntry;

const KIND_AUTO_MCP: &str = "auto_mcp";

#[derive(Debug, Serialize)]
pub struct PatEnsureResponse {
    pub token: Option<String>,
    pub just_minted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_pat: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_prefix: Option<String>,
}

/// Generate a unique PAT name that won't collide with existing rows.
/// The `UNIQUE(admin_id, name)` constraint on `_admin_tokens` means we
/// can't reuse "auto-mcp" once a revoked row with that name exists.
/// We use a stable prefix + the first 12 chars of the hash so each mint
/// gets a distinct name while remaining recognisable in the UI/audit log.
fn auto_mcp_name(hash: &str) -> String {
    format!("auto-mcp-{}", &hash[..hash.len().min(12)])
}

/// `POST /drust/admin/me/mcp-pat/ensure`
///
/// Idempotent: if the calling admin already has an active `kind='auto_mcp'`
/// PAT, returns `{token: null, just_minted: false, has_pat: true,
/// hash_prefix: "<8 chars>"}` without touching the DB.  Otherwise mints
/// a new one and returns the plaintext token exactly once.
pub async fn ensure(
    State(s): State<MgmtState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
) -> Response {
    let plaintext_candidate = generate_token();
    let hash_candidate = hash_token(&plaintext_candidate);
    let name_candidate = auto_mcp_name(&hash_candidate);

    // All DB work in a scoped block; lock dropped before any .await.
    let outcome: Result<EnsureOutcome, Response> = {
        let conn = s.meta.lock().await;

        // Look for an existing active auto_mcp PAT.
        let existing: Option<String> = conn
            .query_row(
                "SELECT token_hash FROM _admin_tokens \
                 WHERE admin_id = ?1 AND kind = ?2 AND revoked_at IS NULL",
                params![caller_id, KIND_AUTO_MCP],
                |r| r.get::<_, String>(0),
            )
            .ok();

        match existing {
            Some(existing_hash) => Ok(EnsureOutcome::Existing {
                hash_prefix: existing_hash.chars().take(8).collect(),
            }),
            None => {
                let insert_result = conn.execute(
                    "INSERT INTO _admin_tokens (admin_id, name, token_hash, kind) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![caller_id, name_candidate, hash_candidate, KIND_AUTO_MCP],
                );
                match insert_result {
                    Ok(_) => Ok(EnsureOutcome::Minted),
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("UNIQUE") {
                            // Concurrent ensure() raced us — re-read.
                            match conn.query_row(
                                "SELECT token_hash FROM _admin_tokens \
                                 WHERE admin_id = ?1 AND kind = ?2 AND revoked_at IS NULL",
                                params![caller_id, KIND_AUTO_MCP],
                                |r| r.get::<_, String>(0),
                            ) {
                                Ok(hash) => Ok(EnsureOutcome::Existing {
                                    hash_prefix: hash.chars().take(8).collect(),
                                }),
                                Err(re) => Err(json_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "INTERNAL",
                                    &re.to_string(),
                                )),
                            }
                        } else {
                            Err(json_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "INTERNAL",
                                &msg,
                            ))
                        }
                    }
                }
            }
        }
        // conn guard drops here — before any .await
    };

    match outcome {
        Ok(EnsureOutcome::Minted) => {
            emit_mint_audit(caller_id);
            Json(PatEnsureResponse {
                token: Some(plaintext_candidate),
                just_minted: true,
                has_pat: None,
                hash_prefix: None,
            })
            .into_response()
        }
        Ok(EnsureOutcome::Existing { hash_prefix }) => Json(PatEnsureResponse {
            token: None,
            just_minted: false,
            has_pat: Some(true),
            hash_prefix: Some(hash_prefix),
        })
        .into_response(),
        Err(resp) => resp,
    }
}

/// `POST /drust/admin/me/mcp-pat/remint`
///
/// Atomically soft-revokes any existing `kind='auto_mcp'` PAT and inserts a
/// new one.  Both operations run inside a single `unchecked_transaction` so
/// the partial unique index `uniq_admin_tokens_auto_mcp` is satisfied even
/// under concurrent calls.  Always returns the new plaintext token.
pub async fn remint(
    State(s): State<MgmtState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
) -> Response {
    let plaintext_new = generate_token();
    let hash_new = hash_token(&plaintext_new);
    let name_new = auto_mcp_name(&hash_new);

    // All DB work in a scoped block; lock dropped before any .await.
    let result: Result<(), Response> = {
        let conn = s.meta.lock().await;

        // Atomic revoke + insert against the partial unique index.
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string()),
        };

        if let Err(e) = tx.execute(
            "UPDATE _admin_tokens \
             SET revoked_at = datetime('now') \
             WHERE admin_id = ?1 AND kind = ?2 AND revoked_at IS NULL",
            params![caller_id, KIND_AUTO_MCP],
        ) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
        }

        if let Err(e) = tx.execute(
            "INSERT INTO _admin_tokens (admin_id, name, token_hash, kind) \
             VALUES (?1, ?2, ?3, ?4)",
            params![caller_id, name_new, hash_new, KIND_AUTO_MCP],
        ) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
        }

        if let Err(e) = tx.commit() {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
        }

        Ok(())
        // conn guard drops here — before any .await
    };

    if let Err(resp) = result {
        return resp;
    }

    emit_revoke_audit(caller_id);
    emit_mint_audit(caller_id);

    Json(PatEnsureResponse {
        token: Some(plaintext_new),
        just_minted: true,
        has_pat: None,
        hash_prefix: None,
    })
    .into_response()
}

// ─── internal helpers ─────────────────────────────────────────────────────────

enum EnsureOutcome {
    Minted,
    Existing { hash_prefix: String },
}

fn emit_mint_audit(caller_id: i64) {
    let mut entry = AuditEntry::success("-", "-", "admin.token.mint", 0);
    entry.actor_admin_id = Some(caller_id);
    entry = entry.with_extra(serde_json::json!({ "kind": "auto_mcp" }));
    crate::safety::audit_db::try_send(&entry);
}

fn emit_revoke_audit(caller_id: i64) {
    let mut entry = AuditEntry::success("-", "-", "admin.token.revoke", 0);
    entry.actor_admin_id = Some(caller_id);
    entry = entry.with_extra(serde_json::json!({ "kind": "auto_mcp", "reason": "remint" }));
    crate::safety::audit_db::try_send(&entry);
}

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
            Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string()),
        };

        if let Err(e) = tx.execute(
            "UPDATE _admin_tokens SET revoked_at = datetime('now') \
             WHERE admin_id = ?1 AND revoked_at IS NULL",
            params![caller_id],
        ) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
        }

        if let Err(e) = tx.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (?1, ?2, ?3)",
            params![caller_id, hash_new, plaintext_new],
        ) {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
        }

        if let Err(e) = tx.commit() {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", &e.to_string());
        }

        Ok(())
        // conn guard drops here — before any .await
    };

    if let Err(resp) = outcome {
        return resp;
    }

    emit_audit_revoke(caller_id);
    emit_audit_mint(caller_id);

    let mut resp = Json(RerollResponse { plaintext: plaintext_new }).into_response();
    resp.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-drust-sensitive"),
        axum::http::header::HeaderValue::from_static("true"),
    );
    resp
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

//! `POST /oauth/revoke` — RFC 7009, always per GRANT.
//!
//! Not rate-limited: the lookup is a primary-key probe that would already have
//! run before any budget could be charged, so a budget saves no work, and the
//! token is a 256-bit secret. Unknown token, foreign prefix and an already
//! revoked grant all answer the same 200 with an empty body.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::mgmt::mcp_oauth::oauth_error_layer::OAuthError;
use crate::mgmt::mcp_oauth::store::{self, GrantOwner, RevokeReason, RevokeTarget, RevokedGrant};
use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};
use crate::mgmt::mcp_oauth::{clients, token};
use crate::mgmt::routes::MgmtState;

/// Defined parameters whose repetition is `invalid_request`.
const REVOKE_PARAMS: &[&str] = &["token", "token_type_hint", "client_id"];

enum Outcome {
    Revoked { grant_id: i64, admin_id: i64 },
    AlreadyGone,
}

pub async fn revoke(State(s): State<MgmtState>, headers: HeaderMap, body: Bytes) -> Response {
    let started = std::time::Instant::now();
    let p = match token::preflight(&headers, &body, REVOKE_PARAMS) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let Some(presented) = p.get("token") else {
        return OAuthError::InvalidRequest.into_response();
    };
    // Optional: a public client; the token itself is the secret.
    let asserted_client = p.get("client_id");
    if let Some(cid) = asserted_client
        && clients::find_client(cid).is_none()
    {
        return OAuthError::InvalidClient.into_response();
    }
    // token_type_hint is ignored: the prefix decides (RFC 7009 §2.1 lets the AS
    // ignore it). Foreign prefix (admin PAT, tenant key, code, garbage): an
    // invalid token, 200, meta never locked, nothing touched.
    if !tokens::looks_like(TokenKind::Access, presented)
        && !tokens::looks_like(TokenKind::Refresh, presented)
    {
        return ok_empty();
    }

    // No `.await` inside this block once `tx` exists: Transaction borrows a
    // !Sync Connection, so holding it across an await makes the future !Send.
    let outcome = {
        let conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => return server_error("begin", e),
        };
        let found = match store::lookup_for_revoke(&tx, presented) {
            Ok(f) => f,
            Err(e) => return server_error("lookup", e),
        };
        match found {
            // Unknown token, or a token whose grant is already revoked or
            // orphaned: nothing to do.
            None => Outcome::AlreadyGone,
            Some(RevokeTarget { grant, client_id }) => {
                if asserted_client.is_some_and(|c| c != client_id) {
                    // RFC 7009 §2.1: the token was not issued to this client.
                    return OAuthError::UnauthorizedClient.into_response(); // tx dropped = rollback
                }
                let (gid, aid) = (grant.grant_id(), grant.admin_id());
                match store::revoke_mcp_grant(
                    &tx,
                    &GrantOwner::holder(&grant),
                    gid,
                    RevokeReason::OauthRevoke,
                ) {
                    Ok(RevokedGrant::Revoked) => {
                        if let Err(e) = tx.commit() {
                            return server_error("commit", e);
                        }
                        Outcome::Revoked {
                            grant_id: gid,
                            admin_id: aid,
                        }
                    }
                    Ok(RevokedGrant::NotFound) => {
                        // Unreachable today: lookup and revoke share this tx under
                        // the meta mutex, and both require `revoked_at IS NULL` on
                        // the same grant id + admin. If it fires, the two
                        // predicates drifted apart. Nothing was written, so no
                        // audit; tx dropped = rollback.
                        tracing::warn!(
                            grant_id = gid,
                            "mcp oauth revoke: lookup found a grant that revoke_mcp_grant did not"
                        );
                        Outcome::AlreadyGone
                    }
                    Err(e) => return server_error("revoke", e),
                }
            }
        }
    }; // meta guard dropped here; audit never runs under it.

    // No cache, bus or PAT eviction follows: MCP OAuth tokens are in no cache
    // and cannot open SSE or rooms (store.rs module doc).
    match outcome {
        Outcome::Revoked { grant_id, admin_id } => {
            audit_revoke(&s, grant_id, admin_id, started).await;
            ok_empty()
        }
        Outcome::AlreadyGone => ok_empty(),
    }
}

/// Written only when a grant was actually revoked, so random traffic and
/// repeated revokes never amplify the audit log. The presenter is not strongly
/// authenticated (an expired or rotated token suffices), so the owner goes in
/// `extra.admin_id`, not in the top-level actor (unlike the code exchange,
/// whose presenter passed the full PKCE binding).
async fn audit_revoke(s: &MgmtState, grant_id: i64, admin_id: i64, started: std::time::Instant) {
    let ms = started.elapsed().as_millis() as u64;
    let mut entry =
        crate::safety::audit::AuditEntry::success("-", "-", "mcp_oauth.grant.revoke", ms);
    entry.auth_method = Some("mcp_oauth".to_string());
    entry = entry.with_extra(serde_json::json!({
        "grant_id": grant_id,
        "reason": RevokeReason::OauthRevoke.as_str(),
        "admin_id": admin_id,
    }));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
}

/// Empty body; `oauth_error_layer` adds `Cache-Control: no-store`.
fn ok_empty() -> Response {
    StatusCode::OK.into_response()
}

fn server_error(stage: &'static str, e: rusqlite::Error) -> Response {
    // The error kind only — never its Display, which can carry SQL text.
    tracing::error!(stage, kind = ?e.sqlite_error_code(), "mcp oauth revoke failed");
    OAuthError::ServerError.into_response()
}

//! `POST /oauth/token` (MA0-PLAN §3.8.4): request validation, grant-type
//! dispatch, the `authorization_code` exchange, and the `refresh_token` grant
//! (MA0-8; the state machine is `refresh::rotate`).
//!
//! Rate limits never read a request that presents a valid credential: an
//! unknown code charges the per-IP miss budget, a failed check on a code that
//! exists charges that code's budget, and an issued or replayed code reads no
//! bucket (MA0-PLAN §4; per-code charges failures only, so whoever holds a code
//! without its verifier cannot lock the real client out of its exchange).
//! Refresh is different by design: an unknown hash charges the per-IP miss
//! budget; a known one (live or not) charges its grant's per-grant budget
//! (10 per 60 s) only on the branches `refresh::rotate` bounds, decided from
//! the snapshot — never on reuse detection or a losing sibling's branch cut.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::mgmt::mcp_oauth::oauth_error_layer::{ClientAuthScheme, OAuthError};
use crate::mgmt::mcp_oauth::params::{self, Params};
use crate::mgmt::mcp_oauth::store::{self, GrantOwner, GrantRef, IssuedTokens, RevokeReason};
use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};
use crate::mgmt::mcp_oauth::{authorize, clients, refresh, rl};
use crate::mgmt::routes::MgmtState;
use crate::safety::ip::ClientIp;
use crate::safety::rate_limit::RateLimitedError;

/// Body cap for `/oauth/token` and `/oauth/revoke` (`DefaultBodyLimit`, and
/// `parse_pairs`' own limit).
pub const OAUTH_BODY_LIMIT: usize = 16 * 1024;

/// Defined parameters whose repetition is `invalid_request` (OAuth 2.1 §3.2.4
/// "repeats a parameter"; `resource` may not repeat here either). Unknown
/// parameters are ignored even when repeated.
const TOKEN_PARAMS: &[&str] = &[
    "grant_type",
    "code",
    "code_verifier",
    "redirect_uri",
    "client_id",
    "resource",
    "refresh_token",
    "scope",
];

/// Steps 3-5 of MA0-PLAN §3.8.4, shared with revoke. Steps 1-2 (POST only,
/// 16 KiB) happen in the router before the handler runs. The credential only
/// ever comes from the form body: no cookie, no query string is read.
pub(crate) fn preflight(
    headers: &HeaderMap,
    body: &[u8],
    defined: &[&str],
) -> Result<Params, OAuthError> {
    if !is_form_urlencoded(headers) {
        return Err(OAuthError::InvalidRequest);
    }
    // drust supports only token_endpoint_auth_method "none" (public client).
    if let Some(v) = headers.get(header::AUTHORIZATION) {
        return Err(OAuthError::InvalidClientHeader {
            scheme: scheme_of(v),
        });
    }
    let p = params::parse_pairs(body, OAUTH_BODY_LIMIT).map_err(|_| OAuthError::InvalidRequest)?;
    if defined.iter().any(|k| p.is_duplicated(k)) {
        return Err(OAuthError::InvalidRequest);
    }
    Ok(p)
}

/// The media-type essence (before any `;` parameter, trimmed), ASCII
/// case-insensitive.
fn is_form_urlencoded(h: &HeaderMap) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|essence| {
            essence
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// First token of the header, ASCII case-insensitive: `bearer` => Bearer,
/// anything else (Basic, unrecognised, non-UTF-8) => Basic.
fn scheme_of(v: &HeaderValue) -> ClientAuthScheme {
    let first = v
        .as_bytes()
        .split(|b| *b == b' ')
        .find(|t| !t.is_empty())
        .unwrap_or_default();
    if first.eq_ignore_ascii_case(b"bearer") {
        ClientAuthScheme::Bearer
    } else {
        ClientAuthScheme::Basic
    }
}

pub async fn token(
    State(s): State<MgmtState>,
    ip: ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let p = match preflight(&headers, &body, TOKEN_PARAMS) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match p.get("grant_type") {
        None => OAuthError::InvalidRequest.into_response(),
        Some("authorization_code") => grant_authorization_code(&s, &ip, &p).await,
        Some("refresh_token") => grant_refresh(&s, &ip, &p).await,
        Some(_) => OAuthError::UnsupportedGrantType.into_response(),
    }
}

/// What the locked section decided; acted on after the meta guard is dropped.
/// No `Debug`: `Issued` holds plaintext tokens.
enum Done {
    Issued(GrantRef, Option<String>, IssuedTokens),
    Miss,
    Invalid,
    Replayed(GrantRef, Option<String>),
}

/// MA0-PLAN §3.8.4 step 7. The parameter checks run in error-priority order
/// before any lock; `redeem_code` decides the rest in one transaction.
async fn grant_authorization_code(s: &MgmtState, ip: &ClientIp, p: &Params) -> Response {
    let started = std::time::Instant::now();
    let Some(client_id) = p.get("client_id") else {
        return OAuthError::InvalidRequest.into_response();
    };
    if clients::find_client(client_id).is_none() {
        // 400: preflight already refused any Authorization header.
        return OAuthError::InvalidClient.into_response();
    }
    let Some(code) = p.get("code") else {
        return OAuthError::InvalidRequest.into_response();
    };
    // Wrong length: a miss, never queried. A right length proves nothing (any
    // 43-char string passes, an admin session cookie included); only the hash
    // lookup below says whether this is a code.
    if !tokens::looks_like(TokenKind::Code, code) {
        return miss_response(s, ip);
    }
    let req = store::CodeRedeemRequest {
        code,
        client_id,
        redirect_uri: p.get("redirect_uri"),
        verifier: p.get("code_verifier"),
        resource: p.get("resource"),
    };

    // No `.await` inside this block once `tx` exists: Transaction borrows a
    // !Sync Connection, so holding it across an await makes the future !Send.
    // Holding the meta mutex for the whole read-mark-issue sequence is also
    // what serialises concurrent redemptions of one code.
    let done = {
        let conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(tx) => tx,
            Err(e) => return server_error("begin", &e),
        };
        let outcome = match store::redeem_code(&tx, &s.mcp_oauth, &req) {
            Ok(o) => o,
            Err(e) => return server_error("redeem", &e), // tx dropped => rollback
        };
        match outcome {
            // NEVER commit on these two arms: dropping `tx` rolls back, which
            // also undoes the redeemed_at mark in the deadline-second Invalid.
            store::RedeemOutcome::Miss => Done::Miss,
            store::RedeemOutcome::Invalid => Done::Invalid,
            store::RedeemOutcome::Replay { grant } => {
                // A second request that passed every check: deny and revoke the
                // whole grant (OAuth 2.1 §4.1.3). One grant has exactly one code,
                // so this is exactly "every token issued from this code".
                // NotFound cannot happen (redeem_code saw the grant live in this
                // tx); either way the answer is invalid_grant.
                match store::revoke_mcp_grant(
                    &tx,
                    &GrantOwner::holder(&grant),
                    grant.grant_id(),
                    RevokeReason::CodeReplay,
                ) {
                    Ok(_revoked_or_not_found) => {}
                    Err(e) => return server_error("replay-revoke", &e),
                }
                let email = admin_email(&tx, grant.admin_id());
                if let Err(e) = tx.commit() {
                    return server_error("commit", &e);
                }
                Done::Replayed(grant, email)
            }
            store::RedeemOutcome::Issued { grant, tokens } => {
                let email = admin_email(&tx, grant.admin_id());
                if let Err(e) = tx.commit() {
                    return server_error("commit", &e);
                }
                Done::Issued(grant, email, tokens)
            }
        }
    }; // meta guard dropped here; audit is an async file write and never runs under it.

    // No cache, bus or PAT eviction follows a replay revoke: MCP OAuth tokens
    // are in no cache and cannot open SSE or rooms (store.rs module doc).
    match done {
        Done::Miss => miss_response(s, ip),
        Done::Invalid => per_code_response(s, code),
        Done::Replayed(grant, email) => {
            // Another process holds code + verifier, or the client misbehaves.
            // Ids only: never the code, verifier, redirect or any request field.
            tracing::warn!(
                grant_id = grant.grant_id(),
                admin_id = grant.admin_id(),
                "mcp_oauth: authorization code replay, grant revoked"
            );
            audit(
                s,
                "mcp_oauth.grant.revoke",
                started,
                &grant,
                email,
                serde_json::json!({
                    "grant_id": grant.grant_id(),
                    "reason": RevokeReason::CodeReplay.as_str(),
                }),
            )
            .await;
            OAuthError::InvalidGrant.into_response()
        }
        Done::Issued(grant, email, t) => {
            audit(
                s,
                "mcp_oauth.token.code",
                started,
                &grant,
                email,
                serde_json::json!({ "grant_id": grant.grant_id() }),
            )
            .await;
            token_success(&t)
        }
    }
}

/// MA0-PLAN §3.8.5b. Every failure is `invalid_grant` — the MCP SDK only
/// discards its tokens and re-authorizes on that code — except a missing
/// `refresh_token` (`invalid_request`), an unknown `scope` item
/// (`invalid_scope`) and an exhausted budget (429). `scope`, `resource` and the
/// token's shape are pure checks before any lock or budget; `client_id` needs
/// the grant row and is checked by `rotate` (branch a).
async fn grant_refresh(s: &MgmtState, ip: &ClientIp, p: &Params) -> Response {
    let started = std::time::Instant::now();
    // 1. required
    let Some(presented) = p.get("refresh_token") else {
        return OAuthError::InvalidRequest.into_response();
    };
    // 2. scope: the SAME item check authorize uses. An empty value counts as
    // absent (params), i.e. "not sent", never `mcp`-by-default here.
    if let Some(scope) = p.get("scope")
        && !authorize::scope_items_ok(scope)
    {
        return OAuthError::InvalidScope.into_response();
    }
    // 3. resource: a mismatch is invalid_grant, not RFC 8707's invalid_target
    // (the SDK re-authorizes only on invalid_grant).
    if let Some(res) = p.get("resource")
        && !s.mcp_oauth.is_our_resource(res)
    {
        return OAuthError::InvalidGrant.into_response();
    }
    // 4. prefix + length: no DB, no budget (an access token lands here too).
    if !tokens::looks_like(TokenKind::Refresh, presented) {
        return OAuthError::InvalidGrant.into_response();
    }
    let hash = tokens::hash(TokenKind::Refresh, presented);
    let req = refresh::RefreshRequest {
        client_id: p.get("client_id"),
    };

    // No `.await` in this block after the lock: `try_acquire` is synchronous,
    // and a Transaction borrows a !Sync Connection. Holding the meta mutex for
    // lookup + snapshot + writes is what serialises concurrent refreshes.
    let outcome = {
        let conn = s.meta.lock().await;
        // 5. hit / miss (liveness ignored: a dead row is a hit).
        let gid = match refresh::lookup_grant_id(&conn, &hash) {
            Ok(Some(g)) => g,
            Ok(None) => {
                drop(conn);
                return miss_response(s, ip);
            }
            Err(e) => return server_error("refresh-lookup", &e),
        };
        // 6. one transaction for the snapshot and every write.
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => return server_error("refresh-begin", &e),
        };
        // 7. the per-grant bucket, read by `rotate` only on the branches it
        // bounds, after the snapshot decided the branch; a 429 from it drops
        // the tx. A refused request is not pushed into the window.
        let charge = || {
            s.mcp_oauth_rl
                .per_grant
                .try_acquire(&rl::grant_key(gid))
                .map_err(|RateLimitedError(d)| OAuthError::TemporarilyUnavailable {
                    retry_after_secs: rl::retry_after_secs(d),
                })
        };
        match refresh::rotate(&tx, &s.mcp_oauth, &hash, &req, charge) {
            Ok(o) => {
                if let Err(e) = tx.commit() {
                    return server_error("refresh-commit", &e);
                }
                o
            }
            Err(e) => return e.into_response(), // tx dropped => rollback
        }
    }; // meta guard dropped here; audit only after this point.

    // No cache, bus or PAT eviction follows a branch or grant revoke: MCP
    // OAuth tokens are in no cache and cannot open SSE or rooms (store.rs).
    match outcome {
        refresh::RotateOutcome::Issued(t) => token_success(&t), // a success writes no audit
        refresh::RotateOutcome::RejectedSibling {
            grant_id,
            refresh_id,
            admin_id,
            branch_revoked,
        } => {
            audit_sibling(s, started, grant_id, refresh_id, admin_id, branch_revoked).await;
            OAuthError::InvalidGrant.into_response()
        }
        refresh::RotateOutcome::RejectedReuse {
            grant_id,
            refresh_id,
            admin_id,
            rotated_secs_ago,
            revoked,
        } => {
            audit_reuse(
                s,
                started,
                grant_id,
                refresh_id,
                admin_id,
                rotated_secs_ago,
                revoked,
            )
            .await;
            OAuthError::InvalidGrant.into_response()
        }
    }
}

/// A superseded sibling (b, `branch_revoked = true`) or a parent presented
/// after its race was decided (d-1, `false`; `refresh_id` is that parent).
/// `admin_id` is the grant OWNER in `extra`, deliberately not the top-level
/// actor: the presenter is unknown (same as `/oauth/revoke`). Never a token,
/// a hash or any request field.
async fn audit_sibling(
    s: &MgmtState,
    started: std::time::Instant,
    grant_id: i64,
    refresh_id: i64,
    admin_id: i64,
    branch_revoked: bool,
) {
    let message = if branch_revoked {
        "superseded sibling refresh presented"
    } else {
        "rotated refresh re-presented after its successor was used"
    };
    let mut e = crate::safety::audit::AuditEntry::failure(
        "-",
        "-",
        "mcp_oauth.refresh.sibling_rejected",
        started.elapsed().as_millis() as u64,
        "invalid_grant",
        message,
    );
    e.auth_method = Some("mcp_oauth".to_string());
    e = e.with_extra(serde_json::json!({
        "grant_id": grant_id,
        "refresh_id": refresh_id,
        "admin_id": admin_id,
        "branch_revoked": branch_revoked,
    }));
    crate::safety::audit::write_entry(&s.log_dir, &e).await;
}

/// Reuse past the grace (e). `rotated_secs_ago` lets an operator tell a laptop
/// that slept past the grace from a race or a theft; owner in `extra.admin_id`,
/// no top-level actor (the presenter is unknown). `success`: the op names the
/// revocation, like the other `mcp_oauth.grant.revoke` rows.
async fn audit_reuse(
    s: &MgmtState,
    started: std::time::Instant,
    grant_id: i64,
    refresh_id: i64,
    admin_id: i64,
    rotated_secs_ago: Option<i64>,
    revoked: bool,
) {
    let mut e = crate::safety::audit::AuditEntry::success(
        "-",
        "-",
        "mcp_oauth.grant.revoke",
        started.elapsed().as_millis() as u64,
    );
    e.auth_method = Some("mcp_oauth".to_string());
    e = e.with_extra(serde_json::json!({
        "grant_id": grant_id,
        "reason": RevokeReason::RefreshReuse.as_str(),
        "refresh_id": refresh_id,
        "admin_id": admin_id,
        "rotated_secs_ago": rotated_secs_ago,
        "revoked": revoked,
    }));
    crate::safety::audit::write_entry(&s.log_dir, &e).await;
}

/// The 200 token response (shared with the refresh grant).
fn token_success(t: &IssuedTokens) -> Response {
    let body = serde_json::json!({
        "access_token": t.access_token,
        "token_type": "Bearer",
        "expires_in": t.expires_in,
        "refresh_token": t.refresh_token,
        // MA0-PLAN §3.8.4 fixes this literal; a grant's scope is always 'mcp'.
        "scope": "mcp",
    });
    // oauth_error_layer `insert`s no-store too, so the result is ONE header.
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(body),
    )
        .into_response()
}

/// An unknown credential: charge the caller's per-IP miss budget. Quota left
/// => the plain `invalid_grant`; exhausted => 429 (shared with the refresh grant).
fn miss_response(s: &MgmtState, ip: &ClientIp) -> Response {
    match s.mcp_oauth_rl.miss_ip.try_acquire(&rl::client_ip_key(ip)) {
        Ok(()) => OAuthError::InvalidGrant.into_response(),
        Err(RateLimitedError(d)) => OAuthError::TemporarilyUnavailable {
            retry_after_secs: rl::retry_after_secs(d),
        }
        .into_response(),
    }
}

/// A known code that failed a check: charge that code's budget. A valid
/// redemption of the same code never reads this bucket.
fn per_code_response(s: &MgmtState, code: &str) -> Response {
    match s.mcp_oauth_rl.per_code.try_acquire(&rl::code_key(code)) {
        Ok(()) => OAuthError::InvalidGrant.into_response(),
        Err(RateLimitedError(d)) => OAuthError::TemporarilyUnavailable {
            retry_after_secs: rl::retry_after_secs(d),
        }
        .into_response(),
    }
}

/// The grant owner's email for the audit snapshot. A read failure or a NULL
/// email only loses the snapshot, never the request.
fn admin_email(conn: &rusqlite::Connection, admin_id: i64) -> Option<String> {
    conn.query_row("SELECT email FROM admins WHERE id = ?1", [admin_id], |r| {
        r.get::<_, Option<String>>(0)
    })
    .ok()
    .flatten()
}

/// Written after the meta guard is dropped. A request that passed every check
/// presented the code and its verifier, so the grant owner is the top-level
/// actor (MA0-PLAN §3.10). `Miss` and `Invalid` write nothing: the endpoint is
/// unauthenticated and audit must not be a disk amplifier.
async fn audit(
    s: &MgmtState,
    op: &str,
    started: std::time::Instant,
    grant: &GrantRef,
    email: Option<String>,
    extra: serde_json::Value,
) {
    let ms = started.elapsed().as_millis() as u64;
    let mut entry = crate::safety::audit::AuditEntry::success("-", "-", op, ms);
    entry.auth_method = Some("mcp_oauth".to_string());
    entry.actor_admin_id = Some(grant.admin_id());
    entry.actor_email_snapshot = email;
    entry = entry.with_extra(extra);
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
}

/// Logs the stage and the error without its SQL text, never a request
/// parameter (the code and the verifier are secrets).
fn server_error(stage: &'static str, e: &rusqlite::Error) -> Response {
    tracing::error!(
        stage,
        err = %crate::error::sqlite_error_without_sql(e),
        "mcp oauth token: meta error"
    );
    OAuthError::ServerError.into_response()
}

//! /oauth/token endpoint — authorization_code + refresh_token grants.
//!
//! Both grants are served here. The authorization_code grant validates:
//!   - code exists + not consumed + not expired
//!   - client_id matches the code's stored client
//!   - redirect_uri matches (TOCTOU re-check vs stored value)
//!   - PKCE S256: SHA-256(code_verifier) == stored code_challenge
//!
//! The refresh_token grant:
//!   - Validates the refresh token exists + not expired + not already rotated
//!   - Issues a new access token + new refresh token
//!   - Marks the old refresh token as rotated (rotated_to_hash + rotated_at)
//!   - Reuse detection (RFC 6819 §5.2.2.3): if the presented token has
//!     rotated_to_hash IS NOT NULL, the entire grant chain for that
//!     client_id + admin_id is revoked and invalid_grant is returned.
//!
//! Error shape: OAuth 2.1 standard `{"error", "error_description"}` with
//! HTTP 400 — NOT drust's standard `{"error_code", "message"}`.
//!
//! v1.29.0 — Task 15.

use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use rusqlite::params;
use serde::Deserialize;

use crate::mgmt::oauth_server::{pkce, storage};
use crate::mgmt::routes::MgmtState;
use crate::safety::audit::AuditEntry;

// ─── request types ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub refresh_token: Option<String>,
    #[allow(dead_code)]
    pub resource: Option<String>,
}

// ─── error helper ────────────────────────────────────────────────────────────

fn oauth_error(status: StatusCode, code: &str, desc: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": desc,
        })),
    )
        .into_response()
}

// ─── dispatcher ──────────────────────────────────────────────────────────────

pub async fn token_endpoint(
    State(s): State<MgmtState>,
    Form(form): Form<TokenForm>,
) -> Response {
    match form.grant_type.as_str() {
        "authorization_code" => handle_code_grant(s, form).await,
        "refresh_token" => handle_refresh_grant(s, form).await,
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only authorization_code and refresh_token are supported",
        ),
    }
}

// ─── authorization_code grant ────────────────────────────────────────────────

async fn handle_code_grant(s: MgmtState, form: TokenForm) -> Response {
    let code = match form.code.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "code required");
        }
    };
    let verifier = match form.code_verifier.as_deref() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_verifier required",
            );
        }
    };
    let client_id = match form.client_id.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id required",
            );
        }
    };
    let redirect_uri = match form.redirect_uri.as_deref() {
        Some(r) if !r.is_empty() => r.to_string(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "redirect_uri required",
            );
        }
    };

    let code_hash = storage::sha256_b64(&code);

    let new_access = storage::new_access_token();
    let new_refresh = storage::new_refresh_token();
    let new_access_hash = storage::sha256_b64(&new_access);
    let new_refresh_hash = storage::sha256_b64(&new_refresh);
    let now = chrono::Utc::now();
    let access_expires = now + chrono::Duration::hours(1);
    let refresh_expires = now + chrono::Duration::days(30);
    let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let access_expires_str = access_expires
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let refresh_expires_str = refresh_expires
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    // All DB work inside one transaction.
    let result: Result<(i64, Option<String>), Response> = {
        let mut conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    &e.to_string(),
                );
            }
        };

        // 1. Look up the code row.
        type CodeRow = (
            String,         // client_id
            i64,            // admin_id
            String,         // redirect_uri
            String,         // pkce_challenge
            String,         // pkce_challenge_method
            String,         // resource_uri
            Option<String>, // scope
            String,         // expires_at
            Option<String>, // consumed_at
        );
        let row: Option<CodeRow> = tx
            .query_row(
                "SELECT client_id, admin_id, redirect_uri, pkce_challenge, pkce_challenge_method,
                        resource_uri, scope, expires_at, consumed_at
                 FROM _oauth_authorization_codes
                 WHERE code_hash = ?1",
                params![&code_hash],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .ok();

        let Some((
            stored_client,
            admin_id,
            stored_redirect,
            challenge,
            challenge_method,
            resource_uri,
            scope,
            expires_at,
            consumed_at,
        )) = row
        else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "unknown code");
        };

        // 2. Already consumed?
        if consumed_at.is_some() {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "code already used",
            );
        }

        // 3. Expired? String compare works because both are ISO-8601 UTC.
        if expires_at <= now_str {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "code expired");
        }

        // 4. client_id must match.
        if stored_client != client_id {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "client_id mismatch",
            );
        }

        // 5. redirect_uri must match.
        if stored_redirect != redirect_uri {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "redirect_uri mismatch",
            );
        }

        // 6. PKCE S256 verification.
        if challenge_method != "S256" || !pkce::verify_s256(&verifier, &challenge) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "PKCE verification failed",
            );
        }

        // 7. Mark the code consumed (same transaction — atomic with token INSERT).
        if let Err(e) = tx.execute(
            "UPDATE _oauth_authorization_codes SET consumed_at = ?1 WHERE code_hash = ?2",
            params![&now_str, &code_hash],
        ) {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }

        // 8. Issue access token.
        if let Err(e) = tx.execute(
            "INSERT INTO _oauth_access_tokens
                (token_hash, client_id, admin_id, resource_uri, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &new_access_hash,
                &client_id,
                admin_id,
                &resource_uri,
                scope.as_deref(),
                &access_expires_str
            ],
        ) {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }

        // 9. Issue refresh token.
        if let Err(e) = tx.execute(
            "INSERT INTO _oauth_refresh_tokens
                (token_hash, client_id, admin_id, resource_uri, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &new_refresh_hash,
                &client_id,
                admin_id,
                &resource_uri,
                scope.as_deref(),
                &refresh_expires_str
            ],
        ) {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }

        if let Err(e) = tx.commit() {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }

        Ok((admin_id, scope))
    };

    let (admin_id, scope) = match result {
        Ok(v) => v,
        Err(r) => return r,
    };

    let entry = AuditEntry::success("-", "-", "admin.oauth.token_issue", 0).with_extra(
        serde_json::json!({
            "client_id": &client_id,
            "actor_admin_id": admin_id,
            "grant": "authorization_code",
        }),
    );
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    Json(serde_json::json!({
        "access_token":  new_access,
        "refresh_token": new_refresh,
        "token_type":    "Bearer",
        "expires_in":    3600,
        "scope":         scope.unwrap_or_else(|| "drust".into()),
    }))
    .into_response()
}

// ─── refresh_token grant ─────────────────────────────────────────────────────

async fn handle_refresh_grant(s: MgmtState, form: TokenForm) -> Response {
    let refresh = match form.refresh_token.as_deref() {
        Some(r) if !r.is_empty() => r.to_string(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "refresh_token required",
            );
        }
    };
    let refresh_hash = storage::sha256_b64(&refresh);

    let new_access = storage::new_access_token();
    let new_refresh = storage::new_refresh_token();
    let new_access_hash = storage::sha256_b64(&new_access);
    let new_refresh_hash = storage::sha256_b64(&new_refresh);
    let now = chrono::Utc::now();
    let access_expires = now + chrono::Duration::hours(1);
    let refresh_expires = now + chrono::Duration::days(30);
    let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let access_expires_str = access_expires
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let refresh_expires_str = refresh_expires
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    enum Outcome {
        Reuse { client_id: String, admin_id: i64 },
        Issued { client_id: String, admin_id: i64, scope: Option<String> },
    }

    // Use an inner async fn pattern via a helper closure to allow early returns
    // as `Err(response)` from the block while keeping the outer function's
    // return type as `Response`.  The labeled-block trick lets us `break`
    // with a value without needing to return from the outer function.
    let outcome: Result<Outcome, Response> = 'db: {
        let mut conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                break 'db Err(oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    &e.to_string(),
                ));
            }
        };

        // Look up the refresh token row.
        type RefRow = (
            String,         // client_id
            i64,            // admin_id
            String,         // resource_uri
            Option<String>, // scope
            String,         // expires_at
            Option<String>, // rotated_to_hash
        );
        let row: Option<RefRow> = tx
            .query_row(
                "SELECT client_id, admin_id, resource_uri, scope, expires_at, rotated_to_hash
                 FROM _oauth_refresh_tokens
                 WHERE token_hash = ?1",
                params![&refresh_hash],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .ok();

        let Some((client_id, admin_id, resource_uri, scope, expires_at, rotated_to_hash)) = row
        else {
            break 'db Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown refresh_token",
            ));
        };

        // Reuse detection (RFC 6819 §5.2.2.3):
        // If this token was already rotated, the entire grant chain is compromised.
        // Revoke all access + refresh tokens for this client_id + admin_id.
        if rotated_to_hash.is_some() {
            let _ = tx.execute(
                "DELETE FROM _oauth_access_tokens WHERE client_id = ?1 AND admin_id = ?2",
                params![&client_id, admin_id],
            );
            let _ = tx.execute(
                "DELETE FROM _oauth_refresh_tokens WHERE client_id = ?1 AND admin_id = ?2",
                params![&client_id, admin_id],
            );
            let _ = tx.commit();
            break 'db Ok(Outcome::Reuse { client_id, admin_id });
        }

        // Expired?
        if expires_at <= now_str {
            break 'db Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token expired",
            ));
        }

        // Mark old refresh token as rotated.
        if let Err(e) = tx.execute(
            "UPDATE _oauth_refresh_tokens
             SET rotated_to_hash = ?1, rotated_at = ?2
             WHERE token_hash = ?3",
            params![&new_refresh_hash, &now_str, &refresh_hash],
        ) {
            break 'db Err(oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            ));
        }

        // Issue new access token.
        if let Err(e) = tx.execute(
            "INSERT INTO _oauth_access_tokens
                (token_hash, client_id, admin_id, resource_uri, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &new_access_hash,
                &client_id,
                admin_id,
                &resource_uri,
                scope.as_deref(),
                &access_expires_str
            ],
        ) {
            break 'db Err(oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            ));
        }

        // Issue new refresh token.
        if let Err(e) = tx.execute(
            "INSERT INTO _oauth_refresh_tokens
                (token_hash, client_id, admin_id, resource_uri, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &new_refresh_hash,
                &client_id,
                admin_id,
                &resource_uri,
                scope.as_deref(),
                &refresh_expires_str
            ],
        ) {
            break 'db Err(oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            ));
        }

        if let Err(e) = tx.commit() {
            break 'db Err(oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            ));
        }

        Ok(Outcome::Issued { client_id, admin_id, scope })
    };

    match outcome {
        Err(r) => r,
        Ok(Outcome::Reuse { client_id, admin_id }) => {
            let entry = AuditEntry::failure(
                "-",
                "-",
                "admin.oauth.token_refresh_reuse_detected",
                0,
                "OAUTH_REFRESH_REUSE",
                "refresh token reuse detected — chain revoked",
            )
            .with_extra(serde_json::json!({
                "client_id": &client_id,
                "actor_admin_id": admin_id,
            }));
            crate::safety::audit::write_entry(&s.log_dir, &entry).await;
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token reuse — chain revoked",
            )
        }
        Ok(Outcome::Issued { client_id, admin_id, scope }) => {
            let entry = AuditEntry::success("-", "-", "admin.oauth.token_refresh", 0).with_extra(
                serde_json::json!({
                    "client_id": &client_id,
                    "actor_admin_id": admin_id,
                    "grant": "refresh_token",
                }),
            );
            crate::safety::audit::write_entry(&s.log_dir, &entry).await;
            Json(serde_json::json!({
                "access_token":  new_access,
                "refresh_token": new_refresh,
                "token_type":    "Bearer",
                "expires_in":    3600,
                "scope":         scope.unwrap_or_else(|| "drust".into()),
            }))
            .into_response()
        }
    }
}

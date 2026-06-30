//! CLI device-flow login (RFC 8628-shaped). v1.44 (CLI Phase 2).
//!
//! Host-plane rendezvous between a headless `drust` CLI and a logged-in admin
//! browser: the CLI `POST`s `/auth/cli/device/start` to mint a `device_code`
//! (returned once, stored only as a hash) + a human `user_code`; the admin
//! opens `/auth/cli/device?user_code=…`, confirms, and `approve` mints a
//! labeled, expiring `drust_pat_cli_*` PAT; the CLI's `poll` then collects it
//! exactly once. Rows live in `meta.sqlite._cli_device_codes` and are reaped
//! hourly by [`sweep_expired_device_codes`].

use crate::auth::admin_token::hash_token;
use crate::error::json_error;
use crate::mgmt::routes::MgmtState;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use rand::{Rng, RngCore};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

pub const CLI_DEVICE_CODE_TTL_SECS: i64 = 900; // 15 min device-code lifetime
pub const CLI_DEVICE_POLL_INTERVAL_SECS: i64 = 5; // RFC 8628 interval
/// Crockford-ish alphabet: no I L O U / 0 1 (visually confusable).
const USER_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 128-bit device_code, returned in plaintext exactly once by `start`; only
/// its `hash_token` digest is persisted (`device_code_hash`).
pub fn generate_device_code() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Human-typed `"XXXX-XXXX"` code drawn from the confusable-free alphabet.
pub fn generate_user_code() -> String {
    let mut rng = rand::thread_rng();
    let pick = |r: &mut rand::rngs::ThreadRng| {
        USER_CODE_ALPHABET[r.gen_range(0..USER_CODE_ALPHABET.len())] as char
    };
    let a: String = (0..4).map(|_| pick(&mut rng)).collect();
    let b: String = (0..4).map(|_| pick(&mut rng)).collect();
    format!("{a}-{b}")
}

#[derive(Deserialize, Default)]
pub struct StartReq {
    #[serde(default)]
    pub client_name: Option<String>,
}

#[derive(Deserialize)]
pub struct PollReq {
    pub device_code: String,
}

/// 200 with a bare `{"status": …}` body — the lifecycle states of the RFC 8628
/// poll (never a 4xx; a 4xx is reserved for a malformed request).
fn poll_status(status: &str) -> Response {
    (StatusCode::OK, Json(json!({ "status": status }))).into_response()
}

/// POST /auth/cli/device/start — mint a device_code + user_code. Unauthenticated
/// (the device_code IS the issued secret); per-IP rate-limited.
pub async fn device_start(
    State(s): State<MgmtState>,
    headers: HeaderMap,
    body: Option<Json<StartReq>>,
) -> Response {
    let fallback: std::net::SocketAddr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback);
    if !s.cli_device_rl.check(ip) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED_IP", "rate limited");
    }
    let client_name = body
        .and_then(|b| b.0.client_name)
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "drust-cli".to_string());

    let ttl_mod = format!("+{CLI_DEVICE_CODE_TTL_SECS} seconds");
    let conn = s.meta.lock().await;
    // user_code is short — retry on the (rare) UNIQUE collision; device_code is
    // 128-bit so its hash never realistically collides.
    let mut last_err = None;
    for _ in 0..8 {
        let device_code = generate_device_code();
        let hash = hash_token(&device_code);
        let user_code = generate_user_code();
        match conn.execute(
            "INSERT INTO _cli_device_codes \
                 (device_code_hash, user_code, client_name, status, expires_at) \
             VALUES (?1, ?2, ?3, 'pending', datetime('now', ?4))",
            params![hash, user_code, client_name, ttl_mod],
        ) {
            Ok(_) => {
                drop(conn);
                let verification_uri = format!(
                    "{}{}",
                    s.public_url,
                    crate::base_path::base("/auth/cli/device")
                );
                let verification_uri_complete =
                    format!("{verification_uri}?user_code={user_code}");
                let out = json!({
                    "device_code": device_code,
                    "user_code": user_code,
                    "verification_uri": verification_uri,
                    "verification_uri_complete": verification_uri_complete,
                    "interval": CLI_DEVICE_POLL_INTERVAL_SECS,
                    "expires_in": CLI_DEVICE_CODE_TTL_SECS,
                });
                return (StatusCode::OK, Json(out)).into_response();
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }
    tracing::warn!(error = ?last_err, "cli device_start: failed to mint a unique code");
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "DEVICE_CODE_MINT_FAILED",
        "could not mint a device code",
    )
}

/// POST /auth/cli/device/poll — the RFC 8628 state machine. Always HTTP 200 with
/// a `status` field for lifecycle states. An unknown code returns a flat
/// `expired` (no enumeration signal).
pub async fn device_poll(State(s): State<MgmtState>, Json(req): Json<PollReq>) -> Response {
    let hash = hash_token(&req.device_code);
    let conn = s.meta.lock().await;

    let row = conn
        .query_row(
            "SELECT status, \
                    datetime(expires_at) < datetime('now') AS expired, \
                    last_polled_at, admin_id \
             FROM _cli_device_codes WHERE device_code_hash = ?1",
            params![hash],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional();
    let (status, expired, last_polled_at, admin_id) = match row {
        Ok(Some(t)) => t,
        Ok(None) => return poll_status("expired"), // unknown code — no enumeration signal
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DEVICE_POLL_FAILED",
                "device poll failed",
            );
        }
    };

    if expired || status == "redeemed" {
        return poll_status("expired");
    }
    if status == "denied" {
        return poll_status("denied");
    }
    if status == "approved" {
        // Consume-once: atomically flip approved → redeemed under the single
        // serialized meta lock. A racing second poll finds `redeemed` → expired.
        let minted: Option<i64> = conn
            .query_row(
                "UPDATE _cli_device_codes SET status='redeemed' \
                 WHERE device_code_hash=?1 AND status='approved' \
                   AND datetime(expires_at) > datetime('now') \
                 RETURNING minted_token_id",
                params![hash],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()
            .ok()
            .flatten()
            .flatten();
        let token_id = match minted {
            Some(tid) => tid,
            None => return poll_status("expired"), // lost the race / no token
        };
        // The PAT plaintext lives only in _admin_tokens.plaintext (never copied
        // into the device table).
        let access_token: Option<String> = conn
            .query_row(
                "SELECT plaintext FROM _admin_tokens WHERE id=?1",
                params![token_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten();
        let Some(access_token) = access_token else {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DEVICE_TOKEN_MISSING",
                "minted token unavailable",
            );
        };
        // PAT expiry — the `expires_at` column is added by T4; tolerate its
        // absence so this scope ships standalone (pre-T4) returning a null expiry.
        let pat_expires: Option<String> = conn
            .query_row(
                "SELECT expires_at FROM _admin_tokens WHERE id=?1",
                params![token_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten();
        let email: Option<String> = match admin_id {
            Some(aid) => conn
                .query_row("SELECT email FROM admins WHERE id=?1", params![aid], |r| {
                    r.get::<_, Option<String>>(0)
                })
                .ok()
                .flatten(),
            None => None,
        };
        let out = json!({
            "status": "approved",
            "access_token": access_token,
            "expires_at": pat_expires,
            "admin": { "id": admin_id, "email": email },
        });
        return (StatusCode::OK, Json(out)).into_response();
    }

    // status == 'pending': decide slow_down from the PREVIOUS poll timestamp,
    // then stamp this poll. A too-fast client keeps tripping slow_down until it
    // backs off to >= interval (steady-cadence RFC semantics).
    let slow_down = match last_polled_at {
        Some(_) => conn
            .query_row(
                "SELECT (julianday('now') - julianday(?1)) * 86400.0 < ?2",
                params![last_polled_at, CLI_DEVICE_POLL_INTERVAL_SECS],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false),
        None => false,
    };
    let _ = conn.execute(
        "UPDATE _cli_device_codes SET last_polled_at = datetime('now') \
         WHERE device_code_hash = ?1",
        params![hash],
    );
    if slow_down {
        poll_status("slow_down")
    } else {
        poll_status("pending")
    }
}

/// Best-effort hourly cleanup: delete every device-code row whose `expires_at`
/// is in the past. `expires_at` is the source of truth (poll/approve reject an
/// expired row regardless), so a missed sweep only leaves rows lingering until
/// the next one. Returns the number of rows deleted.
pub async fn sweep_expired_device_codes(meta: &Arc<Mutex<Connection>>) -> usize {
    let conn = meta.lock().await;
    conn.execute(
        "DELETE FROM _cli_device_codes WHERE datetime(expires_at) < datetime('now')",
        [],
    )
    .unwrap_or(0)
}

#[cfg(test)]
mod gen_tests {
    use super::*;
    #[test]
    fn user_code_excludes_confusables_and_is_grouped() {
        for _ in 0..200 {
            let c = generate_user_code();
            assert_eq!(c.len(), 9); // XXXX-XXXX
            assert_eq!(&c[4..5], "-");
            for ch in c.chars().filter(|c| *c != '-') {
                assert!(!"ILOU01".contains(ch), "confusable {ch} leaked into {c}");
                assert!(USER_CODE_ALPHABET.contains(&(ch as u8)));
            }
        }
    }
    #[test]
    fn device_code_is_high_entropy_and_hashes_stably() {
        let a = generate_device_code();
        let b = generate_device_code();
        assert_ne!(a, b);
        assert!(a.len() >= 20); // 16 bytes base64url
        assert_eq!(
            crate::auth::admin_token::hash_token(&a),
            crate::auth::admin_token::hash_token(&a)
        ); // deterministic
        assert!(!crate::auth::admin_token::hash_token(&a).contains(&a)); // hash != plaintext
    }
}

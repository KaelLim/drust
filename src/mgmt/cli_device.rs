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
use crate::auth::middleware::AdminId;
use crate::error::json_error;
use crate::mgmt::routes::MgmtState;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

pub const CLI_DEVICE_CODE_TTL_SECS: i64 = 900; // 15 min device-code lifetime
pub const CLI_DEVICE_POLL_INTERVAL_SECS: i64 = 5; // RFC 8628 interval
/// Documented default lifetime of the CLI PAT minted on device approval
/// (D-10: 24h). The live value comes from
/// [`crate::mgmt::admin_pat::cli_pat_ttl_secs`] (`DRUST_CLI_PAT_TTL_SECS`, F9);
/// this const records that function's fallback.
pub const CLI_PAT_TTL: i64 = 86400;
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
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED_IP",
            "rate limited",
        );
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
                let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
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
pub async fn device_poll(
    State(s): State<MgmtState>,
    headers: HeaderMap,
    Json(req): Json<PollReq>,
) -> Response {
    let fallback: std::net::SocketAddr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback);
    if !s.cli_poll_rl.check(ip) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED_IP",
            "rate limited",
        );
    }
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

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub user_code: Option<String>,
}

#[derive(Deserialize)]
pub struct DenyForm {
    pub user_code: String,
    pub csrf: String,
}

#[derive(Deserialize)]
pub struct ApproveForm {
    pub user_code: String,
    pub csrf: String,
}

/// GET /auth/cli/device — the admin-facing approval page. Rides inside
/// `protected`, so a no-cookie browser request 302s to /login before reaching
/// here (browser invariant preserved untouched). Sets the double-submit CSRF
/// cookie and bakes the same token into the approve/deny forms.
pub async fn device_page(
    State(s): State<MgmtState>,
    Extension(AdminId(admin_id)): Extension<AdminId>,
    Query(q): Query<PageQuery>,
) -> Response {
    let user_code = q.user_code.unwrap_or_default();
    let conn = s.meta.lock().await;
    let client_name: Option<String> = conn
        .query_row(
            "SELECT client_name FROM _cli_device_codes \
             WHERE user_code=?1 AND status='pending' \
               AND datetime(expires_at) > datetime('now')",
            params![user_code],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .ok()
        .flatten();
    let Some(client_name) = client_name else {
        drop(conn);
        return Html(render_not_found_page()).into_response();
    };
    let email: Option<String> = conn
        .query_row(
            "SELECT email FROM admins WHERE id=?1",
            params![admin_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten();
    drop(conn);

    let csrf = csrf_for(&user_code);
    let html = render_approval_page(&client_name, email.as_deref(), &user_code, &csrf);
    let mut resp = Html(html).into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        build_csrf_cookie(&csrf).parse().unwrap(),
    );
    resp
}

/// POST /auth/cli/device/deny — double-submit-CSRF-gated. Flips a pending row to
/// `denied`; the CLI's next poll then reads `{"status":"denied"}`.
pub async fn device_deny(
    State(s): State<MgmtState>,
    Extension(AdminId(admin_id)): Extension<AdminId>,
    headers: HeaderMap,
    Form(form): Form<DenyForm>,
) -> Response {
    if let Err(resp) = check_csrf(&headers, &form.csrf, &form.user_code) {
        return resp;
    }
    {
        let conn = s.meta.lock().await;
        let _ = conn.execute(
            "UPDATE _cli_device_codes SET status='denied' \
             WHERE user_code=?1 AND status='pending'",
            params![form.user_code],
        );
    }
    let entry =
        crate::safety::audit::AuditEntry::success("-", "-", "POST /auth/cli/device/deny", 0)
            .with_extra(json!({ "admin_id": admin_id, "user_code": form.user_code }));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
    Html(render_denied_page()).into_response()
}

/// POST /auth/cli/device/approve — double-submit-CSRF-gated. Under ONE meta lock
/// (TOCTOU-safe: re-verify → mint → commit all on the serialized connection):
/// re-confirm the row is still `pending` + unexpired, mint a labeled, expiring
/// `drust_pat_cli_*` PAT via the T4 primitive (inserted OUTSIDE the relaxed
/// `uniq_admin_tokens_active` index, so it never collides with the admin's single
/// unlabeled UI/MCP PAT), and flip the row to `approved` carrying `admin_id` +
/// `minted_token_id`. The PAT plaintext is never copied into the device table —
/// the CLI's next poll reads it once from `_admin_tokens.plaintext` and redeems.
pub async fn device_approve(
    State(s): State<MgmtState>,
    Extension(AdminId(admin_id)): Extension<AdminId>,
    headers: HeaderMap,
    Form(form): Form<ApproveForm>,
) -> Response {
    if let Err(resp) = check_csrf(&headers, &form.csrf, &form.user_code) {
        return resp;
    }
    let client_name = {
        let conn = s.meta.lock().await;
        // Re-verify pending + unexpired under the lock (TOCTOU-safe).
        let row: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, client_name FROM _cli_device_codes \
                 WHERE user_code=?1 AND status='pending' \
                   AND datetime(expires_at) > datetime('now')",
                params![form.user_code],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .ok()
            .flatten();
        let Some((row_id, client_name)) = row else {
            return Html(render_not_found_page()).into_response();
        };
        // Mint the labeled, expiring CLI PAT (T4-owned primitive). The non-NULL
        // `label` keeps it outside the relaxed unique index and excludes it from
        // the migration legacy-revoke + reroll sweep.
        let (token_id, _plaintext) = match crate::auth::admin_token::mint_cli_token(
            &conn,
            admin_id,
            &client_name,
            crate::mgmt::admin_pat::cli_pat_ttl_secs(),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = ?e, "cli device_approve: mint_cli_token failed");
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DEVICE_MINT_FAILED",
                    "could not mint CLI token",
                );
            }
        };
        let _ = conn.execute(
            "UPDATE _cli_device_codes \
             SET status='approved', admin_id=?1, minted_token_id=?2 WHERE id=?3",
            params![admin_id, token_id, row_id],
        );
        client_name
    };
    let entry =
        crate::safety::audit::AuditEntry::success("-", "-", "POST /auth/cli/device/approve", 0)
            .with_extra(json!({ "admin_id": admin_id, "client_name": client_name }));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
    Html(render_approved_page()).into_response()
}

/// Double-submit CSRF token, HMAC-bound to the `user_code` (v1.45.1 F1) so it
/// cannot be forged by a party that does not hold the process secret, and is
/// tied to the specific device request. Atop the `SameSite=Lax` admin-session
/// gate (the `AdminId` requirement), this closes sibling-subdomain cookie-toss.
fn check_csrf(headers: &HeaderMap, form_csrf: &str, user_code: &str) -> Result<(), Response> {
    let cookie_csrf = read_cookie(headers, "drust_cli_csrf").unwrap_or_default();
    let expected = csrf_for(user_code);
    let double_submit_ok: bool = cookie_csrf.as_bytes().ct_eq(form_csrf.as_bytes()).into();
    let bound_ok: bool = form_csrf.as_bytes().ct_eq(expected.as_bytes()).into();
    if !form_csrf.is_empty() && double_submit_ok && bound_ok {
        Ok(())
    } else {
        Err(json_error(
            StatusCode::FORBIDDEN,
            "CSRF_MISMATCH",
            "CSRF token missing or mismatched",
        ))
    }
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=')
            && k == name
        {
            return Some(v.to_string());
        }
    }
    None
}

/// Per-process CSRF secret. A restart rotates it — in-flight approval pages
/// then fail CSRF and the admin retries (15-min device TTL bounds the window).
fn csrf_secret() -> &'static [u8; 32] {
    static SECRET: OnceLock<[u8; 32]> = OnceLock::new();
    SECRET.get_or_init(|| {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        b
    })
}

/// Double-submit CSRF token, HMAC-bound to the `user_code` (v1.45.1 F1) so it
/// cannot be forged by a party that does not hold the process secret, and is
/// tied to the specific device request. Atop the `SameSite=Lax` admin-session
/// gate (the `AdminId` requirement), this closes sibling-subdomain cookie-toss.
fn csrf_for(user_code: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(csrf_secret()).expect("hmac key");
    mac.update(user_code.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Server-rendered double-submit cookie. `HttpOnly` is safe here because the
/// SERVER (not JS) bakes the same token into the form; mirrors
/// `build_session_cookie` (`middleware.rs`). `Path` via `base_path::cookie_path`.
fn build_csrf_cookie(csrf: &str) -> String {
    let cpath = crate::base_path::cookie_path("");
    let base = format!("drust_cli_csrf={csrf}; Path={cpath}; HttpOnly; SameSite=Lax");
    if std::env::var("DRUST_DEV_NO_SECURE_COOKIES").is_ok() {
        base
    } else {
        format!("{base}; Secure")
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn render_approval_page(
    client_name: &str,
    email: Option<&str>,
    user_code: &str,
    csrf: &str,
) -> String {
    let approve = crate::base_path::base("/auth/cli/device/approve");
    let deny = crate::base_path::base("/auth/cli/device/deny");
    let cn = html_escape(client_name);
    let uc = html_escape(user_code);
    let who = html_escape(email.unwrap_or("this account"));
    let csrf = html_escape(csrf);
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize CLI device</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;line-height:1.5">
<h1>Authorize a device</h1>
<p>The client <strong>{cn}</strong> is requesting access to your drust account
(<strong>{who}</strong>).</p>
<p>Verification code: <code>{uc}</code></p>
<p>Only continue if you just started a <code>drust auth login</code> on this device.</p>
<form method="post" action="{approve}" style="display:inline">
  <input type="hidden" name="user_code" value="{uc}">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit">Authorize</button>
</form>
<form method="post" action="{deny}" style="display:inline">
  <input type="hidden" name="user_code" value="{uc}">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit">Deny</button>
</form>
</body></html>"#
    )
}

fn render_not_found_page() -> String {
    r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Code not found</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto">
<h1>Code not found or expired</h1>
<p>This verification code is unknown, already used, or has expired. Start a new
<code>drust auth login</code> and try again.</p>
</body></html>"#
        .to_string()
}

fn render_denied_page() -> String {
    r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Request denied</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto">
<h1>Request denied</h1>
<p>The device authorization request was denied. You can close this window.</p>
</body></html>"#
        .to_string()
}

fn render_approved_page() -> String {
    r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Device authorized</title></head>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto">
<h1>Device authorized</h1>
<p>You have authorized the CLI device. Return to your terminal — it will pick up
the credential automatically. You can close this window.</p>
</body></html>"#
        .to_string()
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
    fn csrf_is_bound_to_user_code() {
        let a = csrf_for("ABCD-EFGH");
        assert_eq!(a, csrf_for("ABCD-EFGH")); // stable within process
        assert_ne!(a, csrf_for("WXYZ-2345")); // bound to the code
        // a forged token that merely matches itself in cookie+form must fail:
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "drust_cli_csrf=forged".parse().unwrap());
        assert!(check_csrf(&h, "forged", "ABCD-EFGH").is_err());
        // the server-issued token passes double-submit:
        let mut h2 = HeaderMap::new();
        h2.insert(header::COOKIE, format!("drust_cli_csrf={a}").parse().unwrap());
        assert!(check_csrf(&h2, &a, "ABCD-EFGH").is_ok());
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

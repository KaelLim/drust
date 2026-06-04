use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::auth::middleware::AuthCtx;
use crate::auth::user::hash_password;
use crate::error::json_error;
use crate::safety::audit::AuditEntry;
use crate::tenant::router::TenantAuthState;

const PASSWORD_MIN: usize = 8;
const PASSWORD_MAX: usize = 128;
const PROFILE_MAX_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
pub struct RegisterBody {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub profile: Option<serde_json::Value>,
}

pub async fn register_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Response {
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    // ConnectInfo is unavailable with oneshot (no make_service_with_connect_info).
    // In production, client IP always comes from X-Forwarded-For (S3 spec).
    // Fall back to loopback when XFF is absent (tests, direct loopback calls).
    let fallback_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);
    if !state.register_rl.check(ip) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED_IP",
            "rate limited",
        );
    }
    if body.password.len() < PASSWORD_MIN {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PASSWORD_TOO_SHORT",
            "password too short",
        );
    }
    if body.password.len() > PASSWORD_MAX {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PASSWORD_TOO_LONG",
            "password too long",
        );
    }
    // Canonicalize email — strip surrounding whitespace before validating and
    // storing. Without this, `a@b.com` and ` a@b.com ` would both be accepted
    // as distinct users since SQL's UNIQUE COLLATE NOCASE is case-only, not
    // whitespace-aware.
    let email = body.email.trim().to_string();
    if !email_looks_valid(&email) {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "EMAIL_INVALID",
            "invalid email",
        );
    }
    let profile_str = crate::auth::profile::encode(body.profile.as_ref());
    if let Some(s) = &profile_str
        && s.len() > PROFILE_MAX_BYTES
    {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PROFILE_TOO_LARGE",
            "profile JSON exceeds 64 KB",
        );
    }
    let allow: bool = {
        let conn = state.meta.lock().await;
        conn.query_row(
            "SELECT allow_self_register FROM tenants WHERE id = ?1",
            rusqlite::params![tenant_id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
            != 0
    };
    if !allow {
        return json_error(
            StatusCode::FORBIDDEN,
            "SELF_REGISTER_DISABLED",
            "self-registration disabled for this tenant",
        );
    }
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "HASH_FAILED", ""),
    };
    let now = chrono::Utc::now().to_rfc3339();
    let user_id = format!("u-{}", uuid::Uuid::new_v4());
    let uid_for_insert = user_id.clone();
    let email_for_insert = email.clone();
    let now_for_insert = now.clone();
    let inserted = pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_users \
                 (id, email, password_hash, verified, profile, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, 0, ?4, ?5, ?5)",
                rusqlite::params![
                    uid_for_insert,
                    email_for_insert,
                    hash,
                    profile_str,
                    now_for_insert
                ],
            )
        })
        .await;
    let op = format!("POST /auth/register");
    match inserted {
        Ok(_) => {
            let mut entry =
                AuditEntry::success(&tenant_id, "-", &op, 0).with_extra(serde_json::json!({
                    "email": email,
                    "auth_user_id": user_id,
                    "auth_kind": "user",
                }));
            entry.auth_method = Some("password".to_string());
            crate::safety::audit_db::try_send(&entry);
            (
                StatusCode::CREATED,
                Json(json!({"user_id": user_id, "email": email, "created_at": now})),
            )
                .into_response()
        }
        Err(e) if e.to_string().contains("UNIQUE") => {
            let mut entry = AuditEntry::failure(&tenant_id, "-", &op, 0, "HTTP_409", "")
                .with_extra(serde_json::json!({"email": email, "auth_kind": "user"}));
            entry.auth_method = Some("password".to_string());
            crate::safety::audit_db::try_send(&entry);
            json_error(
                StatusCode::CONFLICT,
                "EMAIL_EXISTS",
                "email already registered",
            )
        }
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    }
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub email: String,
    pub password: String,
}

pub async fn login_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    // ConnectInfo unavailable with oneshot — use XFF header, fall back to loopback.
    let fallback_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);
    if !state.login_rl.check(ip) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED_IP",
            "rate limited",
        );
    }
    let email = body.email.trim().to_string();

    // Validate tenant exists in meta BEFORE opening pool — prevents disk-fill
    // from arbitrary tenant IDs in the URL. Return INVALID_CREDENTIALS (not
    // TENANT_NOT_FOUND) so callers cannot enumerate tenant existence via login.
    let tenant_exists: bool = {
        let conn = state.meta.lock().await;
        conn.query_row(
            "SELECT 1 FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |_| Ok(()),
        )
        .is_ok()
    };
    if !tenant_exists {
        // S1: still spend an argon2 verify so timing matches the legit path.
        let _ = crate::auth::user::verify_password(&body.password, crate::auth::user::dummy_hash());
        return json_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "invalid email or password",
        );
    }
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => {
            let _ =
                crate::auth::user::verify_password(&body.password, crate::auth::user::dummy_hash());
            return json_error(
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "invalid email or password",
            );
        }
    };

    // Lookup user (case-insensitive). If absent, use DUMMY_HASH so argon2
    // still runs (S1 timing equalization). Empty uid flags the absent case.
    let email_for_lookup = email.clone();
    let row: rusqlite::Result<Option<(String, String)>> = pool
        .with_reader(move |c| {
            match c.query_row(
                "SELECT id, password_hash FROM _system_users \
                 WHERE email = ?1 COLLATE NOCASE",
                rusqlite::params![email_for_lookup],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            ) {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await;
    let (uid, phc) = match row {
        Ok(Some(pair)) => pair,
        _ => (String::new(), crate::auth::user::dummy_hash().to_owned()),
    };
    let op = format!("POST /auth/login");
    // v1.12: OAuth-only account — short-circuit BEFORE argon2 verify on the
    // real (sentinel) hash, but still spend one argon2 verify on DUMMY_HASH
    // so latency matches the wrong-password / unknown-email paths above.
    // Without this dummy call, an attacker can distinguish "this email is
    // OAuth-only" from "wrong password" by timing alone (S1 invariant from
    // v1.9 — same defense, new branch). Audit shape stays identical too.
    if crate::auth::oauth_sentinel::is_oauth_only(&phc) {
        let _ = crate::auth::user::verify_password(&body.password, crate::auth::user::dummy_hash());
        let mut entry = AuditEntry::failure(&tenant_id, "-", &op, 0, "HTTP_401", "")
            .with_extra(serde_json::json!({"email": email, "auth_kind": "user"}));
        entry.auth_method = Some("password".to_string());
        crate::safety::audit_db::try_send(&entry);
        return json_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "invalid email or password",
        );
    }
    let ok = crate::auth::user::verify_password(&body.password, &phc).unwrap_or(false);
    if !ok || uid.is_empty() {
        // S6: log email for correlation but never the attempted password.
        let mut entry = AuditEntry::failure(&tenant_id, "-", &op, 0, "HTTP_401", "")
            .with_extra(serde_json::json!({"email": email, "auth_kind": "user"}));
        entry.auth_method = Some("password".to_string());
        crate::safety::audit_db::try_send(&entry);
        return json_error(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "invalid email or password",
        );
    }

    let ip_str = ip.to_string();
    let uid_clone = uid.clone();
    let token = match pool
        .with_writer(move |c| {
            crate::auth::user_session::create_session(c, &uid_clone, Some(&ip_str), 30)
        })
        .await
    {
        Ok(t) => t,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    };
    let exp = chrono::Utc::now() + chrono::Duration::days(30);
    let mut entry = AuditEntry::success(&tenant_id, "-", &op, 0).with_extra(serde_json::json!({
        "email": email,
        "auth_user_id": uid,
        "ip_at_login": ip.to_string(),
        "auth_kind": "user",
    }));
    entry.auth_method = Some("password".to_string());
    crate::safety::audit_db::try_send(&entry);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "token": token,
            "user_id": uid,
            "expires_at": exp.to_rfc3339(),
        })),
    )
        .into_response()
}

/// Light syntactic check. Accepts `local@domain.tld`; rejects bare domains,
/// multiple `@`, empty parts. Not RFC 5321 exhaustive — full validation
/// happens at email-verification time.
fn email_looks_valid(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 3 || s.len() > 254 {
        return false;
    }
    let mut parts = s.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return false;
    }
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

pub async fn logout_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
) -> Response {
    let token_hash = match &ctx {
        AuthCtx::User { token_hash, .. } => token_hash.clone(),
        _ => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "NOT_USER_TOKEN",
                "logout requires user token",
            );
        }
    };
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let _ = pool
        .with_writer(move |c| crate::auth::user_session::revoke_session_by_hash(c, &token_hash))
        .await;
    (StatusCode::OK, Json(json!({}))).into_response()
}

pub async fn logout_all_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
) -> Response {
    let user_id = match &ctx {
        AuthCtx::User { user_id, .. } => user_id.clone(),
        _ => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "NOT_USER_TOKEN",
                "logout-all requires user token",
            );
        }
    };
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let n = pool
        .with_writer(move |c| crate::auth::user_session::revoke_all_sessions(c, &user_id))
        .await
        .unwrap_or(0);
    (StatusCode::OK, Json(json!({"revoked": n}))).into_response()
}

// ── helpers shared by GET /me and PATCH /me ──────────────────────────────────

async fn fetch_me_row(
    pool: &crate::storage::pool::TenantPool,
    user_id: &str,
) -> rusqlite::Result<(String, String, i64, Option<String>, String, String)> {
    let uid = user_id.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT id, email, verified, profile, created_at, updated_at \
             FROM _system_users WHERE id = ?1",
            rusqlite::params![uid],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        )
    })
    .await
}

fn me_row_to_response(
    id: String,
    email: String,
    verified: i64,
    profile: Option<String>,
    created_at: String,
    updated_at: String,
) -> Response {
    let prof = crate::auth::profile::decode(profile.as_deref());
    (
        StatusCode::OK,
        Json(json!({
            "id": id,
            "email": email,
            "verified": verified != 0,
            "profile": prof,
            "created_at": created_at,
            "updated_at": updated_at,
        })),
    )
        .into_response()
}

// ── GET /t/{tenant}/me ────────────────────────────────────────────────────────

pub async fn me_get_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
) -> Response {
    let user_id = match &ctx {
        AuthCtx::User { user_id, .. } => user_id.clone(),
        _ => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "NOT_USER_TOKEN",
                "user token required",
            );
        }
    };
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    match fetch_me_row(&pool, &user_id).await {
        Ok((id, email, verified, profile, ca, ua)) => {
            me_row_to_response(id, email, verified, profile, ca, ua)
        }
        Err(_) => json_error(
            StatusCode::UNAUTHORIZED,
            "TOKEN_REVOKED",
            "user no longer exists",
        ),
    }
}

// ── PATCH /t/{tenant}/me ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PatchMeBody {
    pub profile: serde_json::Value,
}

pub async fn me_patch_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
    Json(body): Json<PatchMeBody>,
) -> Response {
    let user_id = match &ctx {
        AuthCtx::User { user_id, .. } => user_id.clone(),
        _ => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "NOT_USER_TOKEN",
                "user token required",
            );
        }
    };
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    let profile_str = crate::auth::profile::encode(Some(&body.profile)).unwrap_or_default();
    if profile_str.len() > PROFILE_MAX_BYTES {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PROFILE_TOO_LARGE",
            "profile JSON exceeds 64 KB",
        );
    }
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let now = chrono::Utc::now().to_rfc3339();
    let uid_for_update = user_id.clone();
    if pool
        .with_writer(move |c| {
            c.execute(
                "UPDATE _system_users SET profile = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![profile_str, now, uid_for_update],
            )
        })
        .await
        .is_err()
    {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "");
    }
    match fetch_me_row(&pool, &user_id).await {
        Ok((id, email, verified, profile, ca, ua)) => {
            me_row_to_response(id, email, verified, profile, ca, ua)
        }
        Err(_) => json_error(
            StatusCode::UNAUTHORIZED,
            "TOKEN_REVOKED",
            "user no longer exists",
        ),
    }
}

// ── POST /t/{tenant}/me/password ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ChangePasswordBody {
    pub current_password: String,
    pub new_password: String,
}

pub async fn me_password_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    let user_id = match &ctx {
        AuthCtx::User { user_id, .. } => user_id.clone(),
        _ => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "NOT_USER_TOKEN",
                "user token required",
            );
        }
    };
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    if body.new_password.len() < PASSWORD_MIN {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PASSWORD_TOO_SHORT",
            "password too short",
        );
    }
    if body.new_password.len() > PASSWORD_MAX {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PASSWORD_TOO_LONG",
            "password too long",
        );
    }
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    // Fetch current password hash for verification
    let uid_for_read = user_id.clone();
    let phc: String = match pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT password_hash FROM _system_users WHERE id = ?1",
                rusqlite::params![uid_for_read],
                |r| r.get::<_, String>(0),
            )
        })
        .await
    {
        Ok(s) => s,
        Err(_) => return json_error(StatusCode::UNAUTHORIZED, "TOKEN_REVOKED", ""),
    };
    // v1.12: OAuth-only account cannot rotate password — there is no
    // current password to verify. Tell the caller explicitly (unlike the
    // login path, the user is authenticated so existence is not a secret).
    if crate::auth::oauth_sentinel::is_oauth_only(&phc) {
        return json_error(
            StatusCode::CONFLICT,
            "OAUTH_ONLY_NO_PASSWORD",
            "this account has no password; set up password recovery via your OAuth provider",
        );
    }
    if !crate::auth::user::verify_password(&body.current_password, &phc).unwrap_or(false) {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "WRONG_CURRENT_PASSWORD",
            "current password is incorrect",
        );
    }
    let new_hash = match hash_password(&body.new_password) {
        Ok(h) => h,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "HASH_FAILED", ""),
    };
    let fallback_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr).to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let uid_for_tx = user_id.clone();
    // Atomic: update hash, revoke all sessions, issue new session
    let new_token = match pool
        .with_writer(move |c| -> rusqlite::Result<String> {
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE _system_users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![new_hash, now, uid_for_tx],
            )?;
            tx.execute(
                "DELETE FROM _system_sessions WHERE user_id = ?1",
                rusqlite::params![uid_for_tx],
            )?;
            let token = crate::auth::user_session::create_session(&tx, &uid_for_tx, Some(&ip), 30)?;
            tx.commit()?;
            Ok(token)
        })
        .await
    {
        Ok(t) => t,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    };
    let exp = chrono::Utc::now() + chrono::Duration::days(30);
    (
        StatusCode::OK,
        Json(json!({
            "token": new_token,
            "expires_at": exp.to_rfc3339(),
        })),
    )
        .into_response()
}

use axum::Extension;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::auth::middleware::AuthCtx;
use crate::auth::user::hash_password;
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
        None => return err(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    // ConnectInfo is unavailable with oneshot (no make_service_with_connect_info).
    // In production, client IP always comes from X-Forwarded-For (S3 spec).
    // Fall back to loopback when XFF is absent (tests, direct loopback calls).
    let fallback_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);
    if !state.register_rl.check(ip) {
        return err(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED_IP", "rate limited");
    }
    if body.password.len() < PASSWORD_MIN {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PASSWORD_TOO_SHORT",
            "password too short",
        );
    }
    if body.password.len() > PASSWORD_MAX {
        return err(
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
        return err(StatusCode::UNPROCESSABLE_ENTITY, "EMAIL_INVALID", "invalid email");
    }
    let profile_str = body.profile.as_ref().map(|v| v.to_string());
    if let Some(s) = &profile_str {
        if s.len() > PROFILE_MAX_BYTES {
            return err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "PROFILE_TOO_LARGE",
                "profile JSON exceeds 64 KB",
            );
        }
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
        return err(
            StatusCode::FORBIDDEN,
            "SELF_REGISTER_DISABLED",
            "self-registration disabled for this tenant",
        );
    }
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "HASH_FAILED", ""),
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
                rusqlite::params![uid_for_insert, email_for_insert, hash, profile_str, now_for_insert],
            )
        })
        .await;
    match inserted {
        Ok(_) => (
            StatusCode::CREATED,
            Json(json!({"user_id": user_id, "email": email, "created_at": now})),
        )
            .into_response(),
        Err(e) if e.to_string().contains("UNIQUE") => {
            err(StatusCode::CONFLICT, "EMAIL_EXISTS", "email already registered")
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "INSERT_FAILED", ""),
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
        None => return err(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    // ConnectInfo unavailable with oneshot — use XFF header, fall back to loopback.
    let fallback_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);
    if !state.login_rl.check(ip) {
        return err(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED_IP", "rate limited");
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
        let _ = crate::auth::user::verify_password(&body.password, &crate::auth::user::DUMMY_HASH);
        return err(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "invalid email or password",
        );
    }
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => {
            let _ = crate::auth::user::verify_password(
                &body.password,
                &crate::auth::user::DUMMY_HASH,
            );
            return err(
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
        _ => (String::new(), crate::auth::user::DUMMY_HASH.clone()),
    };
    let ok = crate::auth::user::verify_password(&body.password, &phc).unwrap_or(false);
    if !ok || uid.is_empty() {
        return err(
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
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "SESSION_INSERT", ""),
    };
    let exp = chrono::Utc::now() + chrono::Duration::days(30);
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
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

pub async fn logout_handler(
    State(state): State<TenantAuthState>,
    Path(params): Path<HashMap<String, String>>,
    Extension(ctx): Extension<AuthCtx>,
) -> Response {
    let token_hash = match &ctx {
        AuthCtx::User { token_hash, .. } => token_hash.clone(),
        _ => return err(StatusCode::UNAUTHORIZED, "NOT_USER_TOKEN", "logout requires user token"),
    };
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return err(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let _ = pool
        .with_writer(move |c| {
            crate::auth::user_session::revoke_session_by_hash(c, &token_hash)
        })
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
        _ => return err(StatusCode::UNAUTHORIZED, "NOT_USER_TOKEN", "logout-all requires user token"),
    };
    let tenant_id = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return err(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing tenant"),
    };
    let pool = match state.registry.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let n = pool
        .with_writer(move |c| {
            crate::auth::user_session::revoke_all_sessions(c, &user_id)
        })
        .await
        .unwrap_or(0);
    (StatusCode::OK, Json(json!({"revoked": n}))).into_response()
}

fn err(status: StatusCode, code: &str, msg: &str) -> Response {
    (status, Json(json!({"error_code": code, "message": msg}))).into_response()
}

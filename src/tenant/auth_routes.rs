use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;

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
    if !email_looks_valid(&body.email) {
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
    let email = body.email.clone();
    let hash_clone = hash.clone();
    let profile_clone = profile_str.clone();
    let now_clone = now.clone();
    let uid_clone = user_id.clone();
    let inserted = pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_users \
                 (id, email, password_hash, verified, profile, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, 0, ?4, ?5, ?5)",
                rusqlite::params![uid_clone, email, hash_clone, profile_clone, now_clone],
            )
        })
        .await;
    match inserted {
        Ok(_) => (
            StatusCode::CREATED,
            Json(json!({"user_id": user_id, "email": body.email, "created_at": now})),
        )
            .into_response(),
        Err(e) if e.to_string().contains("UNIQUE") => {
            err(StatusCode::CONFLICT, "EMAIL_EXISTS", "email already registered")
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "INSERT_FAILED", ""),
    }
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

fn err(status: StatusCode, code: &str, msg: &str) -> Response {
    (status, Json(json!({"error_code": code, "message": msg}))).into_response()
}

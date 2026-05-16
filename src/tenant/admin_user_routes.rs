//! Service-only admin endpoints for managing users within a tenant.
//!
//! Routes (all service-key-only):
//!   POST   /t/{tenant}/admin/users              — create user
//!   GET    /t/{tenant}/admin/users              — list users (with q/limit/offset)
//!   GET    /t/{tenant}/admin/users/{uid}        — get one user
//!   PATCH  /t/{tenant}/admin/users/{uid}        — update user fields
//!   DELETE /t/{tenant}/admin/users/{uid}        — delete + cascade
//!   POST   /t/{tenant}/admin/users/{uid}/revoke-sessions — kick all sessions

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

use crate::auth::middleware::ServiceTid;
use crate::error::json_error;
use crate::tenant::router::TenantAuthState;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn get_uid(params: &HashMap<String, String>) -> Result<String, Response> {
    params
        .get("uid")
        .cloned()
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing uid"))
}

// ─── request bodies ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateUserBody {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub profile: Option<serde_json::Value>,
    #[serde(default)]
    pub verified: Option<bool>,
}

#[derive(Deserialize)]
pub struct UpdateUserBody {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub profile: Option<serde_json::Value>,
    #[serde(default)]
    pub verified: Option<bool>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub q: Option<String>,
}

fn default_limit() -> i64 {
    50
}

// ─── handlers ─────────────────────────────────────────────────────────────────

pub async fn create_user_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let email = body.email.trim().to_string();
    let hash = match crate::auth::user::hash_password(&body.password) {
        Ok(h) => h,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "HASH_FAILED", ""),
    };
    let uid = format!("u-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let profile_str = crate::auth::profile::encode(body.profile.as_ref());
    let verified = if body.verified.unwrap_or(false) { 1i64 } else { 0i64 };
    let uid2 = uid.clone();
    let email2 = email.clone();
    let now2 = now.clone();
    let res = pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_users \
                 (id, email, password_hash, verified, profile, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                rusqlite::params![uid2, email2, hash, verified, profile_str, now2],
            )
        })
        .await;
    match res {
        Ok(_) => (
            StatusCode::CREATED,
            Json(json!({"user_id": uid, "email": email, "created_at": now})),
        )
            .into_response(),
        Err(e) if e.to_string().contains("UNIQUE") => {
            json_error(StatusCode::CONFLICT, "EMAIL_EXISTS", "email already in use")
        }
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    }
}

pub async fn list_users_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Query(q): Query<ListQuery>,
) -> Response {
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let pat = format!("%{}%", q.q.as_deref().unwrap_or(""));
    let limit = q.limit;
    let offset = q.offset;
    let pat2 = pat.clone();
    let users: Vec<serde_json::Value> = pool
        .with_reader(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, email, verified, profile, created_at, updated_at \
                 FROM _system_users \
                 WHERE email LIKE ?1 COLLATE NOCASE \
                 ORDER BY created_at DESC \
                 LIMIT ?2 OFFSET ?3",
            )?;
            let rows: Vec<serde_json::Value> = stmt
                .query_map(rusqlite::params![pat2, limit, offset], |r| {
                    let profile_raw: Option<String> = r.get(3)?;
                    let profile = crate::auth::profile::decode(profile_raw.as_deref());
                    Ok(json!({
                        "id":         r.get::<_, String>(0)?,
                        "email":      r.get::<_, String>(1)?,
                        "verified":   r.get::<_, i64>(2)? != 0,
                        "profile":    profile,
                        "created_at": r.get::<_, String>(4)?,
                        "updated_at": r.get::<_, String>(5)?,
                    }))
                })?
                .collect::<Result<_, _>>()?;
            Ok::<_, rusqlite::Error>(rows)
        })
        .await
        .unwrap_or_default();
    let pat3 = pat.clone();
    let total: i64 = pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT count(*) FROM _system_users WHERE email LIKE ?1 COLLATE NOCASE",
                rusqlite::params![pat3],
                |r| r.get(0),
            )
        })
        .await
        .unwrap_or(0);
    (StatusCode::OK, Json(json!({"users": users, "total": total}))).into_response()
}

pub async fn get_user_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let uid = match get_uid(&params) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    fetch_user_row(pool, uid).await
}

/// Shared helper — read a single user row without exposing password_hash.
async fn fetch_user_row(
    pool: crate::storage::pool::SharedTenantPool,
    uid: String,
) -> Response {
    let row = pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT id, email, verified, profile, created_at, updated_at \
                 FROM _system_users WHERE id = ?1",
                rusqlite::params![uid],
                |r| {
                    let profile_raw: Option<String> = r.get(3)?;
                    let profile = crate::auth::profile::decode(profile_raw.as_deref());
                    Ok(json!({
                        "id":         r.get::<_, String>(0)?,
                        "email":      r.get::<_, String>(1)?,
                        "verified":   r.get::<_, i64>(2)? != 0,
                        "profile":    profile,
                        "created_at": r.get::<_, String>(4)?,
                        "updated_at": r.get::<_, String>(5)?,
                    }))
                },
            )
        })
        .await;
    match row {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_error(StatusCode::NOT_FOUND, "NOT_FOUND", "user not found"),
    }
}

pub async fn update_user_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Path(params): Path<HashMap<String, String>>,
    Json(body): Json<UpdateUserBody>,
) -> Response {
    let uid = match get_uid(&params) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    // Pre-hash password outside the writer closure (argon2 is slow but sync).
    let new_hash = if let Some(ref pw) = body.password {
        match crate::auth::user::hash_password(pw) {
            Ok(h) => Some(h),
            Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "HASH_FAILED", ""),
        }
    } else {
        None
    };
    let now = chrono::Utc::now().to_rfc3339();
    let new_email = body.email.as_ref().map(|e| e.trim().to_string());
    let new_verified = body.verified;
    let new_profile = crate::auth::profile::encode(body.profile.as_ref());
    let uid2 = uid.clone();
    let res = pool
        .with_writer(move |c| -> rusqlite::Result<usize> {
            let tx = c.transaction()?;
            // Apply each field if provided.
            if let Some(ref e) = new_email {
                tx.execute(
                    "UPDATE _system_users SET email = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![e, now, uid2],
                )?;
            }
            if let Some(ref h) = new_hash {
                tx.execute(
                    "UPDATE _system_users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![h, now, uid2],
                )?;
            }
            if let Some(ref p) = new_profile {
                tx.execute(
                    "UPDATE _system_users SET profile = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![p, now, uid2],
                )?;
            }
            if let Some(v) = new_verified {
                let vi = if v { 1i64 } else { 0i64 };
                tx.execute(
                    "UPDATE _system_users SET verified = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![vi, now, uid2],
                )?;
            }
            // Check row exists (the UPDATE is a no-op for non-existent uid).
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM _system_users WHERE id = ?1",
                rusqlite::params![uid2],
                |r| r.get(0),
            )?;
            tx.commit()?;
            Ok(count as usize)
        })
        .await;
    match res {
        Ok(0) => json_error(StatusCode::NOT_FOUND, "NOT_FOUND", "user not found"),
        Ok(_) => fetch_user_row(pool, uid).await,
        Err(e) if e.to_string().contains("UNIQUE") => {
            json_error(StatusCode::CONFLICT, "EMAIL_EXISTS", "email already in use")
        }
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    }
}

pub async fn delete_user_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let uid = match get_uid(&params) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let uid2 = uid.clone();
    let res = pool
        .with_writer(move |c| -> rusqlite::Result<(serde_json::Map<String, serde_json::Value>, usize)> {
            let tx = c.transaction()?;
            // 1. Find all collections that have owner_field set.
            let owner_cols: Vec<(String, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT collection_name, owner_field \
                     FROM _system_collection_meta \
                     WHERE owner_field IS NOT NULL",
                )?;
                stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<Result<_, _>>()?
            };
            // 2. Cascade-delete user's records from each collection.
            let mut deleted_records = serde_json::Map::new();
            for (coll, field) in &owner_cols {
                let n = tx.execute(
                    &format!(
                        "DELETE FROM \"{}\" WHERE \"{}\" = ?1",
                        coll.replace('"', "\"\""),
                        field.replace('"', "\"\"")
                    ),
                    rusqlite::params![uid2],
                )?;
                deleted_records.insert(coll.clone(), json!(n));
            }
            // 3. Delete all sessions.
            let revoked = tx.execute(
                "DELETE FROM _system_sessions WHERE user_id = ?1",
                rusqlite::params![uid2],
            )?;
            // 4. Delete the user row.
            let n = tx.execute(
                "DELETE FROM _system_users WHERE id = ?1",
                rusqlite::params![uid2],
            )?;
            if n == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            tx.commit()?;
            Ok((deleted_records, revoked))
        })
        .await;
    match res {
        Ok((dr, rs)) => {
            let mut resp = (
                StatusCode::OK,
                Json(json!({"deleted_records": dr, "revoked_sessions": rs})),
            )
                .into_response();
            resp.extensions_mut()
                .insert(crate::safety::audit::AuditExtra(serde_json::json!({
                    "deleted_records": dr,
                    "revoked_sessions": rs,
                })));
            resp
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            json_error(StatusCode::NOT_FOUND, "NOT_FOUND", "user not found")
        }
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    }
}

pub async fn revoke_sessions_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let uid = match get_uid(&params) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let n = pool
        .with_writer(move |c| crate::auth::user_session::revoke_all_sessions(c, &uid))
        .await
        .unwrap_or(0);
    (StatusCode::OK, Json(json!({"revoked": n}))).into_response()
}

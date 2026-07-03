//! Pure async helpers for T24 MCP user-management tools.
//!
//! Each function mirrors the SQL body of the corresponding REST handler in
//! `src/tenant/admin_user_routes.rs`, but returns `anyhow::Result<serde_json::Value>`
//! so it can be called uniformly from `#[tool]` methods in `handler.rs`.

use crate::storage::pool::SharedTenantPool;
use serde_json::json;

// ─── create ──────────────────────────────────────────────────────────────────

pub async fn create_user(
    pool: &SharedTenantPool,
    email: String,
    password: String,
    profile: Option<serde_json::Value>,
    verified: Option<bool>,
) -> anyhow::Result<serde_json::Value> {
    let email = email.trim().to_string();
    let hash = crate::auth::user::hash_password(&password)
        .map_err(|e| anyhow::anyhow!("HASH_FAILED: {e}"))?;
    let uid = format!("u-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let profile_str = crate::auth::profile::encode(profile.as_ref());
    let verified_i = if verified.unwrap_or(false) {
        1i64
    } else {
        0i64
    };
    let uid2 = uid.clone();
    let email2 = email.clone();
    let now2 = now.clone();

    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_users \
             (id, email, password_hash, verified, profile, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            rusqlite::params![uid2, email2, hash, verified_i, profile_str, now2],
        )
    })
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            anyhow::anyhow!("EMAIL_EXISTS: email already in use")
        } else {
            anyhow::anyhow!("DB_ERROR: {e}")
        }
    })?;

    Ok(json!({"user_id": uid, "email": email, "created_at": now}))
}

// ─── list ────────────────────────────────────────────────────────────────────

pub async fn list_users(
    pool: &SharedTenantPool,
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> anyhow::Result<serde_json::Value> {
    let pat = format!("%{}%", q.as_deref().unwrap_or(""));
    let limit = limit.unwrap_or(50).clamp(1, 500);
    let offset = offset.unwrap_or(0).max(0);
    let pat2 = pat.clone();
    let pat3 = pat.clone();

    let pool_r = pool.clone();
    let users: Vec<serde_json::Value> = pool_r
        .with_reader(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, email, verified, profile, created_at, updated_at \
                 FROM _system_users \
                 WHERE email LIKE ?1 COLLATE NOCASE \
                 ORDER BY created_at DESC \
                 LIMIT ?2 OFFSET ?3",
            )?;
            stmt.query_map(rusqlite::params![pat2, limit, offset], |r| {
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
            .collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
        .unwrap_or_default();

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

    Ok(json!({"users": users, "total": total}))
}

// ─── get ─────────────────────────────────────────────────────────────────────

pub async fn get_user(
    pool: &SharedTenantPool,
    user_id: String,
) -> anyhow::Result<serde_json::Value> {
    let row = pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT id, email, verified, profile, created_at, updated_at \
                 FROM _system_users WHERE id = ?1",
                rusqlite::params![user_id],
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
        .await
        .map_err(|_| anyhow::anyhow!("NOT_FOUND: user not found"))?;
    Ok(row)
}

// ─── update ──────────────────────────────────────────────────────────────────

pub async fn update_user(
    pool: &SharedTenantPool,
    user_id: String,
    email: Option<String>,
    password: Option<String>,
    profile: Option<serde_json::Value>,
    verified: Option<bool>,
) -> anyhow::Result<serde_json::Value> {
    let new_hash = if let Some(ref pw) = password {
        Some(
            crate::auth::user::hash_password(pw)
                .map_err(|e| anyhow::anyhow!("HASH_FAILED: {e}"))?,
        )
    } else {
        None
    };
    let now = chrono::Utc::now().to_rfc3339();
    let new_email = email.as_ref().map(|e| e.trim().to_string());
    let new_profile = crate::auth::profile::encode(profile.as_ref());
    let uid2 = user_id.clone();

    let count = pool
        .with_writer(move |c| -> rusqlite::Result<usize> {
            let tx = c.transaction()?;
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
            if let Some(v) = verified {
                let vi = if v { 1i64 } else { 0i64 };
                tx.execute(
                    "UPDATE _system_users SET verified = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![vi, now, uid2],
                )?;
            }
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM _system_users WHERE id = ?1",
                rusqlite::params![uid2],
                |r| r.get(0),
            )?;
            tx.commit()?;
            Ok(count as usize)
        })
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                anyhow::anyhow!("EMAIL_EXISTS: email already in use")
            } else {
                anyhow::anyhow!("DB: {e}")
            }
        })?;

    if count == 0 {
        return Err(anyhow::anyhow!("NOT_FOUND: user not found"));
    }
    get_user(pool, user_id).await
}

// ─── delete (cascade) ────────────────────────────────────────────────────────

pub async fn delete_user(
    pool: &SharedTenantPool,
    user_id: String,
    auth_cache: Option<&crate::tenant::auth_cache::AuthCache>,
) -> anyhow::Result<serde_json::Value> {
    let uid2 = user_id.clone();
    let res = pool
        .with_writer(move |c| {
            let tx = c.transaction()?;
            // 1. Find all collections with owner_field set.
            let owner_cols: Vec<(String, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT collection_name, owner_field \
                     FROM _system_collection_meta \
                     WHERE owner_field IS NOT NULL",
                )?;
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            // 2. Cascade-delete user's records from each collection.
            // v1.46 — per-row history capture BEFORE each bulk DELETE, inside
            // the same tx (spec §4: bulk-delete paths iterate and capture).
            // Deliberately a bare service actor (id=None): MCP is
            // service-key-only with no per-request admin identity to thread.
            let actor = crate::storage::record_history::AuditActor::service();
            let mut deleted_records = serde_json::Map::new();
            for (coll, field) in &owner_cols {
                crate::storage::record_history::capture_owner_cascade(
                    &tx, coll, field, &uid2, &actor,
                )?;
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
            Ok::<_, rusqlite::Error>((deleted_records, revoked))
        })
        .await;

    match res {
        Ok((dr, rs)) => {
            // v1.35 hook 8-MCP — the cascade just deleted the user row AND
            // its sessions inside the writer tx; synchronously drop every
            // cached `CachedAuth::User` entry for this user so a live
            // `drust_user_*` bearer cannot outlive the delete via the auth
            // cache (Finding #3 invalidate-on-write).
            if let Some(cache) = auth_cache {
                cache.clear_user(&user_id);
            }
            Ok(json!({"deleted_records": dr, "revoked_sessions": rs}))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(anyhow::anyhow!("NOT_FOUND: user not found"))
        }
        Err(e) => Err(anyhow::anyhow!("DB: {e}")),
    }
}

// ─── revoke sessions ─────────────────────────────────────────────────────────

pub async fn revoke_user_sessions(
    pool: &SharedTenantPool,
    user_id: String,
    auth_cache: Option<&crate::tenant::auth_cache::AuthCache>,
) -> anyhow::Result<serde_json::Value> {
    let uid = user_id.clone();
    let n = pool
        .with_writer(move |c| crate::auth::user_session::revoke_all_sessions(c, &uid))
        .await
        .unwrap_or(0);
    // v1.35 hook 7-MCP — drop the user's cached session entries synchronously
    // after the revocation write. Cleared even when n == 0 (conservative: a
    // spurious clear only forces a DB re-read on the next request).
    if let Some(cache) = auth_cache {
        cache.clear_user(&user_id);
    }
    Ok(json!({"revoked": n}))
}

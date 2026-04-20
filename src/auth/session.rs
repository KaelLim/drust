use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use rusqlite::Connection;

pub fn create_session(conn: &mut Connection, admin_id: i64, ttl_seconds: i64) -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let expires_at = Utc::now() + Duration::seconds(ttl_seconds);
    conn.execute(
        "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![token, admin_id, expires_at.to_rfc3339()],
    )?;
    Ok(token)
}

pub fn validate_session(conn: &Connection, token: &str) -> anyhow::Result<Option<i64>> {
    let now = Utc::now().to_rfc3339();
    let result: Option<i64> = conn
        .query_row(
            "SELECT admin_id FROM sessions WHERE token = ?1 AND expires_at > ?2",
            rusqlite::params![token, now],
            |r| r.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    Ok(result)
}

pub fn purge_expired(conn: &mut Connection) -> anyhow::Result<usize> {
    let now = Utc::now().to_rfc3339();
    let n = conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", rusqlite::params![now])?;
    Ok(n)
}

pub fn revoke_session(conn: &mut Connection, token: &str) -> anyhow::Result<()> {
    conn.execute("DELETE FROM sessions WHERE token = ?1", rusqlite::params![token])?;
    Ok(())
}

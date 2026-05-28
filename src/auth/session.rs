use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use rusqlite::Connection;

pub fn create_session(
    conn: &mut Connection,
    admin_id: i64,
    ttl_seconds: i64,
) -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let expires_at = Utc::now() + Duration::seconds(ttl_seconds);
    // v1.29.5: dual-write both plaintext and SHA-256 hex of the cookie.
    // Phase 1 of H4-2 migration. Reads match EITHER column.
    let token_hash = crate::auth::bearer::hash_token(&token);
    conn.execute(
        "INSERT INTO sessions (token, token_hash, admin_id, expires_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![token, token_hash, admin_id, expires_at.to_rfc3339()],
    )?;
    Ok(token)
}

pub fn validate_session(conn: &Connection, token: &str) -> anyhow::Result<Option<i64>> {
    let now = Utc::now().to_rfc3339();
    let token_hash = crate::auth::bearer::hash_token(token);
    // v1.29.5: match either column — supports both legacy plaintext-only
    // rows (pre-v1.29.5) and new dual-write rows. v1.31 will switch to
    // hash-only.
    let result: Option<i64> = conn
        .query_row(
            "SELECT admin_id FROM sessions \
             WHERE (token = ?1 OR token_hash = ?2) AND expires_at > ?3",
            rusqlite::params![token, token_hash, now],
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
    let n = conn.execute(
        "DELETE FROM sessions WHERE expires_at <= ?1",
        rusqlite::params![now],
    )?;
    Ok(n)
}

pub fn revoke_session(conn: &mut Connection, token: &str) -> anyhow::Result<()> {
    let token_hash = crate::auth::bearer::hash_token(token);
    conn.execute(
        "DELETE FROM sessions WHERE token = ?1 OR token_hash = ?2",
        rusqlite::params![token, token_hash],
    )?;
    Ok(())
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    use rusqlite::Connection;

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE sessions (
                token TEXT PRIMARY KEY,
                token_hash TEXT,
                admin_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL
            );"
        ).unwrap();
        conn
    }

    #[test]
    fn create_writes_both_columns() {
        let mut conn = fresh();
        let token = create_session(&mut conn, 7, 60).unwrap();
        let (t, h): (String, Option<String>) = conn.query_row(
            "SELECT token, token_hash FROM sessions LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(t, token);
        assert!(h.is_some(), "token_hash must be populated");
        assert_eq!(h.unwrap(), crate::auth::bearer::hash_token(&token));
    }

    #[test]
    fn validate_works_against_legacy_plaintext_only_row() {
        let conn = fresh();
        // Simulate a pre-v1.29.5 row: token populated, token_hash NULL.
        let future = (Utc::now() + Duration::hours(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (token, admin_id, expires_at) VALUES ('plain', 1, ?1)",
            rusqlite::params![future],
        ).unwrap();
        assert_eq!(validate_session(&conn, "plain").unwrap(), Some(1));
    }

    #[test]
    fn revoke_works_against_legacy_plaintext_only_row() {
        let mut conn = fresh();
        let future = (Utc::now() + Duration::hours(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (token, admin_id, expires_at) VALUES ('plain', 1, ?1)",
            rusqlite::params![future],
        ).unwrap();
        revoke_session(&mut conn, "plain").unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
    }
}

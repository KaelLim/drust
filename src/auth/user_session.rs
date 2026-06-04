use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

const TOKEN_PREFIX: &str = "drust_user_";

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub user_id: String,
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!("{TOKEN_PREFIX}{body}")
}

pub fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

/// True iff `token` carries the user-session prefix. Used by the auth layer to
/// skip the `_system_sessions` lookup for service/anon/PAT bearers, which can
/// never be a user session (sessions are minted only via `generate_token()`,
/// always `drust_user_`-prefixed). Behaviour-preserving short-circuit.
pub fn is_user_token(token: &str) -> bool {
    token.starts_with(TOKEN_PREFIX)
}

pub fn create_session(
    conn: &Connection,
    user_id: &str,
    ip_at_login: Option<&str>,
    ttl_days: i64,
) -> rusqlite::Result<String> {
    let token = generate_token();
    let now = Utc::now();
    let exp = now + Duration::days(ttl_days);
    conn.execute(
        "INSERT INTO _system_sessions (token_hash, user_id, created_at, expires_at, last_seen_at, ip_at_login) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            hash_token(&token),
            user_id,
            now.to_rfc3339(),
            exp.to_rfc3339(),
            now.to_rfc3339(),
            ip_at_login,
        ],
    )?;
    Ok(token)
}

pub fn lookup_session(conn: &Connection, token: &str) -> rusqlite::Result<Option<SessionInfo>> {
    let h = hash_token(token);
    let now = Utc::now().to_rfc3339();
    match conn.query_row(
        "SELECT user_id FROM _system_sessions WHERE token_hash = ?1 AND expires_at > ?2",
        params![h, now],
        |r| r.get::<_, String>(0),
    ) {
        Ok(uid) => Ok(Some(SessionInfo { user_id: uid })),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn slide_expiry(conn: &Connection, token: &str, ttl_days: i64) -> rusqlite::Result<()> {
    let h = hash_token(token);
    let now = Utc::now();
    let exp = now + Duration::days(ttl_days);
    conn.execute(
        "UPDATE _system_sessions SET expires_at = ?1, last_seen_at = ?2 WHERE token_hash = ?3",
        params![exp.to_rfc3339(), now.to_rfc3339(), h],
    )?;
    Ok(())
}

pub fn revoke_session(conn: &Connection, token: &str) -> rusqlite::Result<()> {
    let h = hash_token(token);
    conn.execute(
        "DELETE FROM _system_sessions WHERE token_hash = ?1",
        params![h],
    )?;
    Ok(())
}

pub fn revoke_session_by_hash(conn: &Connection, token_hash: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM _system_sessions WHERE token_hash = ?1",
        params![token_hash],
    )?;
    Ok(())
}

pub fn revoke_all_sessions(conn: &Connection, user_id: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM _system_sessions WHERE user_id = ?1",
        params![user_id],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fresh() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE _system_users (id TEXT PRIMARY KEY, email TEXT, password_hash TEXT, verified INTEGER, profile TEXT, created_at TEXT, updated_at TEXT); \
             INSERT INTO _system_users (id,email,password_hash,verified,created_at,updated_at) VALUES ('u-1','a@b','h',0,'2026','2026');"
        ).unwrap();
        c.execute_batch(crate::db::migrations::SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS)
            .unwrap();
        c
    }

    #[test]
    fn issue_token_yields_unique_high_entropy() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert!(a.starts_with("drust_user_"));
        assert!(a.len() > 30);
    }

    #[test]
    fn is_user_token_matches_only_prefixed() {
        assert!(is_user_token("drust_user_abc"));
        assert!(is_user_token(&generate_token()));
        assert!(!is_user_token("drust_service_xxx"));
        assert!(!is_user_token("anything-else"));
        assert!(!is_user_token(""));
    }

    #[test]
    fn hash_token_is_deterministic_and_does_not_round_trip() {
        let t = "drust_user_xyzpdq";
        assert_eq!(hash_token(t), hash_token(t));
        assert!(!hash_token(t).contains("xyzpdq"));
    }

    #[test]
    fn create_then_lookup_returns_user() {
        let c = fresh();
        let token = create_session(&c, "u-1", Some("203.0.113.5"), 30).unwrap();
        let info = lookup_session(&c, &token)
            .unwrap()
            .expect("session must hit");
        assert_eq!(info.user_id, "u-1");
    }

    #[test]
    fn lookup_misses_when_expired() {
        let c = fresh();
        // Backdate by inserting directly with expires_at in the past
        c.execute(
            "INSERT INTO _system_sessions (token_hash, user_id, created_at, expires_at, last_seen_at, ip_at_login) \
             VALUES (?1, 'u-1', '2025-01-01', '2025-01-01', '2025-01-01', NULL)",
            [hash_token("drust_user_old")],
        ).unwrap();
        assert!(lookup_session(&c, "drust_user_old").unwrap().is_none());
    }

    #[test]
    fn slide_pushes_expires_at_forward() {
        let c = fresh();
        let token = create_session(&c, "u-1", None, 1).unwrap();
        let before: String = c
            .query_row("SELECT expires_at FROM _system_sessions LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        slide_expiry(&c, &token, 30).unwrap();
        let after: String = c
            .query_row("SELECT expires_at FROM _system_sessions LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn revoke_by_hash_works() {
        let c = fresh();
        let token = create_session(&c, "u-1", None, 30).unwrap();
        let h = hash_token(&token);
        revoke_session_by_hash(&c, &h).unwrap();
        assert!(lookup_session(&c, &token).unwrap().is_none());
    }

    #[test]
    fn revoke_one_and_revoke_all() {
        let c = fresh();
        let t1 = create_session(&c, "u-1", None, 30).unwrap();
        let t2 = create_session(&c, "u-1", None, 30).unwrap();
        revoke_session(&c, &t1).unwrap();
        assert!(lookup_session(&c, &t1).unwrap().is_none());
        assert!(lookup_session(&c, &t2).unwrap().is_some());

        let n = revoke_all_sessions(&c, "u-1").unwrap();
        assert_eq!(n, 1);
        assert!(lookup_session(&c, &t2).unwrap().is_none());
    }
}

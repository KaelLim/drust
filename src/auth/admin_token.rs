//! Per-admin Personal Access Token (PAT) primitives. v1.29.0.

use base64::Engine;
use rand::RngCore;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

pub const TOKEN_PREFIX: &str = "drust_pat_";

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

#[derive(Debug, Clone, PartialEq)]
pub struct AdminTokenHit {
    pub token_id: i64,
    pub admin_id: i64,
}

/// Lookup a PAT by its plaintext bearer. Returns Ok(Some(hit)) if matched,
/// Ok(None) if no row. Caller must update last_used_at asynchronously.
pub fn lookup(conn: &Connection, bearer: &str) -> rusqlite::Result<Option<AdminTokenHit>> {
    if !bearer.starts_with(TOKEN_PREFIX) {
        return Ok(None);
    }
    let h = hash_token(bearer);
    match conn.query_row(
        "SELECT id, admin_id FROM _admin_tokens \
         WHERE token_hash = ?1 AND revoked_at IS NULL",
        params![h],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    ) {
        Ok((token_id, admin_id)) => Ok(Some(AdminTokenHit { token_id, admin_id })),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_have_prefix_and_high_entropy() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert!(a.starts_with(TOKEN_PREFIX));
        assert!(a.len() > TOKEN_PREFIX.len() + 30);
    }

    #[test]
    fn hash_is_deterministic_and_does_not_leak_plaintext() {
        let t = "drust_pat_abc";
        assert_eq!(hash_token(t), hash_token(t));
        assert!(!hash_token(t).contains("abc"));
    }

    #[test]
    fn lookup_returns_none_for_non_prefix() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::db::migrations::SQL_CREATE_ADMIN_TOKENS_IF_NOT_EXISTS)
            .unwrap();
        assert!(lookup(&conn, "drust_user_xyz").unwrap().is_none());
        assert!(lookup(&conn, "literal-shared-token").unwrap().is_none());
    }

    #[test]
    fn lookup_ignores_soft_revoked_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE _admin_tokens (
                id INTEGER PRIMARY KEY,
                admin_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                revoked_at TEXT
            ) STRICT;",
        )
        .unwrap();
        let plaintext = generate_token();
        let h = hash_token(&plaintext);
        conn.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (7, ?1)",
            rusqlite::params![h],
        )
        .unwrap();

        // Active row resolves.
        assert!(lookup(&conn, &plaintext).unwrap().is_some());

        // Soft-revoked row does NOT resolve.
        conn.execute(
            "UPDATE _admin_tokens SET revoked_at = datetime('now') WHERE token_hash = ?1",
            rusqlite::params![h],
        )
        .unwrap();
        assert!(
            lookup(&conn, &plaintext).unwrap().is_none(),
            "soft-revoked PAT must not authenticate"
        );
    }
}

//! Token primitives + storage layer for the OAuth 2.1 AS.

use base64::Engine;
use rand::RngCore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

pub const ACCESS_TOKEN_PREFIX: &str = "drust_at_";
pub const REFRESH_TOKEN_PREFIX: &str = "drust_rt_";
pub const AUTH_CODE_PREFIX:    &str = "drust_ac_";
pub const CLIENT_ID_PREFIX:    &str = "drust_client_";

pub fn random_b64(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

pub fn sha256_b64(plain: &str) -> String {
    let mut h = Sha256::new();
    h.update(plain.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

pub fn new_access_token() -> String  { format!("{ACCESS_TOKEN_PREFIX}{}",  random_b64(32)) }
pub fn new_refresh_token() -> String { format!("{REFRESH_TOKEN_PREFIX}{}", random_b64(32)) }
pub fn new_auth_code() -> String     { format!("{AUTH_CODE_PREFIX}{}",     random_b64(32)) }
pub fn new_client_id() -> String     { format!("{CLIENT_ID_PREFIX}{}",     random_b64(24)) }

#[derive(Debug, Clone)]
pub struct OauthAccessTokenHit {
    pub admin_id:     i64,
    pub client_id:    String,
    pub resource_uri: String,
    pub expires_at:   String,
}

pub fn lookup_access_token(conn: &Connection, bearer: &str) -> rusqlite::Result<Option<OauthAccessTokenHit>> {
    if !bearer.starts_with(ACCESS_TOKEN_PREFIX) {
        return Ok(None);
    }
    let h = sha256_b64(bearer);
    match conn.query_row(
        "SELECT admin_id, client_id, resource_uri, expires_at
         FROM _oauth_access_tokens
         WHERE token_hash = ?1 AND expires_at > datetime('now')",
        params![h],
        |r| Ok(OauthAccessTokenHit {
            admin_id:     r.get(0)?,
            client_id:    r.get(1)?,
            resource_uri: r.get(2)?,
            expires_at:   r.get(3)?,
        }),
    ) {
        Ok(hit) => Ok(Some(hit)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::db::migrations::SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS).unwrap();
        conn.execute_batch(crate::db::migrations::SQL_CREATE_OAUTH_ACCESS_TOKENS_IF_NOT_EXISTS).unwrap();
        conn.execute_batch("CREATE TABLE admins (id INTEGER PRIMARY KEY);").unwrap();
        conn.execute("INSERT INTO admins (id) VALUES (1)", []).unwrap();
        conn.execute(
            "INSERT INTO _oauth_clients (id, client_name, redirect_uris_json) VALUES ('drust_client_x', 'Test', '[]')",
            [],
        ).unwrap();
        conn
    }

    #[test]
    fn prefixes_distinct() {
        assert!(new_access_token().starts_with(ACCESS_TOKEN_PREFIX));
        assert!(new_refresh_token().starts_with(REFRESH_TOKEN_PREFIX));
        assert!(new_auth_code().starts_with(AUTH_CODE_PREFIX));
        assert!(new_client_id().starts_with(CLIENT_ID_PREFIX));
        assert_ne!(new_access_token(), new_access_token());
    }

    #[test]
    fn lookup_access_token_returns_none_for_wrong_prefix() {
        let conn = fresh();
        assert!(lookup_access_token(&conn, "drust_pat_xxx").unwrap().is_none());
    }

    #[test]
    fn lookup_access_token_returns_none_for_unknown_hash() {
        let conn = fresh();
        assert!(lookup_access_token(&conn, "drust_at_unknown").unwrap().is_none());
    }

    #[test]
    fn lookup_access_token_finds_valid_row() {
        let conn = fresh();
        let token = new_access_token();
        conn.execute(
            "INSERT INTO _oauth_access_tokens (token_hash, client_id, admin_id, resource_uri, expires_at)
             VALUES (?1, 'drust_client_x', 1, 'https://x/t/a/mcp', datetime('now', '+1 hour'))",
            params![sha256_b64(&token)],
        ).unwrap();
        let hit = lookup_access_token(&conn, &token).unwrap().unwrap();
        assert_eq!(hit.admin_id, 1);
        assert_eq!(hit.client_id, "drust_client_x");
    }

    #[test]
    fn lookup_access_token_rejects_expired() {
        let conn = fresh();
        let token = new_access_token();
        conn.execute(
            "INSERT INTO _oauth_access_tokens (token_hash, client_id, admin_id, resource_uri, expires_at)
             VALUES (?1, 'drust_client_x', 1, 'https://x/t/a/mcp', datetime('now', '-1 second'))",
            params![sha256_b64(&token)],
        ).unwrap();
        assert!(lookup_access_token(&conn, &token).unwrap().is_none());
    }
}

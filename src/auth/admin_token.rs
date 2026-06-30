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

pub const CLI_TOKEN_PREFIX: &str = "drust_pat_cli_";

/// Mint a fresh CLI PAT plaintext. `drust_pat_cli_` is a sub-namespace of
/// `TOKEN_PREFIX`, so `lookup` / `SQL_BEARER_AUTH_CTE` resolve it through the
/// SAME admin_pat branch → `AuthCtx::Service { admin_id }` — no resolver change,
/// no new privilege (T4 §4.1).
pub fn generate_cli_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!("{CLI_TOKEN_PREFIX}{body}")
}

/// Mint a labeled, expiring CLI PAT for `admin_id`. Inserts a `label`-bearing,
/// `expires_at`-bearing `_admin_tokens` row OUTSIDE the relaxed
/// `uniq_admin_tokens_active` index (which covers only unlabeled rows), so it
/// never collides with the admin's single unlabeled UI/MCP PAT. Sets `plaintext`
/// (mirrors the reroll mint) so `whoami` / poll can echo it exactly once.
/// `ttl_secs` sets `expires_at = datetime('now','+<ttl_secs> seconds')`.
/// Returns `(token_id, plaintext)`; resolves to `AuthCtx::Service { admin_id }`.
pub fn mint_cli_token(
    conn: &Connection,
    admin_id: i64,
    label: &str,
    ttl_secs: i64,
) -> rusqlite::Result<(i64, String)> {
    let plaintext = generate_cli_token();
    let hash = hash_token(&plaintext);
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext, label, expires_at) \
         VALUES (?1, ?2, ?3, ?4, datetime('now', ?5))",
        params![admin_id, hash, plaintext, label, format!("+{ttl_secs} seconds")],
    )?;
    Ok((conn.last_insert_rowid(), plaintext))
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
    fn cli_token_is_admin_pat_subnamespace() {
        let t = generate_cli_token();
        assert!(t.starts_with(CLI_TOKEN_PREFIX), "cli prefix");
        assert!(
            t.starts_with(TOKEN_PREFIX),
            "must also match the admin_pat resolver prefix"
        );
        assert_ne!(generate_cli_token(), generate_cli_token());
        assert!(t.len() > CLI_TOKEN_PREFIX.len() + 30, "high entropy body");
    }

    #[test]
    fn mint_cli_token_inserts_labeled_expiring_row_and_resolves() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE _admin_tokens (id INTEGER PRIMARY KEY, admin_id INTEGER NOT NULL, \
                token_hash TEXT NOT NULL UNIQUE, plaintext TEXT, revoked_at TEXT, \
                label TEXT, expires_at TEXT) STRICT;",
        )
        .unwrap();
        let (id, plaintext) = mint_cli_token(&conn, 5, "cli:laptop", 86400).unwrap();
        assert!(id > 0);
        assert!(plaintext.starts_with(CLI_TOKEN_PREFIX));
        // Resolves through the SAME admin-PAT lookup path → admin_id 5 (no new privilege).
        let hit = lookup(&conn, &plaintext).unwrap().expect("CLI PAT resolves");
        assert_eq!(hit.admin_id, 5);
        // The label + a future expiry are persisted (outside the relaxed index).
        let (label, exp): (String, String) = conn
            .query_row(
                "SELECT label, expires_at FROM _admin_tokens WHERE id=?1",
                rusqlite::params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(label, "cli:laptop");
        assert!(exp > "2026".to_string(), "expires_at is a future datetime");
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

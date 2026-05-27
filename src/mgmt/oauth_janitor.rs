//! Daily janitor for expired OAuth rows. Pattern mirrors the audit retention
//! task in src/main.rs (sleep_until 03:00 UTC loop). Lives in main drust
//! process — OAuth tables are host-level in meta.sqlite, NOT per-tenant.
//! drust_session_janitor (separate bin) only handles _system_sessions.

use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Sweep expired rows in one pass. Returns (codes_deleted, access_deleted, refresh_deleted).
pub fn sweep_once(conn: &Connection) -> rusqlite::Result<(usize, usize, usize)> {
    let codes   = conn.execute("DELETE FROM _oauth_authorization_codes WHERE expires_at < datetime('now')", [])?;
    let access  = conn.execute("DELETE FROM _oauth_access_tokens       WHERE expires_at < datetime('now')", [])?;
    let refresh = conn.execute("DELETE FROM _oauth_refresh_tokens      WHERE expires_at < datetime('now')", [])?;
    Ok((codes, access, refresh))
}

/// Background task entry point. Fires daily at 03:00 UTC.
///
/// Mirrors the audit-retention loop in main.rs: compute duration to next
/// 03:00 UTC, sleep, sweep, repeat. The task ends only when the process exits.
pub async fn run_oauth_token_janitor(meta: Arc<Mutex<Connection>>) {
    loop {
        let now = chrono::Utc::now();
        let next = crate::safety::audit_db::next_0300_utc(now);
        let dur = (next - now)
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(60));
        tokio::time::sleep(dur).await;

        let conn = meta.lock().await;
        match sweep_once(&conn) {
            Ok((c, a, r)) => tracing::info!(
                codes = c, access = a, refresh = r,
                "oauth_token_janitor sweep ok"
            ),
            Err(e) => tracing::warn!(error = ?e, "oauth_token_janitor sweep failed"),
        }
        drop(conn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Open a fresh in-memory-backed meta DB (via a temp-file path so that
    /// open_meta can create the file). Returns the connection and a TempDir
    /// that must be kept alive for the duration of the test.
    fn fresh() -> (Connection, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().unwrap();
        let conn = crate::storage::meta::open_meta(&tmp.path().join("meta.sqlite")).unwrap();
        let data_dir = tmp.path().to_path_buf();
        crate::db::migrations::run_migrations(&conn, &data_dir).unwrap();
        conn.execute(
            "INSERT INTO admins (id, username, password_hash) VALUES (1, 'u', 'h')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _oauth_clients (id, client_name, redirect_uris_json) \
             VALUES ('c1', 'X', '[]')",
            [],
        )
        .unwrap();
        (conn, tmp)
    }

    #[test]
    fn sweep_removes_expired_rows_only() {
        let (conn, _tmp) = fresh();
        conn.execute(
            "INSERT INTO _oauth_access_tokens \
             (token_hash, client_id, admin_id, resource_uri, expires_at) \
             VALUES ('h1', 'c1', 1, 'r', datetime('now', '-1 hour'))",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _oauth_access_tokens \
             (token_hash, client_id, admin_id, resource_uri, expires_at) \
             VALUES ('h2', 'c1', 1, 'r', datetime('now', '+1 hour'))",
            [],
        )
        .unwrap();
        let (_codes, access, _refresh) = sweep_once(&conn).unwrap();
        assert_eq!(access, 1);
        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM _oauth_access_tokens",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn sweep_removes_expired_codes_and_refresh_tokens() {
        let (conn, _tmp) = fresh();
        conn.execute(
            "INSERT INTO _oauth_authorization_codes \
             (code_hash, client_id, admin_id, redirect_uri, pkce_challenge, \
              pkce_challenge_method, resource_uri, expires_at) \
             VALUES ('ch1', 'c1', 1, 'r', 'p', 'S256', 'r', datetime('now', '-1 minute'))",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _oauth_refresh_tokens \
             (token_hash, client_id, admin_id, resource_uri, expires_at) \
             VALUES ('rh1', 'c1', 1, 'r', datetime('now', '-1 minute'))",
            [],
        )
        .unwrap();
        let (codes, _access, refresh) = sweep_once(&conn).unwrap();
        assert_eq!(codes, 1);
        assert_eq!(refresh, 1);
    }

    #[test]
    fn sweep_on_empty_db_returns_zeros() {
        let (conn, _tmp) = fresh();
        let (c, a, r) = sweep_once(&conn).unwrap();
        assert_eq!((c, a, r), (0, 0, 0));
    }
}

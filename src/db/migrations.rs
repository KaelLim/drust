use rusqlite::Connection;

pub const SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  verified      INTEGER NOT NULL DEFAULT 0,
  profile       TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_users_email ON _system_users(email);
"#;

pub const SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_sessions (
  token_hash    TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES _system_users(id) ON DELETE CASCADE,
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  ip_at_login   TEXT
);
CREATE INDEX IF NOT EXISTS idx_system_sessions_user ON _system_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_system_sessions_expires ON _system_sessions(expires_at);
"#;

pub fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    col: &str,
    decl: &str,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    if !cols.iter().any(|c| c == col) {
        conn.execute(
            &format!("ALTER TABLE {} ADD COLUMN {} {}", table, col, decl),
            [],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fresh() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn create_system_users_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS).unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS).unwrap();
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_users'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn create_system_sessions_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS).unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS).unwrap();
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_sessions'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn add_column_if_missing_adds_once() {
        let c = fresh();
        c.execute("CREATE TABLE t (a TEXT)", []).unwrap();
        add_column_if_missing(&c, "t", "b", "INTEGER NOT NULL DEFAULT 0").unwrap();
        add_column_if_missing(&c, "t", "b", "INTEGER NOT NULL DEFAULT 0").unwrap();
        let cols: Vec<String> = c.prepare("PRAGMA table_info(t)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .collect::<Result<_, _>>().unwrap();
        assert_eq!(cols, vec!["a".to_string(), "b".to_string()]);
    }
}

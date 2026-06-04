//! Persistence wrapper around the `_system_rpc` table.

use crate::rpc::params::ParamSpec;
use crate::tenant::router::TokenRole;
use rusqlite::{Connection, params};
use serde::Serialize;

/// Stored-RPC dispatch mode. Decided at create time, stored on the row.
/// `Read` (default) → v1.6 path: pool.with_reader + read-only authorizer.
/// `Write` (v1.30+) → pool.with_writer + writable authorizer + SAVEPOINT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpcMode {
    Read,
    Write,
}

impl RpcMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RpcMode::Read => "read",
            RpcMode::Write => "write",
        }
    }
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "write" => RpcMode::Write,
            _ => RpcMode::Read,
        }
    }
}

impl Default for RpcMode {
    fn default() -> Self {
        RpcMode::Read
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredRpc {
    pub name: String,
    pub sql: String,
    pub params: Vec<ParamSpec>,
    pub description: Option<String>,
    pub anon_callable: bool,
    pub mode: RpcMode,
    pub anon_calls: i64,
    pub service_calls: i64,
    pub last_called_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("rpc not found: '{0}'")]
    NotFound(String),
    #[error("rpc already exists: '{0}'")]
    AlreadyExists(String),
    #[error("invalid params_json: {0}")]
    BadParams(String),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub fn lookup(conn: &Connection, name: &str) -> Result<Option<StoredRpc>, RegistryError> {
    let row = conn.query_row(
        "SELECT name, sql, params_json, description, anon_callable,
                anon_calls, service_calls, last_called_at,
                created_at, updated_at,
                COALESCE(mode, 'read') AS mode
           FROM _system_rpc WHERE name = ?1",
        params![name],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, String>(10)?,
            ))
        },
    );
    let (n, sql, pj, desc, anon_cb, ac, sc, lca, ca, ua, mode_s) = match row {
        Ok(t) => t,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let params = crate::rpc::params::parse_params_json(&pj)
        .map_err(|e| RegistryError::BadParams(e.to_string()))?;
    Ok(Some(StoredRpc {
        name: n,
        sql,
        params,
        description: desc,
        anon_callable: anon_cb != 0,
        mode: RpcMode::from_db_str(&mode_s),
        anon_calls: ac,
        service_calls: sc,
        last_called_at: lca,
        created_at: ca,
        updated_at: ua,
    }))
}

pub fn list(conn: &Connection) -> Result<Vec<StoredRpc>, RegistryError> {
    let mut stmt = conn.prepare(
        "SELECT name, sql, params_json, description, anon_callable,
                anon_calls, service_calls, last_called_at,
                created_at, updated_at,
                COALESCE(mode, 'read') AS mode
           FROM _system_rpc ORDER BY name",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, Option<String>>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, String>(9)?,
            r.get::<_, String>(10)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (n, sql, pj, desc, anon_cb, ac, sc, lca, ca, ua, mode_s) = row?;
        let params = crate::rpc::params::parse_params_json(&pj)
            .map_err(|e| RegistryError::BadParams(e.to_string()))?;
        out.push(StoredRpc {
            name: n,
            sql,
            params,
            description: desc,
            anon_callable: anon_cb != 0,
            mode: RpcMode::from_db_str(&mode_s),
            anon_calls: ac,
            service_calls: sc,
            last_called_at: lca,
            created_at: ca,
            updated_at: ua,
        });
    }
    Ok(out)
}

pub fn create(
    conn: &Connection,
    name: &str,
    sql: &str,
    params_json: &str,
    description: Option<&str>,
    anon_callable: bool,
    mode: RpcMode,
) -> Result<(), RegistryError> {
    let res = conn.execute(
        "INSERT INTO _system_rpc
            (name, sql, params_json, description, anon_callable, mode,
             created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'), datetime('now'))",
        params![
            name,
            sql,
            params_json,
            description,
            anon_callable as i64,
            mode.as_str()
        ],
    );
    match res {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.extended_code == 1555 => {
            // 1555 = SQLITE_CONSTRAINT_PRIMARYKEY
            Err(RegistryError::AlreadyExists(name.to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

pub fn update(
    conn: &Connection,
    name: &str,
    sql: Option<&str>,
    params_json: Option<&str>,
    description: Option<Option<&str>>,
    anon_callable: Option<bool>,
    mode: Option<RpcMode>,
) -> Result<(), RegistryError> {
    let mut clauses: Vec<&'static str> = Vec::new();
    let mut binds: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(s) = sql {
        clauses.push("sql = ?");
        binds.push(rusqlite::types::Value::Text(s.into()));
    }
    if let Some(p) = params_json {
        clauses.push("params_json = ?");
        binds.push(rusqlite::types::Value::Text(p.into()));
    }
    if let Some(d) = description {
        clauses.push("description = ?");
        binds.push(match d {
            Some(s) => rusqlite::types::Value::Text(s.into()),
            None => rusqlite::types::Value::Null,
        });
    }
    if let Some(b) = anon_callable {
        clauses.push("anon_callable = ?");
        binds.push(rusqlite::types::Value::Integer(b as i64));
    }
    if let Some(m) = mode {
        clauses.push("mode = ?");
        binds.push(rusqlite::types::Value::Text(m.as_str().into()));
    }
    if clauses.is_empty() {
        return Ok(()); // no-op
    }
    clauses.push("updated_at = datetime('now')");
    binds.push(rusqlite::types::Value::Text(name.into()));
    let sql_str = format!(
        "UPDATE _system_rpc SET {} WHERE name = ?",
        clauses.join(", ")
    );
    let n = conn.execute(&sql_str, rusqlite::params_from_iter(binds))?;
    if n == 0 {
        return Err(RegistryError::NotFound(name.to_string()));
    }
    Ok(())
}

pub fn delete(conn: &Connection, name: &str) -> Result<(), RegistryError> {
    let n = conn.execute("DELETE FROM _system_rpc WHERE name = ?1", params![name])?;
    if n == 0 {
        return Err(RegistryError::NotFound(name.to_string()));
    }
    Ok(())
}

/// Bump the appropriate counter and `last_called_at`. Bypasses the
/// caller's auth — this is drust's own bookkeeping write, not user
/// SQL.
pub fn increment(conn: &Connection, name: &str, role: TokenRole) -> rusqlite::Result<()> {
    let col = match role {
        TokenRole::Anon | TokenRole::User => "anon_calls",
        TokenRole::Service => "service_calls",
    };
    let sql = format!(
        "UPDATE _system_rpc SET {col} = {col} + 1, last_called_at = datetime('now')
         WHERE name = ?1"
    );
    conn.execute(&sql, params![name])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tenant_db::open_write;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, Connection) {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), "rpcreg").unwrap();
        (tmp, conn)
    }

    #[test]
    fn create_then_lookup() {
        let (_t, conn) = fresh();
        create(
            &conn,
            "echo",
            "SELECT 1",
            "[]",
            Some("trivial"),
            false,
            RpcMode::Read,
        )
        .unwrap();
        let r = lookup(&conn, "echo").unwrap().unwrap();
        assert_eq!(r.name, "echo");
        assert_eq!(r.sql, "SELECT 1");
        assert_eq!(r.description.as_deref(), Some("trivial"));
        assert!(!r.anon_callable);
        assert_eq!(r.anon_calls, 0);
        assert_eq!(r.service_calls, 0);
        assert_eq!(r.mode, RpcMode::Read);
    }

    #[test]
    fn duplicate_create_errors() {
        let (_t, conn) = fresh();
        create(&conn, "x", "SELECT 1", "[]", None, false, RpcMode::Read).unwrap();
        let err = create(&conn, "x", "SELECT 2", "[]", None, false, RpcMode::Read).unwrap_err();
        assert!(matches!(err, RegistryError::AlreadyExists(_)));
    }

    #[test]
    fn lookup_missing_is_none() {
        let (_t, conn) = fresh();
        assert!(lookup(&conn, "nope").unwrap().is_none());
    }

    #[test]
    fn list_returns_sorted() {
        let (_t, conn) = fresh();
        create(&conn, "b", "SELECT 1", "[]", None, false, RpcMode::Read).unwrap();
        create(&conn, "a", "SELECT 1", "[]", None, false, RpcMode::Read).unwrap();
        let v = list(&conn).unwrap();
        assert_eq!(
            v.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn update_partial_changes() {
        let (_t, conn) = fresh();
        create(&conn, "x", "SELECT 1", "[]", None, false, RpcMode::Read).unwrap();
        update(&conn, "x", Some("SELECT 2"), None, None, Some(true), None).unwrap();
        let r = lookup(&conn, "x").unwrap().unwrap();
        assert_eq!(r.sql, "SELECT 2");
        assert!(r.anon_callable);
    }

    #[test]
    fn update_missing_errors() {
        let (_t, conn) = fresh();
        let err = update(&conn, "nope", Some("SELECT 1"), None, None, None, None).unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    #[test]
    fn delete_missing_errors() {
        let (_t, conn) = fresh();
        let err = delete(&conn, "nope").unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    #[test]
    fn increment_picks_correct_column() {
        let (_t, conn) = fresh();
        create(&conn, "x", "SELECT 1", "[]", None, false, RpcMode::Read).unwrap();
        increment(&conn, "x", TokenRole::Anon).unwrap();
        increment(&conn, "x", TokenRole::Service).unwrap();
        increment(&conn, "x", TokenRole::Anon).unwrap();
        let r = lookup(&conn, "x").unwrap().unwrap();
        assert_eq!(r.anon_calls, 2);
        assert_eq!(r.service_calls, 1);
        assert!(r.last_called_at.is_some());
    }
}

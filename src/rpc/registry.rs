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
#[derive(Default)]
pub enum RpcMode {
    #[default]
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

/// Stored-RPC body kind. Decided at create time, stored on the row, and
/// **immutable afterwards**.
/// `Sql` (default, and what every pre-#950 row reads back as) → the body is
/// the raw `sql` column, executed as-is.
/// `Query` → the body is a structured FilterAst template in `query_json`;
/// `sql` is unused and `mode` is always `Read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum RpcKind {
    #[default]
    Sql,
    Query,
}

impl RpcKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RpcKind::Sql => "sql",
            RpcKind::Query => "query",
        }
    }
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "query" => RpcKind::Query,
            _ => RpcKind::Sql,
        }
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
    pub kind: RpcKind,
    pub query_json: Option<String>,
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
    #[error("kind rule violated: {0}")]
    KindInvalid(String),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub fn lookup(conn: &Connection, name: &str) -> Result<Option<StoredRpc>, RegistryError> {
    let row = conn.query_row(
        "SELECT name, sql, params_json, description, anon_callable,
                anon_calls, service_calls, last_called_at,
                created_at, updated_at,
                COALESCE(mode, 'read') AS mode,
                COALESCE(kind, 'sql') AS kind, query_json
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
                r.get::<_, String>(11)?,
                r.get::<_, Option<String>>(12)?,
            ))
        },
    );
    let (n, sql, pj, desc, anon_cb, ac, sc, lca, ca, ua, mode_s, kind_s, query_json) = match row {
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
        kind: RpcKind::from_db_str(&kind_s),
        query_json,
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
                COALESCE(mode, 'read') AS mode,
                COALESCE(kind, 'sql') AS kind, query_json
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
            r.get::<_, String>(11)?,
            r.get::<_, Option<String>>(12)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (n, sql, pj, desc, anon_cb, ac, sc, lca, ca, ua, mode_s, kind_s, query_json) = row?;
        let params = crate::rpc::params::parse_params_json(&pj)
            .map_err(|e| RegistryError::BadParams(e.to_string()))?;
        out.push(StoredRpc {
            name: n,
            sql,
            params,
            description: desc,
            anon_callable: anon_cb != 0,
            mode: RpcMode::from_db_str(&mode_s),
            kind: RpcKind::from_db_str(&kind_s),
            query_json,
            anon_calls: ac,
            service_calls: sc,
            last_called_at: lca,
            created_at: ca,
            updated_at: ua,
        });
    }
    Ok(out)
}

/// Full row to insert. A named-field struct rather than a positional argument
/// list because three of the fields are adjacent `&str` bodies (`sql`,
/// `params_json`, `query_json`) that a transposition would swap silently — and
/// `query_json` is the kind gate. Deliberately NO `Default`: every field is
/// load-bearing at create time, so a new one must be answered at every site.
#[derive(Debug, Clone)]
pub struct RpcCreate<'a> {
    pub name: &'a str,
    pub sql: &'a str,
    pub params_json: &'a str,
    pub description: Option<&'a str>,
    pub anon_callable: bool,
    pub mode: RpcMode,
    pub kind: RpcKind,
    pub query_json: Option<&'a str>,
}

/// Partial update: every field is a delta, `None` = leave unchanged.
/// `description: Some(None)` clears the description. `Default` is the
/// all-unchanged no-op, so a call site states only what it touches.
#[derive(Debug, Clone, Default)]
pub struct RpcUpdate<'a> {
    pub sql: Option<&'a str>,
    pub params_json: Option<&'a str>,
    pub description: Option<Option<&'a str>>,
    pub anon_callable: Option<bool>,
    pub mode: Option<RpcMode>,
    pub query_json: Option<&'a str>,
}

/// The two views of `query_json` the kind contract needs. Named fields, not a
/// second positional `Option<&str>`, because the two are trivially transposable
/// and they mean opposite things.
#[derive(Debug, Clone, Copy)]
struct QueryJsonView<'a> {
    /// What the row will HAVE once the write lands (stored, merged with the
    /// delta). Equal to `set` on create — an insert has no stored state.
    after: Option<&'a str>,
    /// What this write SETS. `None` on an update that does not touch the column.
    set: Option<&'a str>,
}

/// The kind contract, in ONE place, checked against a COMPLETE row image:
/// a `query` row's body is `query_json` (so `sql` is empty and `mode` is
/// always read), a `sql` row's body is `sql` (so it carries no template).
/// `create` checks the row it is about to insert; `update` checks the row
/// that would result from merging its deltas over the stored one — so the
/// two faces cannot drift, and an unrepairable row (e.g. kind=query with
/// mode=write, which `update` may never fix) cannot be created.
///
/// The two arms need DIFFERENT views of `query_json`, which is why it arrives
/// as a named pair rather than one value (see [`QueryJsonView`]).
fn check_kind_rules(
    kind: RpcKind,
    sql: &str,
    mode: RpcMode,
    query_json: QueryJsonView<'_>,
) -> Result<(), RegistryError> {
    match kind {
        RpcKind::Query => {
            // MERGED view: a query row must still HAVE a template afterwards,
            // and `sql` / `mode` immutability can only be judged against the
            // stored values an omitted delta leaves in place.
            if query_json.after.is_none() {
                return Err(RegistryError::KindInvalid(
                    "kind=query requires a query_json template".into(),
                ));
            }
            if !sql.is_empty() {
                return Err(RegistryError::KindInvalid(
                    "kind=query carries no sql body; its body is query_json".into(),
                ));
            }
            if mode != RpcMode::Read {
                return Err(RegistryError::KindInvalid(
                    "kind=query is always mode=read".into(),
                ));
            }
        }
        RpcKind::Sql => {
            // DELTA view: refuse to WRITE a template onto a sql row. Judging the
            // merged value instead would make a row that already carries a stray
            // one (only reachable by hand-editing the DB) permanently
            // unrepairable — every update, however unrelated, would be refused.
            if query_json.set.is_some() {
                return Err(RegistryError::KindInvalid(
                    "kind=sql carries no query_json template; its body is sql".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Name the offending row in a kind-rule rejection without double-prefixing
/// the `thiserror` message.
fn name_kind_err(name: &str, e: RegistryError) -> RegistryError {
    match e {
        RegistryError::KindInvalid(msg) => {
            RegistryError::KindInvalid(format!("rpc '{name}': {msg}"))
        }
        other => other,
    }
}

pub fn create(conn: &Connection, c: RpcCreate<'_>) -> Result<(), RegistryError> {
    let RpcCreate {
        name,
        sql,
        params_json,
        description,
        anon_callable,
        mode,
        kind,
        query_json,
    } = c;
    check_kind_rules(
        kind,
        sql,
        mode,
        // An insert has no stored state, so both views are the supplied value.
        QueryJsonView {
            after: query_json,
            set: query_json,
        },
    )
    .map_err(|e| name_kind_err(name, e))?;
    let res = conn.execute(
        "INSERT INTO _system_rpc
            (name, sql, params_json, description, anon_callable, mode,
             kind, query_json, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'), datetime('now'))",
        params![
            name,
            sql,
            params_json,
            description,
            anon_callable as i64,
            mode.as_str(),
            kind.as_str(),
            query_json
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

pub fn update(conn: &Connection, name: &str, up: RpcUpdate<'_>) -> Result<(), RegistryError> {
    let RpcUpdate {
        sql,
        params_json,
        description,
        anon_callable,
        mode,
        query_json,
    } = up;
    // `kind` is immutable after create, and each kind owns exactly one body
    // column — so a PARTIAL update has to be judged against the row it would
    // produce, not against the deltas alone. Read only the four scalar columns
    // the rule needs: a full `lookup` would parse `params_json` and turn a row
    // with a malformed one into an unrepairable `BadParams`.
    let stored: (String, String, String, Option<String>) = conn
        .query_row(
            "SELECT COALESCE(kind, 'sql'), sql, COALESCE(mode, 'read'), query_json
               FROM _system_rpc WHERE name = ?1",
            params![name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => RegistryError::NotFound(name.to_string()),
            other => RegistryError::Sqlite(other),
        })?;
    let (stored_kind, stored_sql, stored_mode, stored_query_json) = stored;
    let eff_sql = sql.unwrap_or(&stored_sql);
    let eff_mode = mode.unwrap_or_else(|| RpcMode::from_db_str(&stored_mode));
    let eff_query_json = query_json.or(stored_query_json.as_deref());
    check_kind_rules(
        RpcKind::from_db_str(&stored_kind),
        eff_sql,
        eff_mode,
        QueryJsonView {
            after: eff_query_json,
            set: query_json,
        },
    )
    .map_err(|e| name_kind_err(name, e))?;
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
    if let Some(q) = query_json {
        clauses.push("query_json = ?");
        binds.push(rusqlite::types::Value::Text(q.into()));
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

    /// A minimal valid sql-kind row, so a test states only what it varies.
    fn sql_rpc<'a>(name: &'a str, sql: &'a str) -> RpcCreate<'a> {
        RpcCreate {
            name,
            sql,
            params_json: "[]",
            description: None,
            anon_callable: false,
            mode: RpcMode::Read,
            kind: RpcKind::Sql,
            query_json: None,
        }
    }

    /// A minimal valid query-kind row.
    fn query_rpc<'a>(name: &'a str, query_json: &'a str) -> RpcCreate<'a> {
        RpcCreate {
            name,
            sql: "",
            params_json: "[]",
            description: None,
            anon_callable: true,
            mode: RpcMode::Read,
            kind: RpcKind::Query,
            query_json: Some(query_json),
        }
    }

    #[test]
    fn create_then_lookup() {
        let (_t, conn) = fresh();
        create(
            &conn,
            RpcCreate {
                description: Some("trivial"),
                ..sql_rpc("echo", "SELECT 1")
            },
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
        create(&conn, sql_rpc("x", "SELECT 1")).unwrap();
        let err = create(&conn, sql_rpc("x", "SELECT 2")).unwrap_err();
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
        create(&conn, sql_rpc("b", "SELECT 1")).unwrap();
        create(&conn, sql_rpc("a", "SELECT 1")).unwrap();
        let v = list(&conn).unwrap();
        assert_eq!(
            v.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn update_partial_changes() {
        let (_t, conn) = fresh();
        create(&conn, sql_rpc("x", "SELECT 1")).unwrap();
        update(
            &conn,
            "x",
            RpcUpdate {
                sql: Some("SELECT 2"),
                anon_callable: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        let r = lookup(&conn, "x").unwrap().unwrap();
        assert_eq!(r.sql, "SELECT 2");
        assert!(r.anon_callable);
    }

    #[test]
    fn update_missing_errors() {
        let (_t, conn) = fresh();
        let err = update(
            &conn,
            "nope",
            RpcUpdate {
                sql: Some("SELECT 1"),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    /// A row whose stored `params_json` is malformed must stay REPAIRABLE:
    /// `update` reads only the scalar columns its kind rule needs, so it
    /// never trips over the parse that `lookup` would do.
    #[test]
    fn update_can_repair_a_row_with_malformed_params_json() {
        let (_t, conn) = fresh();
        conn.execute(
            "INSERT INTO _system_rpc (name, sql, params_json) VALUES ('broken', 'SELECT 1', 'not json')",
            [],
        )
        .unwrap();
        assert!(matches!(
            lookup(&conn, "broken"),
            Err(RegistryError::BadParams(_))
        ));
        update(
            &conn,
            "broken",
            RpcUpdate {
                params_json: Some("[]"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(lookup(&conn, "broken").unwrap().unwrap().params.len(), 0);
    }

    #[test]
    fn delete_missing_errors() {
        let (_t, conn) = fresh();
        let err = delete(&conn, "nope").unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    #[test]
    fn create_and_lookup_query_kind() {
        let (_t, conn) = fresh();
        create(&conn, query_rpc("q", r#"{"collection":"posts"}"#)).unwrap();
        let r = lookup(&conn, "q").unwrap().unwrap();
        assert_eq!(r.kind, RpcKind::Query);
        assert_eq!(r.query_json.as_deref(), Some(r#"{"collection":"posts"}"#));
        assert_eq!(r.sql, "");
        assert_eq!(r.mode, RpcMode::Read);
    }

    /// `create` must enforce the SAME kind contract `update` does — otherwise a
    /// row can be born in a state no update may repair (kind=query + mode=write
    /// is the sharp case: `update` refuses to move a query row off mode=read).
    #[test]
    fn create_kind_rules_are_enforced() {
        let (_t, conn) = fresh();
        // query without a template
        assert!(matches!(
            create(
                &conn,
                RpcCreate {
                    query_json: None,
                    ..query_rpc("q1", "unused")
                }
            ),
            Err(RegistryError::KindInvalid(_))
        ));
        // query with a write mode — the unrepairable one
        assert!(matches!(
            create(
                &conn,
                RpcCreate {
                    mode: RpcMode::Write,
                    ..query_rpc("q2", r#"{"collection":"posts"}"#)
                }
            ),
            Err(RegistryError::KindInvalid(_))
        ));
        // query carrying an sql body
        assert!(matches!(
            create(
                &conn,
                RpcCreate {
                    sql: "SELECT 1",
                    ..query_rpc("q3", r#"{"collection":"posts"}"#)
                }
            ),
            Err(RegistryError::KindInvalid(_))
        ));
        // sql carrying a query template
        assert!(matches!(
            create(
                &conn,
                RpcCreate {
                    query_json: Some(r#"{"collection":"posts"}"#),
                    ..sql_rpc("s1", "SELECT 1")
                }
            ),
            Err(RegistryError::KindInvalid(_))
        ));
        // none of them landed
        assert!(list(&conn).unwrap().is_empty());
    }

    /// A row written before #950 has NO `kind` value (or, defensively, an
    /// unknown one). `from_db_str` must read it back as `Sql`, not panic and
    /// not invent `Query`.
    #[test]
    fn legacy_rows_read_as_sql_kind() {
        let (_t, conn) = fresh();
        // Pre-#950 shape: the column exists after migration but nothing wrote it.
        conn.execute(
            "INSERT INTO _system_rpc (name, sql, params_json, kind) VALUES ('g', 'SELECT 1', '[]', 'bogus')",
            [],
        )
        .unwrap();
        let r = lookup(&conn, "g").unwrap().unwrap();
        assert_eq!(r.kind, RpcKind::Sql, "unknown kind string must fall back");
        assert!(r.query_json.is_none());
        // And the same via list(), which parses the column separately.
        let listed = list(&conn).unwrap();
        assert_eq!(listed[0].kind, RpcKind::Sql);
    }

    #[test]
    fn update_kind_rules_are_enforced() {
        let (_t, conn) = fresh();
        create(&conn, query_rpc("q", r#"{"collection":"posts"}"#)).unwrap();
        // query row: sql / mode changes refused
        assert!(matches!(
            update(
                &conn,
                "q",
                RpcUpdate {
                    sql: Some("SELECT 1"),
                    ..Default::default()
                }
            ),
            Err(RegistryError::KindInvalid(_))
        ));
        assert!(matches!(
            update(
                &conn,
                "q",
                RpcUpdate {
                    mode: Some(RpcMode::Write),
                    ..Default::default()
                }
            ),
            Err(RegistryError::KindInvalid(_))
        ));
        // query row: query_json / anon_callable changes allowed
        update(
            &conn,
            "q",
            RpcUpdate {
                anon_callable: Some(false),
                query_json: Some(r#"{"collection":"posts2"}"#),
                ..Default::default()
            },
        )
        .unwrap();
        // …and actually landed: the refusals above must not be the only thing
        // this test can see, or a broken UPDATE clause list stays green.
        let after = lookup(&conn, "q").unwrap().unwrap();
        assert_eq!(
            after.query_json.as_deref(),
            Some(r#"{"collection":"posts2"}"#)
        );
        assert!(!after.anon_callable);
        assert_eq!(after.kind, RpcKind::Query);
        assert_eq!(after.sql, "");
        assert_eq!(after.mode, RpcMode::Read);
        // sql row: query_json refused
        create(&conn, sql_rpc("s", "SELECT 1")).unwrap();
        assert!(matches!(
            update(
                &conn,
                "s",
                RpcUpdate {
                    query_json: Some("{}"),
                    ..Default::default()
                }
            ),
            Err(RegistryError::KindInvalid(_))
        ));
        assert!(lookup(&conn, "s").unwrap().unwrap().query_json.is_none());
    }

    /// N3 — an update that does not mention `query_json` must LEAVE the stored
    /// template in place. The merge (`delta.or(stored)`) is what makes an
    /// unrelated field change legal on a query row at all.
    #[test]
    fn update_preserves_the_stored_template_when_untouched() {
        let (_t, conn) = fresh();
        create(&conn, query_rpc("q", r#"{"collection":"posts"}"#)).unwrap();
        update(
            &conn,
            "q",
            RpcUpdate {
                anon_callable: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
        let r = lookup(&conn, "q").unwrap().unwrap();
        assert_eq!(
            r.query_json.as_deref(),
            Some(r#"{"collection":"posts"}"#),
            "an untouched template must survive an unrelated update"
        );
        assert!(!r.anon_callable, "the unrelated change must have landed");
    }

    /// N4 — a sql row that somehow carries a stray `query_json` (reachable only
    /// by hand-editing the DB; `create` refuses it) must stay REPAIRABLE: the
    /// Sql arm judges what the write SETS, not what the row already holds.
    #[test]
    fn update_repairs_a_sql_row_carrying_a_stray_template() {
        let (_t, conn) = fresh();
        conn.execute(
            "INSERT INTO _system_rpc (name, sql, params_json, kind, query_json)
             VALUES ('s', 'SELECT 1', '[]', 'sql', '{\"collection\":\"posts\"}')",
            [],
        )
        .unwrap();
        update(
            &conn,
            "s",
            RpcUpdate {
                sql: Some("SELECT 2"),
                ..Default::default()
            },
        )
        .expect("a stray template must not brick every future update");
        let r = lookup(&conn, "s").unwrap().unwrap();
        assert_eq!(r.sql, "SELECT 2");
        // The stray survives — dead data on a sql row. WRITING one is still refused.
        assert!(matches!(
            update(
                &conn,
                "s",
                RpcUpdate {
                    query_json: Some("{}"),
                    ..Default::default()
                }
            ),
            Err(RegistryError::KindInvalid(_))
        ));
    }

    #[test]
    fn increment_picks_correct_column() {
        let (_t, conn) = fresh();
        create(&conn, sql_rpc("x", "SELECT 1")).unwrap();
        increment(&conn, "x", TokenRole::Anon).unwrap();
        increment(&conn, "x", TokenRole::Service).unwrap();
        increment(&conn, "x", TokenRole::Anon).unwrap();
        let r = lookup(&conn, "x").unwrap().unwrap();
        assert_eq!(r.anon_calls, 2);
        assert_eq!(r.service_calls, 1);
        assert!(r.last_called_at.is_some());
    }
}

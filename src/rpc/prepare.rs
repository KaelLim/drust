//! Prepare-time SQL safety: reject anything the mode-matched authorizer
//! would deny, before persisting an RPC.

use crate::query::authorizer::{
    attach_readonly_authorizer, attach_writable_authorizer, detach_authorizer,
};
use crate::rpc::params::ParamSpec;
use crate::rpc::registry::RpcMode;
use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("rpc sql failed prepare-time validation: {0}")]
    Rejected(String),
}

/// Validate the SQL body of a stored RPC at registry-write time. The
/// authorizer used matches the RPC's declared `mode`:
///
/// - `RpcMode::Read`  → attaches [`attach_readonly_authorizer`]; SELECTs
///   on user tables are Allowed; anything else (INSERT/UPDATE/DELETE,
///   DDL, ATTACH, sqlite_master / _system_* reads) is Denied at prepare.
/// - `RpcMode::Write` → attaches [`attach_writable_authorizer`]; the
///   same Read surface PLUS Insert/Update/Delete on non-protected user
///   tables. DDL, ATTACH, sqlite_master reads, and _system_* writes are
///   still Denied at prepare.
///
/// Multi-statement bodies are split via [`crate::rpc::exec_write::split_statements`]
/// (the same lexer the executor uses) and validated per-statement so a
/// body that mixes a legitimate INSERT with a sneaky `DROP` fails at the
/// offending statement rather than silently passing.
///
/// Reconciliation note (C5): empirical probe shows
/// `Connection::prepare` of a write statement SUCCEEDS on a connection
/// opened with `SQLITE_OPEN_READONLY` + `PRAGMA query_only = ON` —
/// SQLite's readonly guard fires only at `step()` time, not prepare.
/// So the authorizer (not the open-mode) is what decides allow/deny at
/// prepare-time. This function therefore runs cleanly on a reader
/// connection for BOTH modes; callers should dispatch through
/// `pool.with_reader` (avoids the per-tenant writer mutex on every
/// admin-form save).
pub fn validate_rpc_sql(conn: &Connection, sql: &str, mode: RpcMode) -> Result<(), PrepareError> {
    // Preserve pre-C5 behaviour: an empty body was rejected because
    // `conn.prepare("")` errors with "no SQL". The new split-then-prepare
    // path would otherwise loop zero times and silently accept "".
    if sql.trim().is_empty() {
        return Err(PrepareError::Rejected("rpc sql body is empty".to_string()));
    }

    // Defense in depth: if a previous closure on this conn left an
    // authorizer attached (it shouldn't — every code path is supposed to
    // detach), reset to a known state before we attach our own.
    detach_authorizer(conn);

    // Split first so we can validate each statement under its own attach.
    let stmts = match crate::rpc::exec_write::split_statements(sql) {
        Ok(s) => s,
        Err(e) => return Err(PrepareError::Rejected(e.message)),
    };

    // Defensive: split_statements may return Ok(vec![]) for a body that
    // is purely whitespace-with-semicolons (e.g. "   ;   "). The empty
    // check above only catches all-whitespace bodies, so reject this
    // edge case explicitly too.
    if stmts.is_empty() {
        return Err(PrepareError::Rejected(
            "rpc sql body has no statements".to_string(),
        ));
    }

    for stmt in &stmts {
        match mode {
            RpcMode::Read => attach_readonly_authorizer(conn),
            RpcMode::Write => attach_writable_authorizer(conn),
        }
        let res = conn
            .prepare(stmt)
            .map(|_| ())
            .map_err(|e| PrepareError::Rejected(format!("{e}")));
        // MANDATORY detach BEFORE we propagate the error or move on to
        // the next statement — otherwise the authorizer would leak to
        // the connection's next user (schema introspection, the next
        // RPC, etc.). This is the same invariant `call_rpc`'s STEP 5
        // observes for the runtime path.
        detach_authorizer(conn);
        res?;
    }
    Ok(())
}

/// Rejection sentinel for [`guard_anon_owner_scoped_rpc`]. Surfaced in the
/// `PrepareError::Rejected` message so callers (and tests) can pattern-match
/// the specific footgun rather than a generic prepare failure.
pub const RPC_ANON_OWNER_SCOPED: &str = "RPC_ANON_OWNER_SCOPED";

/// v1.41.3 — create-time guard against an anon-callable RPC whose body touches
/// an owner-scoped collection without binding `:user_id`.
///
/// Unlike `/list` and `/search`, drust does NOT rewrite stored-RPC SQL, so no
/// owner row-filter is injected at call time. An anon-callable RPC that reads an
/// owner-scoped collection therefore returns EVERY user's rows to an anonymous
/// caller; an anon-callable WRITE RPC lets anon mutate every user's rows, which
/// is strictly worse. Either is a cross-user leak that looks like a correct
/// query. We refuse both at create time.
///
/// Fires for `anon_callable` in BOTH modes. The escape hatch is a declared
/// `:user_id` param — the author is then expected to filter
/// `WHERE <owner> = :user_id` (auto-bound from `AuthCtx`), matching the
/// existing `anon_callable` + `:user_id` auto-bind contract. Service-only RPCs
/// (`anon_callable == false`) and bodies over non-owner-scoped collections pass
/// untouched.
///
/// Table discovery reuses the authorizer surface: a capturing authorizer
/// records every table the prepared statement Reads (both modes) and, in write
/// mode, every table it Inserts/Updates/Deletes; then each table's `owner_field`
/// is probed. `sqlite_*` / protected (`_system_*`) tables are skipped — they are
/// never owner-scoped and are already denied by the `validate_rpc_sql` pass that
/// runs before this guard. In read mode an unexpected write action is denied
/// outright (validate should already have rejected it).
pub fn guard_anon_owner_scoped_rpc(
    conn: &Connection,
    sql: &str,
    params: &[ParamSpec],
    anon_callable: bool,
    mode: RpcMode,
) -> Result<(), PrepareError> {
    // Service-only RPCs cannot leak owner-scoped rows to anon (either direction).
    if !anon_callable {
        return Ok(());
    }
    // A declared :user_id param is the sanctioned owner-filter escape hatch for
    // the OWNER_FIELD case only — it does not exempt the policy case below
    // (audit3 F2), so it is now checked per-table rather than as an early return.
    let referenced = referenced_user_tables(conn, sql, mode)?;
    let has_user_id = params.iter().any(|p| p.name == "user_id");
    for table in &referenced {
        // (audit3 F2) Policy-protected collections: call_rpc runs the stored SQL
        // verbatim, so NO RLS policy is applied. Unlike owner_field, a `:user_id`
        // param is NOT a valid escape — an RLS policy need not key on the caller
        // (e.g. `using: {published: true}`), so binding :user_id cannot stand in
        // for it. Refuse unconditionally, mirroring `/query` fail-closing
        // tenant-wide once any policy exists.
        if crate::storage::schema::collection_has_policy(conn, table)
            .map_err(|e| PrepareError::Rejected(format!("policy probe failed: {e}")))?
        {
            return Err(PrepareError::Rejected(format!(
                "{RPC_ANON_OWNER_SCOPED}: an anon-callable RPC over policy-protected collection \
                 '{table}' is refused — drust does not apply RLS policies to stored-RPC SQL, so it \
                 would expose the rows the policy hides; set anon_callable=false on this RPC"
            )));
        }
        // Owner-scoped collection: an anon/user caller must be constrained to
        // their own rows, but drust does not rewrite stored-RPC SQL. The declared
        // :user_id param is the sanctioned escape hatch — but merely DECLARING it
        // is not enough (codex full-scan F1): the body must ALSO bind the owner
        // column to :user_id (e.g. `WHERE user_id = :user_id`), else a body like
        // `WHERE :user_id IS NOT NULL` (declares the param, references it, yet
        // filters nothing) still returns/mutates every user's rows.
        let (owner_field, _scope) = crate::storage::schema::read_owner_field(conn, table)
            .map_err(|e| PrepareError::Rejected(format!("owner_field probe failed: {e}")))?;
        if let Some(owner_col) = owner_field {
            if !has_user_id {
                return Err(PrepareError::Rejected(format!(
                    "{RPC_ANON_OWNER_SCOPED}: an anon-callable RPC over owner-scoped \
                     collection '{table}' must bind :user_id, else it exposes every user's rows; \
                     declare a :user_id param and filter `{owner_col} = :user_id`, or set \
                     anon_callable=false"
                )));
            }
            if !sql_binds_owner_to_user_id(sql, &owner_col) {
                return Err(PrepareError::Rejected(format!(
                    "{RPC_ANON_OWNER_SCOPED}: an anon-callable RPC over owner-scoped \
                     collection '{table}' declares :user_id but its SQL does not constrain \
                     `{owner_col} = :user_id`, so it still exposes every user's rows; add that \
                     predicate on every path over '{table}', or set anon_callable=false"
                )));
            }
        }
    }
    Ok(())
}

/// Discover every user-table a stored-RPC body touches: tables it Reads (both
/// modes) plus, in write mode, tables it Inserts/Updates/Deletes. `sqlite_*` and
/// protected (`_system_*`) tables are excluded — they are never owner-scoped and
/// are already denied by `validate_rpc_sql`. Shared by the create/update guard
/// and the owner-scope-change guard so both reason about the same table set. In
/// read mode an unexpected write action is denied outright (validate should
/// already have rejected it).
fn referenced_user_tables(
    conn: &Connection,
    sql: &str,
    mode: RpcMode,
) -> Result<HashSet<String>, PrepareError> {
    let is_write = mode == RpcMode::Write;
    let stmts = match crate::rpc::exec_write::split_statements(sql) {
        Ok(s) => s,
        Err(e) => return Err(PrepareError::Rejected(e.message)),
    };
    let tables: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    detach_authorizer(conn);
    for stmt in &stmts {
        let sink = Arc::clone(&tables);
        conn.authorizer(Some(move |ctx: AuthContext<'_>| -> Authorization {
            let capture = |table_name: &str| {
                if !table_name.starts_with("sqlite_")
                    && !crate::storage::schema::is_protected_collection(table_name)
                {
                    sink.lock().unwrap().insert(table_name.to_string());
                }
            };
            match ctx.action {
                AuthAction::Read { table_name, .. } => {
                    capture(table_name);
                    Authorization::Allow
                }
                AuthAction::Insert { table_name, .. }
                | AuthAction::Update { table_name, .. }
                | AuthAction::Delete { table_name, .. } => {
                    if is_write {
                        capture(table_name);
                        Authorization::Allow
                    } else {
                        // A write inside a read RPC: validate_rpc_sql should have
                        // rejected it already — fail closed here too.
                        Authorization::Deny
                    }
                }
                AuthAction::Select | AuthAction::Function { .. } | AuthAction::Recursive => {
                    Authorization::Allow
                }
                AuthAction::Pragma { pragma_name, .. } => match pragma_name {
                    "table_info" | "index_list" | "index_info" | "foreign_key_list"
                    | "table_xinfo" => Authorization::Allow,
                    _ => Authorization::Ignore,
                },
                _ => Authorization::Deny,
            }
        }))
        .expect("capturing authorizer must install");
        let prep = conn.prepare(stmt).map(|_| ());
        // Detach BEFORE propagating — never leak the capturing authorizer to
        // the connection's next user (same invariant validate_rpc_sql holds).
        detach_authorizer(conn);
        prep.map_err(|e| PrepareError::Rejected(format!("{e}")))?;
    }
    // Snapshot by value (no fail-open Arc::try_unwrap path).
    let snapshot = tables.lock().unwrap().clone();
    Ok(snapshot)
}

/// Heuristic textual check (codex full-scan F1): does `sql` contain a predicate
/// that binds the owner column to the auto-bound `:user_id` param — i.e.
/// `<owner_col> = :user_id` or `:user_id = <owner_col>` (case-insensitive,
/// whitespace-tolerant, an optional `<qualifier>.` prefix on the column allowed)?
///
/// drust does NOT parse stored-RPC SQL (a deliberate invariant), so this is a
/// SAFETY-NET against the accidental footgun where an anon/user-callable RPC over
/// an owner-scoped collection declares a `:user_id` param but forgets to filter by
/// it (e.g. `WHERE :user_id IS NOT NULL`), which would still expose every user's
/// rows. It is NOT a semantic proof: it cannot see through a multi-table JOIN that
/// leaves a second owner-scoped table unfiltered, and a determined SERVICE author
/// (who already holds full tenant access) could defeat it with a comment/string.
/// That is an accepted limit of the "no SQL rewrite" design; the check exists to
/// catch honest mistakes and to stop the guard's own remediation advice ("declare
/// a :user_id param") from being a silent bypass.
fn sql_binds_owner_to_user_id(sql: &str, owner_col: &str) -> bool {
    let owner = owner_col.to_ascii_lowercase();
    let lc = sql.to_ascii_lowercase();
    // Tokenize: a "word" is a maximal run of [a-z0-9_.] (identifiers + qualified
    // `t.col` names); ':' + word is a named param; '=' is its own token; every
    // other byte is a separator. This preserves token boundaries (so "where
    // user_id" never merges) without a regex dependency.
    let bytes = lc.as_bytes();
    let mut tokens: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'=' {
            tokens.push("=");
            i += 1;
        } else if b == b':' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            tokens.push(&lc[start..i]);
        } else if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
            {
                i += 1;
            }
            tokens.push(&lc[start..i]);
        } else {
            i += 1;
        }
    }
    let is_owner_ref = |t: &str| t == owner || t.rsplit('.').next() == Some(owner.as_str());
    let is_user_id_param = |t: &str| t == ":user_id";
    tokens.windows(3).any(|w| {
        w[1] == "="
            && ((is_owner_ref(w[0]) && is_user_id_param(w[2]))
                || (is_user_id_param(w[0]) && is_owner_ref(w[2])))
    })
}

/// Config-time defense-in-depth (v1.41.3): refuse to make `collection`
/// owner-scoped while an existing `anon_callable` RPC reads or writes it without
/// binding `:user_id`. The create/update guard never re-runs when a collection's
/// owner-scope is toggled AFTER an RPC exists, so without this an admin calling
/// `set_owner_field` on a collection an anon RPC already reads would silently
/// turn that RPC into a cross-user leak (the reachable "becomes-owner-scoped-later"
/// gap surfaced in adversarial review). Symmetric with
/// [`guard_anon_owner_scoped_rpc`]; runs BEFORE the owner_field write (that path
/// is autocommit, so a rejection must precede the write, not roll it back) and
/// reuses [`referenced_user_tables`] so it sees exactly the tables the runtime
/// would. The owner-scope config path is service-only + rare, so the per-RPC
/// probe is off the hot path.
pub fn guard_owner_scope_change_against_anon_rpcs(
    conn: &Connection,
    collection: &str,
    new_owner_field: &str,
) -> Result<(), PrepareError> {
    let rpcs = crate::rpc::registry::list(conn)
        .map_err(|e| PrepareError::Rejected(format!("rpc scan failed: {e}")))?;
    for rpc in rpcs {
        if !rpc.anon_callable {
            continue;
        }
        let tables = referenced_user_tables(conn, &rpc.sql, rpc.mode)?;
        if !tables.contains(collection) {
            continue;
        }
        // The RPC references the collection being made owner-scoped. Safe ONLY if
        // it declares :user_id AND its SQL actually binds the (new) owner column
        // to :user_id — a declared-but-unused :user_id no longer exempts it
        // (codex full-scan F1), mirroring the tightened create-time guard.
        let bound = rpc.params.iter().any(|p| p.name == "user_id")
            && sql_binds_owner_to_user_id(&rpc.sql, new_owner_field);
        if bound {
            continue;
        }
        return Err(PrepareError::Rejected(format!(
            "{RPC_ANON_OWNER_SCOPED}: cannot make collection '{collection}' owner-scoped while \
             anon-callable RPC '{}' references it without binding `{new_owner_field} = :user_id`; \
             add that predicate + a :user_id param, or set anon_callable=false on that RPC first",
            rpc.name
        )));
    }
    Ok(())
}

/// Legacy one-time scan (v1.41.3): names of `anon_callable` RPCs that ALREADY
/// read or write an owner-scoped collection without binding `:user_id` against
/// the CURRENT owner-scope state. Such a row predates the create/update +
/// owner-scope-change guards (e.g. created before v1.41.3, or owner-scope set in
/// a window before the guards existed) and still leaks at call time, because the
/// runtime `call_rpc` path does NOT re-check owner-scope. The startup migration
/// uses this to neutralize them fail-closed. Read-only; the caller performs the
/// remediation. Reuses [`guard_anon_owner_scoped_rpc`] so "unsafe" means exactly
/// what the create/update guard means.
pub fn scan_unsafe_anon_rpcs(conn: &Connection) -> Result<Vec<String>, PrepareError> {
    let rpcs = crate::rpc::registry::list(conn)
        .map_err(|e| PrepareError::Rejected(format!("rpc scan failed: {e}")))?;
    let mut unsafe_names = Vec::new();
    for rpc in rpcs {
        // Do NOT skip :user_id RPCs here: the guard itself exempts :user_id for
        // the owner_field case but NOT for the policy case (audit3 F2), so a
        // :user_id RPC over a policy-protected collection must still be caught.
        if !rpc.anon_callable {
            continue;
        }
        if let Err(PrepareError::Rejected(msg)) =
            guard_anon_owner_scoped_rpc(conn, &rpc.sql, &rpc.params, true, rpc.mode)
            && msg.contains(RPC_ANON_OWNER_SCOPED)
        {
            unsafe_names.push(rpc.name);
        }
    }
    Ok(unsafe_names)
}

/// Config-time defense (audit3 F2): refuse to ATTACH an RLS policy to
/// `collection` while an existing `anon_callable` RPC references it. The
/// create/update guard never re-runs when a policy is attached AFTER an RPC
/// exists, and `call_rpc` applies no policy to stored-RPC SQL, so the RPC would
/// silently begin leaking the rows the new policy is meant to hide. Symmetric
/// with [`guard_owner_scope_change_against_anon_rpcs`], but — unlike owner_field
/// — a `:user_id` param is NOT an escape (a policy need not key on the caller),
/// so EVERY `anon_callable` RPC referencing the collection is refused. Runs
/// BEFORE the `write_policy` (autocommit path, so a rejection must precede the
/// write, not roll it back) and reuses [`referenced_user_tables`] so it sees
/// exactly the tables the runtime would.
pub fn guard_policy_change_against_anon_rpcs(
    conn: &Connection,
    collection: &str,
) -> Result<(), PrepareError> {
    let rpcs = crate::rpc::registry::list(conn)
        .map_err(|e| PrepareError::Rejected(format!("rpc scan failed: {e}")))?;
    for rpc in rpcs {
        if !rpc.anon_callable {
            continue;
        }
        let tables = referenced_user_tables(conn, &rpc.sql, rpc.mode)?;
        if tables.contains(collection) {
            return Err(PrepareError::Rejected(format!(
                "{RPC_ANON_OWNER_SCOPED}: cannot attach an RLS policy to collection '{collection}' \
                 while anon-callable RPC '{}' references it — drust does not apply policies to \
                 stored-RPC SQL; set anon_callable=false on that RPC first",
                rpc.name
            )));
        }
    }
    Ok(())
}

/// Update-path counterpart of [`guard_anon_owner_scoped_rpc`].
///
/// RPC updates are partial — any of `sql` / `params` / `anon_callable` may be
/// omitted. A flag-flip (`anon_callable=Some(true)`, `sql=None`) or an sql-swap
/// (`sql=Some(<owner-scoped>)`, `anon_callable=None`) must be re-checked against
/// the STORED row's other fields, otherwise an update reopens exactly the leak
/// the create-time guard closes (the MCP `update_rpc` path bypassed the guard
/// entirely before v1.41.3 — found in adversarial review). Loads the stored RPC,
/// merges the supplied deltas over it, and runs the guard on the effective
/// values (inheriting the stored `mode`). A missing stored row is a no-op — the
/// update itself will 404.
pub fn guard_anon_owner_scoped_rpc_update(
    conn: &Connection,
    name: &str,
    new_sql: Option<&str>,
    new_params: Option<&[ParamSpec]>,
    new_anon_callable: Option<bool>,
) -> Result<(), PrepareError> {
    let stored = match crate::rpc::registry::lookup(conn, name) {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(()),
        Err(e) => return Err(PrepareError::Rejected(format!("rpc lookup failed: {e}"))),
    };
    let eff_sql = new_sql.unwrap_or(&stored.sql);
    let eff_params = new_params.unwrap_or(stored.params.as_slice());
    let eff_anon = new_anon_callable.unwrap_or(stored.anon_callable);
    guard_anon_owner_scoped_rpc(conn, eff_sql, eff_params, eff_anon, stored.mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tenant_db::open_write;
    use tempfile::TempDir;

    #[test]
    fn sql_binds_owner_to_user_id_matches_real_predicates_only() {
        // positive: the owner column is bound to :user_id (various shapes)
        for sql in [
            "SELECT * FROM orders WHERE user_id = :user_id",
            "select * from orders where USER_ID=:user_id",
            "SELECT * FROM orders WHERE :user_id = user_id",
            "SELECT * FROM orders o WHERE o.user_id = :user_id",
            "SELECT * FROM orders WHERE qty>0 AND user_id  =  :user_id",
        ] {
            assert!(
                sql_binds_owner_to_user_id(sql, "user_id"),
                "should match: {sql}"
            );
        }
        // negative: declared/referenced :user_id but no owner binding
        for sql in [
            "SELECT * FROM orders WHERE :user_id IS NOT NULL",
            "SELECT * FROM orders",
            "SELECT * FROM orders WHERE qty > 0",
            "SELECT * FROM orders WHERE id = :user_id", // binds id, not owner
            "SELECT * FROM orders WHERE user_idx = :user_id", // different column
        ] {
            assert!(
                !sql_binds_owner_to_user_id(sql, "user_id"),
                "should NOT match: {sql}"
            );
        }
        // a differently-named owner column
        assert!(sql_binds_owner_to_user_id(
            "SELECT * FROM t WHERE owner = :user_id",
            "owner"
        ));
        assert!(!sql_binds_owner_to_user_id(
            "SELECT * FROM t WHERE user_id = :user_id",
            "owner"
        ));
    }

    fn fresh() -> (TempDir, Connection) {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), "rpcprep").unwrap();
        conn.execute_batch("CREATE TABLE posts (id INTEGER PRIMARY KEY, body TEXT);")
            .unwrap();
        (tmp, conn)
    }

    #[test]
    fn valid_select_passes() {
        let (_t, conn) = fresh();
        validate_rpc_sql(
            &conn,
            "SELECT id, body FROM posts WHERE id = :id",
            RpcMode::Read,
        )
        .unwrap();
    }

    #[test]
    fn syntax_error_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT FROM", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn update_rejected() {
        let (_t, conn) = fresh();
        let err =
            validate_rpc_sql(&conn, "UPDATE posts SET body = 'x'", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn delete_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "DELETE FROM posts", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn attach_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "ATTACH 'other.db' AS x", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn sqlite_master_rejected() {
        let (_t, conn) = fresh();
        let err =
            validate_rpc_sql(&conn, "SELECT * FROM sqlite_master", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn unknown_table_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT * FROM nope", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn system_rpc_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT * FROM _system_rpc", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn empty_body_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
        let err = validate_rpc_sql(&conn, "   \n\t  ", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn read_mode_does_not_leak_authorizer_on_success() {
        // After a successful read-mode validate, the next prepare should
        // not be authorizer-gated. We check by preparing a DDL — which
        // the read authorizer would Deny but a detached connection
        // accepts at prepare time (rusqlite returns Ok; step would fail
        // on a real readonly handle but this conn is a writer).
        let (_t, conn) = fresh();
        validate_rpc_sql(&conn, "SELECT id FROM posts", RpcMode::Read).unwrap();
        let r = conn.prepare("DROP TABLE posts");
        assert!(r.is_ok(), "authorizer leaked after success: {:?}", r.err());
    }

    #[test]
    fn read_mode_does_not_leak_authorizer_on_failure() {
        // Mirror of the success path: even if validate Rejects, the
        // detach in the body must run so the connection is clean for
        // the next user.
        let (_t, conn) = fresh();
        let _ = validate_rpc_sql(&conn, "UPDATE posts SET body = 'x'", RpcMode::Read).unwrap_err();
        let r = conn.prepare("DROP TABLE posts");
        assert!(r.is_ok(), "authorizer leaked after failure: {:?}", r.err());
    }
}

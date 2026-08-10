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

    // Wave 2 M3: the write branch's authorizer needs the AUTHORITATIVE
    // `_system_search_*` head-vs-internal classifier, and `pragma_table_list`
    // is only readable while the connection is unrestricted — so snapshot once
    // here, before the first attach. Fail-closed: an empty head-set would
    // classify heads as module internals (fail-OPEN), so a snapshot error is
    // propagated as a rejection rather than substituted with a blank.
    //
    // The READ branch deliberately keeps the UNCHANGED strict
    // `attach_readonly_authorizer`. That is the whole leak fix: a stored read
    // RPC's body is CALLER-authored and is never rewritten, so if the strict
    // arm admitted `_system_search_*`, an `anon_callable` RPC
    // `SELECT title, body FROM "<head>"` would validate here, slip past
    // `guard_anon_owner_scoped_rpc` (whose `referenced_user_tables` skips
    // `_system_*` precisely *because* this function denies them), and leak
    // every user's indexed columns to anon.
    let search = crate::storage::search_names::snapshot_search_tables(conn).map_err(|e| {
        PrepareError::Rejected(format!("search-table classifier probe failed: {e}"))
    })?;

    for stmt in &stmts {
        match mode {
            RpcMode::Read => attach_readonly_authorizer(conn),
            RpcMode::Write => attach_writable_authorizer(conn, &search),
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
        // query-kind (#950): no SQL to scan. Its rows MUST be gated at runtime by
        // the /list compile path (caps + owner_field + RLS) — the query execution
        // arm owes that; until it lands no face can create a query row.
        if rpc.kind == crate::rpc::registry::RpcKind::Query {
            continue;
        }
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
        // query-kind (#950): no SQL to scan. Its rows MUST be gated at runtime by
        // the /list compile path (caps + owner_field + RLS) — the query execution
        // arm owes that; until it lands no face can create a query row.
        if rpc.kind == crate::rpc::registry::RpcKind::Query {
            continue;
        }
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
        // query-kind (#950): no SQL to scan. Its rows MUST be gated at runtime by
        // the /list compile path (caps + owner_field + RLS) — the query execution
        // arm owes that; until it lands no face can create a query row.
        if rpc.kind == crate::rpc::registry::RpcKind::Query {
            continue;
        }
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
    // query-kind (#950): no SQL to scan. Its rows MUST be gated at runtime by
    // the /list compile path (caps + owner_field + RLS) — the query execution
    // arm owes that; until it lands no face can create a query row.
    if stored.kind == crate::rpc::registry::RpcKind::Query {
        return Ok(());
    }
    let eff_sql = new_sql.unwrap_or(&stored.sql);
    let eff_params = new_params.unwrap_or(stored.params.as_slice());
    let eff_anon = new_anon_callable.unwrap_or(stored.anon_callable);
    guard_anon_owner_scoped_rpc(conn, eff_sql, eff_params, eff_anon, stored.mode)
}

/// Rejection sentinel for the kind-shape rules (#950). Callers map a
/// `PrepareError::Rejected` carrying it to `400 RPC_KIND_INVALID`.
pub const RPC_KIND_INVALID: &str = "RPC_KIND_INVALID";

/// Rejection sentinel for the CLEAR guard (#950). Callers map a
/// `PrepareError::Rejected` carrying it to `409 RPC_QUERY_GRANT_ACTIVE`.
pub const RPC_QUERY_GRANT_ACTIVE: &str = "RPC_QUERY_GRANT_ACTIVE";

/// Config-time guard on the CLEAR paths (#950): refuse to drop `collection`'s
/// select policy or `owner_field` while an `anon_callable` query-kind RPC
/// targets it.
///
/// The sql guards above all key on the same idea — a config change that
/// RESTRICTS row access must not leave a pre-existing anon RPC reading past
/// the new restriction. Query-kind inverts it. A query RPC IS safe under a
/// restriction (the `/list` compile path applies the policy + owner clause at
/// call time under the caller's identity), which is exactly why the
/// enumerating guards skip it. What it is not safe against is the restriction
/// being REMOVED: `anon_callable=1` + a select policy is a curated grant of
/// the policy's rows, and clearing the policy silently promotes it to a grant
/// of the whole table. No pre-#950 guard runs on a clear, so nothing would say
/// so. Refuse, and name the two-step remedy (`anon_callable=false`, then
/// clear) — the grant is the author's, so only the author may widen it.
///
/// Rows whose template does not PARSE are skipped: such a row cannot execute
/// (`run_query_rpc` fails on the same parse), so it grants nothing, and
/// treating it as a blocker would let one broken row freeze a collection's
/// config with no way back. Symmetric with the sql guards, this runs BEFORE
/// the write (the clear paths are autocommit, so a rejection must precede the
/// write rather than roll it back).
pub fn guard_clear_against_anon_query_rpcs(
    conn: &Connection,
    collection: &str,
    what: &str,
) -> Result<(), PrepareError> {
    let rpcs = crate::rpc::registry::list(conn)
        .map_err(|e| PrepareError::Rejected(format!("rpc scan failed: {e}")))?;
    for rpc in rpcs {
        if rpc.kind != crate::rpc::registry::RpcKind::Query || !rpc.anon_callable {
            continue;
        }
        let Some(raw) = rpc.query_json.as_deref() else {
            continue;
        };
        let Ok(tpl) = crate::rpc::query_template::parse_template(raw) else {
            continue;
        };
        if tpl.collection == collection {
            return Err(PrepareError::Rejected(format!(
                "{RPC_QUERY_GRANT_ACTIVE}: cannot clear {what} on '{collection}' while \
                 anon-callable query RPC '{}' targets it; set anon_callable=false first",
                rpc.name
            )));
        }
    }
    Ok(())
}

/// The select-policy half of the CLEAR guard, transition-gated — the ONE place
/// the "does this write widen the read filter?" rule lives, so the five policy
/// faces that can effect a clear cannot drift apart (#950 T5b, B1 DiD + B5).
///
/// `new_using_present` is what the caller's write leaves behind: `false` for a
/// DELETE / `clear_policy`, and for a REPLACE face
/// `body.select.and_then(|p| p.using).is_some()`.
///
/// The key is the **effective USING clause**, never the presence of a policy
/// ROW. Those two came apart in the worst possible direction: a select policy
/// carrying no `using` filters nothing, yet a row-presence key reads it as
/// "still protected". `validate_policy` now refuses to WRITE that shape (the
/// root fix), and keying on `using` here means even a legacy row that already
/// holds it is judged by what actually filters. It also makes the guard fire
/// only on a real `Some → None` transition, so clearing an absent policy is a
/// no-op rather than a spurious refusal — one query RPC must never freeze
/// config it does not depend on.
pub fn guard_select_policy_clear(
    conn: &Connection,
    collection: &str,
    new_using_present: bool,
) -> Result<(), PrepareError> {
    if new_using_present {
        return Ok(()); // a filter remains — nothing widens
    }
    let stored_using_present = crate::storage::schema::read_policies(conn, collection)
        .map_err(|e| PrepareError::Rejected(format!("policy probe failed: {e}")))?
        .select
        .and_then(|p| p.using)
        .is_some();
    if !stored_using_present {
        return Ok(()); // no filter to lose
    }
    guard_clear_against_anon_query_rpcs(conn, collection, "the select policy")
}

/// The kind-SHAPE rules as a CREATE FACE sees them — before a template is
/// parsed or a row is built.
///
/// `registry::check_kind_rules` re-judges the finished row, so this is the
/// second door of a pair, not the only one. It exists because a face can fail
/// EARLIER and more precisely: `kind='sql'` + a `query` object never reaches
/// the registry at all (that face would simply drop the field on the floor),
/// and `kind='query'` with no template must be refused before we try to parse
/// one. Keep the two in agreement — they encode the same contract.
pub fn check_new_rpc_shape(
    kind: crate::rpc::registry::RpcKind,
    sql: &str,
    mode: RpcMode,
    has_query: bool,
) -> Result<(), PrepareError> {
    use crate::rpc::registry::RpcKind;
    match kind {
        RpcKind::Query => {
            if !has_query {
                return Err(PrepareError::Rejected(format!(
                    "{RPC_KIND_INVALID}: kind='query' requires a `query` template object"
                )));
            }
            if !sql.trim().is_empty() {
                return Err(PrepareError::Rejected(format!(
                    "{RPC_KIND_INVALID}: kind='query' carries no sql body; its body is `query`"
                )));
            }
            if mode != RpcMode::Read {
                return Err(PrepareError::Rejected(format!(
                    "{RPC_KIND_INVALID}: kind='query' is always mode='read' (a template only reads)"
                )));
            }
        }
        RpcKind::Sql => {
            if has_query {
                return Err(PrepareError::Rejected(format!(
                    "{RPC_KIND_INVALID}: kind='sql' carries no `query` template; its body is sql"
                )));
            }
        }
    }
    Ok(())
}

/// Save-time validation of a `kind='query'` body, shared by every create face
/// (MCP `create_rpc`, the admin form) so they cannot drift.
///
/// This REPLACES `validate_rpc_sql` + [`guard_anon_owner_scoped_rpc`] for query
/// rows — deliberately, and only because the query arm re-derives row access at
/// RUNTIME from the caller's identity (`exec_query::run_query_rpc` →
/// `records_list::run_structured_list_rpc_grant`). The sql guards exist
/// precisely because drust cannot rewrite raw SQL; a template is not raw SQL,
/// it is `?`-bound operands the list builder compiles under the caller's
/// owner_field + RLS. Skipping them for a row that did NOT get that runtime
/// gate would be the leak the guards were written for.
///
/// It LOADS the schema itself (rather than taking a `&CollectionSchema`) so no
/// face can hand it the schema of a different collection — a mismatch makes
/// every check inside `validate_template` vacuous, and that function's own
/// name-equality guard would then be the only thing standing between a
/// template for `posts` and a dry compile against `_system_users`.
pub fn validate_new_query_rpc(
    conn: &Connection,
    cache: &crate::storage::schema_cache::SchemaCache,
    tpl: &crate::rpc::query_template::QueryTemplate,
    specs: &[ParamSpec],
) -> Result<(), PrepareError> {
    // A caller-suppliable identity is not an identity. The sql arms HARD-BIND
    // `:user_id` from the bearer token (`handler.rs` overwrites any body value,
    // and refuses an anon caller outright), so an author who declares a
    // `user_id` param reasonably expects the same. A template gets no such
    // binding: the value arrives verbatim from the request body, so an
    // anon-callable "my rows" template keyed on `{"$param":"user_id"}` returns
    // ANY user's rows to ANY caller. Refuse the name and point at the operand
    // that IS bound. (`exec_query::run_query_rpc` re-checks at call time for
    // rows that predate this gate.)
    if specs.iter().any(|p| p.name == "user_id") {
        return Err(PrepareError::Rejected(format!(
            "{RPC_KIND_INVALID}: kind='query' cannot declare a 'user_id' param — unlike the sql \
             arms, a template does NOT bind it from the caller's token, so it would be \
             caller-supplied; use the {{\"$auth\":\"id\"}} operand, which drust substitutes from \
             the bearer identity and no caller can set"
        )));
    }
    // Typed code for the protected case before the generic load, so the face
    // reports `PROTECTED_COLLECTION` rather than a template shape message.
    // `validate_template` refuses it a second time (double door).
    if crate::storage::schema::is_protected_collection(&tpl.collection) {
        return Err(PrepareError::Rejected(format!(
            "PROTECTED_COLLECTION: '{}' is not addressable by a query template",
            tpl.collection
        )));
    }
    let schema = cache
        .ensure_loaded(conn, &tpl.collection)
        .map_err(|e| PrepareError::Rejected(format!("schema probe failed: {e}")))?
        .ok_or_else(|| {
            PrepareError::Rejected(format!(
                "COLLECTION_NOT_FOUND: no such collection: {}",
                tpl.collection
            ))
        })?;
    crate::rpc::query_template::validate_template(&schema, tpl, specs)
        .map_err(|e| PrepareError::Rejected(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tenant_db::open_write;
    use tempfile::TempDir;

    /// A tenant DB with one `posts(owner_id TEXT, title TEXT)` collection, plus
    /// the schema cache the query-template validator reads through.
    fn query_fixture(
        name: &str,
    ) -> (
        TempDir,
        Connection,
        crate::storage::schema_cache::SchemaCache,
    ) {
        let d = TempDir::new().unwrap();
        let conn = open_write(d.path(), name).unwrap();
        conn.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, owner_id TEXT, title TEXT);",
        )
        .unwrap();
        (d, conn, crate::storage::schema_cache::SchemaCache::new())
    }

    #[test]
    fn query_rpc_may_not_declare_a_user_id_param() {
        // #950 T4b F1. The sql arms HARD-BIND `:user_id` from the bearer token,
        // so an author reasonably assumes a `user_id` param is trustworthy. A
        // template has no such binding — the value would come straight from the
        // caller's body, so an anon-callable "my rows" template would hand any
        // caller anyone else's rows. Refused at the ONE choke point both create
        // faces share, pointing at the operand that IS bound: {"$auth":"id"}.
        let (_d, conn, cache) = query_fixture("t4b_userid");
        let tpl = crate::rpc::query_template::parse_template(
            r#"{"collection":"posts","filter":{"owner_id":{"$param":"user_id"}}}"#,
        )
        .unwrap();
        let specs = vec![ParamSpec {
            name: "user_id".into(),
            ty: crate::rpc::params::ParamType::Text,
            required: true,
            default: None,
        }];
        let PrepareError::Rejected(msg) =
            validate_new_query_rpc(&conn, &cache, &tpl, &specs).unwrap_err();
        assert!(msg.contains("$auth"), "must point at the fix: {msg}");
        assert!(msg.contains(RPC_KIND_INVALID), "typed code missing: {msg}");

        // The same template keyed on $auth — the sanctioned form — passes.
        let ok = crate::rpc::query_template::parse_template(
            r#"{"collection":"posts","filter":{"owner_id":{"$auth":"id"}}}"#,
        )
        .unwrap();
        validate_new_query_rpc(&conn, &cache, &ok, &[]).unwrap();
    }

    #[test]
    fn query_rpc_collection_must_exist_and_be_addressable() {
        let (_d, conn, cache) = query_fixture("t4b_coll");
        let missing =
            crate::rpc::query_template::parse_template(r#"{"collection":"nope"}"#).unwrap();
        let PrepareError::Rejected(msg) =
            validate_new_query_rpc(&conn, &cache, &missing, &[]).unwrap_err();
        assert!(msg.contains("COLLECTION_NOT_FOUND"), "{msg}");

        let protected =
            crate::rpc::query_template::parse_template(r#"{"collection":"_system_users"}"#)
                .unwrap();
        let PrepareError::Rejected(msg) =
            validate_new_query_rpc(&conn, &cache, &protected, &[]).unwrap_err();
        assert!(msg.contains("PROTECTED_COLLECTION"), "{msg}");
    }

    #[test]
    fn new_rpc_shape_rules() {
        use crate::rpc::registry::RpcKind;
        // Happy: each kind with its own body.
        check_new_rpc_shape(RpcKind::Sql, "SELECT 1", RpcMode::Read, false).unwrap();
        check_new_rpc_shape(RpcKind::Query, "", RpcMode::Read, true).unwrap();
        // Every violation names the wire code so a face can map it blind.
        for (kind, sql, mode, has_query) in [
            (RpcKind::Query, "", RpcMode::Read, false),
            (RpcKind::Query, "SELECT 1", RpcMode::Read, true),
            (RpcKind::Query, "", RpcMode::Write, true),
            (RpcKind::Sql, "SELECT 1", RpcMode::Read, true),
        ] {
            let PrepareError::Rejected(msg) =
                check_new_rpc_shape(kind, sql, mode, has_query).unwrap_err();
            assert!(msg.contains(RPC_KIND_INVALID), "{msg}");
        }
    }

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

    /// #950 — the three ENUMERATING sql guards skip query-kind rows explicitly.
    /// A query row has no SQL to scan; its collection lives in `query_json` and
    /// its rows are gated at RUNTIME by the same caps/owner/RLS path `/list`
    /// uses, so these config-time sql guards simply do not apply to it.
    ///
    /// The `qraw` fixture is a row that `create` would now refuse (kind=query
    /// with a non-empty `sql`); it is inserted raw on purpose, so the test
    /// proves `kind` ALONE decides — not the accident that a well-formed query
    /// row happens to have an empty `sql` column that scans to zero tables.
    #[test]
    fn enumerating_guards_skip_query_kind() {
        use crate::rpc::registry::{self, RpcCreate, RpcKind};
        let (_t, conn) = fresh();
        conn.execute_batch(
            "CREATE TABLE orders (id INTEGER PRIMARY KEY, qty INTEGER, user_id TEXT);",
        )
        .unwrap();
        crate::storage::schema::set_owner_field(&conn, "orders", Some("user_id"), Some("own"))
            .unwrap();

        // (a) a well-formed anon-callable query row over the owner-scoped collection
        registry::create(
            &conn,
            RpcCreate {
                name: "q",
                sql: "",
                params_json: "[]",
                description: None,
                anon_callable: true,
                mode: RpcMode::Read,
                kind: RpcKind::Query,
                query_json: Some(r#"{"collection":"orders"}"#),
            },
        )
        .unwrap();
        // (b) kind=query carrying sql that WOULD trip every guard if scanned
        conn.execute(
            "INSERT INTO _system_rpc (name, sql, params_json, anon_callable, kind, query_json)
             VALUES ('qraw', 'SELECT id, qty FROM orders', '[]', 1, 'query', '{}')",
            [],
        )
        .unwrap();

        guard_owner_scope_change_against_anon_rpcs(&conn, "orders", "user_id")
            .expect("owner-scope guard must skip query-kind rows");
        guard_policy_change_against_anon_rpcs(&conn, "orders")
            .expect("policy guard must skip query-kind rows");
        let flagged = scan_unsafe_anon_rpcs(&conn).unwrap();
        assert!(
            flagged.is_empty(),
            "legacy scan must not neutralize query-kind rows, got {flagged:?}"
        );
        // The per-row UPDATE guard is the fourth RPC_ANON_OWNER_SCOPED site and
        // skips query rows for the same reason — including the hostile fixture,
        // so `kind` (not an empty sql column) is what makes it pass.
        guard_anon_owner_scoped_rpc_update(&conn, "q", None, None, Some(true))
            .expect("update guard must skip query-kind rows");
        guard_anon_owner_scoped_rpc_update(&conn, "qraw", None, None, Some(true))
            .expect("update guard must decide on kind, not on the sql column");
        let still_anon: i64 = conn
            .query_row(
                "SELECT anon_callable FROM _system_rpc WHERE name = 'q'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(still_anon, 1, "query row must keep anon_callable");

        // Control arm: an equivalent SQL-KIND row is still caught by all three,
        // so the skip narrowed the guards to query rows and nothing else.
        registry::create(
            &conn,
            RpcCreate {
                name: "s",
                sql: "SELECT id, qty FROM orders",
                params_json: "[]",
                description: None,
                anon_callable: true,
                mode: RpcMode::Read,
                kind: RpcKind::Sql,
                query_json: None,
            },
        )
        .unwrap();
        assert!(guard_owner_scope_change_against_anon_rpcs(&conn, "orders", "user_id").is_err());
        assert!(guard_policy_change_against_anon_rpcs(&conn, "orders").is_err());
        assert_eq!(scan_unsafe_anon_rpcs(&conn).unwrap(), vec!["s".to_string()]);
        assert!(guard_anon_owner_scoped_rpc_update(&conn, "s", None, None, Some(true)).is_err());
    }

    /// A query row over `orders`, created through the registry so the kind
    /// contract is the one production writes.
    fn seed_query_row(conn: &Connection, name: &str, query_json: &str, anon_callable: bool) {
        use crate::rpc::registry::{self, RpcCreate, RpcKind};
        registry::create(
            conn,
            RpcCreate {
                name,
                sql: "",
                params_json: "[]",
                description: None,
                anon_callable,
                mode: RpcMode::Read,
                kind: RpcKind::Query,
                query_json: Some(query_json),
            },
        )
        .unwrap();
    }

    /// #950 T5 — the CLEAR guard. An anon-callable query RPC is a GRANT: it
    /// hands anon exactly the rows the collection's select policy / owner
    /// clause leaves visible. Clearing either therefore WIDENS the grant from
    /// "the policy's rows" to "the whole table" — silently, because no
    /// existing guard runs on a clear. So a clear is refused while such an RPC
    /// targets the collection, and the message names the two-step remedy.
    #[test]
    fn clear_guard_blocks_when_query_rpc_targets_coll() {
        let (_t, conn) = fresh();
        conn.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY, qty INTEGER);")
            .unwrap();
        seed_query_row(&conn, "q", r#"{"collection":"orders"}"#, true);

        let PrepareError::Rejected(msg) =
            guard_clear_against_anon_query_rpcs(&conn, "orders", "the select policy").unwrap_err();
        assert!(
            msg.contains(RPC_QUERY_GRANT_ACTIVE),
            "typed code missing: {msg}"
        );
        assert!(msg.contains('q'), "must name the blocking rpc: {msg}");
        assert!(
            msg.contains("the select policy"),
            "must name what is being cleared: {msg}"
        );
        assert!(
            msg.contains("anon_callable=false"),
            "must state the two-step remedy: {msg}"
        );

        // MUTATION CHECK: the guard keys on the TEMPLATE's collection. A clear
        // on a DIFFERENT collection must pass — otherwise one anon query RPC
        // would freeze config on every collection in the tenant.
        guard_clear_against_anon_query_rpcs(&conn, "posts", "owner_field")
            .expect("a clear on a collection no template targets must pass");
    }

    /// (T5b B1 DiD + B5) The select-policy transition rule, keyed on the
    /// effective USING clause rather than on the presence of a policy ROW.
    ///
    /// The middle case is the whole point and the one a row-presence key gets
    /// WRONG: a clause-less select policy (the covert-clear shape
    /// `validate_policy` now refuses to write, still reachable as a legacy
    /// row) filters NOTHING, so clearing it widens NOTHING and must not be
    /// refused — while a row-presence key would read it as "protected" and
    /// block. Getting that backwards is what let the exploit through in the
    /// first place, so it is pinned here rather than inferred.
    #[test]
    fn select_policy_clear_is_gated_on_the_effective_using_clause() {
        use crate::query::policy::Policy;
        use crate::storage::schema::{DmlVerb, write_policy};
        let (_t, conn) = fresh();
        seed_query_row(&conn, "q", r#"{"collection":"posts"}"#, true);
        let set_select = |p: Option<&Policy>| write_policy(&conn, "posts", DmlVerb::Select, p);

        // (a) No stored select policy → nothing to lose → a clear is fine even
        //     with the grant live (B5: no spurious refusal).
        guard_select_policy_clear(&conn, "posts", false)
            .expect("clearing an absent policy widens nothing");

        // (b) A clause-less stored policy → still no read filter → still fine.
        //     A ROW-presence key would wrongly refuse here.
        set_select(Some(&Policy {
            using: None,
            check: None,
        }))
        .unwrap();
        guard_select_policy_clear(&conn, "posts", false)
            .expect("a policy row that filters nothing cannot be widened away");

        // (c) A real USING → clearing it IS the widening → refused.
        set_select(Some(&Policy {
            using: Some(serde_json::from_str(r#"{"body":"x"}"#).unwrap()),
            check: None,
        }))
        .unwrap();
        let PrepareError::Rejected(msg) =
            guard_select_policy_clear(&conn, "posts", false).unwrap_err();
        assert!(msg.contains(RPC_QUERY_GRANT_ACTIVE), "{msg}");

        // (d) …but replacing it with another USING keeps a filter, so it passes.
        guard_select_policy_clear(&conn, "posts", true)
            .expect("a replacement that still filters is not a clear");
    }

    /// The three shapes that cannot grant anything and so must never block a
    /// clear: a sql-kind row (its own guards already refuse it over a
    /// row-restricted collection), a service-only query row (no anon reaches
    /// it), and a query row whose template does not parse (it cannot execute,
    /// so it grants nothing — and treating it as a blocker would make a broken
    /// row freeze the collection's config permanently).
    ///
    /// (T5b B2) Case (a) carries a STRAY non-null `query_json` — the shape
    /// `update_repairs_a_sql_row_carrying_a_stray_template` proves is
    /// reachable — so the guard's `kind` arm is the ONLY thing that lets it
    /// through. With a null `query_json` the row was short-circuited by the
    /// later `is_none()` continue instead, and deleting the `kind` arm reddened
    /// nothing: the arm was untested and the test was a false positive.
    #[test]
    fn clear_guard_ignores_rows_that_cannot_grant() {
        let (_t, conn) = fresh();
        conn.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY, qty INTEGER);")
            .unwrap();
        // (a) anon-callable SQL row over the same collection, carrying a stray
        //     template. Inserted raw — `create` refuses this shape — so `kind`
        //     alone decides. If the guard stopped checking kind, this row's
        //     template would parse and match, and the clear would be refused.
        conn.execute(
            "INSERT INTO _system_rpc (name, sql, params_json, anon_callable, kind, query_json)
             VALUES ('s', 'SELECT id, qty FROM orders', '[]', 1, 'sql',
                     '{\"collection\":\"orders\"}')",
            [],
        )
        .unwrap();
        // (b) service-only query row over the same collection
        seed_query_row(&conn, "qsvc", r#"{"collection":"orders"}"#, false);
        // (c) anon-callable query row whose template is unparsable
        seed_query_row(&conn, "qbad", "{not json", true);

        guard_clear_against_anon_query_rpcs(&conn, "orders", "the select policy")
            .expect("no row here can grant anon anything");

        // Control: add one row that CAN, and the same call now refuses — so
        // the pass above is the guard working, not the guard being inert.
        seed_query_row(&conn, "qlive", r#"{"collection":"orders"}"#, true);
        let PrepareError::Rejected(msg) =
            guard_clear_against_anon_query_rpcs(&conn, "orders", "the select policy").unwrap_err();
        assert!(msg.contains("qlive"), "{msg}");
    }
}

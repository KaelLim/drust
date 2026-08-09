use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

/// Replace the connection's authorizer with a permissive allow-all callback.
/// Called after user-SQL execution so the connection can safely be returned
/// to the pool without leaking the restrictive authorizer to subsequent
/// internal requests (schema introspection, counts, etc.).
pub fn detach_authorizer(conn: &Connection) {
    conn.authorizer(Some(|_ctx: AuthContext<'_>| -> Authorization {
        Authorization::Allow
    }))
    .expect("detach (allow-all) authorizer must install");
}

/// Attach the read-only authorizer. Every SQL action is inspected; anything
/// outside the whitelist is denied. Paired with `SQLITE_OPEN_READONLY` at
/// connection-open time for defense in depth.
pub fn attach_readonly_authorizer(conn: &Connection) {
    conn.authorizer(Some(|ctx: AuthContext<'_>| -> Authorization {
        match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. } => {
                if crate::storage::schema::is_protected_collection(table_name) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            AuthAction::Function { .. } => Authorization::Allow,
            AuthAction::Pragma { pragma_name, .. } => match pragma_name {
                "table_info" | "index_list" | "index_info" | "foreign_key_list" | "table_xinfo" => {
                    Authorization::Allow
                }
                _ => Authorization::Ignore,
            },
            AuthAction::Recursive => Authorization::Allow,
            // Everything below is denied.
            AuthAction::Attach { .. }
            | AuthAction::Detach { .. }
            | AuthAction::Insert { .. }
            | AuthAction::Update { .. }
            | AuthAction::Delete { .. }
            | AuthAction::CreateTable { .. }
            | AuthAction::CreateTempTable { .. }
            | AuthAction::CreateIndex { .. }
            | AuthAction::CreateTempIndex { .. }
            | AuthAction::CreateVtable { .. }
            | AuthAction::CreateView { .. }
            | AuthAction::CreateTempView { .. }
            | AuthAction::CreateTrigger { .. }
            | AuthAction::CreateTempTrigger { .. }
            | AuthAction::DropTable { .. }
            | AuthAction::DropTempTable { .. }
            | AuthAction::DropIndex { .. }
            | AuthAction::DropTempIndex { .. }
            | AuthAction::DropTrigger { .. }
            | AuthAction::DropTempTrigger { .. }
            | AuthAction::DropView { .. }
            | AuthAction::DropTempView { .. }
            | AuthAction::DropVtable { .. }
            | AuthAction::Transaction { .. }
            | AuthAction::Savepoint { .. }
            | AuthAction::Reindex { .. }
            | AuthAction::Analyze { .. }
            | AuthAction::AlterTable { .. } => Authorization::Deny,
            _ => Authorization::Deny,
        }
    }))
    .expect("read-only authorizer must install — fail closed rather than run user SQL unguarded");
}

/// Wave 2 M3 — the read-only authorizer PLUS the `_system_search_*`
/// allowance, for readers running **drust-BUILT** SQL.
///
/// > [!WARNING]
/// > **Attach this ONLY where drust composed the SQL text** — `/list`,
/// > `/search`, `/aggregate` and their MCP / edge mirrors, whose sole
/// > reference to a search table is the subquery a compiled `$fts` operand
/// > emits. **NEVER attach it where the CALLER controls the SQL text**
/// > (`validate_rpc_sql`, the stored-RPC executor, `/query`): those keep the
/// > strict [`attach_readonly_authorizer`], and that is what closes the leak.
///
/// Why the split is load-bearing: row authorization for search is enforced on
/// the PARENT table by the owner / RLS / caps `WHERE` clause, while the
/// shadow subquery only yields candidate rowids — harmless because drust
/// wrote the surrounding statement. A caller-authored body, by contrast, is
/// never rewritten: `rpc::prepare::referenced_user_tables` deliberately skips
/// `_system_*` tables *because `validate_rpc_sql` already denies them*, so an
/// `anon_callable` read RPC `SELECT title, body FROM "<head>"` would validate,
/// bypass the owner-scope guard, and hand every user's indexed columns to an
/// anonymous caller. Widening the shared strict arm — or attaching this one on
/// a caller-SQL site — reopens exactly that hole.
///
/// Two loosenings, both spike-proven necessary (`search_vtable_spike.rs`):
/// `Read` on the prefix (the obvious one), and Insert/Update/Delete on the
/// prefix — the R-tree module PRE-COMPILES its internal DML while PREPARING a
/// plain SELECT, so a Deny there fails the whole statement. Allowing the
/// *authorization* is safe on this connection class only: `SQLITE_OPEN_READONLY`
/// + `query_only` + DEFENSIVE make executing any write impossible.
pub fn attach_search_readonly_authorizer(conn: &Connection) {
    conn.authorizer(Some(|ctx: AuthContext<'_>| -> Authorization {
        match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if table_name.starts_with(crate::storage::search_names::SEARCH_PREFIX) =>
            {
                Authorization::Allow
            }
            AuthAction::Insert { table_name }
            | AuthAction::Update { table_name, .. }
            | AuthAction::Delete { table_name }
                if table_name.starts_with(crate::storage::search_names::SEARCH_PREFIX) =>
            {
                // rtree pre-compiles internal DML while PREPARING a plain
                // SELECT; execution stays impossible (SQLITE_OPEN_READONLY +
                // query_only + DEFENSIVE on every reader).
                Authorization::Allow
            }
            AuthAction::Read { table_name, .. } => {
                if crate::storage::schema::is_protected_collection(table_name) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            AuthAction::Function { .. } => Authorization::Allow,
            AuthAction::Pragma { pragma_name, .. } => match pragma_name {
                "table_info" | "index_list" | "index_info" | "foreign_key_list" | "table_xinfo" => {
                    Authorization::Allow
                }
                _ => Authorization::Ignore,
            },
            AuthAction::Recursive => Authorization::Allow,
            // Everything below is denied.
            AuthAction::Attach { .. }
            | AuthAction::Detach { .. }
            | AuthAction::Insert { .. }
            | AuthAction::Update { .. }
            | AuthAction::Delete { .. }
            | AuthAction::CreateTable { .. }
            | AuthAction::CreateTempTable { .. }
            | AuthAction::CreateIndex { .. }
            | AuthAction::CreateTempIndex { .. }
            | AuthAction::CreateVtable { .. }
            | AuthAction::CreateView { .. }
            | AuthAction::CreateTempView { .. }
            | AuthAction::CreateTrigger { .. }
            | AuthAction::CreateTempTrigger { .. }
            | AuthAction::DropTable { .. }
            | AuthAction::DropTempTable { .. }
            | AuthAction::DropIndex { .. }
            | AuthAction::DropTempIndex { .. }
            | AuthAction::DropTrigger { .. }
            | AuthAction::DropTempTrigger { .. }
            | AuthAction::DropView { .. }
            | AuthAction::DropTempView { .. }
            | AuthAction::DropVtable { .. }
            | AuthAction::Transaction { .. }
            | AuthAction::Savepoint { .. }
            | AuthAction::Reindex { .. }
            | AuthAction::Analyze { .. }
            | AuthAction::AlterTable { .. } => Authorization::Deny,
            _ => Authorization::Deny,
        }
    }))
    .expect(
        "search read-only authorizer must install — fail closed rather than run drust SQL unguarded",
    );
}

/// v1.30 — writable authorizer for stored RPC `mode='write'` bodies.
///
/// Mirrors [`attach_readonly_authorizer`] EXACTLY for every action except
/// Insert/Update/Delete: those are Allowed for tables that are not
/// [`crate::storage::schema::is_protected_collection`] (which covers both
/// `_system_*` and `sqlite_*`, case-insensitively).
/// Triggers, views, vtables, DDL, ATTACH, transaction control, savepoint
/// control, and pragma-writable_schema are all Denied (same as the
/// readonly variant).
///
/// Pair with a writer connection (NOT `SQLITE_OPEN_READONLY`). The caller
/// is responsible for:
///   1. Issuing `SAVEPOINT drust_rpc_v2` BEFORE calling this fn (the
///      Savepoint action would be Denied otherwise).
///   2. Calling `detach_authorizer(conn)` AFTER the RPC body and BEFORE
///      `RELEASE drust_rpc_v2` / `ROLLBACK TO drust_rpc_v2` (same reason).
///
/// Wave 2 M3 — `search` is the AUTHORITATIVE head-vs-internal classifier for
/// the `_system_search_*` namespace, snapshotted from `pragma_table_list`
/// while the connection was still unrestricted (there is deliberately no
/// `SearchTables::empty()`: an empty head-set classifies every name,
/// including heads, as *internal*, which is fail-OPEN — so a snapshot error
/// must be propagated, never substituted with a blank). Writes under the
/// prefix split three ways:
///   * vtable HEAD — allowed only when `AuthContext::accessor` names a
///     `_system_search_*` sync trigger; top-level SQL (accessor `None`)
///     cannot poison an index by hand;
///   * module INTERNALS — allowed by name, because the module writes them
///     itself with accessor `None`; DEFENSIVE (set on every writer open)
///     is what refuses direct SQL on them;
///   * anything else — the pre-existing protected-collection decision.
pub fn attach_writable_authorizer(
    conn: &Connection,
    search: &crate::storage::search_names::SearchTables,
) {
    let search = search.clone();
    conn.authorizer(Some(move |ctx: AuthContext<'_>| -> Authorization {
        match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if table_name.starts_with(crate::storage::search_names::SEARCH_PREFIX) =>
            {
                // The module reads its own shadow while servicing a vtable write.
                Authorization::Allow
            }
            AuthAction::Read { table_name, .. } => {
                if crate::storage::schema::is_protected_collection(table_name) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            AuthAction::Function { .. } => Authorization::Allow,
            AuthAction::Pragma { pragma_name, .. } => match pragma_name {
                "table_info" | "index_list" | "index_info" | "foreign_key_list" | "table_xinfo" => {
                    Authorization::Allow
                }
                _ => Authorization::Ignore,
            },
            AuthAction::Recursive => Authorization::Allow,

            // === v1.30 mutation surface, Wave 2 M3 search classifier ===
            AuthAction::Insert { table_name }
            | AuthAction::Update { table_name, .. }
            | AuthAction::Delete { table_name } => {
                if search.is_head(table_name) {
                    // vtable HEAD: only the drust sync triggers may write it.
                    // `accessor` names the innermost trigger; top-level RPC SQL
                    // is accessor None → denied (cannot poison an index by hand).
                    if ctx
                        .accessor
                        .map(|a| a.starts_with(crate::storage::search_names::SEARCH_PREFIX))
                        .unwrap_or(false)
                    {
                        Authorization::Allow
                    } else {
                        Authorization::Deny
                    }
                } else if search.is_internal(table_name) {
                    // Module internals: written by the module with accessor
                    // None, so they must be allowed by NAME; DEFENSIVE refuses
                    // direct SQL on them one layer down.
                    Authorization::Allow
                } else if crate::storage::schema::is_protected_collection(table_name) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }

            // === Everything else Denied ===
            AuthAction::Attach { .. }
            | AuthAction::Detach { .. }
            | AuthAction::CreateTable { .. }
            | AuthAction::CreateTempTable { .. }
            | AuthAction::CreateIndex { .. }
            | AuthAction::CreateTempIndex { .. }
            | AuthAction::CreateVtable { .. }
            | AuthAction::CreateView { .. }
            | AuthAction::CreateTempView { .. }
            | AuthAction::CreateTrigger { .. }
            | AuthAction::CreateTempTrigger { .. }
            | AuthAction::DropTable { .. }
            | AuthAction::DropTempTable { .. }
            | AuthAction::DropIndex { .. }
            | AuthAction::DropTempIndex { .. }
            | AuthAction::DropTrigger { .. }
            | AuthAction::DropTempTrigger { .. }
            | AuthAction::DropView { .. }
            | AuthAction::DropTempView { .. }
            | AuthAction::DropVtable { .. }
            | AuthAction::AlterTable { .. }
            | AuthAction::Reindex { .. }
            | AuthAction::Analyze { .. }
            | AuthAction::Transaction { .. }
            | AuthAction::Savepoint { .. } => Authorization::Deny,
            _ => Authorization::Deny,
        }
    }))
    .expect(
        "writable authorizer must install — fail closed rather than run RPC write body unguarded",
    );
}

#[cfg(test)]
mod auth_tests {
    use super::*;
    use crate::storage::tenant_db::open_read;
    use tempfile::TempDir;

    fn fresh_with_rpc_table() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let conn = crate::storage::tenant_db::open_write(tmp.path(), "rpcauth").unwrap();
        // _system_rpc table already created by SCHEMA_SQL; insert a row.
        conn.execute(
            "INSERT INTO _system_rpc (name, sql, params_json, created_at, updated_at)
                  VALUES ('test', 'SELECT 1', '[]', datetime('now'), datetime('now'))",
            [],
        )
        .unwrap();
        tmp
    }

    #[test]
    fn anon_cannot_select_system_rpc() {
        let tmp = fresh_with_rpc_table();
        let conn = open_read(tmp.path(), "rpcauth").unwrap();
        attach_readonly_authorizer(&conn);
        let r: rusqlite::Result<i64> =
            conn.query_row("SELECT COUNT(*) FROM _system_rpc", [], |r| r.get(0));
        assert!(r.is_err(), "expected denial, got {:?}", r);
    }

    #[test]
    fn anon_cannot_select_system_files() {
        let tmp = fresh_with_rpc_table();
        let conn = open_read(tmp.path(), "rpcauth").unwrap();
        attach_readonly_authorizer(&conn);
        let r: rusqlite::Result<i64> =
            conn.query_row("SELECT COUNT(*) FROM _system_files", [], |r| r.get(0));
        assert!(r.is_err(), "expected denial, got {:?}", r);
    }

    #[test]
    fn anon_cannot_select_system_collection_meta() {
        let tmp = fresh_with_rpc_table();
        let conn = open_read(tmp.path(), "rpcauth").unwrap();
        attach_readonly_authorizer(&conn);
        let r: rusqlite::Result<i64> =
            conn.query_row("SELECT COUNT(*) FROM _system_collection_meta", [], |r| {
                r.get(0)
            });
        assert!(r.is_err(), "expected denial, got {:?}", r);
    }
}

/// Wave 2 M3 — the `_system_search_*` arms, and the boundary that keeps them
/// from becoming an anon leak.
#[cfg(test)]
mod search_arm_tests {
    use super::*;
    use crate::storage::search_names::{fts_head_name, fts_trigger_names, snapshot_search_tables};
    use crate::storage::tenant_db::{open_read, open_write};
    use tempfile::TempDir;

    const TENANT: &str = "searcharm";

    fn head() -> String {
        fts_head_name("notes", "main")
    }

    /// `notes` + an external-content fts5 head + the three sync triggers,
    /// all under the production `$`-delimited naming grammar.
    fn fts_fixture() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), TENANT).unwrap();
        let h = head();
        let [ai, ad, au] = fts_trigger_names("notes", "main");
        conn.execute_batch(&format!(
            r#"CREATE TABLE "notes" (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 title TEXT,
                 body TEXT,
                 created_at TEXT NOT NULL DEFAULT (datetime('now')),
                 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
               ) STRICT;
               CREATE TABLE "plain" (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 title TEXT
               ) STRICT;
               CREATE VIRTUAL TABLE "{h}"
                 USING fts5(title, body, content='notes', content_rowid='id');
               CREATE TRIGGER "{ai}" AFTER INSERT ON "notes" BEGIN
                 INSERT INTO "{h}"(rowid, title, body) VALUES (new.id, new.title, new.body);
               END;
               CREATE TRIGGER "{ad}" AFTER DELETE ON "notes" BEGIN
                 INSERT INTO "{h}"("{h}", rowid, title, body)
                   VALUES ('delete', old.id, old.title, old.body);
               END;
               CREATE TRIGGER "{au}" AFTER UPDATE ON "notes" BEGIN
                 INSERT INTO "{h}"("{h}", rowid, title, body)
                   VALUES ('delete', old.id, old.title, old.body);
                 INSERT INTO "{h}"(rowid, title, body) VALUES (new.id, new.title, new.body);
               END;
               INSERT INTO "notes"(title, body) VALUES ('alpha report', 'quarterly numbers');
               INSERT INTO "notes"(title, body) VALUES ('beta memo', 'lunch schedule');"#
        ))
        .expect("fts fixture DDL + seed");
        tmp
    }

    /// The shape a compiled `$fts` operand produces: candidate rowids from the
    /// shadow, row authorization applied on the PARENT by the outer WHERE.
    fn fts_query() -> String {
        let h = head();
        format!(
            r#"SELECT id FROM "notes" WHERE id IN (SELECT rowid FROM "{h}" WHERE "{h}" MATCH ?)"#
        )
    }

    #[test]
    fn search_reader_admits_the_fts_shape_and_the_strict_reader_denies_it() {
        let tmp = fts_fixture();
        let conn = open_read(tmp.path(), TENANT).unwrap();
        let q = fts_query();

        attach_readonly_authorizer(&conn);
        let strict: rusqlite::Result<i64> = conn.query_row(&q, ["alpha"], |r| r.get(0));
        detach_authorizer(&conn);
        assert!(
            strict.is_err(),
            "the STRICT reader must keep denying a _system_search_* read (it is the arm \
             caller-authored SQL runs under), got {strict:?}"
        );

        attach_search_readonly_authorizer(&conn);
        let hit: i64 = conn
            .query_row(&q, ["alpha"], |r| r.get(0))
            .expect("the search reader must admit the compiled $fts shape end to end");
        detach_authorizer(&conn);
        assert_eq!(hit, 1);
    }

    #[test]
    fn search_reader_admits_rank_ordering_through_the_module_internals() {
        let tmp = fts_fixture();
        let conn = open_read(tmp.path(), TENANT).unwrap();
        attach_search_readonly_authorizer(&conn);
        let h = head();
        let ranked: Vec<i64> = conn
            .prepare(&format!(
                r#"SELECT rowid FROM "{h}" WHERE "{h}" MATCH ? ORDER BY rank"#
            ))
            .expect("prepare with rank must pass the search reader")
            .query_map(["report OR memo"], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .expect("stepping must survive fts5's internal shadow reads");
        detach_authorizer(&conn);
        assert_eq!(ranked.len(), 2, "both seeded rows should match: {ranked:?}");
    }

    #[test]
    fn search_reader_does_not_widen_anything_else() {
        let tmp = fts_fixture();
        let conn = open_read(tmp.path(), TENANT).unwrap();
        attach_search_readonly_authorizer(&conn);

        let attach = conn.execute_batch("ATTACH DATABASE ':memory:' AS side");
        assert!(attach.is_err(), "ATTACH must stay denied, got {attach:?}");

        let master: rusqlite::Result<i64> =
            conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0));
        assert!(
            master.is_err(),
            "sqlite_master must stay denied, got {master:?}"
        );

        let rpc: rusqlite::Result<i64> =
            conn.query_row("SELECT COUNT(*) FROM _system_rpc", [], |r| r.get(0));
        assert!(
            rpc.is_err(),
            "a NON-search _system_* table must stay denied — the widening is \
             `_system_search_*`, not `_system_*`; got {rpc:?}"
        );

        let ins = conn.execute(r#"INSERT INTO "notes"(title, body) VALUES ('x','y')"#, []);
        assert!(
            ins.is_err(),
            "writes on a non-search table must stay denied, got {ins:?}"
        );

        // The search arms ALLOW write ACTIONS on `_system_search_*` at the
        // authorizer (rtree pre-compiles internal DML while preparing a plain
        // SELECT). What actually stops execution is the layer below.
        let h = head();
        let sw = conn.execute_batch(&format!(
            r#"INSERT INTO "{h}"(rowid, title, body) VALUES (99, 'evil', 'evil')"#
        ));
        let msg = format!("{:?}", sw.as_ref().unwrap_err());
        assert!(
            msg.contains("readonly") || msg.contains("ReadOnly"),
            "head write on the reader must be stopped by SQLITE_OPEN_READONLY, got {msg}"
        );
        let siw = conn.execute_batch(&format!(
            r#"INSERT INTO "{h}_config"(k, v) VALUES ('evil', 1)"#
        ));
        let msg = format!("{:?}", siw.as_ref().unwrap_err());
        assert!(
            msg.contains("may not be modified")
                || msg.contains("readonly")
                || msg.contains("ReadOnly"),
            "internal-shadow write on the reader must be stopped below the authorizer, got {msg}"
        );
        detach_authorizer(&conn);
    }

    #[test]
    fn writable_arm_syncs_via_triggers_but_refuses_hand_written_shadow_dml() {
        let tmp = fts_fixture();
        let conn = open_write(tmp.path(), TENANT).unwrap();
        let search = snapshot_search_tables(&conn).unwrap();
        let h = head();

        conn.execute_batch("SAVEPOINT drust_rpc_v2").unwrap();
        attach_writable_authorizer(&conn, &search);

        // 1. The parent write is admitted; the sync triggers may write the head.
        conn.execute(
            r#"INSERT INTO "notes"(title, body) VALUES ('zeta note', 'from rpc')"#,
            [],
        )
        .expect("parent INSERT on an fts-indexed collection must pass the writable arm");
        // Control: a collection with no fts triggers still writes fine.
        conn.execute(r#"INSERT INTO "plain"(title) VALUES ('fine')"#, [])
            .expect("control INSERT must pass");

        // 2. Top-level (accessor-less) DML on the HEAD is denied.
        let direct = conn.execute(
            &format!(r#"INSERT INTO "{h}"(rowid, title, body) VALUES (99, 'evil', 'evil')"#),
            [],
        );
        assert!(
            direct.is_err(),
            "hand-written head DML must be denied by the accessor scope, got {direct:?}"
        );

        // 3. Module internals are allowed BY NAME at the authorizer; DEFENSIVE
        //    (set on every writer open) is what refuses the direct SQL.
        let internal = conn.execute_batch(&format!(
            r#"INSERT INTO "{h}_config"(k, v) VALUES ('evil', 1)"#
        ));
        assert!(
            internal.is_err(),
            "DEFENSIVE must refuse direct DML on a module internal, got {internal:?}"
        );

        // 4. Non-search protected tables stay denied.
        let sysw = conn.prepare("UPDATE _system_files SET visibility = 'public'");
        assert!(
            sysw.is_err(),
            "a non-search _system_* write must stay denied, got {sysw:?}"
        );

        detach_authorizer(&conn);
        conn.execute_batch("RELEASE drust_rpc_v2").unwrap();

        let hit: i64 = conn
            .query_row(&fts_query(), ["zeta"], |r| r.get(0))
            .expect("the trigger-driven sync really happened");
        let expected: i64 = conn
            .query_row(
                r#"SELECT id FROM "notes" WHERE title = 'zeta note'"#,
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hit, expected);
    }

    /// THE leak regression. `referenced_user_tables` deliberately skips
    /// `_system_*` "already denied by validate_rpc_sql"; if the STRICT reader
    /// ever admitted `_system_search_*`, an `anon_callable` read RPC
    /// `SELECT title, body FROM "<head>"` would validate, dodge the
    /// owner-scope guard entirely, and hand every user's indexed columns to an
    /// anonymous caller. Validation must keep rejecting it at prepare.
    #[test]
    fn a_read_rpc_body_over_a_search_head_is_rejected_at_validation() {
        use crate::rpc::prepare::validate_rpc_sql;
        use crate::rpc::registry::RpcMode;

        let tmp = fts_fixture();
        let conn = open_write(tmp.path(), TENANT).unwrap();
        let h = head();

        for sql in [
            format!(r#"SELECT * FROM "{h}""#),
            format!(r#"SELECT title, body FROM "{h}""#),
            format!(r#"SELECT rowid FROM "{h}" WHERE "{h}" MATCH 'alpha'"#),
            format!(r#"SELECT k, v FROM "{h}_config""#),
        ] {
            let err = validate_rpc_sql(&conn, &sql, RpcMode::Read).expect_err(&format!(
                "a read RPC must NOT be allowed to name a search shadow: {sql}"
            ));
            let msg = format!("{err}");
            // SQLITE_AUTH surfaces as "access to <t>.<c> is prohibited" for a
            // denied Read and "not authorized" for a denied statement; accept
            // either, but insist it is an AUTHORIZER refusal and not, say, a
            // "no such table" that would evaporate the moment the head exists.
            assert!(
                msg.contains("is prohibited") || msg.contains("not authorized"),
                "expected an authorizer denial for {sql}, got {msg}"
            );
        }

        // Control: the same validation still accepts an ordinary user table,
        // so the rejections above are the search gate and not a blanket no.
        validate_rpc_sql(&conn, r#"SELECT id, title FROM "notes""#, RpcMode::Read)
            .expect("an ordinary read RPC must still validate");
    }

    /// The write branch of validation runs the CLASSIFIER writable arm, so it
    /// must also refuse a hand-written shadow write while still accepting a
    /// plain write over an fts-indexed collection.
    #[test]
    fn a_write_rpc_body_may_touch_the_parent_but_not_the_shadow() {
        use crate::rpc::prepare::validate_rpc_sql;
        use crate::rpc::registry::RpcMode;

        let tmp = fts_fixture();
        let conn = open_write(tmp.path(), TENANT).unwrap();
        let h = head();

        validate_rpc_sql(
            &conn,
            r#"UPDATE "notes" SET title = 'x' WHERE id = 1"#,
            RpcMode::Write,
        )
        .expect("a write RPC over an fts-indexed parent must validate");

        for sql in [
            format!(r#"INSERT INTO "{h}"(rowid, title, body) VALUES (1, 'a', 'b')"#),
            format!(r#"DELETE FROM "{h}_data""#),
        ] {
            validate_rpc_sql(&conn, &sql, RpcMode::Write).expect_err(&format!(
                "a write RPC must not hand-write a search table: {sql}"
            ));
        }
    }
}

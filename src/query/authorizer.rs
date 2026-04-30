use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

/// Replace the connection's authorizer with a permissive allow-all callback.
/// Called after user-SQL execution so the connection can safely be returned
/// to the pool without leaking the restrictive authorizer to subsequent
/// internal requests (schema introspection, counts, etc.).
pub fn detach_authorizer(conn: &Connection) {
    conn.authorizer(Some(|_ctx: AuthContext<'_>| -> Authorization {
        Authorization::Allow
    }));
}

/// Attach the read-only authorizer. Every SQL action is inspected; anything
/// outside the whitelist is denied. Paired with `SQLITE_OPEN_READONLY` at
/// connection-open time for defense in depth.
pub fn attach_readonly_authorizer(conn: &Connection) {
    conn.authorizer(Some(|ctx: AuthContext<'_>| -> Authorization {
        match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. } => {
                if table_name.starts_with("sqlite_")
                    || crate::storage::schema::is_protected_collection(table_name)
                {
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
    }));
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
        ).unwrap();
        tmp
    }

    #[test]
    fn anon_cannot_select_system_rpc() {
        let tmp = fresh_with_rpc_table();
        let conn = open_read(tmp.path(), "rpcauth").unwrap();
        attach_readonly_authorizer(&conn);
        let r: rusqlite::Result<i64> = conn.query_row(
            "SELECT COUNT(*) FROM _system_rpc",
            [],
            |r| r.get(0),
        );
        assert!(r.is_err(), "expected denial, got {:?}", r);
    }

    #[test]
    fn anon_cannot_select_system_files() {
        let tmp = fresh_with_rpc_table();
        let conn = open_read(tmp.path(), "rpcauth").unwrap();
        attach_readonly_authorizer(&conn);
        let r: rusqlite::Result<i64> = conn.query_row(
            "SELECT COUNT(*) FROM _system_files",
            [],
            |r| r.get(0),
        );
        assert!(r.is_err(), "expected denial, got {:?}", r);
    }

    #[test]
    fn anon_cannot_select_system_collection_meta() {
        let tmp = fresh_with_rpc_table();
        let conn = open_read(tmp.path(), "rpcauth").unwrap();
        attach_readonly_authorizer(&conn);
        let r: rusqlite::Result<i64> = conn.query_row(
            "SELECT COUNT(*) FROM _system_collection_meta",
            [],
            |r| r.get(0),
        );
        assert!(r.is_err(), "expected denial, got {:?}", r);
    }
}

use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

/// Attach the read-only authorizer. Every SQL action is inspected; anything
/// outside the whitelist is denied. Paired with `SQLITE_OPEN_READONLY` at
/// connection-open time for defense in depth.
pub fn attach_readonly_authorizer(conn: &Connection) {
    conn.authorizer(Some(|ctx: AuthContext<'_>| -> Authorization {
        match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. } => {
                if table_name.starts_with("sqlite_") {
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

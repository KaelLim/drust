use drust::storage::tenant_db::{open_write, open_write_existing};
use tempfile::TempDir;

/// Wave 2 spike contract: the writable authorizer's by-name internal-shadow
/// allowance is only safe because DEFENSIVE refuses direct DML on module
/// shadow tables. That guard must hold on EVERY writer open.
#[test]
fn every_writer_open_carries_defensive() {
    let tmp = TempDir::new().unwrap();
    for opener in [open_write, open_write_existing] {
        let conn = opener(tmp.path(), "defw").unwrap();
        conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS "notes" (id INTEGER PRIMARY KEY AUTOINCREMENT, t TEXT);
               CREATE VIRTUAL TABLE IF NOT EXISTS "_system_search_fts$notes$m"
                 USING fts5(t, content='notes', content_rowid='id');"#,
        )
        .unwrap();
        // Module writes (vtable API) keep working…
        conn.execute_batch(
            r#"INSERT INTO "notes"(t) VALUES ('x');
               INSERT INTO "_system_search_fts$notes$m"(rowid, t) VALUES (1, 'x');"#,
        )
        .expect("vtable-API writes must survive DEFENSIVE");
        // …direct DML on a module internal is refused.
        let direct = conn.execute_batch(
            r#"INSERT INTO "_system_search_fts$notes$m_config"(k, v) VALUES ('evil', 1)"#,
        );
        let msg = format!("{:?}", direct.unwrap_err());
        assert!(msg.contains("may not be modified"), "got {msg}");
    }
}

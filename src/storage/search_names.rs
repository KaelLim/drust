//! Naming grammar + authoritative classification for the `_system_search_*`
//! namespace (Wave 2 spike contract, spec §7 結果).
//!
//! Two rules, both spike-derived:
//! 1. Components are joined with `$`, which `identifier()`'s `[a-z0-9_]`
//!    grammar can never emit — so `<coll>` / `<index>` boundaries never alias.
//! 2. Head-vs-internal is decided by `pragma_table_list.type`
//!    ('virtual' = vtable head, 'shadow' = module internal), never by name.
use std::collections::HashSet;

pub const SEARCH_PREFIX: &str = "_system_search_";
const RESERVED_SUFFIXES: [&str; 5] = ["_data", "_idx", "_docsize", "_config", "_content"];

pub fn fts_head_name(coll: &str, index: &str) -> String {
    format!("_system_search_fts${coll}${index}")
}

pub fn fts_trigger_names(coll: &str, index: &str) -> [String; 3] {
    let h = fts_head_name(coll, index);
    [format!("{h}_ai"), format!("{h}_ad"), format!("{h}_au")]
}

pub fn validate_fts_index_name(name: &str) -> anyhow::Result<()> {
    crate::mcp::tools::schema::identifier(name)?;
    if RESERVED_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        anyhow::bail!(
            "FTS_NAME_RESERVED: index name must not end in a module shadow suffix ({})",
            RESERVED_SUFFIXES.join(", ")
        );
    }
    Ok(())
}

/// Snapshot of which `_system_search_*` tables are vtable HEADS. Everything
/// else under the prefix is a module internal. Must be taken while the
/// connection is unrestricted (BEFORE any authorizer is attached — same
/// discipline as `record_history::audited_data_tables`). There is
/// deliberately NO `empty()` / `Default`: an empty head-set is fail-OPEN
/// (every name, heads included, would classify internal), so callers must
/// propagate a snapshot error, never substitute a blank.
#[derive(Clone)]
pub struct SearchTables {
    heads: HashSet<String>,
}

pub fn snapshot_search_tables(conn: &rusqlite::Connection) -> rusqlite::Result<SearchTables> {
    let mut stmt = conn.prepare(
        "SELECT name FROM pragma_table_list \
         WHERE name LIKE '\\_system\\_search\\_%' ESCAPE '\\' AND type = 'virtual'",
    )?;
    let heads = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<HashSet<_>, _>>()?;
    Ok(SearchTables { heads })
}

impl SearchTables {
    pub fn is_head(&self, table: &str) -> bool {
        self.heads.contains(table)
    }
    pub fn is_internal(&self, table: &str) -> bool {
        table.starts_with(SEARCH_PREFIX) && !self.heads.contains(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tenant_db::open_write;
    use tempfile::TempDir;

    #[test]
    fn head_and_trigger_names_use_dollar_delimiter() {
        assert_eq!(
            fts_head_name("notes", "main"),
            "_system_search_fts$notes$main"
        );
        let [ai, ad, au] = fts_trigger_names("notes", "main");
        assert_eq!(ai, "_system_search_fts$notes$main_ai");
        assert_eq!(ad, "_system_search_fts$notes$main_ad");
        assert_eq!(au, "_system_search_fts$notes$main_au");
    }

    #[test]
    fn reserved_suffixes_are_rejected() {
        for bad in ["main_data", "x_idx", "a_docsize", "b_config", "c_content"] {
            let e = validate_fts_index_name(bad).unwrap_err().to_string();
            assert!(e.contains("FTS_NAME_RESERVED"), "{bad}: {e}");
        }
        validate_fts_index_name("main").unwrap();
        validate_fts_index_name("body_search").unwrap();
    }

    /// pragma_table_list reports fts5 heads as 'virtual' and module internals
    /// as 'shadow'. We create ONE head (index 'main') and check that its own
    /// module internals classify as internal, the head as head, and
    /// non-search tables as neither. (We do NOT create a second head named
    /// like an internal — SQLite reserves `<vtab>_data` for the first index's
    /// shadow and physically refuses the collision, which is itself a defense.)
    #[test]
    fn snapshot_classifies_by_table_list_type_not_name() {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), "names").unwrap();
        conn.execute_batch(
            r#"CREATE TABLE "notes" (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);
               CREATE VIRTUAL TABLE "_system_search_fts$notes$main"
                 USING fts5(title, content='notes', content_rowid='id');"#,
        )
        .unwrap();
        let s = snapshot_search_tables(&conn).unwrap();
        assert!(s.is_head("_system_search_fts$notes$main"));
        assert!(s.is_internal("_system_search_fts$notes$main_docsize"));
        assert!(s.is_internal("_system_search_fts$notes$main_data"));
        assert!(!s.is_head("_system_search_fts$notes$main_docsize"));
        assert!(!s.is_head("notes") && !s.is_internal("notes"));
    }
}

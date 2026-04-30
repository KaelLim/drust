use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// System-managed collections are drop-protected. Any name starting with
/// `_system_` (note the trailing underscore) is refused by schema-mutating
/// tools. `_system` alone is not protected — the prefix is strict.
pub fn is_protected_collection(name: &str) -> bool {
    name.starts_with("_system_")
}

#[cfg(test)]
mod protection_tests {
    use super::*;

    #[test]
    fn system_prefix_is_protected() {
        assert!(is_protected_collection("_system_public_files"));
        assert!(is_protected_collection("_system_anything_else"));
    }

    #[test]
    fn normal_names_are_unprotected() {
        assert!(!is_protected_collection("users"));
        assert!(!is_protected_collection("_system")); // exact, not prefix
        assert!(!is_protected_collection("system_logs"));
        assert!(!is_protected_collection("__private"));
    }
}

/// DML verbs used by the per-collection capability allowlist.
/// Ordering is fixed (Select, Insert, Update, Delete) so serialised
/// output is deterministic.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DmlVerb {
    Select,
    Insert,
    Update,
    Delete,
}

impl DmlVerb {
    pub fn as_str(self) -> &'static str {
        match self {
            DmlVerb::Select => "select",
            DmlVerb::Insert => "insert",
            DmlVerb::Update => "update",
            DmlVerb::Delete => "delete",
        }
    }
}

/// Default capability set — anon may SELECT only. Used when a row is
/// missing from `_system_collection_meta` (e.g. legacy collections
/// pre-dating this feature).
pub fn default_anon_caps() -> BTreeSet<DmlVerb> {
    let mut s = BTreeSet::new();
    s.insert(DmlVerb::Select);
    s
}

/// Parse a JSON array of lowercase verb strings into a `BTreeSet`.
///
/// **Behaviour:** decode is all-or-nothing — any unknown verb (e.g.
/// `["select","yolo"]`) collapses the entire result to an empty set.
/// This is a defensive default for stored JSON read out of the
/// `_system_collection_meta` table.
///
/// For input received from a user (admin form, MCP tool), validate
/// strictly first by deserialising into `Vec<DmlVerb>` directly and
/// surfacing the serde error before encoding back via
/// `anon_caps_to_json`.
pub fn parse_anon_caps_json(raw: &str) -> BTreeSet<DmlVerb> {
    serde_json::from_str::<Vec<DmlVerb>>(raw)
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Serialise a capability set as a sorted JSON array (deterministic).
pub fn anon_caps_to_json(caps: &BTreeSet<DmlVerb>) -> String {
    let v: Vec<&str> = caps.iter().map(|c| c.as_str()).collect();
    serde_json::to_string(&v).expect("BTreeSet<DmlVerb> serialises")
}

#[cfg(test)]
mod anon_caps_tests {
    use super::*;

    #[test]
    fn default_caps_is_select_only() {
        let d = default_anon_caps();
        assert_eq!(d.len(), 1);
        assert!(d.contains(&DmlVerb::Select));
    }

    #[test]
    fn json_roundtrip_preserves_order() {
        let caps: BTreeSet<DmlVerb> =
            [DmlVerb::Delete, DmlVerb::Select, DmlVerb::Insert].into_iter().collect();
        let json = anon_caps_to_json(&caps);
        assert_eq!(json, r#"["select","insert","delete"]"#);
        let parsed = parse_anon_caps_json(&json);
        assert_eq!(parsed, caps);
    }

    #[test]
    fn empty_array_means_locked() {
        let parsed = parse_anon_caps_json("[]");
        assert!(parsed.is_empty());
    }

    #[test]
    fn malformed_json_falls_back_to_empty() {
        let parsed = parse_anon_caps_json("not json");
        assert!(parsed.is_empty());
    }

    #[test]
    fn unknown_verb_collapses_decode_to_empty() {
        let parsed = parse_anon_caps_json(r#"["select","yolo","delete"]"#);
        // serde drops the whole vec on the unknown variant unless we use
        // a tolerant decoder. For now we accept "all-or-nothing" decode.
        // The test pins this behaviour explicitly.
        assert!(parsed.is_empty());
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Collection {
    pub name: String,
    pub row_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub name: String,
    pub sql_type: String,
    pub nullable: bool,
    pub pk: bool,
    pub default_value: Option<String>,
    /// Name of the referenced collection if this field is a foreign key;
    /// `None` otherwise. Sourced from `PRAGMA foreign_key_list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexInfo {
    pub name: String,
    pub fields: Vec<String>,
    pub unique: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectionSchema {
    pub name: String,
    pub fields: Vec<Field>,
    pub indices: Vec<IndexInfo>,
    pub row_count: i64,
    /// Per-collection DML allowlist for the anon role. Service is
    /// always unrestricted regardless of this set. Default is
    /// `[Select]` for backwards compatibility with collections that
    /// pre-date the capability feature.
    pub anon_caps: BTreeSet<DmlVerb>,
}

fn user_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master
         WHERE type='table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    stmt.query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()
}

fn row_count(conn: &Connection, table: &str) -> rusqlite::Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM \"{}\"", table.replace('"', "\"\""));
    conn.query_row(&sql, [], |r| r.get(0))
}

pub fn list_collections(conn: &Connection) -> rusqlite::Result<Vec<Collection>> {
    let names = user_tables(conn)?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        if is_protected_collection(&name) {
            continue;
        }
        let count = row_count(conn, &name)?;
        out.push(Collection {
            name,
            row_count: count,
        });
    }
    Ok(out)
}

pub fn describe_collection(
    conn: &Connection,
    name: &str,
) -> rusqlite::Result<Option<CollectionSchema>> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?1",
        rusqlite::params![name],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(None);
    }

    // Map of field_name -> referenced_table, pulled from
    // foreign_key_list before we build the Field structs so each field
    // can carry its FK target.
    let fk_map: std::collections::HashMap<String, String> = conn
        .prepare(&format!(
            "PRAGMA foreign_key_list(\"{}\")",
            name.replace('"', "\"\"")
        ))?
        .query_map([], |r| {
            // columns: id, seq, table, from, to, on_update, on_delete, match
            Ok((r.get::<_, String>(3)?, r.get::<_, String>(2)?))
        })?
        .collect::<Result<std::collections::HashMap<_, _>, _>>()?;

    let fields = conn
        .prepare(&format!(
            "PRAGMA table_info(\"{}\")",
            name.replace('"', "\"\"")
        ))?
        .query_map([], |r| {
            let nullable_int: i64 = r.get(3)?;
            let pk_int: i64 = r.get(5)?;
            let field_name: String = r.get(1)?;
            let fk = fk_map.get(&field_name).cloned();
            Ok(Field {
                name: field_name,
                sql_type: r.get::<_, String>(2)?,
                nullable: nullable_int == 0,
                pk: pk_int > 0,
                default_value: r.get::<_, Option<String>>(4)?,
                foreign_key: fk,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut indices = Vec::new();
    let idx_rows: Vec<(String, bool)> = conn
        .prepare(&format!(
            "PRAGMA index_list(\"{}\")",
            name.replace('"', "\"\"")
        ))?
        .query_map([], |r| {
            let unique_int: i64 = r.get(2)?;
            Ok((r.get::<_, String>(1)?, unique_int == 1))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (iname, unique) in idx_rows {
        if iname.starts_with("sqlite_autoindex") {
            continue;
        }
        let fields: Vec<String> = conn
            .prepare(&format!(
                "PRAGMA index_info(\"{}\")",
                iname.replace('"', "\"\"")
            ))?
            .query_map([], |r| r.get::<_, String>(2))?
            .collect::<Result<Vec<_>, _>>()?;
        indices.push(IndexInfo {
            name: iname,
            fields,
            unique,
        });
    }

    let rc = row_count(conn, name)?;
    Ok(Some(CollectionSchema {
        name: name.to_string(),
        fields,
        indices,
        row_count: rc,
        anon_caps: default_anon_caps(),  // populated for real in Task 4
    }))
}

pub fn collection_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    let c: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?1",
        rusqlite::params![name],
        |r| r.get(0),
    )?;
    Ok(c > 0)
}

/// Find every other user-table that has a foreign-key column pointing at
/// `target`. Returns `(referring_table, referring_field)` pairs. Used by
/// `drop_collection` to reject drops that would orphan an FK.
pub fn find_fk_referrers(
    conn: &Connection,
    target: &str,
) -> rusqlite::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for t in user_tables(conn)? {
        if t == target {
            continue;
        }
        let mut stmt = conn.prepare(&format!(
            "PRAGMA foreign_key_list(\"{}\")",
            t.replace('"', "\"\"")
        ))?;
        let rows = stmt.query_map([], |r| {
            // columns: id, seq, table, from, to, on_update, on_delete, match
            Ok((r.get::<_, String>(2)?, r.get::<_, String>(3)?))
        })?;
        for row in rows {
            let (ref_table, from_col) = row?;
            if ref_table == target {
                out.push((t.clone(), from_col));
            }
        }
    }
    Ok(out)
}

use crate::query::policy::{CollectionPolicies, Policy};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, schemars::JsonSchema,
)]
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

/// Maximum byte length for any description string. Applies uniformly to
/// collection / field / index descriptions. RPC descriptions are not
/// validated through this path (they flow through the existing
/// `update_rpc` MCP arg shape).
pub const MAX_DESCRIPTION_BYTES: usize = 2048;

/// Pure validator for a description string. Returns the trimmed value
/// on success. Empty input yields `Ok("")` — callers interpret as
/// "clear". Mirrors the shape of `webhook_routes::check_url`:
///   - `(code, message)` pair so callers (REST + MCP + admin UI) can
///     map to their preferred error shape.
///   - All branches are pure; no I/O.
pub fn check_description(raw: &str) -> Result<String, (&'static str, &'static str)> {
    let trimmed = raw.trim();
    if trimmed.len() > MAX_DESCRIPTION_BYTES {
        return Err((
            "DESCRIPTION_TOO_LONG",
            "description exceeds 2048-byte limit",
        ));
    }
    if trimmed.contains('\0') {
        return Err(("DESCRIPTION_INVALID", "description must not contain NUL"));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod description_validator_tests {
    use super::*;

    #[test]
    fn empty_input_is_ok_with_empty_output() {
        assert_eq!(check_description("").unwrap(), "");
        assert_eq!(check_description("   ").unwrap(), "");
        assert_eq!(check_description("\n\t").unwrap(), "");
    }

    #[test]
    fn whitespace_is_trimmed() {
        assert_eq!(check_description("  hello  ").unwrap(), "hello");
    }

    #[test]
    fn exactly_max_length_is_ok() {
        let s = "a".repeat(MAX_DESCRIPTION_BYTES);
        assert!(check_description(&s).is_ok());
    }

    #[test]
    fn one_over_max_length_is_rejected() {
        let s = "a".repeat(MAX_DESCRIPTION_BYTES + 1);
        let err = check_description(&s).unwrap_err();
        assert_eq!(err.0, "DESCRIPTION_TOO_LONG");
    }

    #[test]
    fn nul_byte_is_rejected() {
        let err = check_description("hello\0world").unwrap_err();
        assert_eq!(err.0, "DESCRIPTION_INVALID");
    }

    #[test]
    fn unicode_within_limit_is_ok() {
        let s = "你好，世界 🌏 markdown-ish summary line";
        let got = check_description(s).unwrap();
        assert_eq!(got, s);
    }
}

#[cfg(test)]
mod description_read_tests {
    use super::*;
    use rusqlite::Connection;

    /// Build an in-memory DB with a minimal `_system_collection_meta` table
    /// and one row for `posts` whose `field_descriptions_json` is the
    /// supplied raw JSON. Returns the open connection.
    fn meta_with_field_descs(raw: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE _system_collection_meta ( \
                collection_name        TEXT PRIMARY KEY, \
                anon_caps_json         TEXT NOT NULL DEFAULT '[\"select\"]', \
                field_descriptions_json TEXT NOT NULL DEFAULT '{}', \
                index_descriptions_json TEXT NOT NULL DEFAULT '{}', \
                updated_at             TEXT NOT NULL DEFAULT '' \
            );",
        )
        .unwrap();
        c.execute(
            "INSERT INTO _system_collection_meta \
                  (collection_name, anon_caps_json, field_descriptions_json) \
                  VALUES ('posts', '[\"select\"]', ?1)",
            rusqlite::params![raw],
        )
        .unwrap();
        c
    }

    #[test]
    fn mixed_value_types_partial_decode() {
        // One good string value, one numeric. Partial decode keeps the
        // good one, drops the bad one (vs. the old behaviour of dropping
        // everything).
        let c = meta_with_field_descs(r#"{"good_field": "kept", "bad_field": 42}"#);
        let m = read_field_descriptions(&c, "posts").unwrap();
        assert_eq!(m.get("good_field"), Some(&"kept".to_string()));
        assert!(!m.contains_key("bad_field"));
    }

    #[test]
    fn malformed_outer_json_falls_back_to_empty() {
        let c = meta_with_field_descs("not json at all");
        let m = read_field_descriptions(&c, "posts").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn empty_blob_yields_empty_map() {
        let c = meta_with_field_descs("{}");
        let m = read_field_descriptions(&c, "posts").unwrap();
        assert!(m.is_empty());
    }
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
        let caps: BTreeSet<DmlVerb> = [DmlVerb::Delete, DmlVerb::Select, DmlVerb::Insert]
            .into_iter()
            .collect();
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
    /// Collection-level free-form description (v1.19). Optional;
    /// rendered identically when absent (`skip_serializing_if`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
    /// Per-field description (v1.19). Sourced from
    /// `_system_collection_meta.field_descriptions_json[name]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexInfo {
    pub name: String,
    pub fields: Vec<String>,
    pub unique: bool,
    /// Per-index description (v1.19). Sourced from
    /// `_system_collection_meta.index_descriptions_json[name]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorField {
    pub name: String,
    pub dim: u32,
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
    /// Column used for row-level ownership. None = non-owner-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_field: Option<String>,
    /// Either "own" or "all" (T1 vocabulary). Only meaningful when
    /// `owner_field` is `Some`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_scope: Option<String>,
    /// Vector fields registered on this collection. Empty for
    /// non-vector collections. Sourced from
    /// `_system_collection_meta.vector_fields_json`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub vector_fields: Vec<VectorField>,
    /// Whether SSE realtime broadcast is enabled for this collection.
    /// Defaults to `true` for legacy collections (no meta row) and for
    /// rows present before v1.16 (column default 1). New collections
    /// created from v1.16+ start at `false` via `create_collection`.
    pub realtime_enabled: bool,
    /// Collection-level free-form description (v1.19).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Per-operation row-level security policies (v1.38). All-`None` for
    /// collections with no explicit policy (the common case).
    #[serde(skip_serializing_if = "CollectionPolicies::is_empty", default)]
    pub policies: CollectionPolicies,
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
        let description = read_collection_description(conn, &name)?;
        out.push(Collection {
            name,
            row_count: count,
            description,
        });
    }
    Ok(out)
}

/// Read the anon_caps for a single collection from
/// `_system_collection_meta`. Missing rows yield `default_anon_caps()`
/// (i.e. legacy collections pre-dating the feature behave the same as
/// status quo).
fn read_anon_caps(conn: &Connection, coll: &str) -> rusqlite::Result<BTreeSet<DmlVerb>> {
    let row: Option<String> = conn
        .query_row(
            "SELECT anon_caps_json FROM _system_collection_meta WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| r.get::<_, String>(0),
        )
        .ok();
    Ok(row
        .map(|j| parse_anon_caps_json(&j))
        .unwrap_or_else(default_anon_caps))
}

/// Read the realtime flag for a single collection. Missing rows yield
/// `true` (matches `read_anon_caps`'s default-allow fallback so legacy
/// collections pre-dating v1.16 keep their existing SSE behaviour).
fn read_realtime_enabled(conn: &Connection, coll: &str) -> rusqlite::Result<bool> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT realtime_enabled FROM _system_collection_meta WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| r.get::<_, i64>(0),
        )
        .ok();
    Ok(row.map(|n| n != 0).unwrap_or(true))
}

/// Read the collection-level description for `coll`. Returns `None` if
/// the meta row is absent or the column is NULL.
pub fn read_collection_description(
    conn: &Connection,
    coll: &str,
) -> rusqlite::Result<Option<String>> {
    match conn.query_row(
        "SELECT description FROM _system_collection_meta WHERE collection_name = ?1",
        rusqlite::params![coll],
        |r| r.get::<_, Option<String>>(0),
    ) {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read the per-field description map for `coll`. Missing meta row →
/// empty map. Malformed JSON → empty map (defensive; never panics).
pub fn read_field_descriptions(
    conn: &Connection,
    coll: &str,
) -> rusqlite::Result<BTreeMap<String, String>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT field_descriptions_json FROM _system_collection_meta
                  WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| r.get(0),
        )
        .ok();
    // v1.19.1: forgiving parse — decode into BTreeMap<String, Value> and
    // keep only entries whose value is a string. A single bad value no
    // longer wipes the whole map.
    let parsed: BTreeMap<String, serde_json::Value> = raw
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    Ok(parsed
        .into_iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
        .collect())
}

/// Read the per-index description map. Same semantics as
/// `read_field_descriptions`.
pub fn read_index_descriptions(
    conn: &Connection,
    coll: &str,
) -> rusqlite::Result<BTreeMap<String, String>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT index_descriptions_json FROM _system_collection_meta
                  WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| r.get(0),
        )
        .ok();
    // v1.19.1: forgiving parse — see read_field_descriptions for rationale.
    let parsed: BTreeMap<String, serde_json::Value> = raw
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    Ok(parsed
        .into_iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
        .collect())
}

/// Set / clear the collection-level description. `None` or `Some("")`
/// clears (column → NULL). Upserts the meta row if absent, defaulting
/// `anon_caps_json = '["select"]'` (mirrors other upsert helpers).
/// Caller must hold the writer mutex.
pub fn write_collection_description(
    conn: &Connection,
    coll: &str,
    description: Option<&str>,
) -> rusqlite::Result<()> {
    debug_assert!(
        description.map_or(true, |d| check_description(d).is_ok()),
        "write_collection_description called with unvalidated description; \
         callers must run check_description first"
    );
    let value: Option<&str> = description.filter(|s| !s.is_empty());
    conn.execute(
        "INSERT INTO _system_collection_meta \
              (collection_name, anon_caps_json, description, updated_at) \
              VALUES (?1, '[\"select\"]', ?2, datetime('now')) \
         ON CONFLICT(collection_name) DO UPDATE SET \
              description = excluded.description, \
              updated_at  = excluded.updated_at",
        rusqlite::params![coll, value],
    )?;
    Ok(())
}

/// Set / clear a per-field description. Read-modify-write on the JSON
/// blob (caller holds writer mutex so no concurrent racers). `None` or
/// empty removes the key.
pub fn write_field_description(
    conn: &Connection,
    coll: &str,
    field: &str,
    description: Option<&str>,
) -> rusqlite::Result<()> {
    debug_assert!(
        description.map_or(true, |d| check_description(d).is_ok()),
        "write_field_description called with unvalidated description; \
         callers must run check_description first"
    );
    let mut map = read_field_descriptions(conn, coll)?;
    match description.filter(|s| !s.is_empty()) {
        Some(text) => {
            map.insert(field.to_string(), text.to_string());
        }
        None => {
            map.remove(field);
        }
    }
    let json = serde_json::to_string(&map).expect("BTreeMap<String,String> always serialises");
    conn.execute(
        "INSERT INTO _system_collection_meta \
              (collection_name, anon_caps_json, field_descriptions_json, updated_at) \
              VALUES (?1, '[\"select\"]', ?2, datetime('now')) \
         ON CONFLICT(collection_name) DO UPDATE SET \
              field_descriptions_json = excluded.field_descriptions_json, \
              updated_at              = excluded.updated_at",
        rusqlite::params![coll, json],
    )?;
    Ok(())
}

/// Set / clear a per-index description. Same shape as
/// `write_field_description` but writes to `index_descriptions_json`.
pub fn write_index_description(
    conn: &Connection,
    coll: &str,
    index_name: &str,
    description: Option<&str>,
) -> rusqlite::Result<()> {
    debug_assert!(
        description.map_or(true, |d| check_description(d).is_ok()),
        "write_index_description called with unvalidated description; \
         callers must run check_description first"
    );
    let mut map = read_index_descriptions(conn, coll)?;
    match description.filter(|s| !s.is_empty()) {
        Some(text) => {
            map.insert(index_name.to_string(), text.to_string());
        }
        None => {
            map.remove(index_name);
        }
    }
    let json = serde_json::to_string(&map).expect("BTreeMap<String,String> always serialises");
    conn.execute(
        "INSERT INTO _system_collection_meta \
              (collection_name, anon_caps_json, index_descriptions_json, updated_at) \
              VALUES (?1, '[\"select\"]', ?2, datetime('now')) \
         ON CONFLICT(collection_name) DO UPDATE SET \
              index_descriptions_json = excluded.index_descriptions_json, \
              updated_at              = excluded.updated_at",
        rusqlite::params![coll, json],
    )?;
    Ok(())
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

    let field_descs = read_field_descriptions(conn, name)?;
    let mut fields = conn
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
                description: None,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for f in &mut fields {
        f.description = field_descs.get(&f.name).cloned();
    }

    let index_descs = read_index_descriptions(conn, name)?;
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
        let idx_fields: Vec<String> = conn
            .prepare(&format!(
                "PRAGMA index_info(\"{}\")",
                iname.replace('"', "\"\"")
            ))?
            .query_map([], |r| r.get::<_, String>(2))?
            .collect::<Result<Vec<_>, _>>()?;
        let idx_desc = index_descs.get(&iname).cloned();
        indices.push(IndexInfo {
            name: iname,
            fields: idx_fields,
            unique,
            description: idx_desc,
        });
    }

    let rc = row_count(conn, name)?;
    let anon_caps = read_anon_caps(conn, name)?;
    let (owner_field, read_scope) = read_owner_field(conn, name)?;
    let vector_fields = read_vector_fields(conn, name)?;
    let realtime_enabled = read_realtime_enabled(conn, name)?;
    let description = read_collection_description(conn, name)?;
    let policies = read_policies(conn, name)?;
    Ok(Some(CollectionSchema {
        name: name.to_string(),
        fields,
        indices,
        row_count: rc,
        anon_caps,
        owner_field,
        read_scope,
        vector_fields,
        realtime_enabled,
        description,
        policies,
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

/// Insert / replace the anon_caps row for a collection. Caller must
/// hold the writer mutex. Used by create_collection (default caps)
/// and the admin UI's anon-caps editor.
pub fn write_anon_caps(
    conn: &Connection,
    coll: &str,
    caps: &BTreeSet<DmlVerb>,
) -> rusqlite::Result<()> {
    let json = anon_caps_to_json(caps);
    conn.execute(
        "INSERT INTO _system_collection_meta (collection_name, anon_caps_json, updated_at)
              VALUES (?1, ?2, datetime('now'))
         ON CONFLICT(collection_name) DO UPDATE SET
              anon_caps_json = excluded.anon_caps_json,
              updated_at     = excluded.updated_at",
        rusqlite::params![coll, json],
    )?;
    Ok(())
}

/// Upsert the realtime flag. Mirrors `write_anon_caps`'s upsert shape so
/// legacy collections without a meta row get one created with default
/// `anon_caps = [select]` (never silently dropping the write).
pub fn write_realtime_enabled(
    conn: &Connection,
    coll: &str,
    enabled: bool,
) -> rusqlite::Result<()> {
    let v: i64 = if enabled { 1 } else { 0 };
    conn.execute(
        "INSERT INTO _system_collection_meta \
              (collection_name, anon_caps_json, realtime_enabled, updated_at) \
              VALUES (?1, '[\"select\"]', ?2, datetime('now')) \
         ON CONFLICT(collection_name) DO UPDATE SET \
              realtime_enabled = excluded.realtime_enabled, \
              updated_at       = excluded.updated_at",
        rusqlite::params![coll, v],
    )?;
    Ok(())
}

/// Set or clear `owner_field` + `read_scope` for a collection. Pass `None`
/// for both to unset (revert to non-owner-scoped behavior). Upserts: if no
/// meta row exists yet (legacy collections pre-v1.6), one is created with
/// default `anon_caps_json = '["select"]'` so the setter is never a silent
/// no-op.
pub fn set_owner_field(
    conn: &Connection,
    collection: &str,
    field: Option<&str>,
    read_scope: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO _system_collection_meta \
              (collection_name, anon_caps_json, owner_field, read_scope, updated_at) \
              VALUES (?1, '[\"select\"]', ?2, ?3, datetime('now')) \
         ON CONFLICT(collection_name) DO UPDATE SET \
              owner_field = excluded.owner_field, \
              read_scope  = excluded.read_scope, \
              updated_at  = excluded.updated_at",
        rusqlite::params![collection, field, read_scope],
    )?;
    Ok(())
}

/// Read the current `(owner_field, read_scope)` pair. Returns `(None, None)`
/// for collections with no meta row at all (legacy collections pre-v1.6).
pub fn read_owner_field(
    conn: &Connection,
    collection: &str,
) -> rusqlite::Result<(Option<String>, Option<String>)> {
    match conn.query_row(
        "SELECT owner_field, read_scope FROM _system_collection_meta \
         WHERE collection_name = ?1",
        rusqlite::params![collection],
        |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
            ))
        },
    ) {
        Ok(t) => Ok(t),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok((None, None)),
        Err(e) => Err(e),
    }
}

/// Read the four per-op policies for a collection. Missing meta row → all
/// `None`. A NULL or malformed column → `None` for that op (forgiving parse,
/// matching `read_field_descriptions`).
pub fn read_policies(conn: &Connection, coll: &str) -> rusqlite::Result<CollectionPolicies> {
    let row: Option<(
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = conn
        .query_row(
            "SELECT select_policy_json, insert_policy_json, update_policy_json, delete_policy_json \
             FROM _system_collection_meta WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok();
    let parse = |o: Option<String>| -> Option<Policy> {
        o.as_deref()
            .and_then(|j| serde_json::from_str::<Policy>(j).ok())
    };
    let (s, i, u, d) = row.unwrap_or((None, None, None, None));
    Ok(CollectionPolicies {
        select: parse(s),
        insert: parse(i),
        update: parse(u),
        delete: parse(d),
    })
}

/// Upsert (or clear) one op's policy. `None` clears the column to NULL.
/// Upserts the meta row if absent (default anon_caps), mirroring
/// `set_owner_field`. Caller holds the writer mutex.
pub fn write_policy(
    conn: &Connection,
    coll: &str,
    op: DmlVerb,
    policy: Option<&Policy>,
) -> rusqlite::Result<()> {
    let col = match op {
        DmlVerb::Select => "select_policy_json",
        DmlVerb::Insert => "insert_policy_json",
        DmlVerb::Update => "update_policy_json",
        DmlVerb::Delete => "delete_policy_json",
    };
    let json: Option<String> = match policy {
        Some(p) => Some(serde_json::to_string(p).expect("Policy serialises")),
        None => None,
    };
    // Column name is from a fixed match (not user input) → safe to format.
    let sql = format!(
        "INSERT INTO _system_collection_meta (collection_name, anon_caps_json, {col}, updated_at) \
              VALUES (?1, '[\"select\"]', ?2, datetime('now')) \
         ON CONFLICT(collection_name) DO UPDATE SET \
              {col} = excluded.{col}, updated_at = excluded.updated_at"
    );
    conn.execute(&sql, rusqlite::params![coll, json])?;
    Ok(())
}

/// True if the tenant has adopted row-level rules on ANY collection
/// (`owner_field` set or any explicit policy column populated). Used to
/// gate anon `/query` / `/query/explain` / legacy `?filter` — surfaces drust
/// cannot row-filter (raw un-rewritable SQL). Returns `Err` only on a real
/// DB failure; an absent `_system_collection_meta` table or no rows → `false`.
/// The caller fails closed (treats `Err` as protected).
pub fn tenant_has_protected_collection(conn: &Connection) -> rusqlite::Result<bool> {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _system_collection_meta WHERE \
                 owner_field IS NOT NULL \
              OR select_policy_json IS NOT NULL OR insert_policy_json IS NOT NULL \
              OR update_policy_json IS NOT NULL OR delete_policy_json IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(n > 0)
}

/// Write the full set of vector fields for a collection. Caller holds
/// the writer mutex. Overwrites whatever was there. Upserts so legacy
/// collections (pre-v1.10) get a meta row on first vector add.
pub fn write_vector_fields(
    conn: &Connection,
    coll: &str,
    fields: &[VectorField],
) -> rusqlite::Result<()> {
    let json = serde_json::to_string(fields).expect("VectorField slice serialises");
    conn.execute(
        "INSERT INTO _system_collection_meta \
              (collection_name, anon_caps_json, vector_fields_json, updated_at) \
              VALUES (?1, '[\"select\"]', ?2, datetime('now')) \
         ON CONFLICT(collection_name) DO UPDATE SET \
              vector_fields_json = excluded.vector_fields_json, \
              updated_at         = excluded.updated_at",
        rusqlite::params![coll, json],
    )?;
    Ok(())
}

/// Read the vector fields registered against a collection. Returns an
/// empty Vec when the meta row is absent (legacy / non-vector
/// collections).
pub fn read_vector_fields(conn: &Connection, coll: &str) -> rusqlite::Result<Vec<VectorField>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT vector_fields_json FROM _system_collection_meta \
             WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| r.get::<_, String>(0),
        )
        .ok();
    let raw = match raw {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };
    Ok(serde_json::from_str::<Vec<VectorField>>(&raw).unwrap_or_default())
}

/// Drop the metadata row for a collection. Called from drop_collection.
/// Idempotent — missing row is fine.
pub fn delete_collection_meta(conn: &Connection, coll: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM _system_collection_meta WHERE collection_name = ?1",
        rusqlite::params![coll],
    )?;
    Ok(())
}

#[cfg(test)]
mod meta_io_tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, Connection) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("t.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE _system_collection_meta (
                collection_name    TEXT PRIMARY KEY,
                anon_caps_json     TEXT NOT NULL,
                updated_at         TEXT NOT NULL DEFAULT (datetime('now')),
                owner_field        TEXT,
                read_scope         TEXT,
                realtime_enabled   INTEGER NOT NULL DEFAULT 1,
                select_policy_json TEXT,
                insert_policy_json TEXT,
                update_policy_json TEXT,
                delete_policy_json TEXT
            );",
        )
        .unwrap();
        (tmp, conn)
    }

    #[test]
    fn read_returns_default_when_no_row() {
        let (_t, conn) = fresh();
        let caps = read_anon_caps(&conn, "posts").unwrap();
        assert_eq!(caps, default_anon_caps());
    }

    #[test]
    fn write_then_read_roundtrips() {
        let (_t, conn) = fresh();
        let mut caps = BTreeSet::new();
        caps.insert(DmlVerb::Select);
        caps.insert(DmlVerb::Insert);
        write_anon_caps(&conn, "posts", &caps).unwrap();
        let got = read_anon_caps(&conn, "posts").unwrap();
        assert_eq!(got, caps);
    }

    #[test]
    fn write_overwrites_existing() {
        let (_t, conn) = fresh();
        let only_select: BTreeSet<DmlVerb> = [DmlVerb::Select].into_iter().collect();
        let crud: BTreeSet<DmlVerb> = [
            DmlVerb::Select,
            DmlVerb::Insert,
            DmlVerb::Update,
            DmlVerb::Delete,
        ]
        .into_iter()
        .collect();
        write_anon_caps(&conn, "posts", &only_select).unwrap();
        write_anon_caps(&conn, "posts", &crud).unwrap();
        assert_eq!(read_anon_caps(&conn, "posts").unwrap(), crud);
    }

    #[test]
    fn delete_removes_row() {
        let (_t, conn) = fresh();
        let caps: BTreeSet<DmlVerb> = [DmlVerb::Select, DmlVerb::Insert].into_iter().collect();
        write_anon_caps(&conn, "posts", &caps).unwrap();
        delete_collection_meta(&conn, "posts").unwrap();
        assert_eq!(read_anon_caps(&conn, "posts").unwrap(), default_anon_caps());
    }

    #[test]
    fn delete_missing_row_is_noop() {
        let (_t, conn) = fresh();
        delete_collection_meta(&conn, "nonexistent").unwrap();
    }

    #[test]
    fn policy_write_then_read_roundtrips() {
        let (_t, conn) = fresh();
        use crate::query::policy::Policy;
        use crate::query::vector_filter::FilterAst;
        let p = Policy {
            using: Some(serde_json::from_str::<FilterAst>(r#"{"status":"published"}"#).unwrap()),
            check: None,
        };
        write_policy(&conn, "posts", DmlVerb::Select, Some(&p)).unwrap();
        let got = read_policies(&conn, "posts").unwrap();
        assert!(got.select.is_some(), "select policy should be present");
        assert!(got.insert.is_none());
        // Clear it.
        write_policy(&conn, "posts", DmlVerb::Select, None).unwrap();
        assert!(read_policies(&conn, "posts").unwrap().select.is_none());
    }

    #[test]
    fn tenant_protected_flips_with_owner_field() {
        let (_t, conn) = fresh();
        // No owner_field, no policy → not protected.
        assert!(!tenant_has_protected_collection(&conn).unwrap());
        set_owner_field(&conn, "posts", Some("u"), Some("own")).unwrap();
        assert!(tenant_has_protected_collection(&conn).unwrap());
    }

    #[test]
    fn tenant_protected_flips_with_policy() {
        let (_t, conn) = fresh();
        use crate::query::policy::Policy;
        use crate::query::vector_filter::FilterAst;
        assert!(!tenant_has_protected_collection(&conn).unwrap());
        let p = Policy {
            using: Some(serde_json::from_str::<FilterAst>(r#"{"status":"published"}"#).unwrap()),
            check: None,
        };
        write_policy(&conn, "posts", DmlVerb::Select, Some(&p)).unwrap();
        assert!(tenant_has_protected_collection(&conn).unwrap());
        // Clearing the only policy makes it unprotected again.
        write_policy(&conn, "posts", DmlVerb::Select, None).unwrap();
        assert!(!tenant_has_protected_collection(&conn).unwrap());
    }

    #[test]
    fn vector_fields_roundtrip_through_meta() {
        let (_t, conn) = fresh();
        conn.execute_batch(
            "ALTER TABLE _system_collection_meta \
             ADD COLUMN vector_fields_json TEXT NOT NULL DEFAULT '[]'",
        )
        .unwrap();
        let fields = vec![
            VectorField {
                name: "title_emb".into(),
                dim: 384,
            },
            VectorField {
                name: "body_emb".into(),
                dim: 768,
            },
        ];
        write_vector_fields(&conn, "posts", &fields).unwrap();
        let got = read_vector_fields(&conn, "posts").unwrap();
        assert_eq!(got, fields);
    }

    #[test]
    fn read_vector_fields_missing_row_yields_empty() {
        let (_t, conn) = fresh();
        conn.execute_batch(
            "ALTER TABLE _system_collection_meta \
             ADD COLUMN vector_fields_json TEXT NOT NULL DEFAULT '[]'",
        )
        .unwrap();
        let got = read_vector_fields(&conn, "absent").unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn set_owner_field_upserts_when_row_absent() {
        // Legacy collection: meta row never created yet. Upsert path must
        // create the row instead of silently dropping the write.
        let (_t, conn) = fresh();
        set_owner_field(&conn, "legacy", Some("user_id"), Some("own")).unwrap();
        let (f, s) = read_owner_field(&conn, "legacy").unwrap();
        assert_eq!(f.as_deref(), Some("user_id"));
        assert_eq!(s.as_deref(), Some("own"));
        // The implicit row keeps default anon_caps so the collection is
        // not inadvertently locked down.
        assert_eq!(
            read_anon_caps(&conn, "legacy").unwrap(),
            default_anon_caps()
        );
    }

    #[test]
    fn read_realtime_enabled_defaults_true_when_no_row() {
        let (_t, conn) = fresh();
        assert!(read_realtime_enabled(&conn, "posts").unwrap());
    }

    #[test]
    fn write_realtime_then_read_roundtrips_both_values() {
        let (_t, conn) = fresh();
        write_realtime_enabled(&conn, "posts", false).unwrap();
        assert!(!read_realtime_enabled(&conn, "posts").unwrap());
        write_realtime_enabled(&conn, "posts", true).unwrap();
        assert!(read_realtime_enabled(&conn, "posts").unwrap());
    }

    #[test]
    fn write_realtime_preserves_existing_anon_caps() {
        // Legacy collection: anon_caps row exists, realtime upsert must not
        // wipe anon_caps_json. This is the same upsert-preserves-other-cols
        // invariant tested for owner_field.
        let (_t, conn) = fresh();
        let mut caps = BTreeSet::new();
        caps.insert(DmlVerb::Insert);
        caps.insert(DmlVerb::Update);
        write_anon_caps(&conn, "posts", &caps).unwrap();
        write_realtime_enabled(&conn, "posts", false).unwrap();
        assert_eq!(read_anon_caps(&conn, "posts").unwrap(), caps);
        assert!(!read_realtime_enabled(&conn, "posts").unwrap());
    }

    #[test]
    fn collection_description_roundtrip() {
        let (_t, conn) = fresh();
        conn.execute_batch(
            "ALTER TABLE _system_collection_meta ADD COLUMN description TEXT;
             ALTER TABLE _system_collection_meta ADD COLUMN field_descriptions_json TEXT NOT NULL DEFAULT '{}';
             ALTER TABLE _system_collection_meta ADD COLUMN index_descriptions_json TEXT NOT NULL DEFAULT '{}';",
        ).unwrap();

        assert_eq!(read_collection_description(&conn, "posts").unwrap(), None);
        write_collection_description(&conn, "posts", Some("My posts")).unwrap();
        assert_eq!(
            read_collection_description(&conn, "posts").unwrap(),
            Some("My posts".to_string())
        );
        write_collection_description(&conn, "posts", None).unwrap();
        assert_eq!(read_collection_description(&conn, "posts").unwrap(), None);
        write_collection_description(&conn, "posts", Some("again")).unwrap();
        write_collection_description(&conn, "posts", Some("")).unwrap();
        assert_eq!(read_collection_description(&conn, "posts").unwrap(), None);
    }

    #[test]
    fn field_descriptions_roundtrip() {
        let (_t, conn) = fresh();
        conn.execute_batch(
            "ALTER TABLE _system_collection_meta ADD COLUMN description TEXT;
             ALTER TABLE _system_collection_meta ADD COLUMN field_descriptions_json TEXT NOT NULL DEFAULT '{}';
             ALTER TABLE _system_collection_meta ADD COLUMN index_descriptions_json TEXT NOT NULL DEFAULT '{}';",
        ).unwrap();

        assert!(read_field_descriptions(&conn, "posts").unwrap().is_empty());
        write_field_description(&conn, "posts", "title", Some("post title")).unwrap();
        write_field_description(&conn, "posts", "body", Some("markdown body")).unwrap();
        let m = read_field_descriptions(&conn, "posts").unwrap();
        assert_eq!(m.get("title").map(|s| s.as_str()), Some("post title"));
        assert_eq!(m.get("body").map(|s| s.as_str()), Some("markdown body"));

        write_field_description(&conn, "posts", "title", None).unwrap();
        let m = read_field_descriptions(&conn, "posts").unwrap();
        assert!(!m.contains_key("title"));
        assert!(m.contains_key("body"));

        write_field_description(&conn, "posts", "body", Some("")).unwrap();
        let m = read_field_descriptions(&conn, "posts").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn index_descriptions_roundtrip() {
        let (_t, conn) = fresh();
        conn.execute_batch(
            "ALTER TABLE _system_collection_meta ADD COLUMN description TEXT;
             ALTER TABLE _system_collection_meta ADD COLUMN field_descriptions_json TEXT NOT NULL DEFAULT '{}';
             ALTER TABLE _system_collection_meta ADD COLUMN index_descriptions_json TEXT NOT NULL DEFAULT '{}';",
        ).unwrap();

        assert!(read_index_descriptions(&conn, "posts").unwrap().is_empty());
        write_index_description(
            &conn,
            "posts",
            "idx_posts_author",
            Some("fast lookup by author"),
        )
        .unwrap();
        let m = read_index_descriptions(&conn, "posts").unwrap();
        assert_eq!(
            m.get("idx_posts_author").map(|s| s.as_str()),
            Some("fast lookup by author")
        );
        write_index_description(&conn, "posts", "idx_posts_author", None).unwrap();
        assert!(read_index_descriptions(&conn, "posts").unwrap().is_empty());
    }

    #[test]
    fn malformed_json_blob_reads_as_empty() {
        let (_t, conn) = fresh();
        conn.execute_batch(
            "ALTER TABLE _system_collection_meta ADD COLUMN description TEXT;
             ALTER TABLE _system_collection_meta ADD COLUMN field_descriptions_json TEXT NOT NULL DEFAULT '{}';
             ALTER TABLE _system_collection_meta ADD COLUMN index_descriptions_json TEXT NOT NULL DEFAULT '{}';",
        ).unwrap();
        conn.execute(
            "INSERT INTO _system_collection_meta \
                  (collection_name, anon_caps_json, field_descriptions_json, updated_at) \
                  VALUES ('rotten', '[\"select\"]', 'not json', datetime('now'))",
            [],
        )
        .unwrap();
        let m = read_field_descriptions(&conn, "rotten").unwrap();
        assert!(
            m.is_empty(),
            "malformed JSON must yield empty map (defensive)"
        );
    }
}

/// Returns true if the caller's role is permitted to perform `verb` on
/// the given collection. Service is unrestricted. User is unrestricted ONLY
/// on owner-scoped collections (where the row-level filter limits visibility
/// per row); on non-owner-scoped collections, User falls through to anon_caps
/// — registering users does not grant broader collection access than what
/// the tenant explicitly opened for anon. Anon is always checked against
/// anon_caps. Missing schema (cache miss + DB error) yields `false` — fail
/// closed.
///
/// Note: anon-on-owner-scoped (ANON_FORBIDDEN_OWNER_SCOPED for both
/// reads under read_scope=own and writes) is enforced at the handler
/// level *before* this gate.
pub fn has_dml_cap(
    role: crate::tenant::router::TokenRole,
    verb: DmlVerb,
    schema: &CollectionSchema,
) -> bool {
    match role {
        crate::tenant::router::TokenRole::Service => true,
        crate::tenant::router::TokenRole::User => {
            // Owner-scoped: filter handles row access, cap is open.
            // Non-owner-scoped: inherit anon_caps (no escalation).
            schema.owner_field.is_some() || schema.anon_caps.contains(&verb)
        }
        crate::tenant::router::TokenRole::Anon => schema.anon_caps.contains(&verb),
    }
}

#[cfg(test)]
mod cap_gate_tests {
    use super::*;
    use crate::tenant::router::TokenRole;

    fn schema_with(caps: &[DmlVerb]) -> CollectionSchema {
        CollectionSchema {
            name: "x".into(),
            fields: vec![],
            indices: vec![],
            row_count: 0,
            anon_caps: caps.iter().copied().collect(),
            owner_field: None,
            read_scope: None,
            vector_fields: vec![],
            realtime_enabled: true,
            description: None,
            policies: Default::default(),
        }
    }

    #[test]
    fn service_is_unrestricted() {
        let s = schema_with(&[]);
        for verb in [
            DmlVerb::Select,
            DmlVerb::Insert,
            DmlVerb::Update,
            DmlVerb::Delete,
        ] {
            assert!(has_dml_cap(TokenRole::Service, verb, &s));
        }
    }

    #[test]
    fn anon_default_select_only() {
        let s = schema_with(&[DmlVerb::Select]);
        assert!(has_dml_cap(TokenRole::Anon, DmlVerb::Select, &s));
        assert!(!has_dml_cap(TokenRole::Anon, DmlVerb::Insert, &s));
        assert!(!has_dml_cap(TokenRole::Anon, DmlVerb::Update, &s));
        assert!(!has_dml_cap(TokenRole::Anon, DmlVerb::Delete, &s));
    }

    #[test]
    fn anon_locked_collection_denies_all() {
        let s = schema_with(&[]);
        for verb in [
            DmlVerb::Select,
            DmlVerb::Insert,
            DmlVerb::Update,
            DmlVerb::Delete,
        ] {
            assert!(!has_dml_cap(TokenRole::Anon, verb, &s));
        }
    }

    #[test]
    fn anon_full_crud_collection() {
        let s = schema_with(&[
            DmlVerb::Select,
            DmlVerb::Insert,
            DmlVerb::Update,
            DmlVerb::Delete,
        ]);
        for verb in [
            DmlVerb::Select,
            DmlVerb::Insert,
            DmlVerb::Update,
            DmlVerb::Delete,
        ] {
            assert!(has_dml_cap(TokenRole::Anon, verb, &s));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_field_round_trips_through_meta() {
        use rusqlite::Connection;
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE _system_collection_meta ( \
                collection_name TEXT PRIMARY KEY, \
                anon_caps_json TEXT NOT NULL DEFAULT '[\"select\"]', \
                owner_field TEXT, read_scope TEXT, \
                updated_at TEXT NOT NULL DEFAULT '');",
        )
        .unwrap();
        c.execute(
            "INSERT INTO _system_collection_meta (collection_name, anon_caps_json, updated_at) \
             VALUES ('posts', '[\"select\"]', '2026')",
            [],
        )
        .unwrap();

        set_owner_field(&c, "posts", Some("user_id"), Some("own")).unwrap();
        let (f, s) = read_owner_field(&c, "posts").unwrap();
        assert_eq!(f.as_deref(), Some("user_id"));
        assert_eq!(s.as_deref(), Some("own"));

        set_owner_field(&c, "posts", None, None).unwrap();
        let (f, s) = read_owner_field(&c, "posts").unwrap();
        assert_eq!(f, None);
        assert_eq!(s, None);
    }

    #[test]
    fn read_owner_field_missing_row_yields_none() {
        use rusqlite::Connection;
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE _system_collection_meta ( \
                collection_name TEXT PRIMARY KEY, \
                anon_caps_json TEXT, owner_field TEXT, read_scope TEXT, updated_at TEXT);",
        )
        .unwrap();
        let (f, s) = read_owner_field(&c, "absent").unwrap();
        assert_eq!(f, None);
        assert_eq!(s, None);
    }
}

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

/// Read the anon_caps for a single collection from
/// `_system_collection_meta`. Missing rows yield `default_anon_caps()`
/// (i.e. legacy collections pre-dating the feature behave the same as
/// status quo).
fn read_anon_caps(
    conn: &Connection,
    coll: &str,
) -> rusqlite::Result<BTreeSet<DmlVerb>> {
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
    let anon_caps = read_anon_caps(conn, name)?;
    let (owner_field, read_scope) = read_owner_field(conn, name)?;
    let vector_fields = read_vector_fields(conn, name)?;
    Ok(Some(CollectionSchema {
        name: name.to_string(),
        fields,
        indices,
        row_count: rc,
        anon_caps,
        owner_field,
        read_scope,
        vector_fields,
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
        |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?)),
    ) {
        Ok(t) => Ok(t),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok((None, None)),
        Err(e) => Err(e),
    }
}

/// Write the full set of vector fields for a collection. Caller holds
/// the writer mutex. Overwrites whatever was there. Upserts so legacy
/// collections (pre-v1.10) get a meta row on first vector add.
pub fn write_vector_fields(
    conn: &Connection,
    coll: &str,
    fields: &[VectorField],
) -> rusqlite::Result<()> {
    let json = serde_json::to_string(fields)
        .expect("VectorField slice serialises");
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
pub fn read_vector_fields(
    conn: &Connection,
    coll: &str,
) -> rusqlite::Result<Vec<VectorField>> {
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
pub fn delete_collection_meta(
    conn: &Connection,
    coll: &str,
) -> rusqlite::Result<()> {
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
                collection_name TEXT PRIMARY KEY,
                anon_caps_json  TEXT NOT NULL,
                updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
                owner_field     TEXT,
                read_scope      TEXT
            );",
        ).unwrap();
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
        let crud: BTreeSet<DmlVerb> = [DmlVerb::Select, DmlVerb::Insert,
                                       DmlVerb::Update, DmlVerb::Delete].into_iter().collect();
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
    fn vector_fields_roundtrip_through_meta() {
        let (_t, conn) = fresh();
        conn.execute_batch(
            "ALTER TABLE _system_collection_meta \
             ADD COLUMN vector_fields_json TEXT NOT NULL DEFAULT '[]'",
        )
        .unwrap();
        let fields = vec![
            VectorField { name: "title_emb".into(), dim: 384 },
            VectorField { name: "body_emb".into(),  dim: 768 },
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
        assert_eq!(read_anon_caps(&conn, "legacy").unwrap(), default_anon_caps());
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
        }
    }

    #[test]
    fn service_is_unrestricted() {
        let s = schema_with(&[]);
        for verb in [DmlVerb::Select, DmlVerb::Insert, DmlVerb::Update, DmlVerb::Delete] {
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
        for verb in [DmlVerb::Select, DmlVerb::Insert, DmlVerb::Update, DmlVerb::Delete] {
            assert!(!has_dml_cap(TokenRole::Anon, verb, &s));
        }
    }

    #[test]
    fn anon_full_crud_collection() {
        let s = schema_with(&[DmlVerb::Select, DmlVerb::Insert, DmlVerb::Update, DmlVerb::Delete]);
        for verb in [DmlVerb::Select, DmlVerb::Insert, DmlVerb::Update, DmlVerb::Delete] {
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
                updated_at TEXT NOT NULL DEFAULT '');"
        ).unwrap();
        c.execute(
            "INSERT INTO _system_collection_meta (collection_name, anon_caps_json, updated_at) \
             VALUES ('posts', '[\"select\"]', '2026')",
            [],
        ).unwrap();

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
                anon_caps_json TEXT, owner_field TEXT, read_scope TEXT, updated_at TEXT);"
        ).unwrap();
        let (f, s) = read_owner_field(&c, "absent").unwrap();
        assert_eq!(f, None);
        assert_eq!(s, None);
    }
}

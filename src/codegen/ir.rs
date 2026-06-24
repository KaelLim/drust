//! v1.27 — Neutral intermediate representation. Same shape for OpenAPI,
//! TypeScript, and Zod renderers. `include_descriptions` is honored by
//! `build_ir` so anon callers see empty Option<String> on description
//! fields without the renderer having to know about auth.

use crate::storage::pool::SharedTenantPool;
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct CodegenIr {
    pub tenant_id: String,
    /// Public base URL, e.g. "https://drust.example.com/drust".
    /// Used in OpenAPI servers list and TS client function URLs.
    pub base_url: String,
    pub include_descriptions: bool,
    pub collections: Vec<CollectionIr>,
}

#[derive(Serialize, Debug)]
pub struct CollectionIr {
    pub name: String,
    pub description: Option<String>,
    pub fields: Vec<FieldIr>,
    pub indexes: Vec<IndexIr>,
    pub owner_field: Option<String>,
    pub realtime_enabled: bool,
    /// True iff this collection has at least one vector field.
    /// Renderers use this to decide whether to emit a /search path.
    pub has_vector: bool,
}

#[derive(Serialize, Debug)]
pub struct FieldIr {
    pub name: String,
    pub ty: FieldType,
    pub nullable: bool,
    pub default: Option<DefaultValue>,
    /// Referenced collection name when this field is a foreign key.
    pub fk: Option<String>,
    pub description: Option<String>,
    /// True for the implicit id / created_at / updated_at columns
    /// drust manages — renderers skip them in Insert/Update shapes.
    pub server_managed: bool,
    /// v1.43 — structured CHECK constraints (min/max/enum/max_length),
    /// reflected by each renderer (zod `.min/.max/z.enum`, OpenAPI
    /// `minimum/maximum/maxLength/enum`, TS union + JSDoc).
    pub constraints: Option<crate::mcp::tools::schema::FieldConstraints>,
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldType {
    Text,
    Integer,
    Real,
    Blob,
    Json,
    Boolean,
    Vector { dim: u32 },
}

#[derive(Serialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefaultValue {
    /// JSON-encoded literal (string/number/bool/null).
    Literal(serde_json::Value),
    /// Allowlisted SQL expression like `datetime('now')`.
    SqlExpr(String),
}

#[derive(Serialize, Debug)]
pub struct IndexIr {
    pub name: String,
    pub fields: Vec<String>,
    pub unique: bool,
    pub description: Option<String>,
}

/// Build a `CodegenIr` from a live tenant pool. `include_descriptions`
/// MUST be false when the caller is anon. `base_url` is wired through
/// from the request layer (typically `DRUST_PUBLIC_URL/drust`).
///
/// Reads collection list from `sqlite_master` (matching the admin
/// sidebar logic), then for each collection joins `_system_collection_meta`
/// for owner_field / realtime_enabled / descriptions and PRAGMA
/// `table_info` + `foreign_key_list` + `index_list` for column shape.
pub async fn build_ir(
    pool: &SharedTenantPool,
    tenant_id: &str,
    base_url: &str,
    include_descriptions: bool,
) -> anyhow::Result<CodegenIr> {
    let collections = pool
        .with_reader(|c| build_collections(c, include_descriptions))
        .await?;
    Ok(CodegenIr {
        tenant_id: tenant_id.to_string(),
        base_url: base_url.to_string(),
        include_descriptions,
        collections,
    })
}

fn build_collections(
    c: &rusqlite::Connection,
    include_descriptions: bool,
) -> rusqlite::Result<Vec<CollectionIr>> {
    let mut name_stmt = c.prepare(
        "SELECT name FROM sqlite_master \
         WHERE type='table' AND name NOT LIKE 'sqlite_%' \
         AND name NOT LIKE '\\_system\\_%' ESCAPE '\\' \
         ORDER BY name",
    )?;
    let names: Vec<String> = name_stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let fields = collect_fields(c, &name)?;
        let indexes = collect_indexes(c, &name, include_descriptions)?;
        let meta = read_meta(c, &name, include_descriptions)?;
        let has_vector = fields
            .iter()
            .any(|f| matches!(f.ty, FieldType::Vector { .. }));
        out.push(CollectionIr {
            name,
            description: meta.description,
            fields,
            indexes,
            owner_field: meta.owner_field,
            realtime_enabled: meta.realtime_enabled,
            has_vector,
        });
    }
    Ok(out)
}

struct MetaRow {
    description: Option<String>,
    owner_field: Option<String>,
    realtime_enabled: bool,
}

fn read_meta(
    c: &rusqlite::Connection,
    coll: &str,
    include_descriptions: bool,
) -> rusqlite::Result<MetaRow> {
    use rusqlite::OptionalExtension;
    let row: Option<(Option<String>, Option<String>, i64)> = c
        .query_row(
            "SELECT description, owner_field, realtime_enabled \
             FROM _system_collection_meta \
             WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    match row {
        Some((desc, owner, realtime)) => Ok(MetaRow {
            description: if include_descriptions { desc } else { None },
            owner_field: owner,
            realtime_enabled: realtime != 0,
        }),
        None => Ok(MetaRow {
            description: None,
            owner_field: None,
            realtime_enabled: false,
        }),
    }
}

fn collect_fields(c: &rusqlite::Connection, coll: &str) -> rusqlite::Result<Vec<FieldIr>> {
    // PRAGMA table_info: cid, name, type, notnull, dflt_value, pk
    let pragma = format!("PRAGMA table_info(\"{}\")", coll.replace('"', "\"\""));
    let mut stmt = c.prepare(&pragma)?;
    let raw_rows: Vec<(String, String, i64, Option<String>, i64)> = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(1)?,         // name
                r.get::<_, String>(2)?,         // type
                r.get::<_, i64>(3)?,            // notnull
                r.get::<_, Option<String>>(4)?, // dflt_value
                r.get::<_, i64>(5)?,            // pk
            ))
        })?
        .collect::<Result<_, _>>()?;

    // PRAGMA foreign_key_list — collect into a map { col_name → target_table }
    let fkp = format!("PRAGMA foreign_key_list(\"{}\")", coll.replace('"', "\"\""));
    let mut fk_stmt = c.prepare(&fkp)?;
    let fk_rows: Vec<(String, String)> = fk_stmt
        .query_map([], |r| Ok((r.get::<_, String>(3)?, r.get::<_, String>(2)?)))?
        .collect::<Result<_, _>>()?;
    let fk_map: std::collections::HashMap<String, String> = fk_rows.into_iter().collect();

    // _system_collection_meta.vector_fields_json — list of {name, dim}
    let vec_json: Option<String> = {
        use rusqlite::OptionalExtension;
        c.query_row(
            "SELECT vector_fields_json FROM _system_collection_meta WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
    };
    let vec_dims: std::collections::HashMap<String, u32> = vec_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<serde_json::Value>>(s).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| {
            let name = v.get("name")?.as_str()?.to_string();
            let dim = v.get("dim")?.as_u64()? as u32;
            Some((name, dim))
        })
        .collect();

    // _system_collection_meta.field_descriptions_json
    let fdesc_json: Option<String> = {
        use rusqlite::OptionalExtension;
        c.query_row(
            "SELECT field_descriptions_json FROM _system_collection_meta WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| r.get::<_, Option<String>>(0),
        ).optional()?.flatten()
    };
    let fdesc_map: std::collections::HashMap<String, String> = fdesc_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    // _system_collection_meta.field_constraints_json (v1.43)
    let constraints_map = crate::storage::schema::read_field_constraints(c, coll)?;

    let mut out: Vec<FieldIr> = Vec::with_capacity(raw_rows.len());
    for (name, ty_str, notnull, dflt, _pk) in raw_rows {
        let server_managed = matches!(name.as_str(), "id" | "created_at" | "updated_at");
        let ty = sql_type_to_field_type(&ty_str, vec_dims.get(&name).copied());
        let default = dflt.and_then(parse_default);
        out.push(FieldIr {
            name: name.clone(),
            ty,
            nullable: notnull == 0,
            default,
            fk: fk_map.get(&name).cloned(),
            description: fdesc_map.get(&name).cloned(),
            server_managed,
            constraints: constraints_map.get(&name).cloned(),
        });
    }
    Ok(out)
}

fn sql_type_to_field_type(sql: &str, vec_dim: Option<u32>) -> FieldType {
    if let Some(dim) = vec_dim {
        return FieldType::Vector { dim };
    }
    let upper = sql.to_uppercase();
    match upper.as_str() {
        "INTEGER" => FieldType::Integer,
        "REAL" => FieldType::Real,
        "BLOB" => FieldType::Blob,
        "BOOLEAN" => FieldType::Boolean,
        "JSON" => FieldType::Json,
        _ => FieldType::Text, // SQLite TEXT + everything else (DATETIME etc.)
    }
}

fn parse_default(raw: String) -> Option<DefaultValue> {
    // SQLite stores defaults as their SQL literal text. Common cases:
    // - numbers: "0", "1.5"  → Literal
    // - strings: "'hello'"  → Literal (strip quotes)
    // - NULL → Literal(null)
    // - datetime('now')  → SqlExpr
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("NULL") {
        return Some(DefaultValue::Literal(serde_json::Value::Null));
    }
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        // Wrapped SQL expression (drust wraps allowlisted exprs in parens).
        let inner = trimmed[1..trimmed.len() - 1].trim().to_string();
        return Some(DefaultValue::SqlExpr(inner));
    }
    if trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        let inner = trimmed[1..trimmed.len() - 1].replace("''", "'");
        return Some(DefaultValue::Literal(serde_json::Value::String(inner)));
    }
    if let Ok(n) = trimmed.parse::<i64>() {
        return Some(DefaultValue::Literal(serde_json::json!(n)));
    }
    if let Ok(f) = trimmed.parse::<f64>() {
        return Some(DefaultValue::Literal(serde_json::json!(f)));
    }
    // Fallback: treat as opaque SQL.
    Some(DefaultValue::SqlExpr(trimmed.to_string()))
}

fn collect_indexes(
    c: &rusqlite::Connection,
    coll: &str,
    include_descriptions: bool,
) -> rusqlite::Result<Vec<IndexIr>> {
    let pragma = format!("PRAGMA index_list(\"{}\")", coll.replace('"', "\"\""));
    let mut stmt = c.prepare(&pragma)?;
    // Cols: seq, name, unique, origin, partial
    let rows: Vec<(String, i64, String)> = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<_, _>>()?;

    let idesc_json: Option<String> = {
        use rusqlite::OptionalExtension;
        c.query_row(
            "SELECT index_descriptions_json FROM _system_collection_meta WHERE collection_name = ?1",
            rusqlite::params![coll],
            |r| r.get::<_, Option<String>>(0),
        ).optional()?.flatten()
    };
    let idesc_map: std::collections::HashMap<String, String> = idesc_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let mut out = Vec::with_capacity(rows.len());
    for (name, unique, origin) in rows {
        if origin == "pk" || name.starts_with("sqlite_") {
            continue; // skip PK autoindex + internal indexes
        }
        // PRAGMA index_info(name) → fields
        let ip = format!("PRAGMA index_info(\"{}\")", name.replace('"', "\"\""));
        let mut s2 = c.prepare(&ip)?;
        let fields: Vec<String> = s2
            .query_map([], |r| r.get::<_, String>(2))?
            .collect::<Result<_, _>>()?;
        out.push(IndexIr {
            name: name.clone(),
            fields,
            unique: unique != 0,
            description: if include_descriptions {
                idesc_map.get(&name).cloned()
            } else {
                None
            },
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_literals() {
        assert!(matches!(
            parse_default("NULL".into()),
            Some(DefaultValue::Literal(serde_json::Value::Null))
        ));
        assert!(matches!(
            parse_default("42".into()),
            Some(DefaultValue::Literal(_))
        ));
        assert!(matches!(
            parse_default("'hello'".into()),
            Some(DefaultValue::Literal(_))
        ));
    }

    #[test]
    fn parse_default_sql_expr() {
        let d = parse_default("(datetime('now'))".into()).unwrap();
        assert!(matches!(d, DefaultValue::SqlExpr(s) if s == "datetime('now')"));
    }

    #[test]
    fn sql_type_mapping() {
        assert_eq!(sql_type_to_field_type("TEXT", None), FieldType::Text);
        assert_eq!(sql_type_to_field_type("INTEGER", None), FieldType::Integer);
        assert_eq!(sql_type_to_field_type("BLOB", None), FieldType::Blob);
        assert_eq!(sql_type_to_field_type("JSON", None), FieldType::Json);
        assert_eq!(
            sql_type_to_field_type("TEXT", Some(1536)),
            FieldType::Vector { dim: 1536 }
        );
    }
}

use rusqlite::Connection;
use serde::Serialize;

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

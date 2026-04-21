use crate::mcp::server::DrustMcp;
use crate::storage::schema::{collection_exists, describe_collection};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FieldSpec {
    pub name: String,
    pub sql_type: String, // text|integer|real|boolean|datetime|json
    #[serde(default = "default_true")]
    pub nullable: bool,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub default_value: Option<serde_json::Value>,
    /// Name of another collection whose `id` this field references.
    /// Emits `REFERENCES "<target>"("id") ON DELETE RESTRICT`. The
    /// target must already exist at DDL time.
    #[serde(default)]
    pub foreign_key: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Allowlist of SQL expressions that may appear as a field default.
///
/// Entries are matched with exact string equality after trimming. We do
/// NOT parse or authorize arbitrary SQL here — the allowlist is the
/// entire security surface. Every entry is a zero-argument scalar with
/// no side effects and no column references, so it is safe both in
/// `CREATE TABLE` and in `ALTER TABLE ADD COLUMN`.
pub const SQL_DEFAULT_ALLOWLIST: &[&str] = &[
    "datetime('now')",
    "date('now')",
    "time('now')",
    "CURRENT_TIMESTAMP",
    "CURRENT_DATE",
    "CURRENT_TIME",
];

fn type_to_sqlite(t: &str) -> anyhow::Result<&'static str> {
    Ok(match t {
        "text" | "datetime" | "json" => "TEXT",
        "integer" | "boolean" => "INTEGER",
        "real" => "REAL",
        other => anyhow::bail!("unsupported type: {other}"),
    })
}

fn identifier(s: &str) -> anyhow::Result<()> {
    let ok = !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !ok {
        anyhow::bail!("invalid identifier: {s}");
    }
    Ok(())
}

fn column_expr(f: &FieldSpec) -> anyhow::Result<String> {
    identifier(&f.name)?;
    let ty = type_to_sqlite(&f.sql_type)?;
    let mut s = format!("\"{}\" {}", f.name, ty);
    if !f.nullable {
        s.push_str(" NOT NULL");
    }
    if f.unique {
        s.push_str(" UNIQUE");
    }
    if let Some(d) = &f.default_value {
        let lit = match d {
            serde_json::Value::Null => "NULL".into(),
            serde_json::Value::Bool(b) => {
                if *b {
                    "1".into()
                } else {
                    "0".into()
                }
            }
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(x) => format!("'{}'", x.replace('\'', "''")),
            // `{"sql": "datetime('now')"}` — allowlisted SQL expression.
            // Parenthesised to satisfy SQLite's ALTER TABLE rule that
            // non-constant defaults be wrapped.
            serde_json::Value::Object(o) if o.len() == 1 && o.contains_key("sql") => {
                let expr = o["sql"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("default.sql must be a string"))?
                    .trim();
                if !SQL_DEFAULT_ALLOWLIST.contains(&expr) {
                    anyhow::bail!(
                        "SQL default expression not in allowlist: {expr:?}. \
                         Allowed: {:?}",
                        SQL_DEFAULT_ALLOWLIST
                    );
                }
                format!("({expr})")
            }
            _ => anyhow::bail!("default must be a literal or {{\"sql\": \"<allowlisted>\"}}"),
        };
        s.push_str(&format!(" DEFAULT {lit}"));
    }
    if let Some(fk) = &f.foreign_key {
        identifier(fk)?;
        s.push_str(&format!(
            " REFERENCES \"{}\"(\"id\") ON DELETE RESTRICT",
            fk.replace('"', "\"\"")
        ));
    }
    Ok(s)
}

pub async fn create_collection(
    s: &DrustMcp,
    name: &str,
    fields: &[FieldSpec],
) -> anyhow::Result<serde_json::Value> {
    identifier(name)?;
    // Validate all foreign-key targets exist before running the DDL —
    // SQLite's own error for a missing FK table is cryptic.
    let fk_targets: Vec<String> = fields
        .iter()
        .filter_map(|f| f.foreign_key.clone())
        .collect();
    if !fk_targets.is_empty() {
        let pool = s.inner().pool.clone();
        let targets = fk_targets.clone();
        let own_name = name.to_string();
        pool.with_reader(move |c| {
            for t in &targets {
                // Self-reference is permitted — the collection exists
                // after CREATE.
                if t == &own_name {
                    continue;
                }
                if !collection_exists(c, t)? {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("foreign_key references unknown collection(s): {fk_targets:?}")
        })?;
    }
    let mut col_exprs = vec!["id INTEGER PRIMARY KEY AUTOINCREMENT".to_string()];
    for f in fields {
        col_exprs.push(column_expr(f)?);
    }
    col_exprs.push("created_at TEXT NOT NULL DEFAULT (datetime('now'))".into());
    col_exprs.push("updated_at TEXT NOT NULL DEFAULT (datetime('now'))".into());
    let table = name.to_string();
    let sql = format!(
        "CREATE TABLE \"{}\" ({});",
        table.replace('"', "\"\""),
        col_exprs.join(","),
    );
    let trigger = format!(
        "CREATE TRIGGER \"{name}_updated_at\" AFTER UPDATE ON \"{name}\"
         BEGIN UPDATE \"{name}\" SET updated_at = datetime('now') WHERE id = OLD.id; END;",
        name = table.replace('"', "\"\"")
    );
    let pool = s.inner().pool.clone();
    let pool2 = pool.clone();
    pool.with_writer(move |c| c.execute_batch(&format!("{sql}\n{trigger}")))
        .await?;

    let schema = pool2
        .with_reader(move |c| describe_collection(c, &table))
        .await?
        .unwrap();
    Ok(serde_json::to_value(schema)?)
}

pub async fn add_field(
    s: &DrustMcp,
    collection: &str,
    field: FieldSpec,
) -> anyhow::Result<serde_json::Value> {
    identifier(collection)?;
    if let Some(fk) = &field.foreign_key {
        let pool = s.inner().pool.clone();
        let fk_target = fk.clone();
        let exists = pool
            .with_reader(move |c| collection_exists(c, &fk_target))
            .await?;
        if !exists {
            anyhow::bail!("foreign_key references unknown collection: {fk:?}");
        }
    }
    let col = column_expr(&field)?;
    let sql = format!(
        "ALTER TABLE \"{}\" ADD COLUMN {}",
        collection.replace('"', "\"\""),
        col
    );
    let pool = s.inner().pool.clone();
    let pool2 = pool.clone();
    let coll = collection.to_string();
    pool.with_writer(move |c| c.execute(&sql, [])).await?;
    let schema = pool2
        .with_reader(move |c| describe_collection(c, &coll))
        .await?
        .ok_or_else(|| anyhow::anyhow!("collection missing after alter"))?;
    Ok(json!({ "collection": collection, "fields": schema.fields }))
}

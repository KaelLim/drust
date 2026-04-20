use crate::mcp::server::DrustMcp;
use crate::storage::schema::describe_collection;
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
}

fn default_true() -> bool {
    true
}

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
            _ => anyhow::bail!("default must be literal"),
        };
        s.push_str(&format!(" DEFAULT {lit}"));
    }
    Ok(s)
}

pub async fn create_collection(
    s: &DrustMcp,
    name: &str,
    fields: &[FieldSpec],
) -> anyhow::Result<serde_json::Value> {
    identifier(name)?;
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

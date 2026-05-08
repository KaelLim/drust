use crate::mcp::server::DrustMcp;
use crate::storage::schema::{
    DmlVerb, collection_exists, default_anon_caps, delete_collection_meta, describe_collection,
    find_fk_referrers, is_protected_collection, write_anon_caps,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

/// Columns drust maintains automatically; users cannot drop them.
/// `id` is PRIMARY KEY (SQLite would reject the drop anyway); `created_at`
/// and `updated_at` are referenced by the `<name>_updated_at` trigger
/// installed in `create_collection`, so dropping them would leave broken
/// triggers behind. Block all three in one place for a clean error.
pub const SYSTEM_COLUMNS: &[&str] = &["id", "created_at", "updated_at"];

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
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
        other => anyhow::bail!(
            "unsupported sql_type: '{other}' \
             (allowed: text, integer, real, boolean, datetime, json — all lowercase)"
        ),
    })
}

pub(crate) fn identifier(s: &str) -> anyhow::Result<()> {
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
    let meta_name = name.to_string();
    pool.with_writer(move |c| {
        c.execute_batch(&format!("{sql}\n{trigger}"))?;
        // Seed the anon_caps row so REST / cache lookups don't have to
        // fall back to defaults the first time around.
        write_anon_caps(c, &meta_name, &default_anon_caps())
    })
    .await?;

    // Schema cache must drop any pre-existing entry for this name so the
    // next describe_collection / REST request loads the fresh table.
    pool.schema_cache.invalidate(name);

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
    // The cached schema is stale — column list just changed.
    pool.schema_cache.invalidate(collection);
    let schema = pool2
        .with_reader(move |c| describe_collection(c, &coll))
        .await?
        .ok_or_else(|| anyhow::anyhow!("collection missing after alter"))?;
    Ok(json!({ "collection": collection, "fields": schema.fields }))
}

/// Drop a user-defined column via `ALTER TABLE … DROP COLUMN`.
///
/// Rejects the drop up-front when:
///   * the column is one of the drust-maintained SYSTEM_COLUMNS
///     (`id` / `created_at` / `updated_at`);
///   * the collection does not exist;
///   * the column does not exist on that collection.
///
/// SQLite itself will reject the statement in the pool writer if the
/// column is part of a UNIQUE, an index, a CHECK, a foreign key, a
/// trigger body, or a view — that error is propagated verbatim so the
/// caller sees why the drop is unsafe.
pub async fn drop_field(
    s: &DrustMcp,
    collection: &str,
    field: &str,
) -> anyhow::Result<serde_json::Value> {
    identifier(collection)?;
    identifier(field)?;
    if SYSTEM_COLUMNS.contains(&field) {
        anyhow::bail!(
            "cannot drop system column {field:?} — drust maintains `id`, `created_at`, and `updated_at` automatically and the _updated_at trigger depends on them"
        );
    }
    let pool = s.inner().pool.clone();
    let pool2 = pool.clone();
    let coll = collection.to_string();
    let coll_check = collection.to_string();
    let fld_check = field.to_string();
    // Verify collection + field exist before submitting the DDL so the
    // caller gets a clean error instead of sqlite's "no such column".
    pool.with_reader(move |c| {
        if !collection_exists(c, &coll_check)? {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let has_col: i64 = c.query_row(
            "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
            rusqlite::params![&coll_check, &fld_check],
            |r| r.get(0),
        )?;
        if has_col == 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("unknown collection or field: {collection}.{field}"))?;

    let sql = format!(
        "ALTER TABLE \"{}\" DROP COLUMN \"{}\"",
        collection.replace('"', "\"\""),
        field.replace('"', "\"\"")
    );
    pool.with_writer(move |c| c.execute(&sql, [])).await?;
    // The cached schema is stale — column list just changed.
    pool.schema_cache.invalidate(collection);
    let schema = pool2
        .with_reader(move |c| describe_collection(c, &coll))
        .await?
        .ok_or_else(|| anyhow::anyhow!("collection missing after alter"))?;
    Ok(json!({
        "collection": collection,
        "dropped_field": field,
        "fields": schema.fields,
    }))
}

/// Drop an entire collection (table + its `<name>_updated_at` trigger).
///
/// Rejects the drop when another collection still has a foreign-key
/// column pointing at this one — the caller must `drop_field` those
/// columns first, otherwise the remaining FKs would dangle and break
/// future joins / writes against the referrers.
pub async fn drop_collection(s: &DrustMcp, name: &str) -> anyhow::Result<serde_json::Value> {
    identifier(name)?;
    if is_protected_collection(name) {
        anyhow::bail!("refusing to drop system collection {name:?} (protected by _system_ prefix)");
    }
    let pool = s.inner().pool.clone();
    let name_check = name.to_string();
    let referrers: Vec<(String, String)> = pool
        .with_reader(move |c| {
            if !collection_exists(c, &name_check)? {
                return Err(rusqlite::Error::InvalidQuery);
            }
            find_fk_referrers(c, &name_check)
        })
        .await
        .map_err(|_| anyhow::anyhow!("unknown collection: {name}"))?;
    if !referrers.is_empty() {
        let list = referrers
            .iter()
            .map(|(t, f)| format!("{t}.{f}"))
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "cannot drop collection {name:?}: foreign-key references from {list}. Drop those columns first."
        );
    }
    let table = name.to_string();
    let meta_name = name.to_string();
    // The trigger name matches what create_collection installs.
    let ddl = format!(
        "DROP TRIGGER IF EXISTS \"{trig}\"; DROP TABLE \"{tbl}\";",
        trig = format!("{}_updated_at", table).replace('"', "\"\""),
        tbl = table.replace('"', "\"\""),
    );
    pool.with_writer(move |c| {
        c.execute_batch(&ddl)?;
        // Drop the anon_caps row in the same writer transaction so meta
        // and table go together.
        delete_collection_meta(c, &meta_name)
    })
    .await?;

    // Drop the cached schema so subsequent reads see the collection as
    // gone.
    pool.schema_cache.invalidate(name);

    Ok(json!({ "ok": true, "dropped_collection": name }))
}

/// Replace the anon-role DML capability set for one collection.
///
/// `caps` is a subset of `{select, insert, update, delete}`. Empty
/// caps lock the collection to anon (service is unaffected — service
/// is unrestricted by design). Refuses `_system_*` collections to
/// match the existing protection on `drop_collection`.
pub async fn set_anon_caps(
    s: &DrustMcp,
    collection: &str,
    caps: &[DmlVerb],
) -> anyhow::Result<serde_json::Value> {
    identifier(collection)?;
    if is_protected_collection(collection) {
        anyhow::bail!(
            "refusing to set anon_caps on system collection {collection:?} (protected by _system_ prefix)"
        );
    }
    let pool = s.inner().pool.clone();

    let name_check = collection.to_string();
    let exists = pool
        .with_reader(move |c| collection_exists(c, &name_check))
        .await?;
    if !exists {
        anyhow::bail!("unknown collection: {collection}");
    }

    let caps_set: BTreeSet<DmlVerb> = caps.iter().copied().collect();
    let meta_name = collection.to_string();
    let caps_for_writer = caps_set.clone();
    pool.with_writer(move |c| write_anon_caps(c, &meta_name, &caps_for_writer))
        .await?;
    pool.schema_cache.invalidate(collection);

    Ok(json!({
        "ok": true,
        "collection": collection,
        "anon_caps": caps_set.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
    }))
}

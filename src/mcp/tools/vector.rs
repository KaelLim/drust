//! MCP `search_collection` tool. Thin wrapper that constructs the same
//! search semantics the REST handler accepts and runs the same compile +
//! execute path. Lives on the MCP-only writer/reader pool surface
//! (service-only by transport).

use crate::mcp::server::DrustMcp;
use crate::query::vector_codec;
use crate::query::vector_filter::{self, FilterAst, FilterError};
use rusqlite::types::{Value, ValueRef};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchInput {
    /// Collection name.
    pub collection: String,
    /// Name of the vector field on that collection.
    pub field: String,
    /// Query vector as a JSON array of numbers. Length must equal the
    /// declared `dim` of the vector field.
    // Bare `serde_json::Value` derives a schema strict MCP clients (Zod) reject;
    // render an array-of-numbers schema. Runtime stays `Value` (any JSON), the
    // impl validates length/element types.
    #[schemars(with = "Vec<f64>")]
    pub vector: serde_json::Value,
    /// Number of nearest rows to return. 1..=1000.
    pub k: u32,
    /// Distance metric: `cosine` (default), `l2`, or `l1`.
    #[serde(default = "default_metric")]
    pub metric: String,
    /// Optional structured filter. Tree of `{and:[...]}` / `{or:[...]}`
    /// / `{not:...}` over leaves `{field: scalar}` (eq shorthand) or
    /// `{field: {op: operand}}`. Operators: eq, ne, gt, gte, lt, lte,
    /// like, in (array), nin (array). Vector fields cannot appear in
    /// the filter.
    #[serde(default)]
    pub r#where: Option<serde_json::Value>,
    /// Fields to include in each row. Defaults to all non-vector
    /// columns. The injected `_distance` column is always returned.
    #[serde(default)]
    pub select: Option<Vec<String>>,
}

fn default_metric() -> String {
    "cosine".to_string()
}

pub async fn search_collection(
    s: &DrustMcp,
    input: SearchInput,
) -> anyhow::Result<serde_json::Value> {
    if !(1..=1000).contains(&input.k) {
        anyhow::bail!("K_OUT_OF_RANGE: k must be 1..=1000");
    }
    let distance_fn = match input.metric.as_str() {
        "cosine" => "vec_distance_cosine",
        "l2" => "vec_distance_l2",
        "l1" => "vec_distance_l1",
        _ => anyhow::bail!("INVALID_METRIC: metric must be cosine|l2|l1"),
    };

    let pool = s.inner().pool.clone();
    let cache = pool.schema_cache.clone();
    let coll = input.collection.clone();
    let schema = pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll))
        .await?
        .ok_or_else(|| anyhow::anyhow!("COLLECTION_NOT_FOUND: {}", input.collection))?;

    let vf = schema
        .vector_fields
        .iter()
        .find(|v| v.name == input.field)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "VECTOR_FIELD_NOT_FOUND: no vector field {:?} on {:?}",
                input.field,
                input.collection
            )
        })?;

    let qvec =
        vector_codec::pack(&vf.name, vf.dim, &input.vector).map_err(|e| anyhow::anyhow!("{e}"))?;

    let (where_sql, mut binds): (String, Vec<Value>) = match &input.r#where {
        None => ("1=1".into(), vec![]),
        Some(raw) => {
            let ast: FilterAst = serde_json::from_value(raw.clone())
                .map_err(|e| anyhow::anyhow!("FILTER_PARSE_ERROR: {e}"))?;
            vector_filter::compile(&schema, &ast).map_err(|e| match e {
                FilterError::UnknownField(f) => anyhow::anyhow!("FILTER_UNKNOWN_FIELD: {f}"),
                FilterError::VectorField(f) => anyhow::anyhow!("FILTER_VECTOR_FIELD: {f}"),
                FilterError::TooDeep => anyhow::anyhow!(
                    "FILTER_TOO_DEEP: filter nesting exceeds max depth ({})",
                    vector_filter::MAX_FILTER_DEPTH
                ),
                other => anyhow::anyhow!("FILTER_PARSE_ERROR: {other}"),
            })?
        }
    };

    let select_cols: Vec<String> = match &input.select {
        Some(req) => req
            .iter()
            .filter(|n| !schema.vector_fields.iter().any(|v| v.name == **n))
            .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
            .collect(),
        None => schema
            .fields
            .iter()
            .filter(|f| !schema.vector_fields.iter().any(|v| v.name == f.name))
            .map(|f| format!("\"{}\"", f.name.replace('"', "\"\"")))
            .collect(),
    };
    let select_list = if select_cols.is_empty() {
        "id".to_string()
    } else {
        select_cols.join(", ")
    };

    let sql = format!(
        "SELECT {select_list}, {distance_fn}(\"{}\", ?) AS _distance \
         FROM \"{}\" WHERE {where_sql} ORDER BY _distance LIMIT ?",
        vf.name.replace('"', "\"\""),
        input.collection.replace('"', "\"\""),
    );

    let mut all_binds: Vec<Value> = Vec::with_capacity(2 + binds.len());
    all_binds.push(Value::Blob(qvec));
    all_binds.append(&mut binds);
    all_binds.push(Value::Integer(input.k as i64));

    let rows: Vec<serde_json::Value> = pool
        .with_reader(move |c| {
            let mut stmt = c.prepare(&sql)?;
            let col_names: Vec<String> =
                stmt.column_names().iter().map(|s| s.to_string()).collect();
            let mut iter = stmt.query(rusqlite::params_from_iter(all_binds.iter()))?;
            let mut out = Vec::new();
            while let Some(r) = iter.next()? {
                let mut obj = serde_json::Map::new();
                for (i, n) in col_names.iter().enumerate() {
                    let v = r.get_ref(i)?;
                    obj.insert(
                        n.clone(),
                        match v {
                            ValueRef::Null => serde_json::Value::Null,
                            ValueRef::Integer(x) => json!(x),
                            ValueRef::Real(x) => json!(x),
                            ValueRef::Text(t) => {
                                serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
                            }
                            ValueRef::Blob(b) => json!({ "__blob_bytes": b.len() }),
                        },
                    );
                }
                out.push(serde_json::Value::Object(obj));
            }
            Ok::<_, rusqlite::Error>(out)
        })
        .await?;

    Ok(json!({
        "rows": rows,
        "k": input.k,
        "metric": input.metric,
        "truncated": false,
    }))
}

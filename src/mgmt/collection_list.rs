//! Admin-only POST /admin/tenants/<id>/collections/<coll>/_list endpoint
//! that backs the v1.28 chip filter on the collection editor.
//!
//! Browser sends `{filters, sort, page, per_page}` with filter ops drawn
//! from the toolbar dropdown (`eq`, `contains`, `between`, `is_null`, …).
//! Handler bridges these to FilterAst (`src/query/vector_filter.rs`),
//! compiles to SQL with `?` binds, runs against the read-only connection,
//! and returns `{columns, rows, total, page, per_page, total_pages}`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ListRequest {
    #[serde(default)]
    pub filters: Vec<FilterTriple>,
    #[serde(default)]
    pub sort: Option<SortSpec>,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 { 1 }
fn default_per_page() -> u32 { 50 }

#[derive(Debug, Deserialize)]
pub struct FilterTriple {
    pub field: String,
    pub op: String,
    /// Always present in JSON; for `is_null` / `is_not_null` / `is_true`
    /// / `is_false` the value is ignored by the bridge.
    #[serde(default)]
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct SortSpec {
    pub field: String,
    pub dir: SortDir,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDir {
    Asc,
    Desc,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

/// Translate a flat list of `{field, op, value}` triples to a single
/// FilterAst tree. The result is `FilterAst::And { and: <nodes> }` so an
/// empty input compiles to `1=1` (matches all rows).
///
/// Bridge ops (op → FilterAst):
/// - `contains`      → `{field: {like: "%value%"}}`
/// - `starts_with`   → `{field: {like: "value%"}}`
/// - `ends_with`     → `{field: {like: "%value"}}`
/// - `between`       → `{and: [{field: {gte: lo}}, {field: {lte: hi}}]}`
///                      (value must be a 2-element array)
/// - `is_true`       → `{field: {eq: 1}}`
/// - `is_false`      → `{field: {eq: 0}}`
/// Pass-through ops: eq, ne, gt, gte, lt, lte, in, nin, like, is_null, is_not_null.
pub fn filter_triples_to_ast(
    triples: &[FilterTriple],
) -> Result<crate::query::vector_filter::FilterAst, String> {
    let mut nodes = Vec::with_capacity(triples.len());
    for t in triples {
        nodes.push(triple_to_node(t)?);
    }
    Ok(crate::query::vector_filter::FilterAst::And { and: nodes })
}

fn triple_to_node(
    t: &FilterTriple,
) -> Result<crate::query::vector_filter::FilterAst, String> {
    use crate::query::vector_filter::FilterAst;
    use serde_json::{Map, Value as J};

    fn leaf(field: &str, body: J) -> FilterAst {
        let mut m = Map::new();
        m.insert(field.to_string(), body);
        FilterAst::Leaf(m)
    }
    fn op_obj(op: &str, v: J) -> J {
        let mut m = Map::new();
        m.insert(op.to_string(), v);
        J::Object(m)
    }

    match t.op.as_str() {
        "eq" | "ne" | "gt" | "gte" | "lt" | "lte"
        | "in" | "nin" | "like" | "is_null" | "is_not_null" => {
            Ok(leaf(&t.field, op_obj(&t.op, t.value.clone())))
        }
        "contains" => {
            let s = t.value.as_str().ok_or("contains requires string")?;
            Ok(leaf(&t.field, op_obj("like", J::String(format!("%{s}%")))))
        }
        "starts_with" => {
            let s = t.value.as_str().ok_or("starts_with requires string")?;
            Ok(leaf(&t.field, op_obj("like", J::String(format!("{s}%")))))
        }
        "ends_with" => {
            let s = t.value.as_str().ok_or("ends_with requires string")?;
            Ok(leaf(&t.field, op_obj("like", J::String(format!("%{s}")))))
        }
        "between" => {
            let arr = t.value.as_array().ok_or("between requires 2-element array")?;
            if arr.len() != 2 {
                return Err("between requires exactly 2 elements".into());
            }
            Ok(FilterAst::And {
                and: vec![
                    leaf(&t.field, op_obj("gte", arr[0].clone())),
                    leaf(&t.field, op_obj("lte", arr[1].clone())),
                ],
            })
        }
        "is_true"  => Ok(leaf(&t.field, op_obj("eq", J::Number(1.into())))),
        "is_false" => Ok(leaf(&t.field, op_obj("eq", J::Number(0.into())))),
        other => Err(format!("unknown op {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::vector_filter::{compile, FilterAst};
    use crate::storage::schema::{CollectionSchema, Field};
    use std::collections::BTreeSet;

    fn schema(fields: &[(&str, &str)]) -> CollectionSchema {
        CollectionSchema {
            name: "t".into(),
            fields: fields.iter().map(|(n, ty)| Field {
                name: n.to_string(),
                sql_type: ty.to_string(),
                nullable: true,
                pk: false,
                default_value: None,
                foreign_key: None,
                description: None,
            }).collect(),
            indices: vec![],
            row_count: 0,
            anon_caps: BTreeSet::new(),
            owner_field: None,
            read_scope: None,
            vector_fields: vec![],
            realtime_enabled: true,
            description: None,
        }
    }

    fn triple(field: &str, op: &str, value: serde_json::Value) -> FilterTriple {
        FilterTriple { field: field.into(), op: op.into(), value }
    }

    #[test]
    fn empty_triples_match_all() {
        let ast = filter_triples_to_ast(&[]).unwrap();
        let (sql, _) = compile(&schema(&[("a","TEXT")]), &ast).unwrap();
        assert_eq!(sql, "1=1");
    }

    #[test]
    fn eq_passes_through() {
        let t = vec![triple("name", "eq", serde_json::json!("Kael"))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("name","TEXT")]), &ast).unwrap();
        assert_eq!(sql, r#"("name" = ?)"#);
        assert_eq!(binds.len(), 1);
    }

    #[test]
    fn contains_rewrites_to_like_with_percent_wraps() {
        let t = vec![triple("name", "contains", serde_json::json!("ael"))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("name","TEXT")]), &ast).unwrap();
        assert_eq!(sql, r#"("name" LIKE ?)"#);
        assert_eq!(binds.len(), 1);
        match &binds[0] {
            rusqlite::types::Value::Text(s) => assert_eq!(s, "%ael%"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn starts_with_appends_percent() {
        let t = vec![triple("name", "starts_with", serde_json::json!("Ka"))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (_, binds) = compile(&schema(&[("name","TEXT")]), &ast).unwrap();
        match &binds[0] {
            rusqlite::types::Value::Text(s) => assert_eq!(s, "Ka%"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn between_expands_to_gte_and_lte() {
        let t = vec![triple("age", "between", serde_json::json!([10, 20]))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("age","INTEGER")]), &ast).unwrap();
        assert_eq!(sql, r#"(("age" >= ? AND "age" <= ?))"#);
        assert_eq!(binds.len(), 2);
    }

    #[test]
    fn is_true_becomes_eq_1() {
        let t = vec![triple("active", "is_true", serde_json::json!(true))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("active","INTEGER")]), &ast).unwrap();
        assert_eq!(sql, r#"("active" = ?)"#);
        assert!(matches!(binds[0], rusqlite::types::Value::Integer(1)));
    }

    #[test]
    fn is_null_passes_through() {
        let t = vec![triple("note", "is_null", serde_json::json!(true))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("note","TEXT")]), &ast).unwrap();
        assert_eq!(sql, r#"("note" IS NULL)"#);
        assert!(binds.is_empty());
    }

    #[test]
    fn unknown_op_errors() {
        let t = vec![triple("a", "matches_regex", serde_json::json!("x"))];
        let err = filter_triples_to_ast(&t).unwrap_err();
        assert!(err.contains("unknown op"));
    }

    #[test]
    fn multiple_triples_andd_together() {
        let t = vec![
            triple("a", "eq", serde_json::json!(1)),
            triple("b", "gt", serde_json::json!(2)),
        ];
        let ast = filter_triples_to_ast(&t).unwrap();
        match ast {
            FilterAst::And { and } => assert_eq!(and.len(), 2),
            _ => panic!("expected And"),
        }
    }
}

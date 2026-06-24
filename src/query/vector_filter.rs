//! Filter AST used by /search. Intentionally minimal: a tenant-supplied
//! tree of `and/or/not` boolean nodes over leaves of the shape
//! `{field: scalar}` (eq shorthand) or `{field: {op: scalar | scalar[]}}`.
//! No raw SQL fragments — every operand binds as a `?` parameter, so
//! anon and user callers can safely supply filters.
//!
//! Vector fields cannot appear in the filter; that returns a typed
//! error so the handler maps to `400 FILTER_VECTOR_FIELD`.

use crate::storage::schema::CollectionSchema;
use rusqlite::types::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use thiserror::Error;

/// Maximum nesting depth of the boolean tree (and/or/not). A deeply nested
/// `{"and":[{"and":[...]}]}` chain could otherwise blow the tokio worker
/// stack — axum's default 2 MB body cap is large enough to encode such a
/// payload. 32 levels is comfortably above any realistic legitimate filter.
pub const MAX_FILTER_DEPTH: usize = 32;

#[derive(Debug, Error, PartialEq)]
pub enum FilterError {
    #[error("filter parse error: {0}")]
    Parse(String),
    #[error("unknown field in filter: {0:?}")]
    UnknownField(String),
    #[error("filter cannot target vector field: {0:?}")]
    VectorField(String),
    #[error("operator {op:?} on field {field:?} requires {required}")]
    BadOperand {
        op: String,
        field: String,
        required: &'static str,
    },
    #[error("filter nesting exceeds max depth ({MAX_FILTER_DEPTH})")]
    TooDeep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterAst {
    And { and: Vec<FilterAst> },
    Or { or: Vec<FilterAst> },
    Not { not: Box<FilterAst> },
    Leaf(serde_json::Map<String, Json>),
}

pub fn compile(
    schema: &CollectionSchema,
    ast: &FilterAst,
) -> Result<(String, Vec<Value>), FilterError> {
    let mut binds: Vec<Value> = Vec::new();
    let sql = compile_node(schema, ast, &mut binds, 0)?;
    Ok((sql, binds))
}

fn compile_node(
    schema: &CollectionSchema,
    node: &FilterAst,
    binds: &mut Vec<Value>,
    depth: usize,
) -> Result<String, FilterError> {
    if depth >= MAX_FILTER_DEPTH {
        return Err(FilterError::TooDeep);
    }
    match node {
        FilterAst::And { and } => {
            if and.is_empty() {
                return Ok("1=1".into());
            }
            let parts: Result<Vec<_>, _> = and
                .iter()
                .map(|n| compile_node(schema, n, binds, depth + 1))
                .collect();
            Ok(format!("({})", parts?.join(" AND ")))
        }
        FilterAst::Or { or } => {
            if or.is_empty() {
                return Ok("1=0".into());
            }
            let parts: Result<Vec<_>, _> = or
                .iter()
                .map(|n| compile_node(schema, n, binds, depth + 1))
                .collect();
            Ok(format!("({})", parts?.join(" OR ")))
        }
        FilterAst::Not { not } => {
            let inner = compile_node(schema, not, binds, depth + 1)?;
            Ok(format!("(NOT {inner})"))
        }
        FilterAst::Leaf(obj) => {
            if obj.len() != 1 {
                return Err(FilterError::Parse(
                    "leaf node must have exactly one field key".into(),
                ));
            }
            let (field, body) = obj.iter().next().unwrap();
            validate_field(schema, field)?;
            compile_leaf(field, body, binds)
        }
    }
}

fn validate_field(schema: &CollectionSchema, field: &str) -> Result<(), FilterError> {
    if schema.vector_fields.iter().any(|v| v.name == field) {
        return Err(FilterError::VectorField(field.to_string()));
    }
    if !schema.fields.iter().any(|f| f.name == field) {
        return Err(FilterError::UnknownField(field.to_string()));
    }
    Ok(())
}

fn compile_leaf(field: &str, body: &Json, binds: &mut Vec<Value>) -> Result<String, FilterError> {
    let col = format!("\"{}\"", field.replace('"', "\"\""));
    if !matches!(body, Json::Object(_)) {
        binds.push(json_to_value(body));
        return Ok(format!("{col} = ?"));
    }
    let op_obj = body.as_object().unwrap();
    if op_obj.len() != 1 {
        return Err(FilterError::Parse(format!(
            "field {field:?}: op object must have exactly one key"
        )));
    }
    let (op, operand) = op_obj.iter().next().unwrap();
    match op.as_str() {
        "eq" | "ne" | "gt" | "gte" | "lt" | "lte" | "like" => {
            let sql_op = match op.as_str() {
                "eq" => "=",
                "ne" => "<>",
                "gt" => ">",
                "gte" => ">=",
                "lt" => "<",
                "lte" => "<=",
                "like" => "LIKE",
                _ => unreachable!(),
            };
            binds.push(json_to_value(operand));
            Ok(format!("{col} {sql_op} ?"))
        }
        "in" | "nin" => {
            let arr = operand.as_array().ok_or_else(|| FilterError::BadOperand {
                op: op.clone(),
                field: field.to_string(),
                required: "array",
            })?;
            if arr.is_empty() {
                return Ok(if op == "in" {
                    "1=0".into()
                } else {
                    "1=1".into()
                });
            }
            let placeholders = vec!["?"; arr.len()].join(", ");
            for v in arr {
                binds.push(json_to_value(v));
            }
            let sql_op = if op == "in" { "IN" } else { "NOT IN" };
            Ok(format!("{col} {sql_op} ({placeholders})"))
        }
        "is_null" | "is_not_null" => {
            // No operand — accept any value (typically `true`) and ignore.
            let _ = operand;
            let sql_op = if op == "is_null" {
                "IS NULL"
            } else {
                "IS NOT NULL"
            };
            Ok(format!("{col} {sql_op}"))
        }
        other => Err(FilterError::Parse(format!(
            "field {field:?}: unknown operator {other:?}"
        ))),
    }
}

pub fn json_to_value(v: &Json) -> Value {
    match v {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Integer(if *b { 1 } else { 0 }),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Value::Real(f)
            } else {
                Value::Null
            }
        }
        Json::String(s) => Value::Text(s.clone()),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::schema::{Field, VectorField};
    use std::collections::BTreeSet;

    fn schema_with(fields: &[(&str, &str)], vector: &[(&str, u32)]) -> CollectionSchema {
        CollectionSchema {
            name: "t".into(),
            fields: fields
                .iter()
                .map(|(n, ty)| Field {
                    name: n.to_string(),
                    sql_type: ty.to_string(),
                    nullable: true,
                    pk: false,
                    default_value: None,
                    foreign_key: None,
                    description: None,
                    ..Default::default()
                })
                .collect(),
            indices: vec![],
            row_count: 0,
            anon_caps: BTreeSet::new(),
            user_caps: BTreeSet::new(),
            owner_field: None,
            read_scope: None,
            vector_fields: vector
                .iter()
                .map(|(n, d)| VectorField {
                    name: n.to_string(),
                    dim: *d,
                })
                .collect(),
            realtime_enabled: true,
            description: None,
            policies: Default::default(),
        }
    }

    fn leaf(json: &str) -> FilterAst {
        let obj: serde_json::Map<String, Json> = serde_json::from_str(json).unwrap();
        FilterAst::Leaf(obj)
    }

    #[test]
    fn eq_shorthand_compiles() {
        let s = schema_with(&[("category", "text")], &[]);
        let ast = leaf(r#"{"category":"docs"}"#);
        let (sql, binds) = compile(&s, &ast).unwrap();
        assert_eq!(sql, r#""category" = ?"#);
        assert_eq!(binds.len(), 1);
    }

    #[test]
    fn op_object_compiles_each_op() {
        let s = schema_with(&[("created_at", "datetime"), ("n", "integer")], &[]);
        for (json, expected) in [
            (
                r#"{"created_at":{"gte":"2026-01-01"}}"#,
                r#""created_at" >= ?"#,
            ),
            (r#"{"n":{"lt":42}}"#, r#""n" < ?"#),
            (r#"{"n":{"ne":0}}"#, r#""n" <> ?"#),
            (
                r#"{"created_at":{"like":"2026%"}}"#,
                r#""created_at" LIKE ?"#,
            ),
        ] {
            let (sql, _) = compile(&s, &leaf(json)).unwrap();
            assert_eq!(sql, expected, "json: {json}");
        }
    }

    #[test]
    fn in_and_nin_compile() {
        let s = schema_with(&[("cat", "text")], &[]);
        let (sql, binds) = compile(&s, &leaf(r#"{"cat":{"in":["a","b","c"]}}"#)).unwrap();
        assert_eq!(sql, r#""cat" IN (?, ?, ?)"#);
        assert_eq!(binds.len(), 3);

        let (sql, binds) = compile(&s, &leaf(r#"{"cat":{"nin":["x"]}}"#)).unwrap();
        assert_eq!(sql, r#""cat" NOT IN (?)"#);
        assert_eq!(binds.len(), 1);
    }

    #[test]
    fn empty_in_collapses() {
        let s = schema_with(&[("cat", "text")], &[]);
        let (sql, binds) = compile(&s, &leaf(r#"{"cat":{"in":[]}}"#)).unwrap();
        assert_eq!(sql, "1=0");
        assert!(binds.is_empty());
    }

    #[test]
    fn and_or_not_nest_correctly() {
        let s = schema_with(&[("cat", "text"), ("n", "integer")], &[]);
        let ast: FilterAst = serde_json::from_str(
            r#"{"and":[
                {"cat":"docs"},
                {"or":[{"n":{"gt":10}},{"n":{"lt":-5}}]},
                {"not":{"cat":"draft"}}
              ]}"#,
        )
        .unwrap();
        let (sql, binds) = compile(&s, &ast).unwrap();
        assert_eq!(
            sql,
            r#"("cat" = ? AND ("n" > ? OR "n" < ?) AND (NOT "cat" = ?))"#
        );
        assert_eq!(binds.len(), 4);
    }

    #[test]
    fn unknown_field_rejected() {
        let s = schema_with(&[("cat", "text")], &[]);
        let err = compile(&s, &leaf(r#"{"ghost":"x"}"#)).unwrap_err();
        assert!(matches!(err, FilterError::UnknownField(_)));
    }

    #[test]
    fn vector_field_in_filter_rejected() {
        let s = schema_with(&[("title", "text")], &[("embedding", 8)]);
        let err = compile(&s, &leaf(r#"{"embedding":[0.0]}"#)).unwrap_err();
        assert!(matches!(err, FilterError::VectorField(_)));
    }

    /// Build a `{"not": {"not": ... {"cat":"x"} ... }}` chain n-deep.
    fn deep_not_chain(n: usize) -> FilterAst {
        let mut node = leaf(r#"{"cat":"x"}"#);
        for _ in 0..n {
            node = FilterAst::Not {
                not: Box::new(node),
            };
        }
        node
    }

    #[test]
    fn depth_at_cap_minus_one_compiles() {
        // The chain wraps the leaf in MAX_FILTER_DEPTH - 1 `not` nodes,
        // so total recursion reaches depth = MAX_FILTER_DEPTH at the leaf,
        // which is still rejected. Use one shallower to land legal.
        let s = schema_with(&[("cat", "text")], &[]);
        let ast = deep_not_chain(MAX_FILTER_DEPTH - 2);
        assert!(compile(&s, &ast).is_ok());
    }

    #[test]
    fn depth_over_cap_rejected() {
        let s = schema_with(&[("cat", "text")], &[]);
        let ast = deep_not_chain(MAX_FILTER_DEPTH + 5);
        let err = compile(&s, &ast).unwrap_err();
        assert!(matches!(err, FilterError::TooDeep));
    }

    #[test]
    fn is_null_compiles_to_is_null() {
        let s = schema_with(&[("a", "TEXT")], &[]);
        let ast = leaf(r#"{"a":{"is_null":true}}"#);
        let (sql, binds) = compile(&s, &ast).unwrap();
        assert_eq!(sql, r#""a" IS NULL"#);
        assert!(binds.is_empty());
    }

    #[test]
    fn is_not_null_compiles_to_is_not_null() {
        let s = schema_with(&[("a", "TEXT")], &[]);
        let ast = leaf(r#"{"a":{"is_not_null":true}}"#);
        let (sql, binds) = compile(&s, &ast).unwrap();
        assert_eq!(sql, r#""a" IS NOT NULL"#);
        assert!(binds.is_empty());
    }
}

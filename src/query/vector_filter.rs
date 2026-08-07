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

/// Caller-facing description of the accepted filter shapes. Surfaced whenever
/// a filter value fails to parse — a wrong JSON type, or a double-encoded
/// string that is not valid JSON — in place of serde's opaque
/// "data did not match any variant of untagged enum FilterAst".
pub fn filter_shape_hint() -> String {
    "filter must be a JSON object: a leaf like {\"status\":\"published\"} \
     (equality) or {\"views\":{\"gte\":10}} (operator — one of eq, ne, gt, \
     gte, lt, lte, like, in, nin, is_null, is_not_null), or a boolean node \
     {\"and\":[...]} / {\"or\":[...]} / {\"not\":{...}}. Pass it as an object, \
     not a JSON-encoded string."
        .to_string()
}

/// Parse a caller-supplied JSON value into a [`FilterAst`], tolerating the
/// common MCP-client behaviour of double-encoding a structured argument as a
/// JSON *string*. Several MCP hosts serialize object-typed tool arguments to
/// strings; without this rescue a well-formed filter arrives as
/// `Value::String("{...}")` and fails the `untagged` enum with an opaque
/// "did not match any variant" error. On failure returns the human-facing
/// [`filter_shape_hint`], never the raw serde message.
///
/// Every caller-supplied-filter entry point (`list_records`, `aggregate`,
/// `search_collection`'s `where`, `set_policy`'s `using`/`check`) routes
/// through here so the tolerance and the error text stay in lockstep.
pub fn parse_filter_value(v: Json) -> Result<FilterAst, String> {
    // One layer of string-decoding: a JSON string that itself encodes an
    // object/array is the double-encoding case. A string that is not valid
    // JSON, or that decodes to a scalar, still fails below with the hint.
    let decoded = match v {
        Json::String(s) => serde_json::from_str::<Json>(&s).map_err(|_| filter_shape_hint())?,
        other => other,
    };
    // A JSON object always deserializes as `Leaf(map)`; only a non-object
    // (array, scalar, null) reaches the error arm — exactly the inputs that
    // produced the opaque variant error before.
    serde_json::from_value::<FilterAst>(decoded).map_err(|_| filter_shape_hint())
}

/// `schemars` override for the `filter` / `using` / `check` / `where` MCP tool
/// arguments. The runtime field stays `serde_json::Value` (any JSON — so a
/// double-encoded string still deserializes and [`parse_filter_value`] rescues
/// it), but the advertised inputSchema is an `object`: a bare `Value` renders
/// as schemars' untyped "any", which strict MCP clients (e.g. Zod-validating
/// hosts) reject or coerce into a string — the very double-encoding this
/// module now tolerates. Steering the schema to `object` stops it at the
/// source. Shape detail lives in `src/codegen/filter_ast_schema.rs`.
pub fn filter_arg_json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "description": "Structured filter (FilterAst). A boolean node \
            {\"and\":[...]} / {\"or\":[...]} / {\"not\":{...}}, or a leaf \
            {field: scalar} (equality) or {field: {op: operand}} where op is \
            one of eq, ne, gt, gte, lt, lte, like, in, nin, is_null, \
            is_not_null. Pass as a JSON object, not a JSON-encoded string."
    })
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
            audit_enabled: true,
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

    // --- parse_filter_value: string-double-encoding tolerance (v1.58.6) ---

    #[test]
    fn parse_filter_value_accepts_plain_object() {
        let ast = parse_filter_value(serde_json::json!({"status": "published"})).unwrap();
        assert!(matches!(ast, FilterAst::Leaf(_)));
    }

    #[test]
    fn parse_filter_value_accepts_double_encoded_leaf_string() {
        // The MCP footgun: an object serialized to a JSON *string*. Before the
        // rescue this failed with "did not match any variant".
        let ast = parse_filter_value(serde_json::json!("{\"status\":\"published\"}")).unwrap();
        assert!(matches!(ast, FilterAst::Leaf(_)));
    }

    #[test]
    fn parse_filter_value_accepts_double_encoded_bool_tree_string() {
        let ast = parse_filter_value(serde_json::json!("{\"and\":[{\"a\":1},{\"b\":2}]}")).unwrap();
        assert!(matches!(ast, FilterAst::And { .. }));
    }

    #[test]
    fn parse_filter_value_scalar_yields_shape_hint_not_serde_noise() {
        let err = parse_filter_value(serde_json::json!(true)).unwrap_err();
        assert!(
            err.contains("JSON object"),
            "want teaching hint, got: {err}"
        );
        // The opaque serde message must never leak to the caller.
        assert!(
            !err.contains("did not match any variant"),
            "leaked raw serde message: {err}"
        );
    }

    #[test]
    fn parse_filter_value_non_json_string_yields_hint() {
        let err = parse_filter_value(serde_json::json!("not json at all")).unwrap_err();
        assert!(err.contains("JSON object"), "got: {err}");
    }

    /// Anti-drift guard: the shapes the tool descriptions and the codegen
    /// schema (`src/codegen/filter_ast_schema.rs`) advertise must be exactly
    /// the shapes the real parser accepts. The historically mis-documented
    /// `{op, field, value}` form is NOT a valid leaf — it must fail to compile.
    #[test]
    fn documented_shapes_match_the_real_parser() {
        let s = schema_with(&[("status", "text"), ("views", "integer")], &[]);
        for j in [
            r#"{"status":"published"}"#,
            r#"{"views":{"gte":10}}"#,
            r#"{"and":[{"status":"published"},{"views":{"gte":10}}]}"#,
            r#"{"or":[{"status":"a"},{"status":"b"}]}"#,
            r#"{"not":{"status":"draft"}}"#,
        ] {
            let ast = parse_filter_value(serde_json::from_str(j).unwrap())
                .unwrap_or_else(|e| panic!("{j} must parse: {e}"));
            compile(&s, &ast).unwrap_or_else(|e| panic!("{j} must compile: {e}"));
        }
        // {op, field, value} parses as a 3-key leaf, which compile rejects.
        let wrong = parse_filter_value(serde_json::json!({"op":"eq","field":"status","value":"x"}))
            .unwrap();
        assert!(
            compile(&s, &wrong).is_err(),
            "{{op,field,value}} must NOT be a valid leaf — codegen must document {{field:{{op}}}}"
        );
    }

    /// The "stop it at the source" half of the fix: the schemars override must
    /// advertise an `object` schema, not schemars' untyped "any" (which is what
    /// invited strict MCP clients to stringify the argument).
    #[test]
    fn filter_arg_schema_advertises_object_not_any() {
        let mut g = schemars::SchemaGenerator::default();
        let schema = filter_arg_json_schema(&mut g);
        let v = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            v.get("type").and_then(|t| t.as_str()),
            Some("object"),
            "filter arg must advertise an object schema, got {v}"
        );
        assert!(
            v.get("description").is_some(),
            "filter arg schema should carry a model-facing description"
        );
    }
}

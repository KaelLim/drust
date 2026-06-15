//! Row-level security policy engine. A `Policy` is a per-operation pair of
//! bounded `FilterAst` expressions: `using` (which existing rows) and
//! `check` (is the new row allowed). Two evaluators share the grammar —
//! `compile_policy_using` (→ SQL) and `eval_policy` (→ bool in memory).
//! See `docs/superpowers/specs/2026-06-12-drust-rls-policies-design.md`.

use crate::auth::middleware::AuthCtx;
use crate::query::vector_filter::{FilterAst, MAX_FILTER_DEPTH, json_to_value};
use crate::storage::schema::{CollectionSchema, DmlVerb};
use rusqlite::types::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use thiserror::Error;

/// One operation's policy: a `using` predicate (which existing rows) and/or
/// a `check` predicate (is the new/post-image row allowed). Both are
/// optional; a `None` clause means "no predicate for that direction".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub using: Option<FilterAst>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub check: Option<FilterAst>,
}

/// The four per-operation policies for a collection. All `None` = the
/// collection has no explicit policy (governed by tier rules + owner_field).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectionPolicies {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub select: Option<Policy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insert: Option<Policy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<Policy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<Policy>,
}

impl CollectionPolicies {
    pub fn get(&self, op: DmlVerb) -> Option<&Policy> {
        match op {
            DmlVerb::Select => self.select.as_ref(),
            DmlVerb::Insert => self.insert.as_ref(),
            DmlVerb::Update => self.update.as_ref(),
            DmlVerb::Delete => self.delete.as_ref(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.select.is_none()
            && self.insert.is_none()
            && self.update.is_none()
            && self.delete.is_none()
    }
}

/// Evaluation context: the caller's identity and (for CHECK) the row under
/// test. `auth_id` is `None` for anon. `data` is the row map for `eval_policy`
/// (CHECK); `None` for USING compilation.
#[derive(Debug, Clone, Default)]
pub struct PolicyCtx {
    pub auth_id: Option<String>,
    pub data: Option<serde_json::Map<String, Json>>,
}

impl PolicyCtx {
    pub fn from_auth(ctx: &AuthCtx) -> Self {
        Self {
            auth_id: ctx.user_id().map(|s| s.to_string()),
            data: None,
        }
    }
    pub fn with_row(ctx: &AuthCtx, row: serde_json::Map<String, Json>) -> Self {
        Self {
            auth_id: ctx.user_id().map(|s| s.to_string()),
            data: Some(row),
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(String),
    #[error("unknown field in policy: {0:?}")]
    UnknownField(String),
    #[error("policy cannot target vector field: {0:?}")]
    VectorField(String),
    #[error("policy nesting exceeds max depth ({MAX_FILTER_DEPTH})")]
    TooDeep,
    #[error("$data ref {0:?} not available in this context")]
    DataUnavailable(String),
}

/// Resolve a leaf operand that may be a literal, `{"$auth":"id"}`, or
/// `{"$data":"<field>"}`. Returns the SQL `Value` to bind.
fn resolve_operand(operand: &Json, ctx: &PolicyCtx) -> Result<Value, PolicyError> {
    if let Json::Object(o) = operand {
        if let Some(k) = o.get("$auth") {
            // Only `{"$auth":"id"}` is defined in v1.
            if k.as_str() == Some("id") {
                return Ok(ctx.auth_id.clone().map(Value::Text).unwrap_or(Value::Null));
            }
            return Err(PolicyError::Parse(format!("unknown $auth ref: {k}")));
        }
        if let Some(f) = o.get("$data").and_then(|v| v.as_str()) {
            let row = ctx
                .data
                .as_ref()
                .ok_or_else(|| PolicyError::DataUnavailable(f.to_string()))?;
            return Ok(row.get(f).map(json_to_value).unwrap_or(Value::Null));
        }
    }
    Ok(json_to_value(operand))
}

pub fn compile_policy_using(
    schema: &CollectionSchema,
    ast: &FilterAst,
    ctx: &PolicyCtx,
) -> Result<(String, Vec<Value>), PolicyError> {
    let mut binds = Vec::new();
    let sql = compile_node(schema, ast, ctx, &mut binds, 0)?;
    Ok((sql, binds))
}

fn compile_node(
    schema: &CollectionSchema,
    node: &FilterAst,
    ctx: &PolicyCtx,
    binds: &mut Vec<Value>,
    depth: usize,
) -> Result<String, PolicyError> {
    if depth >= MAX_FILTER_DEPTH {
        return Err(PolicyError::TooDeep);
    }
    match node {
        FilterAst::And { and } => {
            if and.is_empty() {
                return Ok("1=1".into());
            }
            let parts: Result<Vec<_>, _> = and
                .iter()
                .map(|n| compile_node(schema, n, ctx, binds, depth + 1))
                .collect();
            Ok(format!("({})", parts?.join(" AND ")))
        }
        FilterAst::Or { or } => {
            if or.is_empty() {
                return Ok("1=0".into());
            }
            let parts: Result<Vec<_>, _> = or
                .iter()
                .map(|n| compile_node(schema, n, ctx, binds, depth + 1))
                .collect();
            Ok(format!("({})", parts?.join(" OR ")))
        }
        FilterAst::Not { not } => Ok(format!(
            "(NOT {})",
            compile_node(schema, not, ctx, binds, depth + 1)?
        )),
        FilterAst::Leaf(obj) => {
            if obj.len() != 1 {
                return Err(PolicyError::Parse(
                    "leaf must have exactly one key".into(),
                ));
            }
            let (key, body) = obj.iter().next().unwrap();
            // Special leaf: {"$authenticated": bool}.
            if key == "$authenticated" {
                let want = body.as_bool().unwrap_or(true);
                let is_auth = ctx.auth_id.is_some();
                return Ok(if is_auth == want {
                    "1=1".into()
                } else {
                    "1=0".into()
                });
            }
            compile_leaf(schema, key, body, ctx, binds)
        }
    }
}

fn validate_field(schema: &CollectionSchema, field: &str) -> Result<(), PolicyError> {
    if schema.vector_fields.iter().any(|v| v.name == field) {
        return Err(PolicyError::VectorField(field.to_string()));
    }
    // system columns id/created_at/updated_at are always present.
    let system = matches!(field, "id" | "created_at" | "updated_at");
    if !system && !schema.fields.iter().any(|f| f.name == field) {
        return Err(PolicyError::UnknownField(field.to_string()));
    }
    Ok(())
}

fn compile_leaf(
    schema: &CollectionSchema,
    field: &str,
    body: &Json,
    ctx: &PolicyCtx,
    binds: &mut Vec<Value>,
) -> Result<String, PolicyError> {
    validate_field(schema, field)?;
    let col = format!("\"{}\"", field.replace('"', "\"\""));
    // eq shorthand: {field: <scalar-or-ref>}
    if !matches!(body, Json::Object(_)) {
        binds.push(resolve_operand(body, ctx)?);
        return Ok(format!("{col} = ?"));
    }
    let op_obj = body.as_object().unwrap();
    // An object body is EITHER an operand ref ({"$auth"/"$data"}) used as eq
    // shorthand, OR an op object ({"$eq": ...}). Distinguish by key.
    if op_obj.contains_key("$auth") || op_obj.contains_key("$data") {
        binds.push(resolve_operand(body, ctx)?);
        return Ok(format!("{col} = ?"));
    }
    if op_obj.len() != 1 {
        return Err(PolicyError::Parse(format!(
            "field {field:?}: op object must have one key"
        )));
    }
    let (op, operand) = op_obj.iter().next().unwrap();
    match op.as_str() {
        "$eq" | "$ne" | "$gt" | "$gte" | "$lt" | "$lte" | "$like" | "eq" | "ne" | "gt" | "gte"
        | "lt" | "lte" | "like" => {
            let sql_op = match op.trim_start_matches('$') {
                "eq" => "=",
                "ne" => "<>",
                "gt" => ">",
                "gte" => ">=",
                "lt" => "<",
                "lte" => "<=",
                "like" => "LIKE",
                _ => unreachable!(),
            };
            binds.push(resolve_operand(operand, ctx)?);
            Ok(format!("{col} {sql_op} ?"))
        }
        "$in" | "$nin" | "in" | "nin" => {
            let arr = operand.as_array().ok_or_else(|| {
                PolicyError::Parse(format!("field {field:?}: {op} requires array"))
            })?;
            if arr.is_empty() {
                return Ok(if op.ends_with("in") && !op.contains("nin") {
                    "1=0".into()
                } else {
                    "1=1".into()
                });
            }
            let ph = vec!["?"; arr.len()].join(", ");
            for v in arr {
                binds.push(resolve_operand(v, ctx)?);
            }
            let kw = if op.contains("nin") { "NOT IN" } else { "IN" };
            Ok(format!("{col} {kw} ({ph})"))
        }
        "$is_null" | "$is_not_null" | "is_null" | "is_not_null" => {
            let kw = if op.contains("not") {
                "IS NOT NULL"
            } else {
                "IS NULL"
            };
            Ok(format!("{col} {kw}"))
        }
        other => Err(PolicyError::Parse(format!(
            "field {field:?}: unknown op {other:?}"
        ))),
    }
}

/// In-memory evaluation of a policy AST against a JSON row + caller context.
/// MUST agree with `compile_policy_using` (see the consistency corpus test).
/// Comparison semantics mirror SQLite's: numbers compare numerically, text
/// lexically, NULL comparisons are false (SQL `NULL = x` → not-true).
pub fn eval_policy(ast: &FilterAst, row: &serde_json::Map<String, Json>, ctx: &PolicyCtx) -> bool {
    eval_node(ast, row, ctx, 0)
}

fn eval_node(
    node: &FilterAst,
    row: &serde_json::Map<String, Json>,
    ctx: &PolicyCtx,
    depth: usize,
) -> bool {
    if depth >= MAX_FILTER_DEPTH {
        return false;
    }
    match node {
        FilterAst::And { and } => and.iter().all(|n| eval_node(n, row, ctx, depth + 1)),
        FilterAst::Or { or } => or.iter().any(|n| eval_node(n, row, ctx, depth + 1)),
        FilterAst::Not { not } => !eval_node(not, row, ctx, depth + 1),
        FilterAst::Leaf(obj) => {
            if obj.len() != 1 {
                return false;
            }
            let Some((key, body)) = obj.iter().next() else {
                return false;
            };
            if key == "$authenticated" {
                let want = body.as_bool().unwrap_or(true);
                return ctx.auth_id.is_some() == want;
            }
            eval_leaf(key, body, row, ctx)
        }
    }
}

/// Resolve an operand JSON to a comparable `Value` (mirrors `resolve_operand`
/// but returns the json_to_value-shaped SQL value for comparison).
fn resolve_eval_operand(operand: &Json, ctx: &PolicyCtx) -> Value {
    if let Json::Object(o) = operand {
        if o.get("$auth").and_then(|v| v.as_str()) == Some("id") {
            return ctx.auth_id.clone().map(Value::Text).unwrap_or(Value::Null);
        }
        if let Some(f) = o.get("$data").and_then(|v| v.as_str()) {
            return ctx
                .data
                .as_ref()
                .and_then(|d| d.get(f))
                .map(json_to_value)
                .unwrap_or(Value::Null);
        }
    }
    json_to_value(operand)
}

fn eval_leaf(field: &str, body: &Json, row: &serde_json::Map<String, Json>, ctx: &PolicyCtx) -> bool {
    let lhs = row.get(field).map(json_to_value).unwrap_or(Value::Null);
    let (op, operand): (&str, &Json) = if let Json::Object(o) = body {
        if o.contains_key("$auth") || o.contains_key("$data") {
            ("$eq", body)
        } else if o.len() == 1 {
            let (k, v) = o.iter().next().unwrap();
            (k.as_str(), v)
        } else {
            return false;
        }
    } else {
        ("$eq", body)
    };
    match op.trim_start_matches('$') {
        "is_null" => return matches!(lhs, Value::Null),
        "is_not_null" => return !matches!(lhs, Value::Null),
        "in" | "nin" => {
            let arr = match operand.as_array() {
                Some(a) => a,
                None => return false,
            };
            // Mirror SQLite: a NULL lhs is excluded by both IN and NOT IN
            // (NULL IN/NOT IN (...) is not-true), so eval must agree with the
            // compiled `col NOT IN (?)`. Without this, `!hit` wrongly returns
            // true for a NULL row on $nin (fail-open on the anon SSE filter).
            if matches!(lhs, Value::Null) {
                return false;
            }
            let hit = arr.iter().any(|v| {
                value_cmp(&lhs, &resolve_eval_operand(v, ctx)) == Some(std::cmp::Ordering::Equal)
            });
            return if op.contains("nin") { !hit } else { hit };
        }
        _ => {}
    }
    let rhs = resolve_eval_operand(operand, ctx);
    let ord = value_cmp(&lhs, &rhs);
    match op.trim_start_matches('$') {
        "eq" => ord == Some(std::cmp::Ordering::Equal),
        "ne" => ord.is_some() && ord != Some(std::cmp::Ordering::Equal),
        "gt" => ord == Some(std::cmp::Ordering::Greater),
        "gte" => matches!(ord, Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)),
        "lt" => ord == Some(std::cmp::Ordering::Less),
        "lte" => matches!(ord, Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)),
        "like" => like_match(&lhs, &rhs),
        _ => false,
    }
}

/// Three-way compare of two SQL `Value`s. `None` when either is NULL or types
/// are not comparable (matches SQL: NULL comparisons are never true).
///
/// Cross-storage-class operand/column pairs (e.g. a TEXT literal vs an INTEGER
/// column) — where this in-memory `None` would diverge from SQLite's
/// storage-class ordering in the compiled SQL — are rejected up front by
/// `validate_policy`, so a stored policy can never reach this with mismatched
/// classes. See `check_operand_class` (Fix 2, evaluator lockstep).
fn value_cmp(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    use Value::*;
    match (a, b) {
        (Null, _) | (_, Null) => None,
        (Integer(x), Integer(y)) => Some(x.cmp(y)),
        (Real(x), Real(y)) => x.partial_cmp(y),
        (Integer(x), Real(y)) => (*x as f64).partial_cmp(y),
        (Real(x), Integer(y)) => x.partial_cmp(&(*y as f64)),
        (Text(x), Text(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

/// Minimal SQL LIKE: `%` = any run, `_` = one char. ASCII case-insensitive
/// (the `(?si)` regex flags), matching SQLite's default `LIKE` so the two
/// evaluators stay in lockstep.
fn like_match(lhs: &Value, rhs: &Value) -> bool {
    let (Value::Text(s), Value::Text(pat)) = (lhs, rhs) else {
        return false;
    };
    let re = pat.chars().fold(String::from("(?si)^"), |mut acc, c| {
        match c {
            '%' => acc.push_str(".*"),
            '_' => acc.push('.'),
            c => acc.push_str(&regex_lite_escape(c)),
        }
        acc
    }) + "$";
    regex_lite::Regex::new(&re)
        .map(|r| r.is_match(s))
        .unwrap_or(false)
}

fn regex_lite_escape(c: char) -> String {
    if "\\.^$|?*+()[]{}".contains(c) {
        format!("\\{c}")
    } else {
        c.to_string()
    }
}

/// Coarse SQLite storage class of a literal JSON operand: `Some("text")` or
/// `Some("num")`. `None` for operands we never value-compare across a class
/// boundary (JSON null, arrays, objects/`$auth`/`$data` dynamic refs).
fn literal_class(operand: &Json) -> Option<&'static str> {
    match operand {
        Json::String(_) => Some("text"),
        // bool is stored as INTEGER (json_to_value → Value::Integer), so it
        // is numeric for class purposes.
        Json::Number(_) | Json::Bool(_) => Some("num"),
        _ => None,
    }
}

/// Coarse SQLite storage class of a column's declared `sql_type`: `Some("text")`
/// for TEXT-affinity columns, `Some("num")` for INTEGER/REAL. `None` for BLOB or
/// anything we don't classify (system columns id/created_at/updated_at) — those
/// are not type-checked.
fn column_class(sql_type: &str) -> Option<&'static str> {
    let t = sql_type.to_ascii_uppercase();
    if t.contains("INT") || t.contains("REAL") || t.contains("FLOA") || t.contains("DOUB") {
        Some("num")
    } else if t.contains("CHAR") || t.contains("TEXT") || t.contains("CLOB") {
        Some("text")
    } else {
        None
    }
}

/// Reject a literal operand whose storage class disagrees with the target
/// column's — the one case where `value_cmp` (in-memory) and the compiled SQL
/// would order the pair differently, breaking evaluator lockstep. Only fires
/// for LITERAL operands against a DECLARED column with a known class; `$auth` /
/// `$data` (dynamic) and NULL operands are passed through unchecked.
fn check_operand_class(
    schema: &CollectionSchema,
    field: &str,
    operand: &Json,
) -> Result<(), PolicyError> {
    let (Some(lit), Some(col)) = (
        literal_class(operand),
        schema
            .fields
            .iter()
            .find(|f| f.name == field)
            .and_then(|f| column_class(&f.sql_type)),
    ) else {
        return Ok(());
    };
    if lit != col {
        return Err(PolicyError::Parse(format!(
            "field {field:?}: operand storage class ({lit}) does not match column type ({col}) \
             — cross-class comparisons diverge between the eval and SQL policy evaluators"
        )));
    }
    Ok(())
}

/// Walk every leaf of `ast` and run `check_operand_class` on its literal
/// operand(s). Dynamic refs, `is_null`/`is_not_null` (no operand), and unknown
/// fields are skipped here (field existence is enforced by `compile_policy_using`).
fn check_ast_operand_classes(schema: &CollectionSchema, ast: &FilterAst) -> Result<(), PolicyError> {
    match ast {
        FilterAst::And { and } => and
            .iter()
            .try_for_each(|n| check_ast_operand_classes(schema, n)),
        FilterAst::Or { or } => or
            .iter()
            .try_for_each(|n| check_ast_operand_classes(schema, n)),
        FilterAst::Not { not } => check_ast_operand_classes(schema, not),
        FilterAst::Leaf(obj) => {
            let Some((key, body)) = obj.iter().next() else {
                return Ok(());
            };
            if key == "$authenticated" {
                return Ok(());
            }
            // eq shorthand: {field: <scalar-or-dynamic-ref>}
            let op_obj = match body {
                Json::Object(o)
                    if !o.contains_key("$auth") && !o.contains_key("$data") =>
                {
                    o
                }
                _ => return check_operand_class(schema, key, body),
            };
            let Some((op, operand)) = op_obj.iter().next() else {
                return Ok(());
            };
            let bare = op.trim_start_matches('$');
            match bare {
                "is_null" | "is_not_null" => Ok(()),
                "in" | "nin" => operand
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .try_for_each(|v| check_operand_class(schema, key, v))
                    })
                    .unwrap_or(Ok(())),
                _ => check_operand_class(schema, key, operand),
            }
        }
    }
}

/// Validate a policy at write time: every field reference must resolve against
/// the schema and the grammar must be well-formed. We validate by compiling
/// each clause against a probe context (so `$auth`/`$data`/`$authenticated`
/// operands are accepted) and discarding the SQL — only the field/grammar
/// checks (`UnknownField`, `VectorField`, `TooDeep`, `Parse`) are wanted. In
/// addition we reject literal operands whose storage class mismatches the
/// target column (Fix 2 — keeps the two policy evaluators in lockstep).
pub fn validate_policy(
    schema: &CollectionSchema,
    op: DmlVerb,
    policy: &Policy,
) -> Result<(), PolicyError> {
    // A probe ctx: authenticated, with a data map containing every field so
    // $data refs validate. The compiled SQL is thrown away — we only want the
    // field/grammar checks to fire.
    let mut data = serde_json::Map::new();
    for f in &schema.fields {
        data.insert(f.name.clone(), Json::Null);
    }
    let ctx = PolicyCtx {
        auth_id: Some("u-probe".into()),
        data: Some(data),
    };
    if let Some(u) = &policy.using {
        compile_policy_using(schema, u, &ctx)?;
        check_ast_operand_classes(schema, u)?;
    }
    if let Some(c) = &policy.check {
        compile_policy_using(schema, c, &ctx)?;
        check_ast_operand_classes(schema, c)?;
        // $data is only meaningful in CHECK; in USING a $data ref on a delete
        // is nonsensical but harmless. v1 does not separately reject it.
        let _ = op;
    }
    Ok(())
}

/// Resolve the explicit USING predicate that applies to `op` for this caller.
/// Service callers bypass all explicit policies (returns `None`); User/Anon get
/// the collection's op policy `using` clause if one is set. `owner_field` is
/// **not** consulted here — the existing `compute_owner_filter` + cap gate
/// handle it independently (spec §6.2/§7).
pub fn effective_policy_using<'a>(
    ctx: &AuthCtx,
    schema: &'a CollectionSchema,
    op: DmlVerb,
) -> Option<&'a FilterAst> {
    if matches!(ctx, AuthCtx::Service { .. }) {
        return None;
    }
    schema.policies.get(op).and_then(|p| p.using.as_ref())
}

/// Resolve the explicit CHECK predicate that applies to `op` for this caller.
/// Same bypass rule as `effective_policy_using`.
pub fn effective_policy_check<'a>(
    ctx: &AuthCtx,
    schema: &'a CollectionSchema,
    op: DmlVerb,
) -> Option<&'a FilterAst> {
    if matches!(ctx, AuthCtx::Service { .. }) {
        return None;
    }
    schema.policies.get(op).and_then(|p| p.check.as_ref())
}

/// Convenience: resolve + compile the USING for `op` into `(sql_fragment, binds)`.
/// `None` when there is no explicit policy (or the caller is service).
pub fn policy_using_sql(
    ctx: &AuthCtx,
    schema: &CollectionSchema,
    op: DmlVerb,
) -> Result<Option<(String, Vec<Value>)>, PolicyError> {
    match effective_policy_using(ctx, schema, op) {
        None => Ok(None),
        Some(ast) => Ok(Some(compile_policy_using(
            schema,
            ast,
            &PolicyCtx::from_auth(ctx),
        )?)),
    }
}

/// Sentinel error returned from inside a `with_writer` transaction closure to
/// roll the transaction back when a CHECK clause rejects the row. Detected by
/// `is_policy_check_failure` in the handler match.
pub fn policy_check_sentinel() -> rusqlite::Error {
    rusqlite::Error::SqlInputError {
        error: rusqlite::ffi::Error::new(1),
        msg: "POLICY_CHECK_FAILED".into(),
        sql: String::new(),
        offset: 0,
    }
}

pub fn is_policy_check_failure(e: &rusqlite::Error) -> bool {
    e.to_string().contains("POLICY_CHECK_FAILED")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::schema::{CollectionSchema, DmlVerb, Field};
    use rusqlite::types::Value;
    use std::collections::BTreeSet;

    fn schema(fields: &[&str]) -> CollectionSchema {
        CollectionSchema {
            name: "posts".into(),
            fields: fields
                .iter()
                .map(|n| Field {
                    name: n.to_string(),
                    sql_type: "TEXT".into(),
                    nullable: true,
                    pk: false,
                    default_value: None,
                    foreign_key: None,
                    description: None,
                })
                .collect(),
            indices: vec![],
            row_count: 0,
            anon_caps: BTreeSet::new(),
            owner_field: None,
            read_scope: None,
            vector_fields: vec![],
            realtime_enabled: true,
            description: None,
            policies: Default::default(),
        }
    }

    #[test]
    fn compile_auth_ref_binds_user_id() {
        let s = schema(&["author"]);
        let ast: FilterAst = serde_json::from_str(r#"{"author":{"$eq":{"$auth":"id"}}}"#).unwrap();
        let ctx = PolicyCtx {
            auth_id: Some("u-abc".into()),
            data: None,
        };
        let (sql, binds) = compile_policy_using(&s, &ast, &ctx).unwrap();
        assert_eq!(sql, r#""author" = ?"#);
        assert_eq!(binds, vec![Value::Text("u-abc".into())]);
    }

    #[test]
    fn compile_auth_ref_for_anon_is_null_bind() {
        let s = schema(&["author"]);
        let ast: FilterAst = serde_json::from_str(r#"{"author":{"$eq":{"$auth":"id"}}}"#).unwrap();
        let ctx = PolicyCtx {
            auth_id: None,
            data: None,
        };
        let (sql, binds) = compile_policy_using(&s, &ast, &ctx).unwrap();
        assert_eq!(sql, r#""author" = ?"#);
        assert_eq!(binds, vec![Value::Null]); // "author" = NULL → no rows, as intended
    }

    #[test]
    fn compile_authenticated_leaf() {
        let s = schema(&["author"]);
        let user: FilterAst = serde_json::from_str(r#"{"$authenticated":true}"#).unwrap();
        let ctx_user = PolicyCtx {
            auth_id: Some("u-x".into()),
            data: None,
        };
        let ctx_anon = PolicyCtx {
            auth_id: None,
            data: None,
        };
        assert_eq!(compile_policy_using(&s, &user, &ctx_user).unwrap().0, "1=1");
        assert_eq!(compile_policy_using(&s, &user, &ctx_anon).unwrap().0, "1=0");
    }

    #[test]
    fn compile_plain_literal_still_works() {
        let s = schema(&["status"]);
        let ast: FilterAst = serde_json::from_str(r#"{"status":"published"}"#).unwrap();
        let ctx = PolicyCtx::default();
        let (sql, binds) = compile_policy_using(&s, &ast, &ctx).unwrap();
        assert_eq!(sql, r#""status" = ?"#);
        assert_eq!(binds, vec![Value::Text("published".into())]);
    }

    #[test]
    fn compile_or_published_or_owner() {
        let s = schema(&["status", "author"]);
        let ast: FilterAst = serde_json::from_str(
            r#"{"or":[{"status":"published"},{"and":[{"$authenticated":true},{"author":{"$eq":{"$auth":"id"}}}]}]}"#,
        )
        .unwrap();
        let ctx = PolicyCtx {
            auth_id: Some("u-1".into()),
            data: None,
        };
        let (sql, binds) = compile_policy_using(&s, &ast, &ctx).unwrap();
        assert_eq!(sql, r#"("status" = ? OR (1=1 AND "author" = ?))"#);
        assert_eq!(
            binds,
            vec![Value::Text("published".into()), Value::Text("u-1".into())]
        );
    }

    #[test]
    fn compile_unknown_field_rejected() {
        let s = schema(&["status"]);
        let ast: FilterAst = serde_json::from_str(r#"{"ghost":"x"}"#).unwrap();
        let err = compile_policy_using(&s, &ast, &PolicyCtx::default()).unwrap_err();
        assert!(matches!(err, PolicyError::UnknownField(_)));
    }

    #[test]
    fn policy_roundtrips_json() {
        let raw = r#"{"using":{"status":"published"},"check":{"author":{"$eq":{"$auth":"id"}}}}"#;
        let p: Policy = serde_json::from_str(raw).unwrap();
        assert!(p.using.is_some());
        assert!(p.check.is_some());
        let back = serde_json::to_string(&p).unwrap();
        let p2: Policy = serde_json::from_str(&back).unwrap();
        assert!(p2.using.is_some() && p2.check.is_some());
    }

    #[test]
    fn collection_policies_get_by_verb() {
        let cp = CollectionPolicies {
            select: Some(Policy::default()),
            ..Default::default()
        };
        assert!(cp.get(DmlVerb::Select).is_some());
        assert!(cp.get(DmlVerb::Insert).is_none());
    }

    #[test]
    fn policy_ctx_from_anon_has_no_auth_id() {
        let ctx = crate::auth::middleware::AuthCtx::Anon;
        let pc = PolicyCtx::from_auth(&ctx);
        assert!(pc.auth_id.is_none());
    }

    #[test]
    fn eval_eq_against_row() {
        let row: serde_json::Map<String, Json> =
            serde_json::from_str(r#"{"status":"published","author":"u-1"}"#).unwrap();
        let published: FilterAst = serde_json::from_str(r#"{"status":"published"}"#).unwrap();
        let ctx = PolicyCtx {
            auth_id: Some("u-1".into()),
            data: None,
        };
        assert!(eval_policy(&published, &row, &ctx));
        let draft: FilterAst = serde_json::from_str(r#"{"status":"draft"}"#).unwrap();
        assert!(!eval_policy(&draft, &row, &ctx));
    }

    #[test]
    fn eval_auth_ref_and_authenticated() {
        let row: serde_json::Map<String, Json> =
            serde_json::from_str(r#"{"author":"u-1"}"#).unwrap();
        let owner: FilterAst = serde_json::from_str(r#"{"author":{"$eq":{"$auth":"id"}}}"#).unwrap();
        assert!(eval_policy(
            &owner,
            &row,
            &PolicyCtx {
                auth_id: Some("u-1".into()),
                data: None
            }
        ));
        assert!(!eval_policy(
            &owner,
            &row,
            &PolicyCtx {
                auth_id: Some("u-2".into()),
                data: None
            }
        ));
        // anon: author = NULL comparison is false
        assert!(!eval_policy(
            &owner,
            &row,
            &PolicyCtx {
                auth_id: None,
                data: None
            }
        ));

        let authed: FilterAst = serde_json::from_str(r#"{"$authenticated":true}"#).unwrap();
        assert!(eval_policy(
            &authed,
            &row,
            &PolicyCtx {
                auth_id: Some("u-1".into()),
                data: None
            }
        ));
        assert!(!eval_policy(
            &authed,
            &row,
            &PolicyCtx {
                auth_id: None,
                data: None
            }
        ));
    }

    #[test]
    fn eval_and_or_not() {
        let row: serde_json::Map<String, Json> =
            serde_json::from_str(r#"{"status":"published","n":5}"#).unwrap();
        let ast: FilterAst =
            serde_json::from_str(r#"{"or":[{"status":"published"},{"n":{"$gt":100}}]}"#).unwrap();
        assert!(eval_policy(&ast, &row, &PolicyCtx::default()));
    }

    #[test]
    fn validate_rejects_unknown_field() {
        let s = schema(&["status"]);
        let p: Policy = serde_json::from_str(r#"{"using":{"ghost":"x"}}"#).unwrap();
        assert!(matches!(
            validate_policy(&s, DmlVerb::Select, &p),
            Err(PolicyError::UnknownField(_))
        ));
    }

    #[test]
    fn validate_accepts_good_policy() {
        let s = schema(&["status", "author"]);
        let p: Policy = serde_json::from_str(
            r#"{"using":{"or":[{"status":"published"},{"author":{"$eq":{"$auth":"id"}}}]}}"#,
        )
        .unwrap();
        assert!(validate_policy(&s, DmlVerb::Select, &p).is_ok());
    }

    // Build a schema where each field has an explicit storage class, so the
    // cross-storage-class validate check (Fix 2) can be exercised.
    fn schema_typed(fields: &[(&str, &str)]) -> CollectionSchema {
        let mut s = schema(&[]);
        s.fields = fields
            .iter()
            .map(|(n, ty)| Field {
                name: n.to_string(),
                sql_type: ty.to_string(),
                nullable: true,
                pk: false,
                default_value: None,
                foreign_key: None,
                description: None,
            })
            .collect();
        s
    }

    #[test]
    fn validate_rejects_cross_storage_class_literal() {
        // INTEGER column `n` vs a string literal — the in-memory `value_cmp`
        // and the compiled SQL order these differently, so the policy must be
        // refused at config time (eval/compile lockstep).
        let s = schema_typed(&[("n", "INTEGER")]);
        let p: Policy = serde_json::from_str(r#"{"using":{"n":{"$gt":"abc"}}}"#).unwrap();
        let err = validate_policy(&s, DmlVerb::Select, &p).unwrap_err();
        assert!(
            matches!(err, PolicyError::Parse(ref m) if m.contains("n")),
            "expected a Parse error naming field `n`, got {err:?}"
        );

        // Mirror case: a TEXT column compared with a numeric literal.
        let s2 = schema_typed(&[("status", "TEXT")]);
        let p2: Policy = serde_json::from_str(r#"{"using":{"status":{"$gt":5}}}"#).unwrap();
        assert!(validate_policy(&s2, DmlVerb::Select, &p2).is_err());

        // Array operands (`$in`) are element-checked too.
        let p3: Policy = serde_json::from_str(r#"{"using":{"n":{"$in":[1,"two",3]}}}"#).unwrap();
        assert!(validate_policy(&s, DmlVerb::Select, &p3).is_err());
    }

    #[test]
    fn validate_accepts_same_storage_class_literal() {
        // Same-class comparisons, $auth/$data dynamic operands, NULL literals,
        // and is_null/is_not_null (no operand) must all still validate.
        let s = schema_typed(&[("n", "INTEGER"), ("status", "TEXT"), ("author", "TEXT")]);
        let p: Policy = serde_json::from_str(r#"{"using":{"n":{"$gt":5}}}"#).unwrap();
        assert!(validate_policy(&s, DmlVerb::Select, &p).is_ok());
        let p2: Policy = serde_json::from_str(r#"{"using":{"status":{"$eq":"published"}}}"#).unwrap();
        assert!(validate_policy(&s, DmlVerb::Select, &p2).is_ok());
        // boolean literal against an INTEGER column is numeric/numeric → ok.
        let p3: Policy = serde_json::from_str(r#"{"using":{"n":{"$eq":true}}}"#).unwrap();
        assert!(validate_policy(&s, DmlVerb::Select, &p3).is_ok());
        // dynamic operand against an INTEGER column: cannot be type-checked, allowed.
        let p4: Policy = serde_json::from_str(r#"{"using":{"n":{"$eq":{"$auth":"id"}}}}"#).unwrap();
        assert!(validate_policy(&s, DmlVerb::Select, &p4).is_ok());
        // NULL literal is cross-class compatible (never value-compared).
        let p5: Policy = serde_json::from_str(r#"{"using":{"n":{"$ne":null}}}"#).unwrap();
        assert!(validate_policy(&s, DmlVerb::Select, &p5).is_ok());
        // is_null / is_not_null carry no operand.
        let p6: Policy = serde_json::from_str(r#"{"using":{"n":{"$is_null":true}}}"#).unwrap();
        assert!(validate_policy(&s, DmlVerb::Select, &p6).is_ok());
    }

    #[test]
    fn service_bypasses_policy() {
        let mut s = schema(&["status"]);
        s.policies.select = Some(Policy {
            using: Some(serde_json::from_str(r#"{"status":"published"}"#).unwrap()),
            check: None,
        });
        let svc = crate::auth::middleware::AuthCtx::Service { admin_id: None };
        assert!(effective_policy_using(&svc, &s, DmlVerb::Select).is_none());
        let anon = crate::auth::middleware::AuthCtx::Anon;
        assert!(effective_policy_using(&anon, &s, DmlVerb::Select).is_some());
    }

    #[test]
    fn policy_using_sql_compiles_for_anon() {
        let mut s = schema(&["author"]);
        s.policies.update = Some(Policy {
            using: Some(serde_json::from_str(r#"{"author":{"$eq":{"$auth":"id"}}}"#).unwrap()),
            check: None,
        });
        let anon = crate::auth::middleware::AuthCtx::Anon;
        let out = policy_using_sql(&anon, &s, DmlVerb::Update).unwrap();
        let (frag, binds) = out.unwrap();
        assert_eq!(frag, r#""author" = ?"#);
        assert_eq!(binds, vec![rusqlite::types::Value::Null]); // anon → NULL → no rows
    }

    #[test]
    fn owner_field_is_not_consulted_by_resolver() {
        let mut s = schema(&["author"]);
        s.owner_field = Some("author".into());
        s.read_scope = Some("own".into());
        let user = crate::auth::middleware::AuthCtx::User {
            user_id: "u-1".into(),
            token_hash: "h".into(),
        };
        // No explicit policy → resolver returns None; owner_field is handled by
        // compute_owner_filter at the call site, not here.
        assert!(effective_policy_using(&user, &s, DmlVerb::Select).is_none());
    }
}

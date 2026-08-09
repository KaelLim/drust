//! Filter AST used by /search. Intentionally minimal: a tenant-supplied
//! tree of `and/or/not` boolean nodes over leaves of the shape
//! `{field: scalar}` (eq shorthand) or `{field: {op: scalar | scalar[]}}`.
//! No raw SQL fragments — every operand binds as a `?` parameter, so
//! anon and user callers can safely supply filters.
//!
//! Vector fields cannot appear in the filter; that returns a typed
//! error so the handler maps to `400 FILTER_VECTOR_FIELD`.

use crate::storage::schema::{CollectionSchema, FtsIndex};
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
    /// A `$fts` reserved-key operand error that already carries its stable
    /// SCREAMING_SNAKE sentinel code (e.g. `FTS_INDEX_NOT_FOUND`). Kept distinct
    /// from `Parse` so the read faces can surface the exact code instead of the
    /// generic `FILTER_PARSE_ERROR` bucket. A malformed `$fts` *shape* (missing
    /// keys / wrong types) stays a `Parse` — only a resolved-but-invalid operand
    /// (unknown index) becomes `Fts`.
    #[error("{code}: {message}")]
    Fts { code: &'static str, message: String },
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
            let (key, body) = obj.iter().next().unwrap();
            // Reserved leaf key: full-text search. Handled here (like policy.rs's
            // `$authenticated`) so it never reaches validate_field / compile_leaf,
            // which would treat "$fts" as a column name. A `$fts` mixed with other
            // keys is already rejected above by the `obj.len() != 1` guard.
            if key == "$fts" {
                return compile_fts(schema, body, binds);
            }
            validate_field(schema, key)?;
            compile_leaf(key, body, binds)
        }
    }
}

/// Double-quote an identifier for interpolation. Every id passed here is
/// drust-controlled — a schema field name or a `fts_head_name`-derived head —
/// so this only guards the pathological embedded quote.
fn q(id: &str) -> String {
    format!("\"{}\"", id.replace('"', "\"\""))
}

/// The caller-facing shape hint for a malformed `$fts` operand (missing/extra
/// keys, wrong value types). Surfaced as a `Parse` error, in the same
/// teaching-hint style as [`filter_shape_hint`] / the v1.58.6 double-encoding
/// fix — never serde's opaque variant noise.
fn fts_shape_error() -> FilterError {
    FilterError::Parse(
        "$fts operand must be an object {\"index\":\"<name>\",\"query\":\"<text>\"} \
         with exactly those two string keys"
            .to_string(),
    )
}

/// Escape a LIKE pattern's metacharacters (`\` `%` `_`) so a `$fts` trigram
/// fallback matches the query literally under `ESCAPE '\'`.
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Compile a `$fts` reserved-key operand `{"index":"<name>","query":"<text>"}`.
///
/// SECURITY: the head table is derived ONLY from `fts_head_name(schema.name,
/// entry.name)` after resolving `index` in `schema.fts_indexes` — never from
/// caller input. The MATCH string and every LIKE pattern are `?`-bound. The
/// emitted subquery yields candidate rowids only; row authorization stays on the
/// PARENT via the owner/RLS/caps WHERE this fragment is AND-ed into, so a User
/// only ever searches their own rows. This keeps `$fts` in the STRUCTURED camp
/// (anon/user-safe by construction).
/// Resolve a `$fts` operand body to its validated index entry + query string,
/// WITHOUT emitting SQL or binds. Shared by [`compile_fts`] and [`fts_probes`]
/// so the "which index / MATCH-vs-fallback" decision can never drift between the
/// compiler and the FTS_QUERY_INVALID pre-probe walker. Enforces the exact
/// `{index, query}` shape (`fts_shape_error` on a violation) and resolves the
/// name in `schema.fts_indexes` (`FTS_INDEX_NOT_FOUND` when absent).
fn resolve_fts<'a>(
    schema: &'a CollectionSchema,
    body: &'a Json,
) -> Result<(&'a FtsIndex, &'a str), FilterError> {
    let obj = body.as_object().ok_or_else(fts_shape_error)?;
    // Exactly {index, query}; reject missing/extra keys or non-string values.
    let index = obj
        .get("index")
        .and_then(Json::as_str)
        .ok_or_else(fts_shape_error)?;
    let query = obj
        .get("query")
        .and_then(Json::as_str)
        .ok_or_else(fts_shape_error)?;
    if obj.len() != 2 {
        return Err(fts_shape_error());
    }
    // Resolve the index by NAME in the registry — the head is derived, never
    // taken from caller input.
    let entry = schema
        .fts_indexes
        .iter()
        .find(|i| i.name == index)
        .ok_or_else(|| FilterError::Fts {
            code: "FTS_INDEX_NOT_FOUND",
            message: format!(
                "no fts index named {index:?} on collection {:?}",
                schema.name
            ),
        })?;
    Ok((entry, query))
}

/// Whether a resolved `$fts` operand compiles to an fts5 MATCH subquery (true)
/// or the trigram short-term LIKE fallback (false).
///
/// Tokenizer rule (Wave 2 M3 Global Constraint): a MATCH is correct when the
/// tokenizer is unicode61, OR when every whitespace-separated term is ≥ 3 chars.
/// A trigram index cannot satisfy a term shorter than one trigram, and fts5
/// silently treats such a term as a satisfied no-op — so ANY sub-3-char term
/// (measured in CHARS, not bytes, for CJK) forces the substring fallback. An
/// empty / all-whitespace query is vacuously all-≥3 → MATCH. This is the SINGLE
/// authority the compiler and the probe walker both consult.
fn fts_uses_match(entry: &FtsIndex, query: &str) -> bool {
    entry.tokenizer != "trigram" || query.split_whitespace().all(|t| t.chars().count() >= 3)
}

fn compile_fts(
    schema: &CollectionSchema,
    body: &Json,
    binds: &mut Vec<Value>,
) -> Result<String, FilterError> {
    let (entry, query) = resolve_fts(schema, body)?;
    let head_q = q(&crate::storage::search_names::fts_head_name(
        &schema.name,
        &entry.name,
    ));

    if fts_uses_match(entry, query) {
        binds.push(Value::Text(query.to_string()));
        return Ok(format!(
            "\"id\" IN (SELECT rowid FROM {head_q} WHERE {head_q} MATCH ?)"
        ));
    }

    // Trigram short-term fallback (a deliberate v1.60 simplification): the WHOLE
    // query is one phrase-substring `%…%` LIKE per indexed field, `?`-bound and
    // `\`-escaped. Phrase-substring — NOT per-term — semantics: a per-term MATCH
    // would silently satisfy the sub-3-char term as a no-op and over-match (e.g.
    // 'zz 醫院年度' would match rows lacking 'zz'), so the short term is never
    // dropped. A sub-3-char CJK 2-gram like 慈濟 thus still matches.
    let pattern = format!("%{}%", like_escape(query));
    let mut ors = Vec::with_capacity(entry.fields.len());
    for f in &entry.fields {
        ors.push(format!("{} LIKE ? ESCAPE '\\'", q(f)));
        binds.push(Value::Text(pattern.clone()));
    }
    Ok(format!("({})", ors.join(" OR ")))
}

/// A structural `FTS_QUERY_INVALID` pre-probe: the head table and the `?`-bound
/// query string for a single `$fts` MATCH operand. Only MATCH-path operands
/// yield a probe — the trigram short-term LIKE fallback cannot carry an fts5
/// MATCH syntax error, so there is nothing to pre-validate there.
#[derive(Debug, Clone, PartialEq)]
pub struct FtsProbe {
    /// Unquoted head name (`_system_search_fts$<coll>$<index>`); the runner
    /// double-quotes it.
    pub head: String,
    /// The raw `?`-bound MATCH query text (caller-supplied).
    pub query: String,
}

/// Walk a [`FilterAst`] and collect the MATCH-path `$fts` probes.
///
/// Mirrors [`compile_node`]'s traversal and [`compile_fts`]'s resolution +
/// MATCH/LIKE branch EXACTLY (via the shared [`resolve_fts`] / [`fts_uses_match`]),
/// so a probe is emitted for precisely the operands that will reach fts5's MATCH
/// parser at STEP time. A malformed operand *shape* or an unknown index is
/// ignored here — `compile` surfaces those as `Parse` / `Fts` before the probe
/// would ever run; this walker's sole job is to expose the MATCH expressions so a
/// caller can validate their syntax on a reader and map a failure to
/// `400 FTS_QUERY_INVALID` (STRUCTURAL, never message-substring — see
/// `.claude/rules/write-path.md`).
pub fn fts_probes(schema: &CollectionSchema, ast: &FilterAst) -> Vec<FtsProbe> {
    let mut out = Vec::new();
    collect_fts_probes(schema, ast, 0, &mut out);
    out
}

fn collect_fts_probes(
    schema: &CollectionSchema,
    node: &FilterAst,
    depth: usize,
    out: &mut Vec<FtsProbe>,
) {
    if depth >= MAX_FILTER_DEPTH {
        return;
    }
    match node {
        FilterAst::And { and } => {
            for n in and {
                collect_fts_probes(schema, n, depth + 1, out);
            }
        }
        FilterAst::Or { or } => {
            for n in or {
                collect_fts_probes(schema, n, depth + 1, out);
            }
        }
        FilterAst::Not { not } => collect_fts_probes(schema, not, depth + 1, out),
        FilterAst::Leaf(obj) => {
            if obj.len() != 1 {
                return;
            }
            let (key, body) = obj.iter().next().unwrap();
            if key != "$fts" {
                return;
            }
            if let Ok((entry, query)) = resolve_fts(schema, body)
                && fts_uses_match(entry, query)
            {
                out.push(FtsProbe {
                    head: crate::storage::search_names::fts_head_name(&schema.name, &entry.name),
                    query: query.to_string(),
                });
            }
        }
    }
}

/// Run one MATCH probe on a reader connection:
/// `SELECT rowid FROM "<head>" WHERE "<head>" MATCH ? LIMIT 1`. fts5 parses the
/// MATCH expression only at STEP time and raises a plain SQLITE_ERROR, so this
/// forces one `step()` to surface a malformed query STRUCTURALLY. `Ok(())` means
/// the MATCH is well-formed; the caller maps `Err` to `400 FTS_QUERY_INVALID`.
pub fn run_fts_probe(conn: &rusqlite::Connection, probe: &FtsProbe) -> rusqlite::Result<()> {
    let head_q = q(&probe.head);
    let sql = format!("SELECT rowid FROM {head_q} WHERE {head_q} MATCH ? LIMIT 1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params![probe.query])?;
    // Step once to force fts5 to parse the MATCH expression.
    let _ = rows.next()?;
    Ok(())
}

/// Pre-validate every `$fts` MATCH operand in `filter` on a reader BEFORE the
/// main list/count/aggregate/search statement runs, so a malformed fts5 MATCH
/// becomes a clean `400 FTS_QUERY_INVALID` instead of a generic 500 from the main
/// statement failing mid-scan. Shared by every anon-reachable read face (`/list`
/// rows+count, `/aggregate`, `/search`, and the MCP list/aggregate mirror) so the
/// mapping is written once, not five times.
///
/// Returns `Ok(Ok(()))` when there is nothing to probe or every MATCH is
/// well-formed; `Ok(Err(msg))` with the redacted sqlite message when a MATCH is
/// malformed (caller → 400 `FTS_QUERY_INVALID`); `Err(e)` only on a genuine
/// reader/DB failure (caller → 500 `DB_ERROR`). The probe head is guaranteed to
/// exist (it is derived from a resolved `schema.fts_indexes` entry), so in
/// practice the only way a probe errors is a malformed MATCH.
pub async fn probe_fts_queries(
    pool: &crate::storage::pool::SharedTenantPool,
    schema: &CollectionSchema,
    filter: Option<&FilterAst>,
) -> rusqlite::Result<Result<(), String>> {
    let probes = match filter {
        Some(ast) => fts_probes(schema, ast),
        None => return Ok(Ok(())),
    };
    if probes.is_empty() {
        return Ok(Ok(()));
    }
    pool.with_reader(move |c| {
        for p in &probes {
            if let Err(e) = run_fts_probe(c, p) {
                return Ok(Err(crate::error::sqlite_error_without_sql(&e)));
            }
        }
        Ok(Ok(()))
    })
    .await
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
            fts_indexes: vec![],
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

    // --- FTS_QUERY_INVALID pre-probe walker (Task 6) ---

    fn fts_idx(name: &str, fields: &[&str], tok: &str) -> FtsIndex {
        FtsIndex {
            name: name.into(),
            fields: fields.iter().map(|s| s.to_string()).collect(),
            tokenizer: tok.into(),
        }
    }

    fn schema_with_fts(index: FtsIndex) -> CollectionSchema {
        let mut s = schema_with(&[("title", "text"), ("body", "text")], &[]);
        s.name = "notes".into();
        s.fts_indexes = vec![index];
        s
    }

    /// The lockstep pin: `fts_probes` emits a probe for EXACTLY the operands
    /// `compile` renders as a MATCH subquery, and none for the LIKE fallback.
    #[test]
    fn fts_probes_track_the_compile_match_branch() {
        // trigram, all-long term → MATCH path → one probe with derived head+query.
        let s = schema_with_fts(fts_idx("main", &["title", "body"], "trigram"));
        let a = leaf(r#"{"$fts":{"index":"main","query":"hospital"}}"#);
        let (sql, _) = compile(&s, &a).unwrap();
        assert!(sql.contains("MATCH"), "expected MATCH compile: {sql}");
        let probes = fts_probes(&s, &a);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].head, "_system_search_fts$notes$main");
        assert_eq!(probes[0].query, "hospital");

        // trigram, short CJK term → LIKE fallback → NO probe (LIKE can't hold a
        // MATCH syntax error).
        let short = leaf(r#"{"$fts":{"index":"main","query":"慈濟"}}"#);
        let (sql2, _) = compile(&s, &short).unwrap();
        assert!(!sql2.contains("MATCH"), "expected LIKE fallback: {sql2}");
        assert!(fts_probes(&s, &short).is_empty());

        // unicode61 short term still MATCHes → one probe.
        let u = schema_with_fts(fts_idx("uni", &["title"], "unicode61"));
        let ua = leaf(r#"{"$fts":{"index":"uni","query":"慈濟"}}"#);
        assert_eq!(fts_probes(&u, &ua).len(), 1);
    }

    #[test]
    fn fts_probes_walk_boolean_nodes_and_skip_non_fts() {
        let s = schema_with_fts(fts_idx("main", &["title", "body"], "trigram"));
        let nested: FilterAst = serde_json::from_str(
            r#"{"and":[{"title":"x"},{"or":[{"$fts":{"index":"main","query":"hospital"}}]}]}"#,
        )
        .unwrap();
        assert_eq!(fts_probes(&s, &nested).len(), 1);
        // A plain leaf carries no probe.
        assert!(fts_probes(&s, &leaf(r#"{"title":"x"}"#)).is_empty());
        // An unknown index resolves to no probe (compile surfaces the sentinel).
        assert!(
            fts_probes(
                &s,
                &leaf(r#"{"$fts":{"index":"ghost","query":"hospital"}}"#)
            )
            .is_empty()
        );
    }
}

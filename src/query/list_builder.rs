//! Structured list-SQL builder for `POST /t/<id>/collections/<c>/list`
//! and the MCP `list_records` tool. Reuses [`vector_filter::compile`] so
//! the same `FilterAst` parser feeds `/search` and `/list`.
//!
//! Every operand is bound as a `?` parameter — no user-supplied input
//! lands in SQL textually. The optional owner clause is appended after
//! the user filter; both share the same `binds` vector in deterministic
//! order (filter binds first, owner bind last).
//!
//! See spec: `docs/superpowers/specs/2026-05-22-drust-v121-design.md` §2.

use crate::query::vector_filter::{self, FilterAst, FilterError};
use crate::storage::schema::CollectionSchema;
use rusqlite::types::Value;
use serde::Deserialize;
use thiserror::Error;

/// System-managed sortable columns that exist on every drust collection
/// regardless of user-declared fields. Mirrors the `_system_*` column
/// triad added by every `create_collection`.
const SYSTEM_SORTABLE: &[&str] = &["id", "created_at", "updated_at"];

/// Default per-page when caller omits `per_page`. Matches GET `/records`
/// for behavioural parity.
const DEFAULT_PER_PAGE: u32 = 20;
const MAX_PER_PAGE: u32 = 500;

#[derive(Debug, Deserialize, Default)]
pub struct ListRequest {
    #[serde(default)]
    pub filter: Option<FilterAst>,
    #[serde(default)]
    pub sort: Option<SortSpec>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
    #[serde(default)]
    pub select: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SortSpec {
    pub field: String,
    #[serde(default = "default_dir")]
    pub dir: String,
}

fn default_dir() -> String {
    "desc".into()
}

/// Body of `POST /t/<id>/collections/<c>/aggregate` (M1). Same filter/owner/
/// policy authorization surface as `/list`, but projects aggregate metrics with
/// an optional `group_by`.
#[derive(Debug, Deserialize, Default)]
pub struct AggregateRequest {
    #[serde(default)]
    pub filter: Option<FilterAst>,
    #[serde(default)]
    pub group_by: Option<Vec<String>>,
    pub metrics: Vec<AggregateMetric>,
    #[serde(default)]
    pub sort: Option<SortSpec>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AggregateMetric {
    /// One of `count | sum | avg | min | max`.
    pub op: String,
    /// The column to aggregate. Required for every op except `count`
    /// (`count` with no field is `COUNT(*)`).
    #[serde(default)]
    pub field: Option<String>,
    /// Optional result-column name; defaults to `<op>` / `<op>_<field>`.
    #[serde(default, rename = "as")]
    pub alias: Option<String>,
}

#[derive(Debug, Error)]
pub enum ListError {
    #[error(transparent)]
    Filter(#[from] FilterError),
    #[error("sort field unknown: {0:?}")]
    SortFieldUnknown(String),
    #[error("sort field is vector: {0:?}")]
    SortVectorField(String),
    #[error("sort dir must be asc or desc")]
    SortDirInvalid,
    #[error("select field unknown: {0:?}")]
    SelectFieldUnknown(String),
    #[error("page out of range")]
    PageRangeInvalid,
    // ── aggregate (M1) ──
    #[error("aggregate needs at least one metric")]
    NoMetrics,
    #[error("aggregate op invalid: {0:?}")]
    MetricOpInvalid(String),
    #[error("aggregate metric field required for op: {0:?}")]
    MetricFieldRequired(String),
    #[error("aggregate metric field unknown: {0:?}")]
    MetricFieldUnknown(String),
    #[error("aggregate metric field is vector: {0:?}")]
    MetricVectorField(String),
    #[error("group_by field unknown: {0:?}")]
    GroupFieldUnknown(String),
    #[error("group_by field is vector: {0:?}")]
    GroupVectorField(String),
    #[error("aggregate alias invalid: {0:?}")]
    AliasInvalid(String),
}

/// Map a [`ListError`] to its stable `CODE` string (the code half of drust's
/// `CODE: message` convention). Shared by the REST `/list` handler
/// (`records_list::map_list_error`, which additionally picks the HTTP status)
/// and the edge-function enforcement core (`functions::enforce::enforced_list`)
/// so a structured-list failure surfaces the SAME typed code on both faces
/// instead of a Rust `Debug` rendering (e.g. `SORT_DIR_INVALID`, never
/// `SortDirInvalid`). Any new `ListError` variant must extend BOTH this fn and
/// `map_list_error` in lockstep.
pub fn list_error_code(e: &ListError) -> &'static str {
    match e {
        ListError::Filter(FilterError::Parse(_)) => "FILTER_PARSE_ERROR",
        ListError::Filter(FilterError::UnknownField(_)) => "FILTER_UNKNOWN_FIELD",
        ListError::Filter(FilterError::VectorField(_)) => "FILTER_VECTOR_FIELD",
        ListError::Filter(FilterError::TooDeep) => "FILTER_TOO_DEEP",
        // BadOperand + any future Filter variant fall under the parse bucket,
        // matching map_list_error's `Filter(other)` arm.
        ListError::Filter(_) => "FILTER_PARSE_ERROR",
        ListError::SortFieldUnknown(_) => "SORT_FIELD_UNKNOWN",
        ListError::SortVectorField(_) => "SORT_VECTOR_FIELD",
        ListError::SortDirInvalid => "SORT_DIR_INVALID",
        ListError::SelectFieldUnknown(_) => "SELECT_FIELD_UNKNOWN",
        ListError::PageRangeInvalid => "PAGE_RANGE_INVALID",
        ListError::NoMetrics => "AGG_NO_METRICS",
        ListError::MetricOpInvalid(_) => "AGG_OP_INVALID",
        ListError::MetricFieldRequired(_) => "AGG_FIELD_REQUIRED",
        ListError::MetricFieldUnknown(_) => "AGG_FIELD_UNKNOWN",
        ListError::MetricVectorField(_) => "AGG_FIELD_VECTOR",
        ListError::GroupFieldUnknown(_) => "AGG_GROUP_UNKNOWN",
        ListError::GroupVectorField(_) => "AGG_GROUP_VECTOR",
        ListError::AliasInvalid(_) => "AGG_ALIAS_INVALID",
    }
}

/// Compile a structured list request into `(list_sql, count_sql, binds)`.
///
/// Both SQLs use the same bind vector. The caller must supply identical
/// `?`-bound parameters when running the list and count queries.
///
/// `owner` carries `(field_name, user_id)` when the caller is a user
/// token on an owner-scoped collection — drust appends
/// `AND "<field>" = ?` to the WHERE and pushes the user_id bind last.
pub fn build_structured_list_sql(
    schema: &CollectionSchema,
    req: &ListRequest,
    owner: Option<(&str, &str)>,
    policy_clause: Option<(String, Vec<Value>)>,
) -> Result<(String, String, Vec<Value>), ListError> {
    let table = q(&schema.name);

    // (1) projection — caller-supplied `select` (vector-filtered) or all
    // non-vector declared fields.
    let projection = match &req.select {
        None => projection_default(schema),
        Some(cols) => {
            for c in cols {
                if !field_exists(schema, c) {
                    return Err(ListError::SelectFieldUnknown(c.clone()));
                }
            }
            let filtered: Vec<String> = cols
                .iter()
                .filter(|c| !is_vector_field(schema, c))
                .map(|c| q(c))
                .collect();
            if filtered.is_empty() {
                // All requested columns were vector → fall back to id so
                // the SELECT remains syntactically valid.
                "\"id\"".to_string()
            } else {
                filtered.join(", ")
            }
        }
    };

    // (2) WHERE — user filter + optional owner clause + explicit policy.
    // Shared with `/aggregate` via `build_where_clause`, so both faces keep the
    // SAME row-authorization (owner + RLS + `?`-bound filter) by construction.
    let (where_clause, binds) = build_where_clause(schema, &req.filter, owner, policy_clause)?;

    // (3) ORDER BY — sort field allowlist (declared fields + system) and
    // dir must be exactly "asc"|"desc".
    let (sort_field, dir_kw) = match &req.sort {
        None => ("created_at".to_string(), "DESC"),
        Some(s) => {
            let known =
                field_exists(schema, &s.field) || SYSTEM_SORTABLE.contains(&s.field.as_str());
            if !known {
                return Err(ListError::SortFieldUnknown(s.field.clone()));
            }
            if is_vector_field(schema, &s.field) {
                return Err(ListError::SortVectorField(s.field.clone()));
            }
            let dir = match s.dir.as_str() {
                "asc" | "ASC" => "ASC",
                "desc" | "DESC" => "DESC",
                _ => return Err(ListError::SortDirInvalid),
            };
            (s.field.clone(), dir)
        }
    };

    // (4) LIMIT / OFFSET — clamp to [1, 500]; reject out-of-range
    // explicitly (no silent clamp).
    let per_page = req.per_page.unwrap_or(DEFAULT_PER_PAGE);
    let page = req.page.unwrap_or(1);
    if per_page == 0 || per_page > MAX_PER_PAGE || page == 0 {
        return Err(ListError::PageRangeInvalid);
    }
    let offset = (page as u64 - 1) * (per_page as u64);

    let list_sql = format!(
        "SELECT {projection} FROM {table}{where_clause} \
         ORDER BY {sort_col} {dir_kw} LIMIT {per_page} OFFSET {offset}",
        sort_col = q(&sort_field),
    );
    let count_sql = format!("SELECT COUNT(*) FROM {table}{where_clause}");
    Ok((list_sql, count_sql, binds))
}

/// The shared WHERE fragment (`" WHERE …"` with a leading space, or empty) for
/// both `/list` and `/aggregate`: the user `FilterAst` (compiled to `?`-bound
/// SQL), the optional owner clause, and the optional explicit-policy USING —
/// AND-ed in a fixed order so the `?` binds line up. Extracting this keeps the
/// two faces' row-authorization identical by construction.
fn build_where_clause(
    schema: &CollectionSchema,
    filter: &Option<FilterAst>,
    owner: Option<(&str, &str)>,
    policy_clause: Option<(String, Vec<Value>)>,
) -> Result<(String, Vec<Value>), ListError> {
    let mut binds: Vec<Value> = Vec::new();
    let mut wheres: Vec<String> = Vec::new();
    if let Some(ast) = filter {
        let (sql, mut filter_binds) = vector_filter::compile(schema, ast)?;
        wheres.push(format!("({sql})"));
        binds.append(&mut filter_binds);
    }
    if let Some((field, uid)) = owner {
        wheres.push(format!("{} = ?", q(field)));
        binds.push(Value::Text(uid.to_string()));
    }
    if let Some((frag, mut pbinds)) = policy_clause {
        wheres.push(format!("({frag})"));
        binds.append(&mut pbinds);
    }
    let where_clause = if wheres.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", wheres.join(" AND "))
    };
    Ok((where_clause, binds))
}

/// The five aggregate operations drust exposes — a fixed allowlist, never
/// interpolated from raw user text.
fn is_valid_agg_op(op: &str) -> bool {
    matches!(op, "count" | "sum" | "avg" | "min" | "max")
}

/// A result-column alias must be a strict identifier: it is echoed into the
/// SELECT text (quoted) AND becomes a JSON key in the response, so it may not
/// carry arbitrary bytes.
fn valid_alias(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 64
        && (a.as_bytes()[0].is_ascii_alphabetic() || a.as_bytes()[0] == b'_')
        && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A column referenced by an aggregate metric or `group_by` must be a declared
/// (or system) non-vector field — same allowlist discipline as sort/select.
fn validate_agg_field(schema: &CollectionSchema, f: &str) -> Result<(), ListError> {
    if !(field_exists(schema, f) || SYSTEM_SORTABLE.contains(&f)) {
        return Err(ListError::MetricFieldUnknown(f.to_string()));
    }
    if is_vector_field(schema, f) {
        return Err(ListError::MetricVectorField(f.to_string()));
    }
    Ok(())
}

/// Compile an aggregate request into `(sql, binds)`. The WHERE (filter + owner +
/// policy) is built by the same `build_where_clause` as `/list`, so a User only
/// aggregates rows they may read and anon obeys `anon_caps`/policy — the row
/// authorization is in lockstep by construction. Group/metric columns go
/// through the schema allowlist; ops through `is_valid_agg_op`; every value is
/// `?`-bound. No aggregate function is exposed beyond the fixed five.
pub fn build_aggregate_sql(
    schema: &CollectionSchema,
    req: &AggregateRequest,
    owner: Option<(&str, &str)>,
    policy_clause: Option<(String, Vec<Value>)>,
) -> Result<(String, Vec<Value>), ListError> {
    let table = q(&schema.name);
    if req.metrics.is_empty() {
        return Err(ListError::NoMetrics);
    }

    // (1) GROUP BY columns — declared/system, non-vector.
    let group_cols: Vec<String> = match &req.group_by {
        None => Vec::new(),
        Some(cols) => {
            let mut out = Vec::new();
            for c in cols {
                if !(field_exists(schema, c) || SYSTEM_SORTABLE.contains(&c.as_str())) {
                    return Err(ListError::GroupFieldUnknown(c.clone()));
                }
                if is_vector_field(schema, c) {
                    return Err(ListError::GroupVectorField(c.clone()));
                }
                out.push(c.clone());
            }
            out
        }
    };

    // (2) SELECT list — group cols (quoted) then metric exprs.
    let mut select_parts: Vec<String> = group_cols.iter().map(|c| q(c)).collect();
    let mut aliases: Vec<String> = Vec::new();
    for m in &req.metrics {
        let op = m.op.to_ascii_lowercase();
        if !is_valid_agg_op(&op) {
            return Err(ListError::MetricOpInvalid(m.op.clone()));
        }
        let (expr, default_alias) = if op == "count" {
            match &m.field {
                None => ("COUNT(*)".to_string(), "count".to_string()),
                Some(f) => {
                    validate_agg_field(schema, f)?;
                    (format!("COUNT({})", q(f)), format!("count_{f}"))
                }
            }
        } else {
            let f = m
                .field
                .as_ref()
                .ok_or_else(|| ListError::MetricFieldRequired(op.clone()))?;
            validate_agg_field(schema, f)?;
            (
                format!("{}({})", op.to_ascii_uppercase(), q(f)),
                format!("{op}_{f}"),
            )
        };
        let alias = match &m.alias {
            Some(a) => {
                if !valid_alias(a) {
                    return Err(ListError::AliasInvalid(a.clone()));
                }
                a.clone()
            }
            None => default_alias,
        };
        select_parts.push(format!("{expr} AS {}", q(&alias)));
        aliases.push(alias);
    }
    let select_list = select_parts.join(", ");

    // (3) WHERE — identical to /list.
    let (where_clause, binds) = build_where_clause(schema, &req.filter, owner, policy_clause)?;

    // (4) GROUP BY.
    let group_by_clause = if group_cols.is_empty() {
        String::new()
    } else {
        format!(
            " GROUP BY {}",
            group_cols
                .iter()
                .map(|c| q(c))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    // (5) ORDER BY — optional; must reference a group column or a metric alias
    // (both are in the SELECT). dir asc|desc.
    let order_clause = match &req.sort {
        None => String::new(),
        Some(s) => {
            let known =
                group_cols.iter().any(|c| c == &s.field) || aliases.iter().any(|a| a == &s.field);
            if !known {
                return Err(ListError::SortFieldUnknown(s.field.clone()));
            }
            let dir = match s.dir.as_str() {
                "asc" | "ASC" => "ASC",
                "desc" | "DESC" => "DESC",
                _ => return Err(ListError::SortDirInvalid),
            };
            format!(" ORDER BY {} {dir}", q(&s.field))
        }
    };

    // (6) LIMIT / OFFSET — bound the number of groups returned.
    let per_page = req.per_page.unwrap_or(DEFAULT_PER_PAGE);
    let page = req.page.unwrap_or(1);
    if per_page == 0 || per_page > MAX_PER_PAGE || page == 0 {
        return Err(ListError::PageRangeInvalid);
    }
    let offset = (page as u64 - 1) * (per_page as u64);

    let sql = format!(
        "SELECT {select_list} FROM {table}{where_clause}{group_by_clause}{order_clause} \
         LIMIT {per_page} OFFSET {offset}"
    );
    Ok((sql, binds))
}

// ── helpers ────────────────────────────────────────────────────────────

fn q(id: &str) -> String {
    format!("\"{}\"", id.replace('"', "\"\""))
}

/// True if `name` is any declared field on the collection — declared
/// scalar fields, vector fields, or one of the system columns (`id` /
/// `created_at` / `updated_at`). Vector fields are recognised here so
/// the caller can reject them with a typed `SortVectorField` /
/// `SelectFieldUnknown`-shaped error rather than `SortFieldUnknown`.
fn field_exists(s: &CollectionSchema, name: &str) -> bool {
    s.fields.iter().any(|f| f.name == name)
        || s.vector_fields.iter().any(|v| v.name == name)
        || SYSTEM_SORTABLE.contains(&name)
}

fn is_vector_field(s: &CollectionSchema, name: &str) -> bool {
    s.vector_fields.iter().any(|v| v.name == name)
}

fn projection_default(s: &CollectionSchema) -> String {
    let cols: Vec<String> = s
        .fields
        .iter()
        .filter(|f| !is_vector_field(s, &f.name))
        .map(|f| q(&f.name))
        .collect();
    if cols.is_empty() {
        // Empty schema (defensive) — keep SELECT syntactically valid.
        "*".to_string()
    } else {
        cols.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::schema::{Field, VectorField};
    use std::collections::BTreeSet;

    fn fixture_schema() -> CollectionSchema {
        CollectionSchema {
            name: "posts".into(),
            fields: vec![
                Field {
                    name: "title".into(),
                    sql_type: "TEXT".into(),
                    nullable: false,
                    pk: false,
                    default_value: None,
                    foreign_key: None,
                    description: None,
                    ..Default::default()
                },
                Field {
                    name: "score".into(),
                    sql_type: "INTEGER".into(),
                    nullable: false,
                    pk: false,
                    default_value: None,
                    foreign_key: None,
                    description: None,
                    ..Default::default()
                },
                Field {
                    name: "owner_id".into(),
                    sql_type: "TEXT".into(),
                    nullable: false,
                    pk: false,
                    default_value: None,
                    foreign_key: None,
                    description: None,
                    ..Default::default()
                },
            ],
            indices: vec![],
            row_count: 0,
            anon_caps: BTreeSet::new(),
            user_caps: BTreeSet::new(),
            owner_field: None,
            read_scope: None,
            vector_fields: vec![VectorField {
                name: "embedding".into(),
                dim: 8,
            }],
            realtime_enabled: true,
            audit_enabled: true,
            description: None,
            policies: Default::default(),
        }
    }

    fn leaf(json: &str) -> FilterAst {
        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json).unwrap();
        FilterAst::Leaf(obj)
    }

    fn agg_metric(op: &str, field: Option<&str>, alias: Option<&str>) -> AggregateMetric {
        AggregateMetric {
            op: op.into(),
            field: field.map(String::from),
            alias: alias.map(String::from),
        }
    }

    #[test]
    fn aggregate_count_star_default_alias() {
        let s = fixture_schema();
        let req = AggregateRequest {
            metrics: vec![agg_metric("count", None, None)],
            ..Default::default()
        };
        let (sql, binds) = build_aggregate_sql(&s, &req, None, None).unwrap();
        assert!(sql.contains("COUNT(*) AS \"count\""), "sql: {sql}");
        assert!(sql.contains("FROM \"posts\""), "sql: {sql}");
        assert!(!sql.contains("GROUP BY"), "no group: {sql}");
        assert!(sql.contains("LIMIT 20 OFFSET 0"), "sql: {sql}");
        assert!(binds.is_empty());
    }

    #[test]
    fn aggregate_sum_group_by_with_alias() {
        let s = fixture_schema();
        let req = AggregateRequest {
            group_by: Some(vec!["title".into()]),
            metrics: vec![agg_metric("sum", Some("score"), Some("total"))],
            ..Default::default()
        };
        let (sql, _b) = build_aggregate_sql(&s, &req, None, None).unwrap();
        assert!(
            sql.contains("SELECT \"title\", SUM(\"score\") AS \"total\""),
            "sql: {sql}"
        );
        assert!(sql.contains("GROUP BY \"title\""), "sql: {sql}");
    }

    #[test]
    fn aggregate_owner_clause_in_lockstep() {
        // The owner clause + bind must appear exactly as /list builds it — the
        // shared build_where_clause guarantees this.
        let s = fixture_schema();
        let req = AggregateRequest {
            metrics: vec![agg_metric("count", None, None)],
            ..Default::default()
        };
        let (sql, binds) = build_aggregate_sql(&s, &req, Some(("owner_id", "u1")), None).unwrap();
        assert!(
            sql.contains("WHERE \"owner_id\" = ?"),
            "owner clause: {sql}"
        );
        assert_eq!(binds.len(), 1, "binds: {binds:?}");
        assert!(matches!(binds.first(), Some(Value::Text(t)) if t == "u1"));
    }

    #[test]
    fn aggregate_rejects_bad_inputs() {
        let s = fixture_schema();
        let one = |m: AggregateMetric| AggregateRequest {
            metrics: vec![m],
            ..Default::default()
        };
        assert!(matches!(
            build_aggregate_sql(&s, &AggregateRequest::default(), None, None),
            Err(ListError::NoMetrics)
        ));
        assert!(matches!(
            build_aggregate_sql(
                &s,
                &one(agg_metric("median", Some("score"), None)),
                None,
                None
            ),
            Err(ListError::MetricOpInvalid(_))
        ));
        assert!(matches!(
            build_aggregate_sql(&s, &one(agg_metric("sum", None, None)), None, None),
            Err(ListError::MetricFieldRequired(_))
        ));
        assert!(matches!(
            build_aggregate_sql(&s, &one(agg_metric("sum", Some("nope"), None)), None, None),
            Err(ListError::MetricFieldUnknown(_))
        ));
        assert!(matches!(
            build_aggregate_sql(
                &s,
                &one(agg_metric("avg", Some("embedding"), None)),
                None,
                None
            ),
            Err(ListError::MetricVectorField(_))
        ));
        assert!(matches!(
            build_aggregate_sql(
                &s,
                &one(agg_metric("count", None, Some("a b; drop"))),
                None,
                None
            ),
            Err(ListError::AliasInvalid(_))
        ));
    }

    #[test]
    fn aggregate_sort_by_alias_or_group_only() {
        let s = fixture_schema();
        let req = AggregateRequest {
            group_by: Some(vec!["title".into()]),
            metrics: vec![agg_metric("count", None, Some("n"))],
            sort: Some(SortSpec {
                field: "n".into(),
                dir: "desc".into(),
            }),
            ..Default::default()
        };
        let (sql, _b) = build_aggregate_sql(&s, &req, None, None).unwrap();
        assert!(sql.contains("ORDER BY \"n\" DESC"), "sort by alias: {sql}");

        let bad = AggregateRequest {
            metrics: vec![agg_metric("count", None, None)],
            sort: Some(SortSpec {
                field: "score".into(),
                dir: "asc".into(),
            }),
            ..Default::default()
        };
        assert!(matches!(
            build_aggregate_sql(&s, &bad, None, None),
            Err(ListError::SortFieldUnknown(_))
        ));
    }

    #[test]
    fn empty_request_yields_default_list_sql() {
        let s = fixture_schema();
        let (list, count, binds) =
            build_structured_list_sql(&s, &ListRequest::default(), None, None).unwrap();
        assert!(list.contains("FROM \"posts\""), "list: {list}");
        assert!(
            list.contains("ORDER BY \"created_at\" DESC"),
            "list: {list}"
        );
        assert!(list.contains("LIMIT 20 OFFSET 0"), "list: {list}");
        assert!(
            list.contains("\"title\""),
            "should select declared fields: {list}"
        );
        assert!(
            !list.contains("\"embedding\""),
            "must not select vector: {list}"
        );
        assert_eq!(count, "SELECT COUNT(*) FROM \"posts\"");
        assert!(binds.is_empty());
    }

    #[test]
    fn filter_only_uses_question_mark_binds() {
        let s = fixture_schema();
        let req = ListRequest {
            filter: Some(leaf(r#"{"title":"hello"}"#)),
            ..Default::default()
        };
        let (list, count, binds) = build_structured_list_sql(&s, &req, None, None).unwrap();
        assert!(list.contains("WHERE (\"title\" = ?)"), "list: {list}");
        assert!(count.contains("WHERE (\"title\" = ?)"), "count: {count}");
        assert_eq!(binds.len(), 1);
        match &binds[0] {
            Value::Text(t) => assert_eq!(t, "hello"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn sort_asc_compiles() {
        let s = fixture_schema();
        let req = ListRequest {
            sort: Some(SortSpec {
                field: "score".into(),
                dir: "asc".into(),
            }),
            ..Default::default()
        };
        let (list, _c, _b) = build_structured_list_sql(&s, &req, None, None).unwrap();
        assert!(list.contains("ORDER BY \"score\" ASC"), "list: {list}");
    }

    #[test]
    fn owner_clause_appends_bind_last() {
        let s = fixture_schema();
        let req = ListRequest::default();
        let (list, count, binds) =
            build_structured_list_sql(&s, &req, Some(("owner_id", "u-deadbeef")), None).unwrap();
        assert!(list.contains("WHERE \"owner_id\" = ?"), "list: {list}");
        assert!(count.contains("WHERE \"owner_id\" = ?"), "count: {count}");
        assert_eq!(binds.len(), 1);
        match &binds[0] {
            Value::Text(t) => assert_eq!(t, "u-deadbeef"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn policy_clause_ands_after_owner() {
        let s = fixture_schema();
        let req = ListRequest::default();
        let policy = Some((r#""score" > ?"#.to_string(), vec![Value::Integer(10)]));
        let (list, _count, binds) =
            build_structured_list_sql(&s, &req, Some(("owner_id", "u-1")), policy).unwrap();
        assert!(
            list.contains(r#"WHERE "owner_id" = ? AND ("score" > ?)"#),
            "list: {list}"
        );
        // owner bind first, policy bind second
        assert_eq!(binds.len(), 2);
        assert!(matches!(binds[0], Value::Text(_)));
        assert!(matches!(binds[1], Value::Integer(10)));
    }

    #[test]
    fn filter_and_owner_combined_binds_in_order() {
        let s = fixture_schema();
        let req = ListRequest {
            filter: Some(leaf(r#"{"score":{"gt":5}}"#)),
            sort: Some(SortSpec {
                field: "id".into(),
                dir: "desc".into(),
            }),
            ..Default::default()
        };
        let (list, _c, binds) =
            build_structured_list_sql(&s, &req, Some(("owner_id", "u-1234")), None).unwrap();
        // Filter clause first, owner clause AND-joined second.
        assert!(
            list.contains("WHERE (\"score\" > ?) AND \"owner_id\" = ?"),
            "list: {list}"
        );
        assert!(list.contains("ORDER BY \"id\" DESC"), "list: {list}");
        assert_eq!(binds.len(), 2);
        // Order: filter bind (5), then owner bind (u-1234).
        match &binds[0] {
            Value::Integer(5) => {}
            other => panic!("expected Integer(5), got {other:?}"),
        }
        match &binds[1] {
            Value::Text(t) => assert_eq!(t, "u-1234"),
            other => panic!("expected Text(u-1234), got {other:?}"),
        }
    }

    #[test]
    fn sort_field_unknown_rejected() {
        let s = fixture_schema();
        let req = ListRequest {
            sort: Some(SortSpec {
                field: "ghost".into(),
                dir: "asc".into(),
            }),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(matches!(err, ListError::SortFieldUnknown(_)), "got {err:?}");
    }

    #[test]
    fn sort_vector_field_rejected() {
        let s = fixture_schema();
        let req = ListRequest {
            sort: Some(SortSpec {
                field: "embedding".into(),
                dir: "asc".into(),
            }),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(matches!(err, ListError::SortVectorField(_)), "got {err:?}");
    }

    #[test]
    fn sort_dir_invalid_rejected() {
        let s = fixture_schema();
        let req = ListRequest {
            sort: Some(SortSpec {
                field: "score".into(),
                dir: "sideways".into(),
            }),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(matches!(err, ListError::SortDirInvalid), "got {err:?}");
    }

    #[test]
    fn per_page_too_large_rejected() {
        let s = fixture_schema();
        let req = ListRequest {
            per_page: Some(501),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(matches!(err, ListError::PageRangeInvalid), "got {err:?}");
    }

    #[test]
    fn per_page_zero_rejected() {
        let s = fixture_schema();
        let req = ListRequest {
            per_page: Some(0),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(matches!(err, ListError::PageRangeInvalid), "got {err:?}");
    }

    #[test]
    fn page_zero_rejected() {
        let s = fixture_schema();
        let req = ListRequest {
            page: Some(0),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(matches!(err, ListError::PageRangeInvalid), "got {err:?}");
    }

    #[test]
    fn select_unknown_field_rejected() {
        let s = fixture_schema();
        let req = ListRequest {
            select: Some(vec!["title".into(), "ghost".into()]),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(
            matches!(err, ListError::SelectFieldUnknown(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn select_drops_vector_field_silently() {
        let s = fixture_schema();
        let req = ListRequest {
            select: Some(vec!["title".into(), "embedding".into()]),
            ..Default::default()
        };
        let (list, _c, _b) = build_structured_list_sql(&s, &req, None, None).unwrap();
        assert!(list.contains("\"title\""), "list: {list}");
        assert!(
            !list.contains("\"embedding\""),
            "vector must be dropped: {list}"
        );
    }

    #[test]
    fn vector_field_in_filter_propagates_typed_error() {
        let s = fixture_schema();
        let req = ListRequest {
            filter: Some(leaf(r#"{"embedding":[0.0]}"#)),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(
            matches!(err, ListError::Filter(FilterError::VectorField(_))),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_filter_field_propagates() {
        let s = fixture_schema();
        let req = ListRequest {
            filter: Some(leaf(r#"{"ghost":"x"}"#)),
            ..Default::default()
        };
        let err = build_structured_list_sql(&s, &req, None, None).unwrap_err();
        assert!(
            matches!(err, ListError::Filter(FilterError::UnknownField(_))),
            "got {err:?}"
        );
    }

    #[test]
    fn pagination_offset_computed() {
        let s = fixture_schema();
        let req = ListRequest {
            page: Some(3),
            per_page: Some(7),
            ..Default::default()
        };
        let (list, _c, _b) = build_structured_list_sql(&s, &req, None, None).unwrap();
        assert!(list.contains("LIMIT 7 OFFSET 14"), "list: {list}");
    }
}

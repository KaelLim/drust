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

    // (2) WHERE — user filter + optional owner clause.
    let mut binds: Vec<Value> = Vec::new();
    let mut wheres: Vec<String> = Vec::new();
    if let Some(ast) = &req.filter {
        let (sql, mut filter_binds) = vector_filter::compile(schema, ast)?;
        wheres.push(format!("({sql})"));
        binds.append(&mut filter_binds);
    }
    if let Some((field, uid)) = owner {
        wheres.push(format!("{} = ?", q(field)));
        binds.push(Value::Text(uid.to_string()));
    }
    // Explicit-policy USING — AND-ed alongside the unchanged owner clause.
    // The fragment is already `?`-bound; its binds append after the owner
    // bind so the parameter order matches the `?` order in the assembled SQL.
    if let Some((frag, mut pbinds)) = policy_clause {
        wheres.push(format!("({frag})"));
        binds.append(&mut pbinds);
    }
    let where_clause = if wheres.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", wheres.join(" AND "))
    };

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
            description: None,
            policies: Default::default(),
        }
    }

    fn leaf(json: &str) -> FilterAst {
        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json).unwrap();
        FilterAst::Leaf(obj)
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

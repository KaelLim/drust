use crate::mcp::server::DrustMcp;
use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::executor::{ExecError, execute_read_query};
use crate::query::list_builder::{
    self, ListError, ListRequest, SortSpec,
};
use crate::query::vector_filter::{FilterAst, FilterError};
use crate::storage::schema::is_protected_collection;
use rusqlite::types::{Value, ValueRef};
use serde_json::json;

/// Wrap a string message in `rusqlite::Error::SqliteFailure` so its `Display`
/// renders the message verbatim. `rusqlite::Error::InvalidQuery` — the
/// obvious-looking variant — is wrong: its `Display` is hard-coded to
/// `"Query is not read-only"`, which surfaces as a confusing error for
/// every authorizer rejection (including things that ARE read-only, like
/// `SELECT * FROM sqlite_master`).
fn as_rusqlite_error(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(msg))
}

pub async fn query(s: &DrustMcp, sql: &str) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql_owned = sql.to_string();
    let qr = pool
        .with_reader(move |c| {
            execute_read_query(c, &sql_owned, 10_000, 16_384).map_err(|e| match e {
                ExecError::TooLarge { bytes, limit } => {
                    as_rusqlite_error(format!("query too large: {bytes} bytes (limit {limit})"))
                }
                ExecError::Timeout(ms) => {
                    as_rusqlite_error(format!("query timed out after {ms}ms"))
                }
                ExecError::Sql(msg) => as_rusqlite_error(format!("query error: {msg}")),
                ExecError::Forbidden(detail) => {
                    let low = detail.to_lowercase();
                    let msg = if low.contains("sqlite_master")
                        || low.contains("sqlite_temp_master")
                        || low.contains("sqlite_schema")
                    {
                        format!(
                            "access to SQLite metadata tables is denied — use \
                             `list_collections` or `describe_collection` to inspect \
                             schema (underlying: {detail})"
                        )
                    } else {
                        format!(
                            "`query` is read-only — use `insert_record` / \
                             `update_record` / `delete_record` for row writes, or \
                             `create_collection` / `drop_collection` / `add_field` / \
                             `drop_field` for schema changes (underlying: {detail})"
                        )
                    };
                    as_rusqlite_error(msg)
                }
            })
        })
        .await?;
    Ok(serde_json::to_value(qr)?)
}

/// MCP arg shape for `list_records`. Mirrors REST `POST /list` 1:1.
///
/// `filter` is typed as `serde_json::Value` (not `FilterAst`) because
/// `FilterAst` is a serde `untagged` enum whose `schemars::JsonSchema`
/// output would surface raw enum-variant noise to the LLM tool catalog.
/// We parse to `FilterAst` inline so the LLM still sees a friendly
/// `object` shape in the tool description and the parser still validates
/// the structure.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListRecordsArgs {
    /// Collection name.
    pub collection: String,
    /// Optional structured filter. Tree of `{and:[...]}` / `{or:[...]}`
    /// / `{not:...}` over leaves `{field: scalar}` (eq shorthand) or
    /// `{field: {op: operand}}`. Same shape as `search_collection`'s
    /// `where`. Operators: eq, ne, gt, gte, lt, lte, like, in, nin.
    /// Vector fields cannot appear in the filter.
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
    /// Optional sort spec: `{"field": "<name>", "dir": "asc"|"desc"}`.
    /// Field must be declared on the collection (or `id` / `created_at`
    /// / `updated_at`); vector fields are rejected.
    #[serde(default)]
    pub sort: Option<SortSpec>,
    /// Page number (1-indexed). Defaults to 1.
    #[serde(default)]
    pub page: Option<u32>,
    /// Rows per page. 1..=500; default 20.
    #[serde(default)]
    pub per_page: Option<u32>,
    /// Projected columns. Defaults to all non-vector declared fields.
    /// Vector fields supplied here are silently dropped.
    #[serde(default)]
    pub select: Option<Vec<String>>,
}

/// MCP `list_records` impl. Service-only at the transport layer
/// (`MCP_USER_DENIED` covers user tokens in `mcp_dispatch`); this
/// function therefore has no auth branching. owner_field is bypassed
/// (`None`) to match the service-key REST behaviour.
pub async fn list_records(
    s: &DrustMcp,
    args: ListRecordsArgs,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(&args.collection) {
        anyhow::bail!(
            "COLLECTION_NOT_FOUND: no such collection: {}",
            args.collection
        );
    }
    let pool = s.inner().pool.clone();
    let cache = pool.schema_cache.clone();
    let coll = args.collection.clone();
    let schema = pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll))
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "COLLECTION_NOT_FOUND: no such collection: {}",
                args.collection
            )
        })?;

    // Parse the JSON filter into FilterAst now so we surface FILTER_*
    // errors with the same codes as REST.
    let filter_ast: Option<FilterAst> = match args.filter {
        None => None,
        Some(raw) => Some(
            serde_json::from_value(raw)
                .map_err(|e| anyhow::anyhow!("FILTER_PARSE_ERROR: {e}"))?,
        ),
    };

    let req = ListRequest {
        filter: filter_ast,
        sort: args.sort,
        page: args.page,
        per_page: args.per_page,
        select: args.select,
    };

    let (list_sql, count_sql, binds) =
        list_builder::build_structured_list_sql(&schema, &req, None)
            .map_err(map_list_error)?;

    let vector_names: std::collections::HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    // Run list query.
    let pool_list = s.inner().pool.clone();
    let list_sql_owned = list_sql.clone();
    let binds_for_list = binds.clone();
    let rows: Vec<serde_json::Value> = pool_list
        .with_reader(move |c| -> rusqlite::Result<Vec<serde_json::Value>> {
            attach_readonly_authorizer(c);
            let result = run_bound_select(c, &list_sql_owned, &binds_for_list);
            detach_authorizer(c);
            result
        })
        .await?;
    // Default-hide vector columns.
    let records_out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            if let serde_json::Value::Object(mut m) = row {
                m.retain(|k, _| !vector_names.contains(k));
                serde_json::Value::Object(m)
            } else {
                row
            }
        })
        .collect();

    // Run count query.
    let pool_count = s.inner().pool.clone();
    let count_sql_owned = count_sql.clone();
    let binds_for_count = binds.clone();
    let total: i64 = pool_count
        .with_reader(move |c| -> rusqlite::Result<i64> {
            attach_readonly_authorizer(c);
            let r = (|| -> rusqlite::Result<i64> {
                let mut stmt = c.prepare(&count_sql_owned)?;
                let refs: Vec<&dyn rusqlite::ToSql> = binds_for_count
                    .iter()
                    .map(|v| v as &dyn rusqlite::ToSql)
                    .collect();
                stmt.query_row(rusqlite::params_from_iter(refs), |r| r.get(0))
            })();
            detach_authorizer(c);
            r
        })
        .await
        .unwrap_or(0);

    let per_page = req.per_page.unwrap_or(20);
    let page = req.page.unwrap_or(1);
    Ok(json!({
        "records": records_out,
        "total": total,
        "page": page,
        "perPage": per_page,
    }))
}

/// Map a `ListError` to a typed-code error message. The MCP transport
/// surfaces these as the `anyhow` `Display` body; tests assert on the
/// `CODE:` prefix.
fn map_list_error(e: ListError) -> anyhow::Error {
    match e {
        ListError::Filter(FilterError::Parse(msg)) => {
            anyhow::anyhow!("FILTER_PARSE_ERROR: {msg}")
        }
        ListError::Filter(FilterError::UnknownField(f)) => {
            anyhow::anyhow!("FILTER_UNKNOWN_FIELD: {f}")
        }
        ListError::Filter(FilterError::VectorField(f)) => {
            anyhow::anyhow!("FILTER_VECTOR_FIELD: {f}")
        }
        ListError::Filter(FilterError::TooDeep) => anyhow::anyhow!(
            "FILTER_TOO_DEEP: filter nesting exceeds max depth ({})",
            crate::query::vector_filter::MAX_FILTER_DEPTH
        ),
        ListError::Filter(other) => anyhow::anyhow!("FILTER_PARSE_ERROR: {other}"),
        ListError::SortFieldUnknown(f) => {
            anyhow::anyhow!("SORT_FIELD_UNKNOWN: {f}")
        }
        ListError::SortVectorField(f) => {
            anyhow::anyhow!("SORT_VECTOR_FIELD: {f}")
        }
        ListError::SortDirInvalid => {
            anyhow::anyhow!("SORT_DIR_INVALID: sort.dir must be 'asc' or 'desc'")
        }
        ListError::SelectFieldUnknown(f) => {
            anyhow::anyhow!("SELECT_FIELD_UNKNOWN: {f}")
        }
        ListError::PageRangeInvalid => anyhow::anyhow!(
            "PAGE_RANGE_INVALID: per_page must be 1..=500 and page must be >= 1"
        ),
    }
}

/// Materialise a SELECT result as a vector of JSON objects keyed by
/// column name. Caller manages the read-only authorizer.
fn run_bound_select(
    conn: &rusqlite::Connection,
    sql: &str,
    binds: &[Value],
) -> rusqlite::Result<Vec<serde_json::Value>> {
    let mut stmt = conn.prepare(sql)?;
    let col_names: Vec<String> =
        stmt.column_names().iter().map(|s| s.to_string()).collect();
    let refs: Vec<&dyn rusqlite::ToSql> =
        binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let mut rows_iter = stmt.query(rusqlite::params_from_iter(refs))?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    while let Some(r) = rows_iter.next()? {
        let mut obj = serde_json::Map::new();
        for (i, name) in col_names.iter().enumerate() {
            let v = r.get_ref(i)?;
            obj.insert(
                name.clone(),
                match v {
                    ValueRef::Null => serde_json::Value::Null,
                    ValueRef::Integer(n) => json!(n),
                    ValueRef::Real(f) => json!(f),
                    ValueRef::Text(t) => serde_json::Value::String(
                        String::from_utf8_lossy(t).into_owned(),
                    ),
                    ValueRef::Blob(b) => json!({ "__blob_bytes": b.len() }),
                },
            );
        }
        out.push(serde_json::Value::Object(obj));
    }
    Ok(out)
}

pub async fn explain(s: &DrustMcp, sql: &str, _analyze: bool) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql_owned = sql.to_string();
    let plan: String = pool
        .with_reader(move |c| -> rusqlite::Result<String> {
            attach_readonly_authorizer(c);
            let explain_sql = format!("EXPLAIN QUERY PLAN {sql_owned}");
            let result = (|| -> rusqlite::Result<String> {
                let mut stmt = c.prepare(&explain_sql)?;
                let lines: Vec<String> = stmt
                    .query_map([], |r| {
                        let detail: String = r.get(3)?;
                        Ok(detail)
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(lines.join("\n"))
            })();
            detach_authorizer(c);
            result
        })
        .await?;
    Ok(json!({ "plan": plan }))
}

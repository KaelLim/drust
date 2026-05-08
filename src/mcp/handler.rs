//! rmcp Streamable HTTP handler that exposes the 13 drust tools.
//!
//! This file is a thin adapter layer: each `#[tool]` method delegates
//! to the existing `pub async fn` in `src/mcp/tools/*` and converts
//! `anyhow::Result<serde_json::Value>` into the rmcp-native
//! `Result<CallToolResult, McpError>` shape. Keeping the underlying
//! functions untouched means the in-process integration tests that
//! already cover them continue to work.

use crate::mcp::server::DrustMcp;
use crate::mcp::tools::{
    exploration, files as file_tools, read, schema as schema_tools, write as write_tools,
};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

// --- Parameter types ---------------------------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DescribeCollectionArgs {
    pub collection: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SampleRowsArgs {
    pub collection: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CountRowsArgs {
    pub collection: String,
    #[serde(default)]
    pub where_clause: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QueryArgs {
    pub sql: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExplainArgs {
    pub sql: String,
    #[serde(default)]
    pub analyze: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateCollectionArgs {
    pub name: String,
    pub fields: Vec<schema_tools::FieldSpec>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddFieldArgs {
    pub collection: String,
    pub field: schema_tools::FieldSpec,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DropFieldArgs {
    pub collection: String,
    pub field: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DropCollectionArgs {
    pub collection: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateIndexArgs {
    pub collection: String,
    pub fields: Vec<String>,
    #[serde(default)]
    pub unique: Option<bool>,
    #[serde(default)]
    pub force: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DropIndexArgs {
    pub collection: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetAnonCapsArgs {
    pub collection: String,
    /// Subset of `["select", "insert", "update", "delete"]`. Empty array
    /// locks the collection from the anon role entirely (service is
    /// unrestricted by design and not affected).
    pub caps: Vec<crate::storage::schema::DmlVerb>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InsertRecordArgs {
    pub collection: String,
    /// JSON object mapping field name → value for the new row.
    pub data: HashMap<String, Value>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateRecordArgs {
    pub collection: String,
    pub id: i64,
    /// JSON object of fields to set. Omitted fields are left unchanged.
    pub data: HashMap<String, Value>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteRecordArgs {
    pub collection: String,
    pub id: i64,
}

#[derive(Debug, Clone, schemars::JsonSchema, Deserialize)]
pub struct CreateRpcParams {
    pub name: String,
    pub sql: String,
    pub params: Vec<crate::rpc::params::ParamSpec>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub anon_callable: Option<bool>,
}

#[derive(Debug, Clone, schemars::JsonSchema, Deserialize)]
pub struct UpdateRpcParams {
    pub name: String,
    #[serde(default)]
    pub sql: Option<String>,
    #[serde(default)]
    pub params: Option<Vec<crate::rpc::params::ParamSpec>>,
    /// Pass `Some(Some("..."))` to set, `Some(None)` to clear, omit to leave alone.
    #[serde(default)]
    pub description: Option<Option<String>>,
    #[serde(default)]
    pub anon_callable: Option<bool>,
}

#[derive(Debug, Clone, schemars::JsonSchema, Deserialize)]
pub struct NameOnly {
    pub name: String,
}

#[derive(Debug, Clone, Default, schemars::JsonSchema, Deserialize)]
pub struct EmptyParams {}

#[derive(Debug, Clone, schemars::JsonSchema, Deserialize)]
pub struct CallRpcParams {
    pub name: String,
    /// Optional named-param body. Same shape as the REST POST body —
    /// keys must match the RPC's declared params, values are scalars
    /// (text / integer / real / boolean / null).
    #[serde(default)]
    pub body: Option<HashMap<String, Value>>,
}

// --- Handler -----------------------------------------------------------

#[derive(Clone)]
pub struct DrustMcpService {
    state: DrustMcp,
}

fn json_content(v: Value) -> Result<CallToolResult, McpError> {
    let text =
        serde_json::to_string(&v).map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

fn bail_mcp<T>(e: anyhow::Error) -> Result<T, McpError> {
    Err(McpError::internal_error(e.to_string(), None))
}

#[tool_router]
impl DrustMcpService {
    pub fn new(state: DrustMcp) -> Self {
        Self { state }
    }

    #[tool(description = "List all collections in this tenant's database, with their row counts.")]
    async fn list_collections(&self) -> Result<CallToolResult, McpError> {
        match exploration::list_collections(&self.state).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Return this tenant's identity, both bearer tokens \
        (anon + service, plaintext), the relative REST/MCP/files/rpc \
        endpoint paths, and the configured `max_upload_bytes`. Use this \
        to surface credentials needed for surfaces with no MCP tool — \
        most importantly the multipart file upload endpoint. Tokens \
        minted before v1.1c only stored the hash; their `plaintext` \
        field is null and require an admin reroll to recover.")]
    async fn whoami(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        match exploration::whoami(&self.state).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Return the full schema for one collection: all fields \
        (name, sql_type, nullable, pk, default, foreign_key), all indices, and row count. \
        Returns {\"error_code\": \"UNKNOWN_COLLECTION\"} if the collection does not exist.")]
    async fn describe_collection(
        &self,
        Parameters(DescribeCollectionArgs { collection }): Parameters<DescribeCollectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match exploration::describe_collection(&self.state, &collection).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Return up to `limit` rows from a collection, ordered by id ascending. \
        `limit` defaults to 20 and is clamped to 500. Use this to peek at a collection's data shape."
    )]
    async fn sample_rows(
        &self,
        Parameters(SampleRowsArgs { collection, limit }): Parameters<SampleRowsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let n = limit.unwrap_or(20);
        match exploration::sample_rows(&self.state, &collection, n).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Return COUNT(*) for a collection, with an optional SQL WHERE fragment \
        (e.g. \"status = 'published' AND created_at > '2026-01-01'\"). \
        The WHERE clause passes through the read-only SQL authorizer — no writes, no joins, no DDL."
    )]
    async fn count_rows(
        &self,
        Parameters(CountRowsArgs { collection, where_clause }): Parameters<CountRowsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match exploration::count_rows(&self.state, &collection, where_clause.as_deref()).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Run a read-only SELECT against this tenant's database. \
        The SQL is validated by a strict authorizer: no INSERT/UPDATE/DELETE/DDL, \
        no ATTACH, no sqlite_master reads. Limits: 16 KB SQL, 10,000 rows, 5 second timeout."
    )]
    async fn query(
        &self,
        Parameters(QueryArgs { sql }): Parameters<QueryArgs>,
    ) -> Result<CallToolResult, McpError> {
        match read::query(&self.state, &sql).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Return `EXPLAIN QUERY PLAN` output for a read-only SQL statement. \
        Use this to diagnose slow queries before running them. `analyze` is accepted for \
        forward-compatibility but currently ignored."
    )]
    async fn explain(
        &self,
        Parameters(ExplainArgs { sql, analyze }): Parameters<ExplainArgs>,
    ) -> Result<CallToolResult, McpError> {
        match read::explain(&self.state, &sql, analyze.unwrap_or(false)).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Create a new collection (SQLite table). \
        Every collection implicitly gets: id INTEGER PRIMARY KEY AUTOINCREMENT, \
        created_at, updated_at (both auto-maintained). \
        Each field in `fields` is {name, sql_type, nullable?, unique?, default_value?, foreign_key?}. \
        `sql_type` must be lowercase and one of: `text`, `integer`, `real`, `boolean`, `datetime`, `json`. \
        `default_value` accepts JSON scalars or {\"sql\": \"datetime('now')\"} (allowlisted expressions). \
        `foreign_key` names another collection; emits ON DELETE RESTRICT.")]
    async fn create_collection(
        &self,
        Parameters(CreateCollectionArgs { name, fields }): Parameters<CreateCollectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match schema_tools::create_collection(&self.state, &name, &fields).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Add a new field (column) to an existing collection via ALTER TABLE. \
        `field` has the same shape as entries in `create_collection.fields` \
        (sql_type must be lowercase: text, integer, real, boolean, datetime, json)."
    )]
    async fn add_field(
        &self,
        Parameters(AddFieldArgs { collection, field }): Parameters<AddFieldArgs>,
    ) -> Result<CallToolResult, McpError> {
        match schema_tools::add_field(&self.state, &collection, field).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Drop a field (column) from a collection via \
        `ALTER TABLE … DROP COLUMN`. Cannot drop the system columns `id`, \
        `created_at`, `updated_at` (drust maintains them automatically). \
        SQLite will also reject the drop if the column is part of an \
        index, UNIQUE, foreign key, CHECK, trigger, or view — fix those \
        first. Irreversible.")]
    async fn drop_field(
        &self,
        Parameters(DropFieldArgs { collection, field }): Parameters<DropFieldArgs>,
    ) -> Result<CallToolResult, McpError> {
        match schema_tools::drop_field(&self.state, &collection, &field).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Drop an entire collection (DROP TABLE plus its \
        `_updated_at` trigger). Irreversible — all rows are destroyed. \
        Rejected if any other collection still has a `foreign_key` column \
        pointing at this one; drop those columns first.")]
    async fn drop_collection(
        &self,
        Parameters(DropCollectionArgs { collection }): Parameters<DropCollectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match schema_tools::drop_collection(&self.state, &collection).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Create a non-unique or unique index on one or more fields of a \
        collection. Speeds up `WHERE field = ?` and `ORDER BY field` queries. \
        `fields` is a non-empty list of column names (order matters for composite indices). \
        `unique` defaults to false. \
        Tables with more than DRUST_INDEX_LARGE_TABLE_ROWS rows return LARGE_TABLE — \
        pass force=true only after understanding the temporary write lock implication.")]
    async fn create_index(
        &self,
        Parameters(CreateIndexArgs { collection, fields, unique, force }): Parameters<CreateIndexArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::index::create_index_with_threshold(
            &self.state.inner().pool,
            &collection,
            &fields,
            unique.unwrap_or(false),
            force.unwrap_or(false),
            self.state.inner().index_large_table_rows,
        ).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Drop an index by name (use `name`) or by field set (use `fields`). \
        Exactly one of `name` or `fields` must be provided. \
        Removes the lookup structure but does NOT touch row data. Irreversible.")]
    async fn drop_index(
        &self,
        Parameters(DropIndexArgs { collection, name, fields }): Parameters<DropIndexArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::index::drop_index(
            &self.state.inner().pool,
            &collection,
            name.as_deref(),
            fields.as_deref(),
        ).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Replace the anon-role DML capability set for one \
        collection. `caps` is a subset of [\"select\",\"insert\",\"update\",\"delete\"]; \
        empty locks anon out entirely. Service tokens are unrestricted and \
        not affected. Refuses `_system_*` collections.")]
    async fn set_anon_caps(
        &self,
        Parameters(SetAnonCapsArgs { collection, caps }): Parameters<SetAnonCapsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match schema_tools::set_anon_caps(&self.state, &collection, &caps).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Insert one record into a collection. `data` is a JSON object whose keys \
        must be known fields of the collection (unknown fields are rejected). \
        Returns the inserted row including the auto-generated id and timestamps."
    )]
    async fn insert_record(
        &self,
        Parameters(InsertRecordArgs { collection, data }): Parameters<InsertRecordArgs>,
    ) -> Result<CallToolResult, McpError> {
        let data = Value::Object(data.into_iter().collect());
        match write_tools::insert_record(&self.state, &collection, data).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Partially update one record. `data` is a JSON object of fields to set; \
        omitted fields are left unchanged. `updated_at` is bumped automatically."
    )]
    async fn update_record(
        &self,
        Parameters(UpdateRecordArgs {
            collection,
            id,
            data,
        }): Parameters<UpdateRecordArgs>,
    ) -> Result<CallToolResult, McpError> {
        let data = Value::Object(data.into_iter().collect());
        match write_tools::update_record(&self.state, &collection, id, data).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Delete one record by id. A foreign-key constraint from another \
        collection (ON DELETE RESTRICT) will block the delete if any children reference this row."
    )]
    async fn delete_record(
        &self,
        Parameters(DeleteRecordArgs { collection, id }): Parameters<DeleteRecordArgs>,
    ) -> Result<CallToolResult, McpError> {
        match write_tools::delete_record(&self.state, &collection, id).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "List files stored by this tenant in Garage. \
        Optional `visibility` filter (\"public\" | \"private\"); anything else returns all. \
        Paginate with `limit` (1–500, default 50) and `offset`. \
        Returns {files, total_count} where each file has id, original_name, size_bytes, \
        content_type, visibility, content_disposition, uploaded_at.")]
    async fn list_files(
        &self,
        Parameters(args): Parameters<file_tools::ListFilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match file_tools::list_files(&self.state, args).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Delete a file by its id (the UUID key). \
        Removes the S3 object from the tenant's bucket first (idempotent on 404) \
        then deletes the metadata row. Returns {\"ok\": true} on success or \
        {\"error_code\": \"NOT_FOUND\" | \"STORAGE_UNAVAILABLE\"}.")]
    async fn delete_file(
        &self,
        Parameters(args): Parameters<file_tools::DeleteFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        match file_tools::delete_file(&self.state, args).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Get a URL to download a file by its id. \
        Public files → stable public URL (expires_at is null). \
        Private files → pre-signed URL with TTL (1..=604800s, default 3600); \
        pass `download: true` to inject Content-Disposition=attachment so \
        browsers download instead of previewing.")]
    async fn get_file_url(
        &self,
        Parameters(args): Parameters<file_tools::GetFileUrlArgs>,
    ) -> Result<CallToolResult, McpError> {
        match file_tools::get_file_url(&self.state, args).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Create a new stored RPC (named SELECT-only function). \
        Required: name (snake_case), sql (a SELECT body using :name placeholders), \
        params (array of {name, type, required, default}). \
        Optional: description, anon_callable (default false). \
        SQL is validated at create time via the read-only authorizer — \
        non-SELECT actions, ATTACH, sqlite_master references, and unknown \
        tables are refused before storage.")]
    async fn create_rpc(
        &self,
        Parameters(p): Parameters<CreateRpcParams>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        let params_json = serde_json::to_string(&p.params)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let name = p.name.clone();
        let sql = p.sql.clone();
        let description = p.description.clone();
        let anon_callable = p.anon_callable.unwrap_or(false);

        pool.with_writer(move |c| {
            crate::rpc::prepare::validate_rpc_sql(c, &sql).map_err(|e| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(e.to_string()),
                )
            })?;
            crate::rpc::registry::create(
                c,
                &name,
                &sql,
                &params_json,
                description.as_deref(),
                anon_callable,
            )
            .map_err(|e| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(e.to_string()),
                )
            })?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "rpc '{}' created",
            p.name
        ))]))
    }

    #[tool(description = "Update an existing RPC. All fields except `name` are \
        optional — pass only the fields you want to change. Same SQL validation \
        as create_rpc applies if you provide a new sql body.")]
    async fn update_rpc(
        &self,
        Parameters(p): Parameters<UpdateRpcParams>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        let name = p.name.clone();
        let sql = p.sql.clone();
        let description = p.description.clone();
        let anon_callable = p.anon_callable;
        let params_json: Option<String> = match &p.params {
            Some(v) => Some(
                serde_json::to_string(v)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            ),
            None => None,
        };

        pool.with_writer(move |c| {
            if let Some(s) = sql.as_deref() {
                crate::rpc::prepare::validate_rpc_sql(c, s).map_err(|e| {
                    rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(1),
                        Some(e.to_string()),
                    )
                })?;
            }
            crate::rpc::registry::update(
                c,
                &name,
                sql.as_deref(),
                params_json.as_deref(),
                description.as_ref().map(|d| d.as_deref()),
                anon_callable,
            )
            .map_err(|e| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(e.to_string()),
                )
            })?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "rpc '{}' updated",
            p.name
        ))]))
    }

    #[tool(description = "Delete an RPC by name. Errors if no RPC with that name exists.")]
    async fn delete_rpc(
        &self,
        Parameters(p): Parameters<NameOnly>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        let name = p.name.clone();
        pool.with_writer(move |c| {
            crate::rpc::registry::delete(c, &name).map_err(|e| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(e.to_string()),
                )
            })
        })
        .await
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "rpc '{}' deleted",
            p.name
        ))]))
    }

    #[tool(description = "List every stored RPC for this tenant, including \
        the SQL body, params, anon_callable flag, call counters, and last-called \
        timestamp.")]
    async fn list_rpc(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        let rows = pool
            .with_reader(move |c| {
                crate::rpc::registry::list(c).map_err(|e| {
                    rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(1),
                        Some(e.to_string()),
                    )
                })
            })
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let json = serde_json::to_string_pretty(&rows)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Invoke a stored RPC by name with named params. \
        Returns the same envelope as the query tool: {column_names, rows, \
        row_count, truncated}. MCP is service-only, so anon_callable is not \
        consulted on this surface — a service-key holder may call any RPC.")]
    async fn call_rpc(
        &self,
        Parameters(p): Parameters<CallRpcParams>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        let name = p.name.clone();
        // HashMap → serde_json::Map for params::validate_and_bind.
        let body_map: serde_json::Map<String, Value> =
            p.body.unwrap_or_default().into_iter().collect();

        let lookup_name = name.clone();
        let bind_body = body_map.clone();
        let outcome = pool
            .with_reader(move |c| {
                let rpc = match crate::rpc::registry::lookup(c, &lookup_name).map_err(|e| {
                    rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(1),
                        Some(e.to_string()),
                    )
                })? {
                    Some(r) => r,
                    None => return Ok(Err(format!("no such rpc: {lookup_name}"))),
                };
                let bound = match crate::rpc::params::validate_and_bind(&rpc.params, &bind_body) {
                    Ok(b) => b,
                    Err(e) => return Ok(Err(e.to_string())),
                };
                let qr = match crate::query::executor::execute_read_query_with_named(
                    c,
                    &rpc.sql,
                    &bound,
                    1_000,
                    1_048_576,
                ) {
                    Ok(qr) => qr,
                    Err(e) => return Ok(Err(e.to_string())),
                };
                Ok(Ok(qr))
            })
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let qr = match outcome {
            Ok(qr) => qr,
            Err(msg) => return Err(McpError::invalid_params(msg, None)),
        };

        // Fire-and-forget counter bump on the writer mutex. MCP is
        // service-only, so the role is hardcoded.
        let pool_clone = pool.clone();
        let bump_name = name.clone();
        tokio::spawn(async move {
            let res = pool_clone
                .with_writer(move |c| {
                    crate::rpc::registry::increment(
                        c,
                        &bump_name,
                        crate::tenant::router::TokenRole::Service,
                    )
                })
                .await;
            if let Err(e) = res {
                tracing::warn!(error = %e, "rpc counter bump failed (mcp call_rpc)");
            }
        });

        let row_count = qr.rows.len();
        let envelope = serde_json::json!({
            "column_names": qr.column_names,
            "rows": qr.rows,
            "row_count": row_count,
            "truncated": qr.truncated,
        });
        let body_str = serde_json::to_string(&envelope)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(body_str)]))
    }
}

#[tool_handler]
impl ServerHandler for DrustMcpService {
    fn get_info(&self) -> ServerInfo {
        let tenant_id = self.state.tenant_id();
        let base = self.state.public_base_url();
        let instructions = format!(
            "drust multi-tenant SQLite BaaS — tenant '{tenant_id}'.\n\n\
             23 tools: `list_collections`, `describe_collection`, `sample_rows`, \
             `count_rows`, `query`, `explain`, `insert_record`, `update_record`, \
             `delete_record`, `create_collection`, `add_field`, `drop_field`, \
             `drop_collection`, `create_index`, `drop_index`, `list_files`, `delete_file`, \
             `get_file_url`, `create_rpc`, `update_rpc`, `delete_rpc`, `list_rpc`, \
             `call_rpc`.\n\n\
             Files are stored in the tenant's Garage buckets (tenant-{tenant_id}-pub / \
             tenant-{tenant_id}-prv). MCP does NOT expose an upload tool — use the REST \
             endpoint instead:\n\n  \
             POST {base}/drust/t/{tenant_id}/files\n  \
             Header: Authorization: Bearer $DRUST_TOKEN\n  \
             Body: multipart/form-data with fields:\n    \
             - file        (required — the bytes)\n    \
             - visibility  (required — 'public' or 'private')\n    \
             - disposition (optional — 'inline' or 'attachment', default inline)\n    \
             - cache_control (optional — default 'public, max-age=86400' for public / \
             'private, no-store' for private)\n    \
             - meta        (optional — JSON object for custom metadata)\n\n\
             After upload, use `list_files` to discover, `get_file_url` to produce a \
             public or pre-signed URL (pass download=true for attachment), and \
             `delete_file` to remove. Schema drops and delete_file are irreversible."
        );
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("drust", env!("CARGO_PKG_VERSION")))
            .with_instructions(instructions)
    }
}

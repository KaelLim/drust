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
}

#[tool_handler]
impl ServerHandler for DrustMcpService {
    fn get_info(&self) -> ServerInfo {
        let tenant_id = self.state.tenant_id();
        let base = self.state.public_base_url();
        let instructions = format!(
            "drust multi-tenant SQLite BaaS — tenant '{tenant_id}'.\n\n\
             16 tools: `list_collections`, `describe_collection`, `sample_rows`, \
             `count_rows`, `query`, `explain`, `insert_record`, `update_record`, \
             `delete_record`, `create_collection`, `add_field`, `drop_field`, \
             `drop_collection`, `list_files`, `delete_file`, `get_file_url`.\n\n\
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

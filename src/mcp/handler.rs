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
    exploration, files as file_tools, oauth as oauth_tools,
    owner_field as owner_field_tools, read, schema as schema_tools, user as user_tools,
    vector as vector_tools, webhook as webhook_tools, write as write_tools,
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

/// Map an anyhow error from a `set_*_description` impl into either
/// `invalid_params` (typed codes) or `internal_error` (anything else).
/// Typed codes are the prefix-before-colon of the message.
fn map_desc_error(e: anyhow::Error) -> McpError {
    let msg = e.to_string();
    let code = msg.split(':').next().unwrap_or("");
    match code {
        "DESCRIPTION_TOO_LONG" | "DESCRIPTION_INVALID"
        | "COLLECTION_NOT_FOUND" | "FIELD_NOT_FOUND" | "INDEX_NOT_FOUND"
        | "PROTECTED_COLLECTION" => McpError::invalid_params(msg, None),
        _ => McpError::internal_error(msg, None),
    }
}

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
    /// Optional plain-text description for the collection (v1.19).
    #[serde(default)]
    pub description: Option<String>,
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
    #[serde(default)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateIndexArgs {
    pub collection: String,
    pub fields: Vec<String>,
    #[serde(default)]
    pub unique: Option<bool>,
    #[serde(default)]
    pub force: Option<bool>,
    /// Optional plain-text description for the index (v1.19).
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DropIndexArgs {
    pub collection: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub fields: Option<Vec<String>>,
    #[serde(default)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecentWritesArgs {
    /// 1..=200; defaults to 50.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Optional filter — only entries whose collection matches.
    #[serde(default)]
    pub collection: Option<String>,
    /// Optional ISO-8601 timestamp. Only entries with `ts > since_ts`
    /// are returned. Use this to poll incrementally.
    #[serde(default)]
    pub since_ts: Option<String>,
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
pub struct SetRealtimeArgs {
    pub collection: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetCollectionDescriptionArgs {
    pub collection: String,
    /// Empty string clears the description (column → NULL).
    /// Trimmed to ≤2048 bytes (MAX_DESCRIPTION_BYTES).
    pub description: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetFieldDescriptionArgs {
    pub collection: String,
    pub field: String,
    /// Empty string removes the key from field_descriptions_json.
    pub description: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetIndexDescriptionArgs {
    pub collection: String,
    pub index_name: String,
    /// Empty string removes the key from index_descriptions_json.
    pub description: String,
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
    /// v1.26: when true, return blast radius (fk_blocks etc.) without
    /// actually deleting. Defaults to false (existing behavior).
    #[serde(default)]
    pub dry_run: Option<bool>,
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

// --- T24: User-management parameter types --------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateUserArgs {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub profile: Option<serde_json::Value>,
    #[serde(default)]
    pub verified: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListUsersArgs {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UserIdArgs {
    pub user_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateUserArgs {
    pub user_id: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub profile: Option<serde_json::Value>,
    #[serde(default)]
    pub verified: Option<bool>,
}

// --- T25: Owner-field + self-register parameter types --------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetOwnerFieldArgs {
    pub collection: String,
    pub field: String,
    /// `"own"` (default) — anon reads see only their own rows.
    /// `"all"` — anon reads see all rows.
    #[serde(default = "default_own")]
    pub read_scope: String,
}

fn default_own() -> String {
    "own".to_string()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClearOwnerFieldArgs {
    pub collection: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetSelfRegisterArgs {
    pub enabled: bool,
}

// --- v1.12: Per-tenant OAuth-provider admin parameter types ----------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetOauthProviderArgs {
    /// `"google"` or `"github"`.
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    /// Non-empty list of allowed redirect URIs. Each must be https:// or a
    /// localhost/127.0.0.1 URL (the same allowlist the start handler enforces).
    pub allowed_redirect_uris: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProviderOnlyArgs {
    pub provider: String,
}

// --- v1.13: Webhook subscription admin parameter types ---------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateWebhookArgs {
    pub collection: String,
    /// Non-empty subset of `["created", "updated", "deleted"]`.
    pub events: Vec<String>,
    /// Subscriber URL — must be `https://…` OR `http://` with a loopback host.
    pub url: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateWebhookArgs {
    pub id: i64,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub events: Option<Vec<String>>,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WebhookIdArgs {
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

/// v1.26 — Wrap an anyhow error into McpError, attaching error_code +
/// suggested_fix to the `data` field so LLM tools see structured
/// remediation hints. Convention: tool functions `anyhow::bail!` with
/// `"<CODE>: <message>"`, mirroring the REST `json_error` shape.
fn bail_mcp<T>(e: anyhow::Error) -> Result<T, McpError> {
    let msg = e.to_string();
    let code = msg.split(':').next().unwrap_or("").trim();
    let fix = crate::safety::error_fixes::lookup(code);
    let mut data = serde_json::Map::new();
    if !code.is_empty() {
        data.insert("error_code".into(), serde_json::Value::String(code.to_string()));
    }
    if let Some(f) = fix {
        data.insert("suggested_fix".into(), serde_json::Value::String(f.to_string()));
    }
    let data_val = if data.is_empty() { None } else { Some(serde_json::Value::Object(data)) };
    Err(McpError::internal_error(msg, data_val))
}

#[cfg(test)]
mod bail_mcp_tests {
    use super::*;

    #[test]
    fn known_code_yields_data_with_fix() {
        let r: Result<(), McpError> = bail_mcp(anyhow::anyhow!("LARGE_TABLE: too many rows"));
        let err = r.unwrap_err();
        let data = err.data.expect("data present");
        assert_eq!(data["error_code"], "LARGE_TABLE");
        assert!(data["suggested_fix"].as_str().unwrap().contains("force"));
    }

    #[test]
    fn unknown_code_yields_data_with_code_only() {
        let r: Result<(), McpError> = bail_mcp(anyhow::anyhow!("MADE_UP: boom"));
        let err = r.unwrap_err();
        let data = err.data.expect("data present");
        assert_eq!(data["error_code"], "MADE_UP");
        assert!(data.get("suggested_fix").is_none());
    }

    #[test]
    fn no_colon_message_yields_no_data() {
        let r: Result<(), McpError> = bail_mcp(anyhow::anyhow!("just a free-form message"));
        let err = r.unwrap_err();
        let data = err.data.expect("data present");
        assert_eq!(data["error_code"], "just a free-form message");
    }
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
        Returns {\"error_code\": \"COLLECTION_NOT_FOUND\"} if the collection does not exist.")]
    async fn describe_collection(
        &self,
        Parameters(DescribeCollectionArgs { collection }): Parameters<DescribeCollectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match exploration::describe_collection(&self.state, &collection).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "One-shot schema bootstrap for the tenant. Returns every \
        collection's full schema (fields, indices, descriptions, anon_caps, owner_field, \
        realtime_enabled, vector_fields) plus every stored RPC's metadata in a single \
        response. Service-key only. Use this when an LLM first connects to learn the data \
        model; the cheaper `list_collections` + `describe_collection` round-trips remain \
        available for per-collection inspection.")]
    async fn get_schema_overview(&self) -> Result<CallToolResult, McpError> {
        match exploration::get_schema_overview(&self.state).await {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).expect("serialise"),
            )])),
            Err(e) => Err(McpError::internal_error(e.to_string(), None)),
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
        Parameters(CreateCollectionArgs { name, fields, description }): Parameters<CreateCollectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match schema_tools::create_collection_with_desc(&self.state, &name, &fields, description.as_deref()).await {
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

    #[tool(description = "Drop an entire collection (DROP TABLE + _updated_at trigger). \
        Irreversible. Rejected if other collections still FK-reference this one. \
        v1.26: pass `dry_run: true` to preview row_count + indexes + RPCs + \
        reverse FK list without dropping.")]
    async fn drop_collection(
        &self,
        Parameters(DropCollectionArgs { collection, dry_run }): Parameters<DropCollectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        if dry_run.unwrap_or(false) {
            if crate::storage::schema::is_protected_collection(&collection) {
                return bail_mcp(anyhow::anyhow!("PROTECTED_COLLECTION: cannot drop {collection}"));
            }
            let coll_check = collection.clone();
            let exists: i64 = self.state.inner().pool
                .with_reader(move |c| {
                    c.query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                        rusqlite::params![coll_check],
                        |r| r.get(0),
                    )
                })
                .await
                .unwrap_or(0);
            if exists == 0 {
                return bail_mcp(anyhow::anyhow!("COLLECTION_NOT_FOUND: {collection}"));
            }
            return match crate::storage::blast_radius::drop_collection_blast_radius(
                &self.state.inner().pool,
                &collection,
            ).await {
                Ok(br) => json_content(serde_json::to_value(br).expect("serialise")),
                Err(e) => bail_mcp(e),
            };
        }
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
        Parameters(CreateIndexArgs { collection, fields, unique, force, description }): Parameters<CreateIndexArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::index::create_index_with_threshold_and_desc(
            &self.state.inner().pool,
            &collection,
            &fields,
            unique.unwrap_or(false),
            force.unwrap_or(false),
            self.state.inner().index_large_table_rows,
            description.as_deref(),
        ).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Drop an index by name or by field set. \
        Removes the lookup structure but does NOT touch row data. \
        v1.26: pass `dry_run: true` to confirm the index exists and \
        receive its name without dropping.")]
    async fn drop_index(
        &self,
        Parameters(DropIndexArgs { collection, name, fields, dry_run }): Parameters<DropIndexArgs>,
    ) -> Result<CallToolResult, McpError> {
        if dry_run.unwrap_or(false) {
            let resolved = match (name.as_deref(), fields.as_deref()) {
                (Some(n), _) => n.to_string(),
                (None, Some(fs)) if !fs.is_empty() => {
                    crate::mcp::tools::index::derive_index_name(&collection, fs)
                }
                _ => return bail_mcp(anyhow::anyhow!("INVALID_PARAMS: provide either name or non-empty fields")),
            };
            return match crate::storage::blast_radius::drop_index_blast_radius(
                &self.state.inner().pool,
                &resolved,
            ).await {
                Ok(br) => json_content(serde_json::to_value(br).expect("serialise")),
                Err(e) => bail_mcp(e),
            };
        }
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

    #[tool(description = "Toggle SSE realtime broadcast for one collection. \
        When enabled, clients can subscribe to GET /records/<coll>/subscribe; \
        anon callers additionally need anon_caps containing 'select'. When \
        disabled, existing in-flight SSE connections are dropped within ~1s. \
        Refuses `_system_*` collections.")]
    async fn set_realtime(
        &self,
        Parameters(SetRealtimeArgs { collection, enabled }): Parameters<SetRealtimeArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::realtime::set_realtime(&self.state, &collection, enabled).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Set or clear the collection-level description for a tenant \
        collection. Service-key only. Empty / whitespace description clears (column → NULL). \
        Bounded to 2048 bytes after trimming. Returns the post-state description.")]
    async fn set_collection_description(
        &self,
        Parameters(args): Parameters<SetCollectionDescriptionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        match schema_tools::set_collection_description(&pool, &args.collection, &args.description)
            .await
        {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).expect("serialise"),
            )])),
            Err(e) => Err(map_desc_error(e)),
        }
    }

    #[tool(description = "Set or clear a per-field description on a tenant collection. \
        Service-key only. Returns FIELD_NOT_FOUND if the named field is not on the collection.")]
    async fn set_field_description(
        &self,
        Parameters(args): Parameters<SetFieldDescriptionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        match schema_tools::set_field_description(
            &pool, &args.collection, &args.field, &args.description,
        )
        .await
        {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).expect("serialise"),
            )])),
            Err(e) => Err(map_desc_error(e)),
        }
    }

    #[tool(description = "Set or clear a per-index description on a tenant collection. \
        Service-key only. Returns INDEX_NOT_FOUND if the named index is not on the collection.")]
    async fn set_index_description(
        &self,
        Parameters(args): Parameters<SetIndexDescriptionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        match schema_tools::set_index_description(
            &pool, &args.collection, &args.index_name, &args.description,
        )
        .await
        {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).expect("serialise"),
            )])),
            Err(e) => Err(map_desc_error(e)),
        }
    }

    #[tool(description = "Search a collection by vector similarity. Builds the \
        SQL itself from the structured body — no raw SQL accepted. Returns up to \
        `k` nearest rows ordered by distance, each row carrying an injected \
        `_distance` column. Default metric is `cosine`; alternatives are `l2` \
        and `l1`. Optional `where` filter accepts an and/or/not tree of \
        eq/ne/gt/gte/lt/lte/like/in/nin leaves; vector fields cannot appear \
        in the filter. Optional `select` lists projected columns (default: all \
        non-vector columns).")]
    async fn search_collection(
        &self,
        Parameters(input): Parameters<vector_tools::SearchInput>,
    ) -> Result<CallToolResult, McpError> {
        match vector_tools::search_collection(&self.state, input).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "List records from a collection with structured filter, \
        sort, and pagination. Reuses the same FilterAst as `search_collection`; \
        rejects raw SQL by construction. `filter` is a tree of \
        `{and:[...]}` / `{or:[...]}` / `{not:...}` over leaves \
        `{field: scalar}` (eq) or `{field: {op: operand}}`. Operators: eq, ne, \
        gt, gte, lt, lte, like, in (array), nin (array). `sort` is \
        `{field, dir}` with dir in {asc, desc}. `per_page` must be 1..=500 \
        (default 20). `select` is a list of column names; vector \
        fields are auto-excluded. Returns up to 500 rows per page. \
        owner_field enforcement is guaranteed by drust — service tokens \
        bypass; user tokens (REST only) get an auto-appended owner clause; \
        MCP is service-only at the transport layer so this tool sees all \
        rows.")]
    async fn list_records(
        &self,
        Parameters(args): Parameters<read::ListRecordsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match read::list_records(&self.state, args).await {
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

    #[tool(description = "Delete a record from a collection by primary key. \
        Returns RECORD_NOT_FOUND if the row does not exist; FK_RESTRICT if \
        another collection still references it. \
        v1.26: pass `dry_run: true` to receive blast radius (which collections \
        would block the delete) without actually deleting.")]
    async fn delete_record(
        &self,
        Parameters(DeleteRecordArgs { collection, id, dry_run }): Parameters<DeleteRecordArgs>,
    ) -> Result<CallToolResult, McpError> {
        if dry_run.unwrap_or(false) {
            match crate::mcp::tools::write::delete_record_validate(&self.state, &collection, id).await {
                Ok(()) => {}
                Err(e) => return bail_mcp(e),
            }
            match crate::storage::blast_radius::delete_blast_radius(
                &self.state.inner().pool,
                &collection,
                id,
            ).await {
                Ok(br) => return json_content(serde_json::to_value(br).expect("serialise")),
                Err(e) => return bail_mcp(e),
            }
        }
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
            // C5: mode = Read until create_rpc accepts a `mode` param
            // (queued follow-up). Same default as the admin form.
            crate::rpc::prepare::validate_rpc_sql(
                c,
                &sql,
                crate::rpc::registry::RpcMode::Read,
            ).map_err(|e| {
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
                crate::rpc::registry::RpcMode::Read,
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
                // C5: mode = Read for update_rpc until the tool accepts
                // an explicit mode param. Matches create_rpc.
                crate::rpc::prepare::validate_rpc_sql(
                    c,
                    s,
                    crate::rpc::registry::RpcMode::Read,
                ).map_err(|e| {
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
                None,
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

    // ── T24: User-management tools ─────────────────────────────────────────

    #[tool(description = "Create a new user in this tenant's _system_users table. \
        Required: email (unique, case-insensitive), password (hashed server-side). \
        Optional: profile (JSON object), verified (boolean, default false). \
        Returns {user_id, email, created_at}. \
        Errors with EMAIL_EXISTS if the email is already taken.")]
    async fn create_user(
        &self,
        Parameters(CreateUserArgs { email, password, profile, verified }): Parameters<CreateUserArgs>,
    ) -> Result<CallToolResult, McpError> {
        match user_tools::create_user(&self.state.inner().pool, email, password, profile, verified)
            .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "List users in this tenant. Optional: q (email substring filter), \
        limit (1–500, default 50), offset. \
        Returns {users: [...], total}.")]
    async fn list_users(
        &self,
        Parameters(ListUsersArgs { q, limit, offset }): Parameters<ListUsersArgs>,
    ) -> Result<CallToolResult, McpError> {
        match user_tools::list_users(&self.state.inner().pool, q, limit, offset).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Get a single user by user_id. \
        Returns {id, email, verified, profile, created_at, updated_at} (no password_hash). \
        Errors with NOT_FOUND if the user does not exist.")]
    async fn get_user(
        &self,
        Parameters(UserIdArgs { user_id }): Parameters<UserIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        match user_tools::get_user(&self.state.inner().pool, user_id).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Update one or more fields of a user. All fields except user_id \
        are optional — only supplied fields are changed. password is re-hashed server-side. \
        Returns the updated row. Errors: NOT_FOUND, EMAIL_EXISTS, HASH_FAILED.")]
    async fn update_user(
        &self,
        Parameters(UpdateUserArgs { user_id, email, password, profile, verified }): Parameters<UpdateUserArgs>,
    ) -> Result<CallToolResult, McpError> {
        match user_tools::update_user(
            &self.state.inner().pool,
            user_id,
            email,
            password,
            profile,
            verified,
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Delete a user and cascade: removes the user's records from every \
        collection that has owner_field set, revokes all sessions, then deletes the user row. \
        Returns {deleted_records: {<collection>: <count>, ...}, revoked_sessions: <n>}. \
        Errors with NOT_FOUND if the user does not exist.")]
    async fn delete_user(
        &self,
        Parameters(UserIdArgs { user_id }): Parameters<UserIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        match user_tools::delete_user(&self.state.inner().pool, user_id).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Revoke all active sessions for a user (forces re-login on all devices). \
        Returns {revoked: <n>}. Safe to call on a non-existent user (returns revoked: 0).")]
    async fn revoke_user_sessions(
        &self,
        Parameters(UserIdArgs { user_id }): Parameters<UserIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        match user_tools::revoke_user_sessions(&self.state.inner().pool, user_id).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    // ── T25: Owner-field + self-register tools ─────────────────────────────

    #[tool(description = "Declare that a column in `collection` is the owner-field — \
        a foreign key to _system_users(id) that links rows to their creator. \
        `field` must already exist on the table and carry a FK to _system_users(id). \
        `read_scope`: 'own' (default) — anon reads filtered to caller's user_id; \
        'all' — anon reads unfiltered. \
        Returns {owner_field, read_scope}. \
        Errors: OWNER_FIELD_INVALID_COLUMN (no such column), OWNER_FIELD_NOT_FK (missing FK).")]
    async fn set_owner_field(
        &self,
        Parameters(SetOwnerFieldArgs { collection, field, read_scope }): Parameters<SetOwnerFieldArgs>,
    ) -> Result<CallToolResult, McpError> {
        match owner_field_tools::set_owner_field(
            &self.state.inner().pool,
            collection,
            field,
            read_scope,
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Remove the owner-field declaration from a collection, \
        reverting to no ownership filtering. Does not touch row data. \
        Returns {cleared: true}.")]
    async fn clear_owner_field(
        &self,
        Parameters(ClearOwnerFieldArgs { collection }): Parameters<ClearOwnerFieldArgs>,
    ) -> Result<CallToolResult, McpError> {
        match owner_field_tools::clear_owner_field(&self.state.inner().pool, collection).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Enable or disable self-registration for this tenant. \
        When enabled (true), unauthenticated users may POST /auth/register to create an account. \
        When disabled (false, the default), /auth/register returns 403. \
        Returns {allow_self_register: <bool>}. \
        Requires meta.sqlite access — errors with NOT_FOUND if the tenant row is missing.")]
    async fn set_self_register(
        &self,
        Parameters(SetSelfRegisterArgs { enabled }): Parameters<SetSelfRegisterArgs>,
    ) -> Result<CallToolResult, McpError> {
        let meta = match self.state.meta() {
            Some(m) => m.clone(),
            None => {
                return Err(McpError::internal_error(
                    "meta connection not available in this context".to_string(),
                    None,
                ))
            }
        };
        let tenant_id = self.state.tenant_id().to_string();
        match owner_field_tools::set_self_register(&meta, &tenant_id, enabled).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    // ── v1.12: Per-tenant OAuth-provider admin tools ──────────────────────

    #[tool(description = "List the OAuth providers configured for this tenant's \
        end-user login flow (the `_system_oauth_providers` table). \
        Returns {providers: [{provider, client_id, client_secret, \
        allowed_redirect_uris, created_at, updated_at}]}. \
        `client_secret` is always returned as the literal '●●●●' — real \
        secrets never leave the writer. Service-key-only; anon callers \
        cannot reach MCP.")]
    async fn list_oauth_providers(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        match oauth_tools::list_oauth_providers(&self.state.inner().pool).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Upsert an OAuth provider config for this tenant's \
        end-user login flow. `provider` must be 'google' or 'github'. \
        `client_id` / `client_secret` are the OAuth app credentials from \
        the provider's console. `allowed_redirect_uris` is a non-empty list \
        of full URIs the frontend may pass to `/oauth/{provider}/start` — \
        each must be https:// or a localhost/127.0.0.1 URL. \
        Replaces any existing row for the same provider. \
        Returns {ok: true, provider}. \
        Errors with a granular code on validation failure: \
        INVALID_PROVIDER, INVALID_CLIENT_ID, INVALID_CLIENT_SECRET, \
        EMPTY_REDIRECT_URIS, or INVALID_REDIRECT_URI.")]
    async fn set_oauth_provider(
        &self,
        Parameters(SetOauthProviderArgs { provider, client_id, client_secret, allowed_redirect_uris }): Parameters<SetOauthProviderArgs>,
    ) -> Result<CallToolResult, McpError> {
        match oauth_tools::set_oauth_provider(
            &self.state.inner().pool,
            provider,
            client_id,
            client_secret,
            allowed_redirect_uris,
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Delete the OAuth provider config for this tenant. \
        `provider` must be 'google' or 'github'. Removes the row from \
        `_system_oauth_providers`; in-flight OAuth callbacks for this \
        provider will fail with PROVIDER_NOT_CONFIGURED. \
        Returns {ok: true, provider, deleted: true}. \
        Errors with NOT_FOUND if the provider was not configured.")]
    async fn delete_oauth_provider(
        &self,
        Parameters(ProviderOnlyArgs { provider }): Parameters<ProviderOnlyArgs>,
    ) -> Result<CallToolResult, McpError> {
        match oauth_tools::delete_oauth_provider(&self.state.inner().pool, provider).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    // ── v1.13: Webhook subscription tools (service-only) ───────────────────

    #[tool(description = "Create an outbound webhook subscription for this tenant. \
        `events` is a non-empty subset of {created, updated, deleted}. \
        `url` must be https:// or http:// with a loopback host (127.0.0.1/localhost/::1). \
        Returns {id, secret, collection, events, url, active, created_at}. \
        The raw 64-hex `secret` is returned **once**; subsequent reads redact it to '●●●●'. \
        Errors: INVALID_URL, INVALID_EVENTS, DB_ERROR.")]
    async fn create_webhook(
        &self,
        Parameters(CreateWebhookArgs { collection, events, url }): Parameters<CreateWebhookArgs>,
    ) -> Result<CallToolResult, McpError> {
        match webhook_tools::create_webhook(&self.state.inner().pool, collection, events, url).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "List all webhook subscriptions for this tenant. \
        Returns {webhooks: [{id, collection, events, url, secret, active, \
        last_failure_at, last_failure_reason, created_at}]}. \
        Secrets are always redacted to '●●●●'.")]
    async fn list_webhooks(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        match webhook_tools::list_webhooks(&self.state.inner().pool).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Update one or more fields of a webhook subscription. \
        All fields except `id` are optional — only supplied fields are changed. \
        `secret` cannot be rotated through this tool; delete + recreate instead. \
        Returns {updated: true, id}. \
        Errors: NOT_FOUND, INVALID_URL, INVALID_EVENTS.")]
    async fn update_webhook(
        &self,
        Parameters(UpdateWebhookArgs { id, active, events, url }): Parameters<UpdateWebhookArgs>,
    ) -> Result<CallToolResult, McpError> {
        match webhook_tools::update_webhook(&self.state.inner().pool, id, active, events, url).await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "Delete a webhook subscription. \
        Returns {deleted: true, id}. \
        Errors with NOT_FOUND if the id does not exist.")]
    async fn delete_webhook(
        &self,
        Parameters(WebhookIdArgs { id }): Parameters<WebhookIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        match webhook_tools::delete_webhook(&self.state.inner().pool, id).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "v1.26 — Recent write events for this tenant. \
        Returns ts/op/collection/status/error_code for the latest \
        insert/update/delete/DDL operations. Use this to replan after \
        errors or to confirm what the previous tool calls actually \
        changed. Service-key + MCP only (anon and user tokens are \
        rejected by the MCP layer).")]
    async fn recent_writes(
        &self,
        Parameters(RecentWritesArgs { limit, collection, since_ts }): Parameters<RecentWritesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tenant_id = self.state.inner().tenant_id.clone();
        match crate::safety::recent_writes::query_recent(
            &self.state.inner().audit_meta_read,
            &tenant_id,
            limit.unwrap_or(50),
            collection.as_deref(),
            since_ts.as_deref(),
        ).await {
            Ok(rows) => json_content(serde_json::to_value(rows).expect("serialise")),
            Err(e) => bail_mcp(anyhow::anyhow!("RECENT_WRITES_UNAVAILABLE: {e}")),
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
             Tools: `whoami`, `list_collections`, `describe_collection`, `get_schema_overview`, `sample_rows`, \
             `count_rows`, `list_records`, `query`, `explain`, `insert_record`, `update_record`, \
             `delete_record`, `create_collection`, `add_field`, `drop_field`, \
             `drop_collection`, `set_anon_caps`, `set_collection_description`, \
             `set_field_description`, `set_index_description`, `set_realtime`, \
             `create_index`, `drop_index`, \
             `search_collection`, `list_files`, `delete_file`, `get_file_url`, \
             `create_rpc`, `update_rpc`, `delete_rpc`, `list_rpc`, `call_rpc`, \
             `create_user`, `list_users`, `get_user`, `update_user`, `delete_user`, \
             `revoke_user_sessions`, `set_owner_field`, `clear_owner_field`, \
             `set_self_register`, `list_oauth_providers`, `set_oauth_provider`, \
             `delete_oauth_provider`, `create_webhook`, `list_webhooks`, \
             `update_webhook`, `delete_webhook`. \
             (Call `tools/list` for the canonical schema-and-list.)\n\n\
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

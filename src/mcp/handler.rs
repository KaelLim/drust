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
    exploration, files as file_tools, oauth as oauth_tools, owner_field as owner_field_tools, read,
    schema as schema_tools, user as user_tools, vector as vector_tools, webhook as webhook_tools,
    write as write_tools,
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
        "DESCRIPTION_TOO_LONG"
        | "DESCRIPTION_INVALID"
        | "COLLECTION_NOT_FOUND"
        | "FIELD_NOT_FOUND"
        | "INDEX_NOT_FOUND"
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
pub struct SetDescriptionArgs {
    /// One of "collection" | "field" | "index".
    pub target: String,
    pub collection: String,
    /// Required when target == "field".
    #[serde(default)]
    pub field: Option<String>,
    /// Required when target == "index".
    #[serde(default)]
    pub index_name: Option<String>,
    /// Empty string clears (collection -> NULL, field/index -> key removed).
    /// Trimmed to <=2048 bytes (MAX_DESCRIPTION_BYTES).
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

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DeleteFunctionArgs {
    pub name: String,
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct SetFunctionActiveArgs {
    pub name: String,
    pub active: bool,
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct InvokeFunctionArgs {
    pub name: String,
    pub event: serde_json::Value,
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct GetFunctionLogsArgs {
    pub name: String,
    #[serde(default)]
    pub limit: Option<i64>,
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
    /// The owner column (FK to _system_users(id)). Pass `null` or "" to CLEAR
    /// the owner-field declaration (reverting to no ownership filtering).
    #[serde(default)]
    pub field: Option<String>,
    /// `"own"` (default) — anon reads see only their own rows. `"all"` — unfiltered.
    /// Ignored when clearing.
    #[serde(default = "default_own")]
    pub read_scope: String,
}

fn default_own() -> String {
    "own".to_string()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetSelfRegisterArgs {
    pub enabled: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetPublishPolicyArgs {
    /// When `Some`, sets `allow_user_publish` to this value. Omit to leave
    /// the flag unchanged. Default is `false` (publish denied for user
    /// tokens until admin opts in).
    pub allow_user_publish: Option<bool>,
    /// When `Some`, sets `allow_anon_publish` to this value. Omit to leave
    /// the flag unchanged. Default is `false` (publish denied for anon
    /// tokens until admin opts in).
    pub allow_anon_publish: Option<bool>,
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BroadcastArgs {
    /// Room name. Must match `^[a-zA-Z][a-zA-Z0-9_:.-]{0,127}$`. The
    /// `_system_` prefix is reserved and returns PROTECTED_ROOM.
    pub room: String,
    /// Any JSON value. Bound to the per-tenant `payload_max_bytes`
    /// (default 64 KiB) measured against the serialised payload.
    pub payload: Value,
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
        data.insert(
            "error_code".into(),
            serde_json::Value::String(code.to_string()),
        );
    }
    if let Some(f) = fix {
        data.insert(
            "suggested_fix".into(),
            serde_json::Value::String(f.to_string()),
        );
    }
    let data_val = if data.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(data))
    };
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

    /// Number of MCP tools this service exposes, derived from the
    /// macro-generated router so it can never drift from reality.
    /// Cached: building the router walks every tool's schema once.
    /// Drives the "N tools" pill on the admin `_api_keys` page.
    pub fn tool_count() -> usize {
        static COUNT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *COUNT.get_or_init(|| Self::tool_router().list_all().len())
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

    #[tool(
        description = "One-shot schema bootstrap for the tenant — your FIRST call on \
        connect. Returns every collection's full schema plus its access state \
        (anon_caps, owner_field + read_scope ALWAYS present — null when not owner-scoped, \
        realtime_enabled, vector_fields flagged with `dim`) and every stored RPC's callable \
        contract (declared `params`, `anon_callable`, and `user_id_autobound` — true when the \
        RPC declares a `user_id` param, which drust auto-binds from the caller's user token). \
        After this one call you know enough to act: which collections require an owner field on \
        INSERT, which won't be visible to anon, and which fields are vectors (use \
        `search_collection`, not list — vectors are excluded from default list/get responses). \
        Service-key only. `list_collections` + `describe_collection` remain for narrower inspection."
    )]
    async fn get_schema_overview(&self) -> Result<CallToolResult, McpError> {
        match exploration::get_schema_overview(&self.state).await {
            Ok(v) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&v).expect("serialise"),
            )])),
            Err(e) => Err(McpError::internal_error(e.to_string(), None)),
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
        Parameters(CreateCollectionArgs {
            name,
            fields,
            description,
        }): Parameters<CreateCollectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match schema_tools::create_collection_with_desc(
            &self.state,
            &name,
            &fields,
            description.as_deref(),
        )
        .await
        {
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

    #[tool(
        description = "Drop an entire collection (DROP TABLE + _updated_at trigger). \
        Irreversible. Rejected if other collections still FK-reference this one. \
        v1.26: pass `dry_run: true` to preview row_count + indexes + RPCs + \
        reverse FK list without dropping."
    )]
    async fn drop_collection(
        &self,
        Parameters(DropCollectionArgs {
            collection,
            dry_run,
        }): Parameters<DropCollectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        if dry_run.unwrap_or(false) {
            if crate::storage::schema::is_protected_collection(&collection) {
                return bail_mcp(anyhow::anyhow!(
                    "PROTECTED_COLLECTION: cannot drop {collection}"
                ));
            }
            let coll_check = collection.clone();
            let exists: i64 = self
                .state
                .inner()
                .pool
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
            )
            .await
            {
                Ok(br) => json_content(serde_json::to_value(br).expect("serialise")),
                Err(e) => bail_mcp(e),
            };
        }
        match schema_tools::drop_collection(&self.state, &collection).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Create a non-unique or unique index on one or more fields of a \
        collection. Speeds up `WHERE field = ?` and `ORDER BY field` queries. \
        `fields` is a non-empty list of column names (order matters for composite indices). \
        `unique` defaults to false. \
        Tables with more than DRUST_INDEX_LARGE_TABLE_ROWS rows return LARGE_TABLE — \
        pass force=true only after understanding the temporary write lock implication."
    )]
    async fn create_index(
        &self,
        Parameters(CreateIndexArgs {
            collection,
            fields,
            unique,
            force,
            description,
        }): Parameters<CreateIndexArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::index::create_index_with_threshold_and_desc(
            &self.state.inner().pool,
            &collection,
            &fields,
            unique.unwrap_or(false),
            force.unwrap_or(false),
            self.state.inner().index_large_table_rows,
            description.as_deref(),
        )
        .await
        {
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
        Parameters(DropIndexArgs {
            collection,
            name,
            fields,
            dry_run,
        }): Parameters<DropIndexArgs>,
    ) -> Result<CallToolResult, McpError> {
        if dry_run.unwrap_or(false) {
            let resolved = match (name.as_deref(), fields.as_deref()) {
                (Some(n), _) => n.to_string(),
                (None, Some(fs)) if !fs.is_empty() => {
                    crate::mcp::tools::index::derive_index_name(&collection, fs)
                }
                _ => {
                    return bail_mcp(anyhow::anyhow!(
                        "INVALID_PARAMS: provide either name or non-empty fields"
                    ));
                }
            };
            return match crate::storage::blast_radius::drop_index_blast_radius(
                &self.state.inner().pool,
                &resolved,
            )
            .await
            {
                Ok(br) => json_content(serde_json::to_value(br).expect("serialise")),
                Err(e) => bail_mcp(e),
            };
        }
        match crate::mcp::tools::index::drop_index(
            &self.state.inner().pool,
            &collection,
            name.as_deref(),
            fields.as_deref(),
        )
        .await
        {
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
        Parameters(SetRealtimeArgs {
            collection,
            enabled,
        }): Parameters<SetRealtimeArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::realtime::set_realtime(&self.state, &collection, enabled).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Set or clear a plain-text description on a tenant collection, \
        one of its fields, or one of its indexes. `target` selects which: \
        \"collection\" (needs `collection`), \"field\" (needs `collection` + `field`), \
        \"index\" (needs `collection` + `index_name`). Service-key only. Empty / \
        whitespace `description` clears (collection -> NULL; field/index -> key removed). \
        Bounded to 2048 bytes after trimming. Errors: COLLECTION_NOT_FOUND, \
        FIELD_NOT_FOUND, INDEX_NOT_FOUND, PROTECTED_COLLECTION, DESCRIPTION_TOO_LONG, \
        DESCRIPTION_INVALID. Example: \
        {\"target\":\"field\",\"collection\":\"posts\",\"field\":\"title\",\"description\":\"Post title\"}."
    )]
    async fn set_description(
        &self,
        Parameters(args): Parameters<SetDescriptionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        let result = match args.target.as_str() {
            "collection" => {
                schema_tools::set_collection_description(&pool, &args.collection, &args.description).await
            }
            "field" => {
                let Some(field) = args.field.as_deref() else {
                    return Err(McpError::invalid_params(
                        "FIELD_REQUIRED: target=field requires `field`".to_string(),
                        None,
                    ));
                };
                schema_tools::set_field_description(&pool, &args.collection, field, &args.description).await
            }
            "index" => {
                let Some(index_name) = args.index_name.as_deref() else {
                    return Err(McpError::invalid_params(
                        "INDEX_NAME_REQUIRED: target=index requires `index_name`".to_string(),
                        None,
                    ));
                };
                schema_tools::set_index_description(&pool, &args.collection, index_name, &args.description).await
            }
            other => {
                return Err(McpError::invalid_params(
                    format!("INVALID_TARGET: target must be collection|field|index, got {other}"),
                    None,
                ));
            }
        };
        match result {
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

    #[tool(
        description = "List records from a collection with structured filter, \
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
        rows."
    )]
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
        Parameters(DeleteRecordArgs {
            collection,
            id,
            dry_run,
        }): Parameters<DeleteRecordArgs>,
    ) -> Result<CallToolResult, McpError> {
        if dry_run.unwrap_or(false) {
            match crate::mcp::tools::write::delete_record_validate(&self.state, &collection, id)
                .await
            {
                Ok(()) => {}
                Err(e) => return bail_mcp(e),
            }
            match crate::storage::blast_radius::delete_blast_radius(
                &self.state.inner().pool,
                &collection,
                id,
            )
            .await
            {
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

    #[tool(
        description = "Change a file's visibility between public and private by \
        its id (the UUID key). Moves the S3 object to the target bucket and updates \
        the metadata row (cache_control is reset to the target's default). Returns \
        {\"ok\": true, \"from\", \"to\"} on change, {\"ok\": true, \"noop\": true} if \
        already that visibility, or {\"error_code\": \"NOT_FOUND\" | \
        \"INVALID_VISIBILITY\" | \"STORAGE_UNAVAILABLE\"}."
    )]
    async fn set_file_visibility(
        &self,
        Parameters(args): Parameters<file_tools::SetFileVisibilityArgs>,
    ) -> Result<CallToolResult, McpError> {
        match file_tools::set_file_visibility(&self.state, args).await {
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
            crate::rpc::prepare::validate_rpc_sql(c, &sql, crate::rpc::registry::RpcMode::Read)
                .map_err(|e| {
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
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
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
                crate::rpc::prepare::validate_rpc_sql(c, s, crate::rpc::registry::RpcMode::Read)
                    .map_err(|e| {
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
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
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
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
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
                    c, &rpc.sql, &bound, 1_000, 1_048_576,
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

    #[tool(
        description = "Create a new user in this tenant's _system_users table. \
        Required: email (unique, case-insensitive), password (hashed server-side). \
        Optional: profile (JSON object), verified (boolean, default false). \
        Returns {user_id, email, created_at}. \
        Errors with EMAIL_EXISTS if the email is already taken."
    )]
    async fn create_user(
        &self,
        Parameters(CreateUserArgs {
            email,
            password,
            profile,
            verified,
        }): Parameters<CreateUserArgs>,
    ) -> Result<CallToolResult, McpError> {
        match user_tools::create_user(&self.state.inner().pool, email, password, profile, verified)
            .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "List users in this tenant. Optional: q (email substring filter), \
        limit (1–500, default 50), offset. \
        Returns {users: [...], total}."
    )]
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

    #[tool(
        description = "Update one or more fields of a user. All fields except user_id \
        are optional — only supplied fields are changed. password is re-hashed server-side. \
        Returns the updated row. Errors: NOT_FOUND, EMAIL_EXISTS, HASH_FAILED."
    )]
    async fn update_user(
        &self,
        Parameters(UpdateUserArgs {
            user_id,
            email,
            password,
            profile,
            verified,
        }): Parameters<UpdateUserArgs>,
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

    #[tool(
        description = "Delete a user and cascade: removes the user's records from every \
        collection that has owner_field set, revokes all sessions, then deletes the user row. \
        Returns {deleted_records: {<collection>: <count>, ...}, revoked_sessions: <n>}. \
        Errors with NOT_FOUND if the user does not exist."
    )]
    async fn delete_user(
        &self,
        Parameters(UserIdArgs { user_id }): Parameters<UserIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        // v1.35 hook 8-MCP — pass the shared auth cache so the tool fn can
        // drop the deleted user's cached session entries synchronously.
        let inner = self.state.inner();
        match user_tools::delete_user(&inner.pool, user_id, inner.auth_cache.as_deref()).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        description = "Revoke all active sessions for a user (forces re-login on all devices). \
        Returns {revoked: <n>}. Safe to call on a non-existent user (returns revoked: 0)."
    )]
    async fn revoke_user_sessions(
        &self,
        Parameters(UserIdArgs { user_id }): Parameters<UserIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        // v1.35 hook 7-MCP — pass the shared auth cache so the tool fn can
        // drop the user's cached session entries synchronously.
        let inner = self.state.inner();
        match user_tools::revoke_user_sessions(&inner.pool, user_id, inner.auth_cache.as_deref())
            .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    // ── T25: Owner-field + self-register tools ─────────────────────────────

    #[tool(
        description = "Declare that a column in `collection` is the owner-field — \
        a foreign key to _system_users(id) that links rows to their creator. \
        `field` must already exist on the table and carry a FK to _system_users(id). \
        `read_scope`: 'own' (default) — anon reads filtered to caller's user_id; \
        'all' — anon reads unfiltered. \
        Returns {owner_field, read_scope}. \
        Errors: OWNER_FIELD_INVALID_COLUMN (no such column), OWNER_FIELD_NOT_FK (missing FK). \
        Pass field: null (or \"\") to CLEAR the owner-field (returns {cleared:true})."
    )]
    async fn set_owner_field(
        &self,
        Parameters(SetOwnerFieldArgs {
            collection,
            field,
            read_scope,
        }): Parameters<SetOwnerFieldArgs>,
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
                ));
            }
        };
        let tenant_id = self.state.tenant_id().to_string();
        match owner_field_tools::set_self_register(&meta, &tenant_id, enabled).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "v1.32.5 — Set this tenant's broadcast publish policy. \
        Two opt-in flags (both default false) gate `op:publish` (WS) and \
        POST /t/{tenant}/rooms/{room} (REST) for non-service tokens. Either \
        arg may be omitted to leave that flag unchanged. \
        - allow_user_publish=true: logged-in end-users (drust_user_*) may publish. \
        - allow_anon_publish=true: the public anon bearer may publish — treat \
          as public-write; per-tenant rate-limit still applies. \
        MCP `broadcast` is service-only regardless of these flags (MCP \
        dispatch enforces). Returns {allow_user_publish, allow_anon_publish} \
        with the post-update state. NOT_FOUND if the tenant is missing.")]
    async fn set_publish_policy(
        &self,
        Parameters(SetPublishPolicyArgs {
            allow_user_publish,
            allow_anon_publish,
        }): Parameters<SetPublishPolicyArgs>,
    ) -> Result<CallToolResult, McpError> {
        let meta = match self.state.meta() {
            Some(m) => m.clone(),
            None => {
                return Err(McpError::internal_error(
                    "meta connection not available in this context".to_string(),
                    None,
                ));
            }
        };
        let tenant_id = self.state.tenant_id().to_string();
        // v1.35 hook 11 (MCP face) — pass the cache so a flag change drops
        // the tenant's cached auth entries synchronously.
        let inner = self.state.inner();
        match owner_field_tools::set_publish_policy(
            &meta,
            &tenant_id,
            allow_user_publish,
            allow_anon_publish,
            inner.auth_cache.as_deref(),
        )
        .await
        {
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
        Parameters(SetOauthProviderArgs {
            provider,
            client_id,
            client_secret,
            allowed_redirect_uris,
        }): Parameters<SetOauthProviderArgs>,
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

    #[tool(
        description = "Create an outbound webhook subscription for this tenant. \
        `events` is a non-empty subset of {created, updated, deleted}. \
        `url` must be https:// or http:// with a loopback host (127.0.0.1/localhost/::1). \
        Returns {id, secret, collection, events, url, active, created_at}. \
        The raw 64-hex `secret` is returned **once**; subsequent reads redact it to '●●●●'. \
        Errors: INVALID_URL, INVALID_EVENTS, DB_ERROR."
    )]
    async fn create_webhook(
        &self,
        Parameters(CreateWebhookArgs {
            collection,
            events,
            url,
        }): Parameters<CreateWebhookArgs>,
    ) -> Result<CallToolResult, McpError> {
        match webhook_tools::create_webhook(&self.state.inner().pool, collection, events, url).await
        {
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
        Parameters(UpdateWebhookArgs {
            id,
            active,
            events,
            url,
        }): Parameters<UpdateWebhookArgs>,
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
        Parameters(RecentWritesArgs {
            limit,
            collection,
            since_ts,
        }): Parameters<RecentWritesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tenant_id = self.state.inner().tenant_id.clone();
        match crate::safety::recent_writes::query_recent(
            &self.state.inner().audit_meta_read,
            &tenant_id,
            limit.unwrap_or(50),
            collection.as_deref(),
            since_ts.as_deref(),
        )
        .await
        {
            Ok(rows) => json_content(serde_json::to_value(rows).expect("serialise")),
            Err(e) => bail_mcp(anyhow::anyhow!("RECENT_WRITES_UNAVAILABLE: {e}")),
        }
    }

    #[tool(description = "v1.31 — Publish a JSON payload to a broadcast room. \
        Service-key only (MCP dispatch already gates this). Fans out to every \
        WebSocket subscriber currently connected to /t/<tenant>/realtime on the \
        same room name. Fire-and-forget: messages are not persisted; subscribers \
        connected later receive nothing. Returns `{room, delivered_to, byte_count}`. \
        Errors: ROOM_NAME_INVALID, PROTECTED_ROOM (`_system_` prefix), PAYLOAD_TOO_LARGE, \
        RATE_LIMITED.")]
    async fn broadcast(
        &self,
        Parameters(BroadcastArgs { room, payload }): Parameters<BroadcastArgs>,
    ) -> Result<CallToolResult, McpError> {
        use crate::tenant::rooms::audit::{write_publish_audit, write_publish_audit_failure};
        use crate::tenant::rooms::envelope::codes;
        use crate::tenant::rooms::rest::{PublishCtx, PublishError, publish_into_bus};
        let inner = self.state.inner();
        let tenant = inner.tenant_id.clone();
        let pc = PublishCtx {
            bus: inner.bus_rooms.clone(),
            bucket: inner.bucket.clone(),
            cfg: inner.rooms_cfg.clone(),
        };
        let started = std::time::Instant::now();
        let byte_count = serde_json::to_vec(&payload).map(|v| v.len()).unwrap_or(0);
        match publish_into_bus(&pc, &tenant, &room, payload, "mcp") {
            Ok(delivered_to) => {
                let ms = started.elapsed().as_millis() as u64;
                write_publish_audit(
                    &tenant,
                    "service",
                    ms,
                    &room,
                    byte_count,
                    "mcp",
                    delivered_to,
                    None,
                );
                json_content(serde_json::json!({
                    "room": room,
                    "delivered_to": delivered_to,
                    "byte_count": byte_count,
                }))
            }
            Err(e) => {
                let (code, msg) = match e {
                    PublishError::RoomNameInvalid => (
                        codes::ROOM_NAME_INVALID,
                        "room name does not match ^[a-zA-Z][a-zA-Z0-9_:.-]{0,127}$".to_string(),
                    ),
                    PublishError::ProtectedRoom => (
                        codes::PROTECTED_ROOM,
                        "`_system_` prefix is reserved".to_string(),
                    ),
                    PublishError::PayloadTooLarge => {
                        let max = inner.rooms_cfg.payload_max_bytes;
                        (
                            codes::PAYLOAD_TOO_LARGE,
                            format!("payload {byte_count} bytes exceeds cap {max}"),
                        )
                    }
                    PublishError::RateLimited(d) => (
                        codes::RATE_LIMITED,
                        format!(
                            "per-tenant publish quota exhausted; retry after {} ms",
                            d.as_millis()
                        ),
                    ),
                };
                let ms = started.elapsed().as_millis() as u64;
                write_publish_audit_failure(
                    &tenant, "service", ms, &room, byte_count, "mcp", code, None,
                );
                bail_mcp(anyhow::anyhow!("{code}: {msg}"))
            }
        }
    }

    #[tool(description = "v1.36 — List this tenant's edge functions: name, \
        wasm sha256, size, trigger bindings, active flag, description. \
        There is NO MCP upload tool by design — POST the .wasm to \
        /t/<tenant>/functions (multipart: name, wasm, triggers, description) \
        with the service bearer; call whoami for the exact URL.")]
    async fn list_functions(&self) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::list_functions(&self.state).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "v1.36 — Delete an edge function by name. The wasm \
        artifact is garbage-collected when no other function references it. \
        Irreversible; re-upload to restore.")]
    async fn delete_function(
        &self,
        Parameters(DeleteFunctionArgs { name }): Parameters<DeleteFunctionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::delete_function(&self.state, &name).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "v1.36 — Enable/disable an edge function without \
        deleting it. Disabled functions keep their logs and bindings.")]
    async fn set_function_active(
        &self,
        Parameters(SetFunctionActiveArgs { name, active }): Parameters<SetFunctionActiveArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::set_function_active(&self.state, &name, active).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "v1.36 — Enqueue a manual invocation of an edge \
        function with an arbitrary event JSON. ASYNC: returns the enqueue \
        ack immediately; read the outcome via get_function_logs \
        (trigger=manual). For synchronous test runs use REST \
        POST /t/<tenant>/functions/<name>/invoke.")]
    async fn invoke_function(
        &self,
        Parameters(InvokeFunctionArgs { name, event }): Parameters<InvokeFunctionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::invoke_function(&self.state, &name, event).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(description = "v1.36 — Recent invocation log rows for one edge \
        function (newest first): status ok|error|trap|timeout|oom|dropped, \
        duration_ms, captured guest log() text, result/error JSON.")]
    async fn get_function_logs(
        &self,
        Parameters(GetFunctionLogsArgs { name, limit }): Parameters<GetFunctionLogsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::get_function_logs(&self.state, &name, limit).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }
}

// v1.31.4 — onboarding map for LLM clients. Replaces the legacy 50-name
// conga line. Industry pattern (Phil Schmid, Anthropic GitHub MCP): the
// `initialize.instructions` string is the natural server prologue — zero
// round-trip, every client sees it once. Structured by capability group
// + recipes so the LLM can map intent → tool without exhausting tools/list.
fn build_instructions(tenant_id: &str, base: &str) -> String {
    format!(
        r#"drust multi-tenant SQLite BaaS — tenant '{tenant_id}'.

START HERE — make these two calls first, before anything else:
  1. `get_schema_overview` — everything this tenant has in ONE call: collections,
     fields, indexes, RPCs (with their params + callable contract), and each
     collection's access state (owner_field, anon_caps, realtime_enabled, vector
     dims). After this one call you know enough to act correctly on THIS tenant.
  2. `whoami` — your identity, both bearer tokens (plaintext), the REST/MCP/files
     base URLs, and `max_upload_bytes`. (Tokens live ONLY here, never in the
     schema overview.)

CHOOSING A READ TOOL (the most common mis-pick — pick once, here):
  • `list_records` — THE DEFAULT. Structured filter / sort / paginate over ONE
    collection; returns the rows AND `total` + `per_page`. Use it to read, to
    just count (read `total`), or to just sample N (set `per_page:n`, no filter).
    Input is a FilterAst (`?`-bound), so owner_field is always enforced.
  • `query` — raw read-only `SELECT` across non-system tables; SERVICE-ONLY and
    it does NOT enforce owner_field (drust does not rewrite your SQL). Use ONLY
    for ad-hoc analytics a FilterAst cannot express (joins, aggregates).
  • `search_collection` — vector similarity ONLY (a `vector` field + metric).
    Vector fields are excluded from list/GET responses, so this is how you read
    them.

CAPABILITY GROUPS

1. SCHEMA (inspect + DDL)
   Inspect:  get_schema_overview, list_collections, describe_collection
   Mutate:   create_collection, add_field, drop_field, drop_collection
   Indexes:  create_index, drop_index
   Docs:     set_description (target: collection | field | index)
   Gates:    set_realtime, set_anon_caps, set_owner_field (field: name | null to clear)

2. DATA (per-collection CRUD + search)
   Read:    list_records (default), query (raw SELECT, service-only) + explain,
            search_collection (vector)   — see CHOOSING A READ TOOL above
   Write:   insert_record, update_record, delete_record   (all accept dry_run: true)
   RPCs:    create_rpc, update_rpc, delete_rpc, list_rpc, call_rpc

3. STORAGE (per-tenant Garage buckets — public + private)
   Manage: list_files, delete_file, get_file_url, set_file_visibility  (get_file_url: pass download=true for attachment disposition)
   Upload (small): single request — MCP has no upload tool by design. Use REST:
     POST {base}/drust/t/{tenant_id}/files
     Header: Authorization: Bearer $DRUST_TOKEN
     Body:   multipart/form-data
       file          (required — bytes)
       visibility    (required — 'public' | 'private')
       disposition   (optional — 'inline' | 'attachment', default 'inline')
       cache_control (optional — default 'public, max-age=86400' (public) / 'private, no-store' (private))
       meta          (optional — JSON object)
   Upload (large / resumable): when the file exceeds limits.max_upload_bytes
   (see whoami) or you need resume-on-disconnect, use the tus 1.0 protocol:
     POST {base}/drust/t/{tenant_id}/uploads    (create session; 201 + Location)
       Header: Upload-Length, Upload-Metadata (tus); Authorization: Bearer $DRUST_TOKEN
     then PATCH each chunk per tus 1.0; HEAD to resume from the server offset.
     Send OPTIONS {base}/drust/t/{tenant_id}/uploads to discover Tus-Max-Size
     and the per-chunk limit. Service token only (same as small upload).

4. IDENTITY + INTEGRATIONS
   Users:    create_user, list_users, get_user, update_user, delete_user, revoke_user_sessions
   OAuth:    list_oauth_providers, set_oauth_provider, delete_oauth_provider, set_self_register
   Webhooks: create_webhook, list_webhooks, update_webhook, delete_webhook   (CRUD events fan out)
   Broadcast (v1.31+): broadcast — publish JSON to a WS room; fire-and-forget, no replay
   Publish policy (v1.32.5+): set_publish_policy — opt non-service tokens into WS/REST publish

5. OBSERVABILITY (service-only)
   recent_writes — last 100 mutations for THIS tenant. Use after a retry to see what the previous attempt wrote.

6. FUNCTIONS (v1.36+, service-only — edge functions: user-uploaded wasm triggered by record CRUD + file.uploaded)
   Manage:  list_functions, set_function_active, delete_function
   Run:     invoke_function (async — returns enqueue ack; read outcome via get_function_logs, trigger=manual)
   Logs:    get_function_logs
   Upload:  NO MCP upload tool by design. POST the .wasm via REST:
     POST {base}/drust/t/{tenant_id}/functions   (multipart: name, wasm, triggers, description; service bearer)

RECIPES
  "Look around"           → get_schema_overview
  "Read a collection"     → list_records (filter + select + sort + page)
  "Just count rows"       → list_records, read `total` (no separate count tool)
  "Sample a few rows"     → list_records with per_page:n and no filter
  "Run my own SELECT"     → query (read-only; service-only; no owner_field enforcement)
  "Find by similarity"    → search_collection (vector field + metric)
  "Write rows safely"     → <op>_record with dry_run: true first, then again without
  "Recover after a retry" → recent_writes
  "Live broadcast"        → broadcast  (room name regex ^[a-zA-Z][a-zA-Z0-9_:.-]{{0,127}}$)

RECOVERY — experiment cheaply, you can always see and undo-plan:
  • Every destructive tool (delete_record, drop_collection, drop_index) accepts
    `dry_run: true` and returns would_* counts + blast radius WITHOUT mutating.
  • Every error JSON carries a `suggested_fix` hint tailored to the failure —
    read it before retrying.
  • `recent_writes` returns your last 100 mutations, so after a failed/retried
    attempt you can recover exactly what already changed.

NOTES
  • Schema drops and delete_file are irreversible (use dry_run first).
  • Call `tools/list` for the canonical input schema of every tool listed above."#
    )
}

#[tool_handler]
impl ServerHandler for DrustMcpService {
    fn get_info(&self) -> ServerInfo {
        let tenant_id = self.state.tenant_id();
        let base = self.state.public_base_url();
        let instructions = build_instructions(tenant_id, base);
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("drust", env!("CARGO_PKG_VERSION")))
            .with_instructions(instructions)
    }
}

#[cfg(test)]
mod tool_count_tests {
    use super::DrustMcpService;

    #[test]
    fn tool_count_matches_source_annotations() {
        // The admin `_api_keys` page renders an "N tools" pill from
        // `tool_count()`. Lock router reality against the source: every
        // tool annotation in this file must be registered by the macro,
        // and the count must be what the pill shows. The needle is
        // assembled at runtime so this test doesn't count itself.
        let needle = format!("#[tool{}", "(");
        let annotated = include_str!("handler.rs").matches(&needle).count();
        assert_eq!(
            DrustMcpService::tool_count(),
            annotated,
            "router tool count drifted from #[tool] annotations in handler.rs"
        );
        assert!(DrustMcpService::tool_count() > 0, "router must not be empty");
    }
}

#[cfg(test)]
mod description_tests {
    use super::DrustMcpService;
    use rmcp::model::Tool;

    /// Pull one tool's description text out of the live macro-generated
    /// router. `tool_router()` has inherited (private) visibility, so this
    /// MUST live in-file (like `tool_count_tests`); an external
    /// `tests/*.rs` file cannot reach it.
    fn desc_of(name: &str) -> String {
        let tools: Vec<Tool> = DrustMcpService::tool_router().list_all();
        let t = tools.into_iter().find(|t| t.name == name)
            .unwrap_or_else(|| panic!("tool {name:?} not in router"));
        t.description.unwrap_or_else(|| panic!("tool {name:?} has no description")).to_string()
    }

    #[test]
    fn router_exposes_read_cluster_descriptions() {
        for name in ["list_records", "query", "search_collection"] {
            let d = desc_of(name);
            assert!(!d.is_empty(), "{name} description empty");
        }
    }
}

#[cfg(test)]
mod instructions_tests {
    use super::build_instructions;

    #[test]
    fn instructions_includes_all_groups_and_tenant_id() {
        let s = build_instructions("test-tenant-abc", "https://example.test");
        assert!(
            s.contains("'test-tenant-abc'"),
            "tenant id not in identity line"
        );
        assert!(
            s.contains("https://example.test"),
            "base url not interpolated"
        );
        assert!(s.contains("START HERE"), "missing START HERE");
        for group in &[
            "1. SCHEMA",
            "2. DATA",
            "3. STORAGE",
            "4. IDENTITY",
            "5. OBSERVABILITY",
            "6. FUNCTIONS",
        ] {
            assert!(s.contains(group), "missing group heading: {group}");
        }
        assert!(s.contains("RECIPES"), "missing RECIPES section");
        assert!(s.contains("dry_run"), "missing dry_run note");
        assert!(s.contains("broadcast"), "missing v1.31 broadcast surface");
        assert!(s.contains("recent_writes"), "missing observability tool");
        assert!(
            s.contains("/uploads"),
            "tus resumable-upload path must be advertised"
        );
        assert!(
            s.contains("tus"),
            "must name the tus protocol so the LLM knows the verb sequence"
        );
        // Regex range survived format! escaping (literal {0,127}, not a placeholder error)
        assert!(s.contains("{0,127}"), "regex range escaped wrong");
    }

    #[test]
    fn instructions_does_not_leak_other_tenant_ids() {
        let s = build_instructions("alpha", "https://example.test");
        // Defense vs cross-tenant leak: prologue is per-instance; no static
        // literals from other tenants should ever appear in the rendered text.
        for forbidden in &[
            "00000000-0000-0000-0000-000000000000",
            "beta-tenant",
            "gamma-tenant",
            "11111111-1111-1111-1111-111111111111",
        ] {
            assert!(
                !s.contains(forbidden),
                "prologue leaks literal: {forbidden}"
            );
        }
        // Tenant id must appear (identity line + upload URL = at least once).
        assert!(s.contains("alpha"), "own tenant id must appear");
    }

    #[test]
    fn instructions_lead_with_bootstrap_and_disambiguate_reads() {
        let s = build_instructions("test-tenant-abc", "https://example.test");

        // (a) Leads with the two bootstrap calls.
        assert!(s.contains("get_schema_overview"), "must name get_schema_overview as a bootstrap call");
        assert!(s.contains("whoami"), "must name whoami as a bootstrap call");
        let go = s.find("get_schema_overview").expect("get_schema_overview present");
        let groups = s.find("CAPABILITY GROUPS").expect("CAPABILITY GROUPS present");
        assert!(go < groups, "bootstrap calls must appear before the capability-group body");

        // (b) The CHOOSING A READ TOOL disambiguation block exists and names all three.
        assert!(s.contains("CHOOSING A READ TOOL"), "missing CHOOSING A READ TOOL disambiguation block");
        assert!(s.contains("list_records"), "read block must name list_records");
        assert!(s.contains("search_collection"), "read block must name search_collection");
        assert!(s.contains("does not enforce") || s.contains("does NOT enforce"),
            "read block must warn that query does not enforce owner_field");

        // (c) Recovery affordances are stated by name (Lever 5).
        assert!(s.contains("dry_run"), "missing dry_run recovery affordance");
        assert!(s.contains("suggested_fix"), "missing suggested_fix recovery affordance");
        assert!(s.contains("recent_writes"), "missing recent_writes recovery affordance");

        // (d) Post-Lever-4 tool set: merged names present, removed names absent.
        assert!(s.contains("set_description"), "must advertise merged set_description");
        assert!(s.contains("set_owner_field"), "must advertise set_owner_field");
        for removed in &[
            "sample_rows", "count_rows", "set_collection_description",
            "set_field_description", "set_index_description", "clear_owner_field",
        ] {
            assert!(!s.contains(removed), "instructions still reference removed/merged tool: {removed}");
        }
    }
}

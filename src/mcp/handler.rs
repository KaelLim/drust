//! rmcp Streamable HTTP handler for the per-tenant MCP endpoint — the drust
//! tools (see the `#[tool]` annotations; count asserted by `tool_count_tests`)
//! plus the hand-written Resources + Prompts surface.
//!
//! This file is a thin adapter layer: each `#[tool]` method delegates
//! to the existing `pub async fn` in `src/mcp/tools/*` and converts
//! `anyhow::Result<serde_json::Value>` into the rmcp-native
//! `Result<CallToolResult, McpError>` shape. Keeping the underlying
//! functions untouched means the in-process integration tests that
//! already cover them continue to work.

use crate::mcp::server::DrustMcp;
use crate::mcp::tools::{
    batch, exploration, file_policy as file_policy_tools, files as file_tools,
    oauth as oauth_tools, owner_field as owner_field_tools, read, schema as schema_tools,
    user as user_tools, vector as vector_tools, webhook as webhook_tools, write as write_tools,
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
pub struct CreateFtsIndexArgs {
    pub collection: String,
    /// Index name (identifier grammar). May not end in an fts5 shadow suffix
    /// (`_data`/`_idx`/`_docsize`/`_config`/`_content`).
    pub name: String,
    /// One or more TEXT fields to index. Non-TEXT, vector, and
    /// id/created_at/updated_at fields are rejected (FTS_FIELD_INVALID).
    pub fields: Vec<String>,
    /// `"trigram"` (default) or `"unicode61"`.
    #[serde(default)]
    pub tokenizer: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DropFtsIndexArgs {
    pub collection: String,
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListFtsIndexesArgs {
    pub collection: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecentWritesArgs {
    // NOT prose: schemars publishes the doc line below verbatim as this
    // parameter's `description` in `tools/list` — the surface the prologue
    // itself calls canonical and that most clients paste into the system
    // prompt. Keep it in lockstep with `limit.unwrap_or(..)` in
    // `recent_writes` and with the "last 100 mutations" prologue text.
    /// 1..=200; defaults to 100.
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
pub struct SetUserCapsArgs {
    pub collection: String,
    /// Subset of `["select", "insert", "update", "delete"]` governing the
    /// logged-in User role (`drust_user_*` tokens), independent of
    /// `anon_caps`. Empty array locks the collection from the User role
    /// (service is unrestricted by design and not affected).
    pub caps: Vec<crate::storage::schema::DmlVerb>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetRealtimeArgs {
    pub collection: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetAuditEnabledArgs {
    pub collection: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetRecordHistoryArgs {
    pub collection: String,
    /// Optional — restrict the trail to one record's id.
    #[serde(default)]
    pub record_id: Option<i64>,
    /// 1..=200; defaults to 50 (newest first).
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetPolicyArgs {
    pub collection: String,
    /// One of "select" | "insert" | "update" | "delete".
    pub op: String,
    /// `using` clause: a FilterAst (and/or/not tree of eq/ne/gt/.../like/in
    /// leaves) selecting WHICH existing rows the op may touch. Operands may
    /// reference `{"$auth":"id"}` (the caller's user id), `{"$data":"<field>"}`
    /// (the new/post-image row, CHECK only), or `{"$authenticated":true}`.
    /// Omit to leave the op's `using` clause unset. Pass as a JSON object,
    /// not a JSON-encoded string.
    #[serde(default)]
    #[schemars(schema_with = "crate::query::vector_filter::filter_arg_json_schema")]
    pub using: Option<serde_json::Value>,
    /// `check` clause: a FilterAst asserting the NEW row (post-image) is
    /// allowed (insert/update). Omit to leave the op's `check` clause unset.
    /// Pass as a JSON object, not a JSON-encoded string.
    #[serde(default)]
    #[schemars(schema_with = "crate::query::vector_filter::filter_arg_json_schema")]
    pub check: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetPoliciesArgs {
    pub collection: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClearPolicyArgs {
    pub collection: String,
    /// One of "select" | "insert" | "update" | "delete".
    pub op: String,
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
pub struct SetFunctionInvokeAclArgs {
    pub name: String,
    /// Allow anon-bearer invocation (runs capability-gated as Anon). Default-deny.
    pub anon: bool,
    /// Allow end-user (`drust_user_*`) invocation (runs as that user). Default-deny.
    pub user: bool,
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct InvokeFunctionArgs {
    pub name: String,
    /// JSON event payload passed to the function.
    // `serde_json::Value` derives the boolean `true` schema in schemars 1.x,
    // which stricter MCP clients (Zod) reject as an invalid property schema.
    // Render it as an object schema (like the working `data` fields) — the
    // field stays `Value` at runtime, so any JSON is still accepted.
    #[schemars(with = "std::collections::HashMap<String, serde_json::Value>")]
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
    /// The SQL body, using `:name` placeholders. Required for kind="sql"
    /// (the default); must be omitted or empty for kind="query", whose body
    /// is `query` instead.
    #[serde(default)]
    pub sql: String,
    pub params: Vec<crate::rpc::params::ParamSpec>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub anon_callable: Option<bool>,
    /// "read" (default) or "write". Write bodies may contain multi-statement
    /// INSERT/UPDATE/DELETE; DDL, transactions and _system_* writes are
    /// refused at create time.
    #[serde(default)]
    pub mode: Option<String>,
    /// "sql" (default) or "query". A "query" RPC stores a structured filter
    /// template in `query` instead of SQL and runs through the /list pipeline
    /// under the CALLER's identity, so owner_field + RLS policies apply.
    /// Immutable after create.
    #[serde(default)]
    pub kind: Option<String>,
    /// The template for kind="query": `{collection, filter?, sort?, select?}`.
    /// `filter` is a FilterAst that may additionally use the two
    /// template-only leaf operands `{"$param":"<declared param>"}` and
    /// `{"$auth":"id"}`. Validated (and dry-compiled) at create time.
    #[serde(default)]
    #[schemars(with = "Option<crate::rpc::query_template::QueryTemplate>")]
    pub query: Option<Value>,
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
    /// "read" or "write". Omit to keep the stored mode. A new sql body is
    /// validated under the effective mode (this param if given, else the
    /// stored row's).
    #[serde(default)]
    pub mode: Option<String>,
    /// Replacement template for a kind="query" RPC (#950), same shape as
    /// create_rpc's `query`. Omit to keep the stored template. Refused on a
    /// kind="sql" row — `kind` is immutable after create.
    #[serde(default)]
    #[schemars(with = "Option<crate::rpc::query_template::QueryTemplate>")]
    pub query: Option<Value>,
}

/// Parse the optional `kind` param on create_rpc (#950). `None` means "not
/// supplied" — create defaults to Sql. `kind` is immutable after create, so
/// update_rpc deliberately has no such param.
fn parse_rpc_kind(raw: Option<&str>) -> Result<Option<crate::rpc::registry::RpcKind>, McpError> {
    match raw {
        None => Ok(None),
        Some("sql") => Ok(Some(crate::rpc::registry::RpcKind::Sql)),
        Some("query") => Ok(Some(crate::rpc::registry::RpcKind::Query)),
        Some(_) => Err(McpError::invalid_params(
            "RPC_KIND_INVALID: kind must be \"sql\" or \"query\"",
            None,
        )),
    }
}

/// Parse the optional `mode` param shared by create_rpc / update_rpc.
/// `None` means "not supplied" — create defaults to Read, update preserves
/// the stored value.
fn parse_rpc_mode(raw: Option<&str>) -> Result<Option<crate::rpc::registry::RpcMode>, McpError> {
    match raw {
        None => Ok(None),
        Some("read") => Ok(Some(crate::rpc::registry::RpcMode::Read)),
        Some("write") => Ok(Some(crate::rpc::registry::RpcMode::Write)),
        Some(_) => Err(McpError::invalid_params(
            "mode must be \"read\" or \"write\"",
            None,
        )),
    }
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetFileCapsArgs {
    /// Full desired ANON file-cap set (REPLACE, not merge) — a subset of
    /// ["read","list","upload","delete"]. Omit to leave anon caps unchanged.
    /// Empty `[]` = service-only for anon (the default). make-public stays
    /// service-only and is not a cap.
    pub anon: Option<Vec<crate::storage::schema::FileVerb>>,
    /// Full desired USER (drust_user_*) file-cap set (REPLACE). Omit to leave
    /// unchanged. Empty `[]` = service-only for users.
    pub user: Option<Vec<crate::storage::schema::FileVerb>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetEgressAllowlistArgs {
    /// Full desired egress allowlist (REPLACE, not merge). Each entry is
    /// `{system, uri}` where `system` is `"webhook"` or `"function"` and
    /// `uri` is an origin (`scheme://host[:port]`, no path). An empty list
    /// denies EVERY outbound path (deny-all default). Bad origin shape →
    /// EGRESS_BAD_ORIGIN; unknown system → EGRESS_BAD_SYSTEM; over the
    /// per-tenant limit → EGRESS_TOO_MANY.
    pub entries: Vec<crate::tenant::egress_config::RawEgressEntry>,
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetRedirectUrisArgs {
    /// `"google"` or `"github"` — must already be configured.
    pub provider: String,
    /// Full replacement list of allowed redirect URIs. Each must be
    /// https:// or a localhost/127.0.0.1 URL. Non-empty.
    pub allowed_redirect_uris: Vec<String>,
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
    // See InvokeFunctionArgs::event — render an object schema so strict MCP
    // clients accept the property (bare `Value` derives a boolean `true` schema).
    #[schemars(with = "std::collections::HashMap<String, serde_json::Value>")]
    pub payload: Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateCronJobArgs {
    /// Job name — `[a-z0-9_-]{1,64}`, unique per tenant.
    pub name: String,
    /// 5-field cron expression (minute hour day month weekday), UTC.
    /// No seconds field, no `@aliases`.
    pub schedule: String,
    /// "function" (edge function) or "rpc" (stored RPC).
    pub target_kind: String,
    /// Name of the edge function or stored RPC to run.
    pub target_name: String,
    /// Optional JSON OBJECT as a string, <= 64 KiB. Functions receive it
    /// as `event.payload`; RPCs bind it as named params. Omitted →
    /// functions get a null payload / RPCs run with no binds.
    #[serde(default)]
    pub payload_json: Option<String>,
    /// Defaults to true.
    #[serde(default)]
    pub active: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteCronJobArgs {
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetCronJobActiveArgs {
    pub name: String,
    pub active: bool,
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

/// Turn a fully-built axum `json_error` response (the shape
/// `exec_query::run_query_rpc` returns) into an `McpError`, preserving the
/// `error_code` + `suggested_fix` fields on `data` — the same structured shape
/// `bail_mcp` produces, so an MCP client sees a uniform error surface across the
/// sql and query `call_rpc` arms (#950 T6).
async fn mcp_error_from_response(resp: axum::response::Response) -> McpError {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let msg = v
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("rpc query failed")
        .to_string();
    let mut data = serde_json::Map::new();
    if let Some(code) = v.get("error_code") {
        data.insert("error_code".into(), code.clone());
    }
    if let Some(fix) = v.get("suggested_fix") {
        data.insert("suggested_fix".into(), fix.clone());
    }
    let data_val = if data.is_empty() {
        None
    } else {
        Some(Value::Object(data))
    };
    McpError::invalid_params(msg, data_val)
}

/// Fire-and-forget RPC call-counter bump on the writer mutex. MCP is
/// service-only, so the role is hardcoded `Service`; shared by both the sql and
/// query arms of `call_rpc` (#950 T6).
fn spawn_rpc_counter_bump(pool: crate::storage::pool::SharedTenantPool, name: String) {
    tokio::spawn(async move {
        let res = pool
            .with_writer(move |c| {
                crate::rpc::registry::increment(c, &name, crate::tenant::router::TokenRole::Service)
            })
            .await;
        if let Err(e) = res {
            tracing::warn!(error = %e, "rpc counter bump failed (mcp call_rpc)");
        }
    });
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

    #[tool(
        annotations(read_only_hint = true),
        description = "List all collections in this tenant's database, with their row counts."
    )]
    async fn list_collections(&self) -> Result<CallToolResult, McpError> {
        match exploration::list_collections(&self.state).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "Return this tenant's identity, both bearer tokens \
        (anon + service, plaintext), the relative REST/MCP/files/rpc \
        endpoint paths, and the configured `max_upload_bytes`. Use this \
        to surface credentials needed for surfaces with no MCP tool — \
        most importantly the multipart file upload endpoint. Tokens \
        minted before v1.1c only stored the hash; their `plaintext` \
        field is null and require an admin reroll to recover. \
        `file_upload` names the `drust://<tenant>/files-guide.md` resource — \
        read it before uploading files, it is where the upload endpoints, the \
        visibility model and the publish grant are explained."
    )]
    async fn whoami(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        match exploration::whoami(&self.state).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "Return the full schema for one collection: all fields \
        (name, sql_type, nullable, pk, default, foreign_key), all indices, and row count. \
        Returns {\"error_code\": \"COLLECTION_NOT_FOUND\"} if the collection does not exist."
    )]
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
        annotations(read_only_hint = true),
        description = "One-shot schema bootstrap for the tenant — your FIRST call on \
        connect. Returns every collection's full schema plus its access state \
        (anon_caps, owner_field + read_scope ALWAYS present — null when not owner-scoped, \
        realtime_enabled, vector_fields flagged with `dim`, and a per-op RLS `policies` map — ALWAYS present, empty when none) and every stored RPC's callable \
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
        annotations(read_only_hint = true),
        description = "Raw read-only SELECT across this tenant's non-system tables. \
        USE WHEN: an ad-hoc analytic shape a FilterAst cannot express (GROUP BY, \
        JOIN-free aggregates, expressions). NOT WHEN: you just want filtered/\
        sorted/paginated rows of ONE collection — use `list_records` (it builds \
        the SQL for you and returns `total`). VS SIBLINGS: `query` takes raw SELECT \
        and does NOT enforce `owner_field`, so it is service-only and un-rewritable; \
        `list_records` and `search_collection` take structured input and always \
        enforce scoping. The SQL is validated by a strict authorizer: no INSERT/\
        UPDATE/DELETE/DDL, no ATTACH, no sqlite_master reads. Limits: 16 KB SQL, \
        10,000 rows, 5 second timeout."
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
        annotations(read_only_hint = true),
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

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = false),
        description = "Create a new collection (SQLite table). \
        USE WHEN: defining a brand-new entity for this tenant. NOT WHEN: adding \
        one column to an existing collection — use `add_field` (same FieldSpec \
        shape). Every collection implicitly gets id INTEGER PRIMARY KEY \
        AUTOINCREMENT, created_at, updated_at (all auto-maintained — do NOT \
        declare them). Each entry in `fields` is {name, sql_type, nullable?, \
        unique?, default_value?, foreign_key?, dim?}. `sql_type` is lowercase, one \
        of: text, integer, real, boolean, datetime, json, vector. `default_value` \
        accepts JSON scalars or {\"sql\": \"datetime('now')\"} (allowlisted \
        expressions). `foreign_key` names another existing collection; emits \
        ON DELETE RESTRICT. `dim` (1..=4096) is REQUIRED when sql_type is vector \
        and ignored otherwise. EXAMPLE call: {\"name\": \"posts\", \"fields\": [\
        {\"name\": \"title\", \"sql_type\": \"text\", \"nullable\": false}, \
        {\"name\": \"published_at\", \"sql_type\": \"datetime\", \
        \"default_value\": {\"sql\": \"datetime('now')\"}}, \
        {\"name\": \"author_id\", \"sql_type\": \"integer\", \
        \"foreign_key\": \"users\"}, {\"name\": \"embedding\", \
        \"sql_type\": \"vector\", \"dim\": 384}]}"
    )]
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
        annotations(destructive_hint = false, idempotent_hint = false),
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

    #[tool(
        annotations(destructive_hint = true),
        description = "Drop a field (column) from a collection via \
        `ALTER TABLE … DROP COLUMN`. Cannot drop the system columns `id`, \
        `created_at`, `updated_at` (drust maintains them automatically). \
        SQLite will also reject the drop if the column is part of an \
        index, UNIQUE, foreign key, CHECK, trigger, or view — fix those \
        first. Irreversible."
    )]
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
        annotations(destructive_hint = true),
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
        annotations(destructive_hint = false, idempotent_hint = false),
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

    #[tool(
        annotations(destructive_hint = true),
        description = "Drop an index by name or by field set. \
        Removes the lookup structure but does NOT touch row data. \
        v1.26: pass `dry_run: true` to confirm the index exists and \
        receive its name without dropping."
    )]
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

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = false),
        description = "Create a full-text-search (FTS5) index over one or more \
        TEXT fields of a collection. `name` is the index identifier; `fields` is \
        a non-empty list of TEXT column names (id/created_at/updated_at, vector, \
        and non-TEXT fields are rejected). `tokenizer` is \"trigram\" (default) \
        or \"unicode61\". Builds an external-content FTS5 vtable + three sync \
        triggers and runs a corpus rebuild in one transaction — this holds the \
        tenant writer lock for the whole collection and is the documented DDL \
        quota carve-out (a service key can transiently exceed its cap building \
        one index; the next record/upload write then blocks)."
    )]
    async fn create_fts_index(
        &self,
        Parameters(CreateFtsIndexArgs {
            collection,
            name,
            fields,
            tokenizer,
        }): Parameters<CreateFtsIndexArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::fts::create_fts_index(
            &self.state,
            &collection,
            &name,
            &fields,
            tokenizer.as_deref(),
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = true),
        description = "Drop a full-text-search index by name: removes its sync \
        triggers and the underlying FTS5 vtable (row data in the collection is \
        untouched) and unregisters it. Returns FTS_INDEX_NOT_FOUND if absent."
    )]
    async fn drop_fts_index(
        &self,
        Parameters(DropFtsIndexArgs { collection, name }): Parameters<DropFtsIndexArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::fts::drop_fts_index(&self.state, &collection, &name).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "List the full-text-search indexes registered on a \
        collection, each with its name, indexed fields, and tokenizer."
    )]
    async fn list_fts_indexes(
        &self,
        Parameters(ListFtsIndexesArgs { collection }): Parameters<ListFtsIndexesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::fts::list_fts_indexes(&self.state, &collection).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Replace the anon-role DML capability set for one \
        collection. `caps` is a subset of [\"select\",\"insert\",\"update\",\"delete\"]; \
        empty locks anon out entirely. Service tokens are unrestricted and \
        not affected. Refuses `_system_*` collections."
    )]
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
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Replace the logged-in User-role DML capability set \
        for one collection. `caps` is a subset of \
        [\"select\",\"insert\",\"update\",\"delete\"], independent of anon_caps; \
        empty locks the User role out entirely. Service tokens are \
        unrestricted and not affected. Refuses `_system_*` collections."
    )]
    async fn set_user_caps(
        &self,
        Parameters(SetUserCapsArgs { collection, caps }): Parameters<SetUserCapsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match schema_tools::set_user_caps(&self.state, &collection, &caps).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Toggle SSE realtime broadcast for one collection. \
        When enabled, clients can subscribe to GET /records/<coll>/subscribe; \
        anon callers additionally need anon_caps containing 'select'. When \
        disabled, existing in-flight SSE connections are dropped within ~1s. \
        Refuses `_system_*` collections."
    )]
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
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "v1.46 — Toggle record-history capture for one \
        collection. When enabled (the default), every insert/update/delete \
        writes a full old/new row snapshot into the tenant's \
        _system_record_history trail, atomically with the mutation; when \
        disabled, new writes leave no trail (rows already captured are kept \
        until retention prunes them, default 7 days). Does NOT affect SSE or \
        row visibility. Read the trail back with `get_record_history`. \
        Refuses `_system_*` collections."
    )]
    async fn set_audit_enabled(
        &self,
        Parameters(SetAuditEnabledArgs {
            collection,
            enabled,
        }): Parameters<SetAuditEnabledArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::audit::set_audit_enabled(&self.state, &collection, enabled).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "v1.46 — Read one collection's record-history trail \
        (newest first): rows {id, op: insert|update|delete, old, new, \
        actor_kind, actor_id, ts} carrying full old/new row snapshots \
        captured atomically with each write. Pass `record_id` to follow one \
        record's timeline; `limit` is 1..=200 (default 50), `total` reports \
        the full match count. Service-only — history aggregates every user's \
        row values. Rows older than the retention window (default 7 days) \
        are pruned."
    )]
    async fn get_record_history(
        &self,
        Parameters(GetRecordHistoryArgs {
            collection,
            record_id,
            limit,
        }): Parameters<GetRecordHistoryArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::audit::get_record_history(
            &self.state,
            &collection,
            record_id,
            limit,
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Set (replace) one operation's row-level-security policy on a \
        collection. `op` is select|insert|update|delete. `using` is a FilterAst \
        (and/or/not tree of eq/ne/gt/.../like/in leaves) selecting WHICH existing \
        rows the op may read or target; `check` is a FilterAst asserting the NEW \
        row (post-image) is allowed (insert/update). Operands may reference \
        {\"$auth\":\"id\"} (caller's user id), {\"$data\":\"<field>\"} (post-image \
        row, CHECK only), or {\"$authenticated\":true}. The policy AND-composes \
        ALONGSIDE any owner_field rule — it does not replace it. Service tokens \
        bypass all explicit policies. Validated at write time: unknown fields / \
        vector fields / over-deep nesting are rejected (POLICY_INVALID). Refuses \
        `_system_*` collections. EXAMPLE call: {\"collection\":\"posts\",\"op\":\
        \"select\",\"using\":{\"owner\":{\"$auth\":\"id\"}}}."
    )]
    async fn set_policy(
        &self,
        Parameters(SetPolicyArgs {
            collection,
            op,
            using,
            check,
        }): Parameters<SetPolicyArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::policy::set_policy(&self.state, &collection, &op, using, check)
            .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "Read the stored row-level-security policy set for a \
        collection (all four ops). Returns `{collection, stored:{select?,insert?,\
        update?,delete?}}`; an op key is absent when that op has no policy. See \
        `set_policy` for the policy shape."
    )]
    async fn get_policies(
        &self,
        Parameters(GetPoliciesArgs { collection }): Parameters<GetPoliciesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::policy::get_policies(&self.state, &collection).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = true),
        description = "Clear (remove) one operation's row-level-security policy \
        on a collection, reverting that op to owner_field + cap-gate rules only. \
        `op` is select|insert|update|delete. Refuses `_system_*` collections."
    )]
    async fn clear_policy(
        &self,
        Parameters(ClearPolicyArgs { collection, op }): Parameters<ClearPolicyArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::policy::clear_policy(&self.state, &collection, &op).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
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
                schema_tools::set_collection_description(&pool, &args.collection, &args.description)
                    .await
            }
            "field" => {
                let Some(field) = args.field.as_deref() else {
                    return Err(McpError::invalid_params(
                        "FIELD_REQUIRED: target=field requires `field`".to_string(),
                        None,
                    ));
                };
                schema_tools::set_field_description(
                    &pool,
                    &args.collection,
                    field,
                    &args.description,
                )
                .await
            }
            "index" => {
                let Some(index_name) = args.index_name.as_deref() else {
                    return Err(McpError::invalid_params(
                        "INDEX_NAME_REQUIRED: target=index requires `index_name`".to_string(),
                        None,
                    ));
                };
                schema_tools::set_index_description(
                    &pool,
                    &args.collection,
                    index_name,
                    &args.description,
                )
                .await
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

    #[tool(
        annotations(read_only_hint = true),
        description = "Nearest-neighbour search over a `vector` field. \
        USE WHEN: you have a query vector and want the `k` most-similar rows \
        (semantic/embedding search). NOT WHEN: you can express the match as a \
        scalar filter — use `list_records` (vector fields are excluded from its \
        output, so similarity is the ONLY reason to reach here). VS SIBLINGS: \
        `list_records`/`query` cannot rank by vector distance; this tool can do \
        nothing but. Builds the SQL itself from the structured body — no raw SQL. \
        Returns up to `k` nearest rows ordered by distance, each carrying an \
        injected `_distance` column. Default metric `cosine`; alternatives `l2`, \
        `l1`. Optional `where` is an and/or/not tree of eq/ne/gt/gte/lt/lte/like/\
        in/nin leaves; vector fields cannot appear in the filter. Optional `select` \
        lists projected columns (default: all non-vector columns). \
        EXAMPLE call: {\"collection\": \"posts\", \"field\": \"embedding\", \
        \"vector\": [0.1, 0.1, 0.1, 0.1], \"k\": 5, \"metric\": \"cosine\", \
        \"where\": {\"status\": \"published\"}, \"select\": [\"id\", \"title\"]}"
    )]
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
        annotations(read_only_hint = true),
        description = "THE DEFAULT READ TOOL: structured filter + sort + pagination \
        over ONE collection. USE WHEN: you want rows of a collection by some \
        condition, a sorted/paged slice, just a count (read `total` in the \
        response), or just a sample (set `per_page`, omit `filter`). NOT WHEN: you \
        need a raw SQL shape a FilterAst can't express (use `query`) or vector \
        similarity ranking (use `search_collection`). VS SIBLINGS: `list_records` \
        reuses the same FilterAst as `search_collection` and rejects raw SQL by \
        construction, so `owner_field` is always enforceable — unlike `query`. \
        `filter` is a tree of `{and:[...]}` / `{or:[...]}` / `{not:...}` over \
        leaves `{field: scalar}` (eq) or `{field: {op: operand}}`. Operators: eq, \
        ne, gt, gte, lt, lte, like, in (array), nin (array). `sort` is \
        `{field, dir}` with dir in {asc, desc}. `per_page` is 1..=500 (default 20). \
        `select` lists column names; vector fields are auto-excluded. Returns \
        `{records, total, page, perPage}`. owner_field enforcement is guaranteed \
        by drust; MCP is service-only at the transport layer so this tool sees all \
        rows. \
        EXAMPLE call: {\"collection\": \"posts\", \"filter\": {\"and\": [\
        {\"status\": \"published\"}, {\"views\": {\"gte\": 10}}]}, \
        \"sort\": {\"field\": \"created_at\", \"dir\": \"desc\"}, \
        \"page\": 1, \"per_page\": 20, \"select\": [\"id\", \"title\"]}"
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
        annotations(read_only_hint = true),
        description = "Aggregate ONE collection: count / sum / avg / min / max over \
        rows, with an optional `group_by`. USE WHEN: you want computed rollups \
        (totals, averages, per-group counts) instead of raw rows — e.g. \"count \
        posts per status\" or \"average score by author\". NOT WHEN: you want the \
        rows themselves (use `list_records`) or nearest-vector ranking (use \
        `search_collection`). Builds the SQL itself from the structured body — no \
        raw SQL — so the SAME owner_field / policy / cap row-authorization as \
        `list_records` applies (MCP is service-only, so this tool sees all rows). \
        `metrics` is a list of `{op, field?, as?}`: op in {count, sum, avg, min, \
        max}; `field` is required for every op except `count` (bare count is \
        COUNT(*)); `as` names the output column (defaults to `<op>` / \
        `<op>_<field>`). `group_by` lists columns to group on; `sort` must \
        reference a group column or a metric alias; `per_page` bounds the number \
        of groups returned (1..=500, default 20). Returns `{rows, page, perPage}`. \
        EXAMPLE call: {\"collection\": \"posts\", \"group_by\": [\"status\"], \
        \"metrics\": [{\"op\": \"count\", \"as\": \"n\"}, {\"op\": \"avg\", \
        \"field\": \"score\", \"as\": \"avg_score\"}], \"sort\": {\"field\": \"n\", \
        \"dir\": \"desc\"}}"
    )]
    async fn aggregate(
        &self,
        Parameters(args): Parameters<read::AggregateArgs>,
    ) -> Result<CallToolResult, McpError> {
        match read::aggregate(&self.state, args).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = false),
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
        annotations(destructive_hint = false, idempotent_hint = false),
        description = "Insert MANY records into a collection in ONE atomic transaction \
        (all-or-nothing: any invalid row rolls back the WHOLE batch — no partial writes, no \
        orphan history). USE WHEN: bulk-loading rows. Each row is validated exactly like \
        `insert_record` (known fields, CHECK constraints) and captured to record-history per \
        row. `records` is a JSON array of objects; up to DRUST_BATCH_MAX_ROWS (default 1000). \
        Service-key only. Returns {inserted:[rows], count}. Errors: BATCH_EMPTY, \
        BATCH_TOO_LARGE, OWNER_FIELD_REQUIRED, CHECK_CONSTRAINT_FAILED, TENANT_QUOTA_EXCEEDED. \
        EXAMPLE call: {\"collection\": \"posts\", \"records\": [{\"title\": \"a\"}, \
        {\"title\": \"b\"}]}"
    )]
    async fn insert_records(
        &self,
        Parameters(batch::InsertRecordsArgs {
            collection,
            records,
        }): Parameters<batch::InsertRecordsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match batch::batch_insert(
            &self.state,
            &collection,
            records,
            crate::storage::record_history::AuditActor::service(),
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "UPSERT many records in ONE atomic transaction (all-or-nothing). Each row is \
        INSERTed, or — when it collides with an existing row on the `on_conflict` key — UPDATEs \
        that row (`INSERT ... ON CONFLICT DO UPDATE`). USE WHEN: syncing external data by a natural \
        key (e.g. `sku`). `on_conflict` MUST match a declared UNIQUE index (incl. a UNIQUE column) \
        or the primary key, else UPSERT_NO_UNIQUE; every row MUST include the `on_conflict` \
        column(s), else UPSERT_MISSING_KEY. Record-history captures the correct per-row op \
        (insert vs update, with old/new). Service-key only. Returns {results:[{op,record}], count} \
        where op is \"inserted\"|\"updated\". Errors: UPSERT_NO_UNIQUE, UPSERT_MISSING_KEY, \
        BATCH_EMPTY, BATCH_TOO_LARGE, OWNER_FIELD_REQUIRED, CHECK_CONSTRAINT_FAILED, \
        TENANT_QUOTA_EXCEEDED. EXAMPLE call: {\"collection\": \"products\", \"records\": \
        [{\"sku\": \"a\", \"name\": \"Apple\"}], \"on_conflict\": [\"sku\"]}"
    )]
    async fn upsert_records(
        &self,
        Parameters(batch::UpsertRecordsArgs {
            collection,
            records,
            on_conflict,
        }): Parameters<batch::UpsertRecordsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match batch::batch_upsert(
            &self.state,
            &collection,
            records,
            on_conflict,
            crate::storage::record_history::AuditActor::service(),
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
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
        annotations(destructive_hint = true),
        description = "Delete a record from a collection by primary key. \
        Returns RECORD_NOT_FOUND if the row does not exist; FK_RESTRICT if \
        another collection still references it. \
        v1.26: pass `dry_run: true` to receive blast radius (which collections \
        would block the delete) without actually deleting."
    )]
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

    #[tool(
        annotations(read_only_hint = true),
        description = "List files stored by this tenant in Garage. \
        Optional `visibility` filter (\"public\" | \"private\"); anything else returns all. \
        Paginate with `limit` (1–500, default 50) and `offset`. \
        Returns {files, total_count} where each file has id, original_name, size_bytes, \
        content_type, visibility, content_disposition, uploaded_at, and `path` — the \
        caller-declared logical path (\"avatars/alice/me.png\"), null when the file was \
        uploaded without one. `path` is metadata only: it is what the prefix rules from \
        `list_file_policies` match against, never the physical object key."
    )]
    async fn list_files(
        &self,
        Parameters(args): Parameters<file_tools::ListFilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        match file_tools::list_files(&self.state, args).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = true),
        description = "Delete a file by its id (the UUID key). \
        Removes the S3 object from the tenant's bucket first (idempotent on 404) \
        then deletes the metadata row. Returns {\"ok\": true} on success or \
        {\"error_code\": \"NOT_FOUND\" | \"STORAGE_UNAVAILABLE\"}."
    )]
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
        annotations(destructive_hint = false, idempotent_hint = true),
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

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "v1.63 — Register (or replace) the file-access rule for one \
        folder PREFIX of the tenant's file `path` metadata. A \"folder\" is a \
        prefix, never an object: `prefix` is \"\" (the tenant root, which also \
        governs files uploaded with no path) or a string ending in `/`, and the \
        LONGEST matching prefix wins, so a deeper rule overrides its parent. A \
        rule is one of three shapes — `owner_scoped: true` (only the uploader \
        reaches the file), a `select` FilterAst (only matching rows), or \
        `public_read: true` (not access-restricted). They compose: \
        owner_scoped AND select both apply. A rule that is NONE of the three \
        denies every read, so it is refused at write time \
        (FILE_POLICY_OPEN_REQUIRES_FLAG). `delete` defaults to the `select` \
        semantics. This is a SECOND gate under the per-verb file caps \
        (`set_file_caps`), never a replacement, and service keys bypass it. \
        v1.64 — the same rule carries `public_upload_roles`, the PUBLISH GRANT: \
        which non-service roles (\"anon\" / \"user\") may upload into this \
        prefix with visibility=public. Absent grants nobody, and re-registering \
        without it REVOKES an existing grant; read the \
        `drust://<tenant>/files-guide.md` resource for the model and the \
        FILE_PUBLIC_UPLOAD_DENIED remedy. \
        Errors: FILE_POLICY_PREFIX_INVALID, FILE_POLICY_OPEN_REQUIRES_FLAG, \
        FILE_POLICY_OPERAND_UNSUPPORTED, FILE_POLICY_INVALID. EXAMPLE: \
        {\"prefix\":\"avatars/\",\"owner_scoped\":true,\"public_upload_roles\":[\"user\"]}."
    )]
    async fn set_file_policy(
        &self,
        Parameters(file_policy_tools::SetFilePolicyArgs {
            prefix,
            owner_scoped,
            public_read,
            select,
            delete,
            public_upload_roles,
        }): Parameters<file_policy_tools::SetFilePolicyArgs>,
    ) -> Result<CallToolResult, McpError> {
        match file_policy_tools::set_file_policy(
            &self.state,
            &prefix,
            owner_scoped,
            public_read,
            select,
            delete,
            public_upload_roles,
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "v1.63 — List every registered file-access rule for this \
        tenant, ordered by prefix: {policies:[{prefix, owner_scoped, \
        public_read, select?, delete?, public_upload_roles?}]}. This is the \
        tenant's file-access map — read it before changing one rule, since the \
        LONGEST matching prefix decides a file and a deeper rule may already \
        override the one you are editing. `public_upload_roles` is the v1.64 \
        PUBLISH GRANT (which non-service roles may upload into that prefix with \
        visibility=public; absent = nobody) — the \
        `drust://<tenant>/files-guide.md` resource explains the model and how to \
        clear FILE_PUBLIC_UPLOAD_DENIED. A tenant created on v1.63+ starts with \
        a single seeded root rule (\"\" → public_read), which preserves \
        pre-v1.63 behaviour until it is cleared or overridden."
    )]
    async fn list_file_policies(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        match file_policy_tools::list_file_policies(&self.state).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = true),
        description = "v1.63 — Remove the file-access rule registered for one \
        exact prefix (\"\" clears the tenant root). This does NOT open the \
        prefix: its files fall to the next-longest matching rule, or — when \
        none matches — to the owner-scoped default, where only the uploader \
        reaches a file. Clearing a prefix that has no rule returns \
        FILE_POLICY_NOT_FOUND rather than a silent success."
    )]
    async fn clear_file_policy(
        &self,
        Parameters(file_policy_tools::ClearFilePolicyArgs { prefix }): Parameters<
            file_policy_tools::ClearFilePolicyArgs,
        >,
    ) -> Result<CallToolResult, McpError> {
        match file_policy_tools::clear_file_policy(&self.state, &prefix).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "Get a URL to download a file by its id. \
        Public files → stable public URL (expires_at is null). \
        Private files → pre-signed URL with TTL (1..=604800s, default 3600); \
        pass `download: true` to inject Content-Disposition=attachment so \
        browsers download instead of previewing."
    )]
    async fn get_file_url(
        &self,
        Parameters(args): Parameters<file_tools::GetFileUrlArgs>,
    ) -> Result<CallToolResult, McpError> {
        match file_tools::get_file_url(&self.state, args).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = false),
        description = "Create a new stored RPC (named SQL function). \
        Required: name (snake_case), sql (a body using :name placeholders), \
        params (array of {name, type, required, default}). \
        Optional: description, anon_callable (default false), \
        mode (\"read\", the default, or \"write\"). \
        SQL is validated at create time under the mode-matched authorizer: \
        read bodies are SELECT-only (non-SELECT actions, ATTACH, \
        sqlite_master references, and unknown tables are refused before \
        storage); write bodies may contain multi-statement \
        INSERT/UPDATE/DELETE, while DDL, transaction control, and \
        _system_* writes are refused. MCP call_rpc always executes on the \
        read-only connection regardless of mode — write RPCs run via REST \
        POST /t/<tenant>/rpc/<name>, the admin playground, or cron. \
        Pass kind:\"query\" + `query` (and no sql) for a structured query RPC: \
        a stored filter template that runs through the /list pipeline under \
        the CALLER's identity, so owner_field and RLS policies apply and it is \
        safe to set anon_callable on one."
    )]
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
        let params_for_guard = p.params.clone();
        let mode =
            parse_rpc_mode(p.mode.as_deref())?.unwrap_or(crate::rpc::registry::RpcMode::Read);
        let kind = parse_rpc_kind(p.kind.as_deref())?.unwrap_or(crate::rpc::registry::RpcKind::Sql);
        // Shape half of the kind contract, before any DB work (#950). The
        // registry re-judges the finished row.
        crate::rpc::prepare::check_new_rpc_shape(kind, &sql, mode, p.query.is_some())
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        // A query row's `sql` column is EXACTLY `''` (spec §儲存). The shape
        // check above already refused any non-blank body, so this only
        // normalizes whitespace — the registry's own rule is `is_empty()`, and
        // a stray "\n" would otherwise fail there with a worse message.
        let sql = match kind {
            crate::rpc::registry::RpcKind::Query => String::new(),
            crate::rpc::registry::RpcKind::Sql => sql,
        };
        // Store the CANONICAL serialization of the template — it is what
        // `parse_template` re-reads on every call (and what the 64 KiB cap is
        // measured against).
        let query_json: Option<String> = match &p.query {
            Some(v) => Some(
                serde_json::to_string(v)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            ),
            None => None,
        };
        let cache = pool.schema_cache.clone();

        pool.with_writer(move |c| {
            let reject = |e: crate::rpc::prepare::PrepareError| {
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
            };
            match kind {
                crate::rpc::registry::RpcKind::Sql => {
                    crate::rpc::prepare::validate_rpc_sql(c, &sql, mode).map_err(reject)?;
                    // v1.41.3: refuse an anon-callable read RPC that reads an
                    // owner-scoped collection without binding :user_id — drust does not
                    // rewrite stored-RPC SQL, so it would return every user's rows.
                    crate::rpc::prepare::guard_anon_owner_scoped_rpc(
                        c,
                        &sql,
                        &params_for_guard,
                        anon_callable,
                        mode,
                    )
                    .map_err(reject)?;
                }
                // #950: a template is not raw SQL, so the two sql guards do not
                // apply — row access is re-derived per call from the caller's
                // identity by `exec_query::run_query_rpc`. What replaces them is
                // the save-time template validation (existence, protected
                // collection, declared↔referenced params, dry compile).
                crate::rpc::registry::RpcKind::Query => {
                    let tpl = crate::rpc::query_template::parse_template(
                        query_json.as_deref().unwrap_or(""),
                    )
                    .map_err(|e| {
                        reject(crate::rpc::prepare::PrepareError::Rejected(e.to_string()))
                    })?;
                    crate::rpc::prepare::validate_new_query_rpc(c, &cache, &tpl, &params_for_guard)
                        .map_err(reject)?;
                }
            }
            crate::rpc::registry::create(
                c,
                crate::rpc::registry::RpcCreate {
                    name: &name,
                    sql: &sql,
                    params_json: &params_json,
                    description: description.as_deref(),
                    anon_callable,
                    mode,
                    kind,
                    query_json: query_json.as_deref(),
                },
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

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Update an existing RPC. All fields except `name` are \
        optional — pass only the fields you want to change. \
        mode (\"read\" or \"write\") switches the dispatch mode; omit to keep \
        the stored value. Same SQL validation as create_rpc applies if you \
        provide a new sql body, under the EFFECTIVE mode (the mode param if \
        given, else the stored row's) — so downgrading a write RPC to read \
        requires swapping the sql to a SELECT body in the same call. \
        On a kind=\"query\" RPC pass `query` to replace the template (sql and \
        mode are refused — `kind` is immutable). A new template, or setting \
        anon_callable=true, re-runs the create-time template validation."
    )]
    async fn update_rpc(
        &self,
        Parameters(p): Parameters<UpdateRpcParams>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        let name = p.name.clone();
        let sql = p.sql.clone();
        let description = p.description.clone();
        let anon_callable = p.anon_callable;
        let params_for_guard = p.params.clone();
        let params_json: Option<String> = match &p.params {
            Some(v) => Some(
                serde_json::to_string(v)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            ),
            None => None,
        };
        let mode_param = parse_rpc_mode(p.mode.as_deref())?;
        // Store the CANONICAL serialization, exactly as create_rpc does — it
        // is what `parse_template` re-reads on every call.
        let query_json: Option<String> = match &p.query {
            Some(v) => Some(
                serde_json::to_string(v)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            ),
            None => None,
        };
        let cache = pool.schema_cache.clone();

        pool.with_writer(move |c| {
            let reject = |e: crate::rpc::prepare::PrepareError| {
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
            };
            // ONE lookup, read before any validation: the kind of the STORED
            // row decides which validator applies. A missing row falls through
            // as Sql — `registry::update` below answers it with NotFound.
            let stored = crate::rpc::registry::lookup(c, &name).ok().flatten();
            let stored_kind = stored
                .as_ref()
                .map(|r| r.kind)
                .unwrap_or(crate::rpc::registry::RpcKind::Sql);

            match stored_kind {
                crate::rpc::registry::RpcKind::Sql => {
                    if let Some(s) = sql.as_deref() {
                        // Validate under the EFFECTIVE mode: the explicit param
                        // wins, else the stored row's mode — a write RPC's new
                        // write body must not be rejected by the read-only
                        // authorizer.
                        let effective = match mode_param {
                            Some(m) => m,
                            // Fail-closed: a missing row will 404 in
                            // registry::update below anyway.
                            None => stored
                                .as_ref()
                                .map(|r| r.mode)
                                .unwrap_or(crate::rpc::registry::RpcMode::Read),
                        };
                        crate::rpc::prepare::validate_rpc_sql(c, s, effective).map_err(reject)?;
                    }
                }
                // #950 — a query row has no sql to validate (and `registry::
                // update` refuses an sql/mode delta on one outright). What
                // replaces the sql guards is the same save-time template
                // validation the create faces run, on the EFFECTIVE template.
                //
                // It runs on exactly two triggers, and the narrowness is
                // load-bearing: a NEW template (the author is rewriting the
                // body), or anon_callable=true (the GRANT moment — a template
                // saved service-only was never judged as an anon grant, and a
                // stored one may declare a caller-suppliable `user_id` param or
                // have gone stale since). Validating on EVERY update instead
                // would brick a row whose collection was dropped: the author
                // could no longer even set anon_callable=false to disarm it.
                crate::rpc::registry::RpcKind::Query => {
                    // A params change is ALSO a widening trigger: a `$param`'s
                    // declared TYPE feeds the #954 storage-class check, so an
                    // Integer→Text swap on `col < :n` turns the template into
                    // `col < 'text'` — which SQLite makes match every integer
                    // row (all integers sort before all text), a full-table
                    // read for an anon-callable query RPC where `RpcGrant` skips
                    // caps. Both final-audit engines caught this independently.
                    // The disarm path (anon_callable=false, no params/query
                    // change) still skips, so a dropped-collection row stays
                    // repairable.
                    let widening = query_json.is_some()
                        || params_for_guard.is_some()
                        || anon_callable == Some(true);
                    if widening {
                        let effective = query_json
                            .as_deref()
                            .or_else(|| stored.as_ref().and_then(|r| r.query_json.as_deref()))
                            .unwrap_or("");
                        let tpl =
                            crate::rpc::query_template::parse_template(effective).map_err(|e| {
                                reject(crate::rpc::prepare::PrepareError::Rejected(e.to_string()))
                            })?;
                        let effective_params = params_for_guard.as_deref().unwrap_or_else(|| {
                            stored.as_ref().map(|r| r.params.as_slice()).unwrap_or(&[])
                        });
                        crate::rpc::prepare::validate_new_query_rpc(
                            c,
                            &cache,
                            &tpl,
                            effective_params,
                        )
                        .map_err(reject)?;
                    }
                }
            }
            // v1.41.3: re-run the owner-scoped guard on the EFFECTIVE post-update
            // values (a partial update — flag-flip or sql-swap — must be checked
            // against the stored row, else it reopens the create-path leak).
            // Self-skips query rows (they have no sql to scan).
            crate::rpc::prepare::guard_anon_owner_scoped_rpc_update(
                c,
                &name,
                sql.as_deref(),
                params_for_guard.as_deref(),
                anon_callable,
            )
            .map_err(|e| {
                rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
            })?;
            crate::rpc::registry::update(
                c,
                &name,
                crate::rpc::registry::RpcUpdate {
                    sql: sql.as_deref(),
                    params_json: params_json.as_deref(),
                    description: description.as_ref().map(|d| d.as_deref()),
                    anon_callable,
                    mode: mode_param,
                    query_json: query_json.as_deref(),
                },
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

    #[tool(
        annotations(destructive_hint = true),
        description = "Delete an RPC by name. Errors if no RPC with that name exists."
    )]
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

    #[tool(
        annotations(read_only_hint = true),
        description = "List every stored RPC for this tenant, including \
        the SQL body, params, anon_callable flag, call counters, and last-called \
        timestamp."
    )]
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

    #[tool(
        annotations(read_only_hint = false, open_world_hint = false),
        description = "Invoke a stored RPC by name with named params. The result \
        envelope depends on the RPC's stored kind. A kind=\"sql\" RPC returns \
        the query tool's shape {column_names, rows, row_count, truncated}. A \
        kind=\"query\" RPC (a structured filter template) runs through the /list \
        pipeline and returns {records, total, page, perPage} — the same page \
        shape as list_records; page/perPage default here (they are not tool \
        params). MCP is service-only, so anon_callable is not consulted on this \
        surface — a service-key holder may call any RPC, and a query RPC runs \
        under the service identity."
    )]
    async fn call_rpc(
        &self,
        Parameters(p): Parameters<CallRpcParams>,
    ) -> Result<CallToolResult, McpError> {
        let pool = self.state.inner().pool.clone();
        let name = p.name.clone();
        // HashMap → serde_json::Map for params::validate_and_bind /
        // exec_query::run_query_rpc (they take the same arg map).
        let body_map: serde_json::Map<String, Value> =
            p.body.unwrap_or_default().into_iter().collect();

        // One lookup up front: the stored `kind` selects BOTH the executor and
        // the result envelope. A missing row is reported exactly as before.
        let lookup_name = name.clone();
        let stored = pool
            .with_reader(move |c| {
                crate::rpc::registry::lookup(c, &lookup_name).map_err(|e| {
                    rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(1),
                        Some(e.to_string()),
                    )
                })
            })
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let stored = match stored {
            Some(r) => r,
            None => {
                return Err(McpError::invalid_params(
                    format!("no such rpc: {name}"),
                    None,
                ));
            }
        };

        // #950: a kind='query' RPC is a structured filter template. It runs
        // through the SAME single executor REST uses (`exec_query::run_query_rpc`
        // → the /list pipeline) — MCP is service-only, so the caller is
        // `AuthCtx::Service` (anon_callable is not consulted) and the envelope is
        // the /list page {records,total,page,perPage}, NOT the sql arm's columnar
        // shape. `page`/`per_page` are not MCP params, so the default window
        // applies.
        if stored.kind == crate::rpc::registry::RpcKind::Query {
            let ctx = crate::auth::middleware::AuthCtx::Service { admin_id: None };
            let page = match crate::rpc::exec_query::run_query_rpc(
                &pool, &ctx, &stored, body_map, None, None,
            )
            .await
            {
                Ok(pg) => pg,
                Err(resp) => return Err(mcp_error_from_response(resp).await),
            };
            spawn_rpc_counter_bump(pool.clone(), name.clone());
            let envelope = serde_json::json!({
                "records": page.records,
                "total": page.total,
                "page": page.page,
                "perPage": page.per_page,
            });
            let body_str = serde_json::to_string(&envelope)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            return Ok(CallToolResult::success(vec![Content::text(body_str)]));
        }

        // kind == Sql: unchanged read-only execution + columnar envelope.
        let bind_body = body_map.clone();
        let sql = stored.sql.clone();
        let params = stored.params.clone();
        let outcome = pool
            .with_reader(move |c| {
                let bound = match crate::rpc::params::validate_and_bind(&params, &bind_body) {
                    Ok(b) => b,
                    Err(e) => return Ok(Err(e.to_string())),
                };
                let qr = match crate::query::executor::execute_read_query_with_named(
                    c, &sql, &bound, 1_000, 1_048_576,
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

        spawn_rpc_counter_bump(pool.clone(), name.clone());

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
        annotations(destructive_hint = false, idempotent_hint = false),
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
        annotations(read_only_hint = true),
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

    #[tool(
        annotations(read_only_hint = true),
        description = "Get a single user by user_id. \
        Returns {id, email, verified, profile, created_at, updated_at} (no password_hash). \
        Errors with NOT_FOUND if the user does not exist."
    )]
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
        annotations(destructive_hint = false, idempotent_hint = true),
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
        annotations(destructive_hint = true),
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
            Ok(v) => {
                // #952 — the cascade revoked the deleted user's sessions; drop
                // the tenant's in-flight WS room subscribers so the revoked
                // token cannot keep a room (tenant-wide, blunt but fail-safe —
                // there is no per-user room index; mirrors token-reroll evict).
                inner.bus_rooms.evict_tenant(&inner.tenant_id);
                json_content(v)
            }
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = true),
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
            Ok(v) => {
                // #952 — sessions revoked; evict the tenant's in-flight WS room
                // subscribers so a revoked user token cannot keep a room open
                // (tenant-wide, blunt but fail-safe; mirrors token-reroll evict).
                inner.bus_rooms.evict_tenant(&inner.tenant_id);
                json_content(v)
            }
            Err(e) => bail_mcp(e),
        }
    }

    // ── T25: Owner-field + self-register tools ─────────────────────────────

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
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
        let inner = self.state.inner();
        match owner_field_tools::set_owner_field(
            &inner.pool,
            collection,
            field,
            read_scope,
            &inner.bus,
            &inner.tenant_id,
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Enable or disable self-registration for this tenant. \
        When enabled (true), unauthenticated users may POST /auth/register to create an account. \
        When disabled (false, the default), /auth/register returns 403. \
        Returns {allow_self_register: <bool>}. \
        Requires meta.sqlite access — errors with NOT_FOUND if the tenant row is missing."
    )]
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

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "v1.32.5 — Set this tenant's broadcast publish policy. \
        Two opt-in flags (both default false) gate `op:publish` (WS) and \
        POST /t/{tenant}/rooms/{room} (REST) for non-service tokens. Either \
        arg may be omitted to leave that flag unchanged. \
        - allow_user_publish=true: logged-in end-users (drust_user_*) may publish. \
        - allow_anon_publish=true: the public anon bearer may publish — treat \
          as public-write; per-tenant rate-limit still applies. \
        MCP `broadcast` is service-only regardless of these flags (MCP \
        dispatch enforces). Returns {allow_user_publish, allow_anon_publish} \
        with the post-update state. NOT_FOUND if the tenant is missing."
    )]
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
        //
        // #955 — and the rooms bus, so a REAL flag change also closes the
        // live WS sockets still holding the old `TenantPublishPolicy` (they
        // capture it once at upgrade). Unlike `delete_user` /
        // `revoke_user_sessions` above, the evict is NOT in this arm, for ONE
        // reason: it is conditional on a pre-image only readable under the
        // meta lock the tool fn holds, and this arm has no pre-image to
        // compare against — it could only evict unconditionally, which would
        // thunder-herd the tenant on a no-op call.
        //
        // Testability is NOT a reason. Until the #955 T3 round-2 review this
        // comment also claimed a `#[tool]` method is unreachable from an
        // integration test; that is false (`tools/call` reaches these
        // wrappers — see the tool fn's doc comment). Pinned by
        // `tests/auth_cache_mcp_publish_policy.rs`.
        let inner = self.state.inner();
        match owner_field_tools::set_publish_policy(
            &meta,
            &tenant_id,
            allow_user_publish,
            allow_anon_publish,
            inner.auth_cache.as_deref(),
            &inner.bus_rooms,
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "v1.42 — Set this tenant's opt-in file-storage \
        capabilities for non-service bearers. Two cap sets (both default empty = \
        service-only): `anon` gates the public anon bearer, `user` gates \
        logged-in end-users (drust_user_*); each is a subset of \
        [read, list, upload, delete] over the tenant's shared file pool (NOT \
        per-owner). Each arg REPLACES that role's set; omit to leave it \
        unchanged. make-public (set-visibility) stays service-only and is not a \
        cap. upload/delete are per-IP rate-limited. Returns \
        {file_anon_caps, file_user_caps}. NOT_FOUND if the tenant is missing."
    )]
    async fn set_file_caps(
        &self,
        Parameters(SetFileCapsArgs { anon, user }): Parameters<SetFileCapsArgs>,
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
        // v1.35 hook 12 (MCP face) — pass the cache so a caps change drops the
        // tenant's cached auth entries synchronously.
        let inner = self.state.inner();
        match owner_field_tools::set_file_caps(
            &meta,
            &tenant_id,
            anon,
            user,
            inner.auth_cache.as_deref(),
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "v1.49 — REPLACE this tenant's egress allowlist (whole \
        list, not merge). Service-only. The allowlist is origin-level \
        (`scheme://host[:port]`, no path) and tagged by `system`: \
        `webhook` entries gate outbound webhook delivery, `function` entries \
        gate the edge-function `http-fetch` host import. Deny-all default — an \
        empty list denies EVERY outbound path; each subsystem sees only its own \
        tagged entries. Enforcement is defense-in-depth: this allowlist AND the \
        `PinnedPublicResolver` (private-IP block) both apply on every outbound \
        request. Validation: bad origin → EGRESS_BAD_ORIGIN, unknown system \
        (want webhook|function) → EGRESS_BAD_SYSTEM, over the per-tenant limit \
        → EGRESS_TOO_MANY. Returns {entries:[{system,uri}]} normalized."
    )]
    async fn set_egress_allowlist(
        &self,
        Parameters(SetEgressAllowlistArgs { entries }): Parameters<SetEgressAllowlistArgs>,
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
        match crate::tenant::egress_config::set_allowlist(&meta, &tenant_id, entries, "service")
            .await
        {
            Ok(Ok(stored)) => {
                let entries: Value =
                    serde_json::from_str(&stored).unwrap_or_else(|_| serde_json::json!([]));
                json_content(serde_json::json!({ "entries": entries }))
            }
            Ok(Err(e)) => Err(McpError::invalid_params(e.to_string(), None)),
            Err(e) => Err(McpError::internal_error(e.to_string(), None)),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "v1.49 — Read this tenant's egress allowlist (the \
        outbound origins gating webhook delivery and the function `http-fetch` \
        host import). Service-only. Returns {entries:[{system,uri}]}; an empty \
        list means deny-all (no outbound path is permitted)."
    )]
    async fn get_egress_allowlist(
        &self,
        Parameters(_): Parameters<EmptyParams>,
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
        let stored = crate::tenant::egress_config::get_allowlist(&meta, &tenant_id).await;
        let entries: Value =
            serde_json::from_str(&stored).unwrap_or_else(|_| serde_json::json!([]));
        json_content(serde_json::json!({ "entries": entries }))
    }

    // ── v1.12: Per-tenant OAuth-provider admin tools ──────────────────────

    #[tool(
        annotations(read_only_hint = true),
        description = "List the OAuth providers configured for this tenant's \
        end-user login flow (the `_system_oauth_providers` table). \
        Returns {providers: [{provider, client_id, client_secret, \
        allowed_redirect_uris, created_at, updated_at}]}. \
        `client_secret` is always returned as the literal '●●●●' — real \
        secrets never leave the writer. Service-key-only; anon callers \
        cannot reach MCP."
    )]
    async fn list_oauth_providers(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        match oauth_tools::list_oauth_providers(&self.state.inner().pool).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Upsert an OAuth provider config for this tenant's \
        end-user login flow. `provider` must be 'google' or 'github'. \
        `client_id` / `client_secret` are the OAuth app credentials from \
        the provider's console. `allowed_redirect_uris` is a non-empty list \
        of full URIs the frontend may pass to `/oauth/{provider}/start` — \
        each must be https:// or a localhost/127.0.0.1 URL. \
        Replaces any existing row for the same provider. \
        Returns {ok: true, provider}. \
        Errors with a granular code on validation failure: \
        INVALID_PROVIDER, INVALID_CLIENT_ID, INVALID_CLIENT_SECRET, \
        EMPTY_REDIRECT_URIS, or INVALID_REDIRECT_URI."
    )]
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

    #[tool(
        annotations(destructive_hint = true),
        description = "Delete the OAuth provider config for this tenant. \
        `provider` must be 'google' or 'github'. Removes the row from \
        `_system_oauth_providers`; in-flight OAuth callbacks for this \
        provider will fail with PROVIDER_NOT_CONFIGURED. \
        Returns {ok: true, provider, deleted: true}. \
        Errors with NOT_FOUND if the provider was not configured."
    )]
    async fn delete_oauth_provider(
        &self,
        Parameters(ProviderOnlyArgs { provider }): Parameters<ProviderOnlyArgs>,
    ) -> Result<CallToolResult, McpError> {
        match oauth_tools::delete_oauth_provider(&self.state.inner().pool, provider).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Replace ONLY the allowed_redirect_uris list for an \
        already-configured OAuth provider. Does NOT touch client_id / \
        client_secret (use set_oauth_provider to change credentials). \
        `provider` must be an existing 'google' or 'github' config. \
        `allowed_redirect_uris` is the full replacement list; each must be \
        https:// or a localhost/127.0.0.1 URL. \
        Returns {ok: true, provider, redirect_uris_count}. \
        Errors: NOT_FOUND (provider not configured), EMPTY_REDIRECT_URIS, \
        INVALID_REDIRECT_URI."
    )]
    async fn set_redirect_uris(
        &self,
        Parameters(SetRedirectUrisArgs {
            provider,
            allowed_redirect_uris,
        }): Parameters<SetRedirectUrisArgs>,
    ) -> Result<CallToolResult, McpError> {
        match oauth_tools::set_redirect_uris(
            &self.state.inner().pool,
            provider,
            allowed_redirect_uris,
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    // ── v1.13: Webhook subscription tools (service-only) ───────────────────

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = false),
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
        // Egress registration gate (v1.49) — parity with the REST/admin
        // create paths. In prod `meta()` is always Some; test ctors pass None
        // (they exercise the SQL body, not egress policy) and skip the gate.
        if let Some(meta) = self.state.meta()
            && !crate::tenant::webhook_dispatcher::registration_egress_allowed(
                meta,
                self.state.tenant_id(),
                &url,
            )
            .await
        {
            return bail_mcp(anyhow::anyhow!(
                "EGRESS_NOT_ALLOWLISTED: target origin is not on this tenant's \
                 egress allowlist (system=webhook); add it via set_egress_allowlist first"
            ));
        }
        match webhook_tools::create_webhook(&self.state.inner().pool, collection, events, url).await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "List all webhook subscriptions for this tenant. \
        Returns {webhooks: [{id, collection, events, url, secret, active, \
        last_failure_at, last_failure_reason, created_at}]}. \
        Secrets are always redacted to '●●●●'."
    )]
    async fn list_webhooks(
        &self,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<CallToolResult, McpError> {
        match webhook_tools::list_webhooks(&self.state.inner().pool).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Update one or more fields of a webhook subscription. \
        All fields except `id` are optional — only supplied fields are changed. \
        `secret` cannot be rotated through this tool; delete + recreate instead. \
        Returns {updated: true, id}. \
        Errors: NOT_FOUND, INVALID_URL, INVALID_EVENTS."
    )]
    async fn update_webhook(
        &self,
        Parameters(UpdateWebhookArgs {
            id,
            active,
            events,
            url,
        }): Parameters<UpdateWebhookArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Egress registration gate on a URL change (v1.49) — parity with the
        // REST PATCH path. Only gates when a new url is supplied.
        if let (Some(meta), Some(u)) = (self.state.meta(), url.as_ref())
            && !crate::tenant::webhook_dispatcher::registration_egress_allowed(
                meta,
                self.state.tenant_id(),
                u,
            )
            .await
        {
            return bail_mcp(anyhow::anyhow!(
                "EGRESS_NOT_ALLOWLISTED: target origin is not on this tenant's \
                 egress allowlist (system=webhook); add it via set_egress_allowlist first"
            ));
        }
        match webhook_tools::update_webhook(&self.state.inner().pool, id, active, events, url).await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = true),
        description = "Delete a webhook subscription. \
        Returns {deleted: true, id}. \
        Errors with NOT_FOUND if the id does not exist."
    )]
    async fn delete_webhook(
        &self,
        Parameters(WebhookIdArgs { id }): Parameters<WebhookIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        match webhook_tools::delete_webhook(&self.state.inner().pool, id).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "v1.26 — Recent write events for this tenant. \
        Returns ts/op/collection/status/error_code for the latest \
        insert/update/delete/DDL operations. Use this to replan after \
        errors or to confirm what the previous tool calls actually \
        changed. Service-key + MCP only (anon and user tokens are \
        rejected by the MCP layer)."
    )]
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
            // v1.58 — was 50 while both this tool's own description and the
            // MCP prologue promised the last 100 mutations. The tool exists to
            // reconcile after a retry, so under-returning silently invites
            // duplicate writes. `query_recent` clamps to 1..=200.
            limit.unwrap_or(100),
            collection.as_deref(),
            since_ts.as_deref(),
        )
        .await
        {
            Ok(rows) => json_content(serde_json::to_value(rows).expect("serialise")),
            Err(e) => bail_mcp(anyhow::anyhow!("RECENT_WRITES_UNAVAILABLE: {e}")),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = false),
        description = "v1.31 — Publish a JSON payload to a broadcast room. \
        Service-key only (MCP dispatch already gates this). Fans out to every \
        WebSocket subscriber currently connected to /t/<tenant>/realtime on the \
        same room name. Fire-and-forget: messages are not persisted; subscribers \
        connected later receive nothing. Returns `{room, delivered_to, byte_count}`. \
        Errors: ROOM_NAME_INVALID, PROTECTED_ROOM (`_system_` prefix), PAYLOAD_TOO_LARGE, \
        RATE_LIMITED."
    )]
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

    #[tool(
        annotations(read_only_hint = true),
        description = "v1.36 — List this tenant's edge functions: name, \
        wasm sha256, size, trigger bindings, active flag, description. \
        There is NO MCP upload tool by design — POST the .wasm to \
        /t/<tenant>/functions (multipart: name, wasm, triggers, description) \
        with the service bearer; call whoami for the exact URL."
    )]
    async fn list_functions(&self) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::list_functions(&self.state).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = true),
        description = "v1.36 — Delete an edge function by name. The wasm \
        artifact is garbage-collected when no other function references it. \
        Irreversible; re-upload to restore."
    )]
    async fn delete_function(
        &self,
        Parameters(DeleteFunctionArgs { name }): Parameters<DeleteFunctionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::delete_function(&self.state, &name).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "v1.36 — Enable/disable an edge function without \
        deleting it. Disabled functions keep their logs and bindings."
    )]
    async fn set_function_active(
        &self,
        Parameters(SetFunctionActiveArgs { name, active }): Parameters<SetFunctionActiveArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::set_function_active(&self.state, &name, active).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "Service-only — set who may invoke an edge function \
        under their own identity: anon and/or end-user (drust_user_*). Both \
        flags default-deny; an anon/user invocation runs capability-gated \
        (anon_caps/user_caps + owner_field + RLS), never god-mode. Grant AND \
        revoke both flow through here (config is service-only)."
    )]
    async fn set_function_invoke_acl(
        &self,
        Parameters(SetFunctionInvokeAclArgs { name, anon, user }): Parameters<
            SetFunctionInvokeAclArgs,
        >,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::set_function_invoke_acl(&self.state, &name, anon, user)
            .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = false, open_world_hint = true),
        description = "v1.36 — Enqueue a manual invocation of an edge \
        function with an arbitrary event JSON. ASYNC: returns the enqueue \
        ack immediately; read the outcome via get_function_logs \
        (trigger=manual). For synchronous test runs use REST \
        POST /t/<tenant>/functions/<name>/invoke."
    )]
    async fn invoke_function(
        &self,
        Parameters(InvokeFunctionArgs { name, event }): Parameters<InvokeFunctionArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::invoke_function(&self.state, &name, event).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "v1.36 — Recent invocation log rows for one edge \
        function (newest first): status ok|error|trap|timeout|oom|dropped, \
        duration_ms, captured guest log() text, result/error JSON."
    )]
    async fn get_function_logs(
        &self,
        Parameters(GetFunctionLogsArgs { name, limit }): Parameters<GetFunctionLogsArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::functions::get_function_logs(&self.state, &name, limit).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = false),
        description = "v1.48 — Create a cron job: run one edge function \
        or stored RPC on a 5-field cron schedule (minute hour day month \
        weekday), UTC, minute resolution — no seconds field, no @aliases. \
        Service-only. Jobs run at service (Privileged) identity; an RPC \
        declaring :user_id is refused (CRON_RPC_USER_ID), and so is a \
        kind=\"query\" RPC (CRON_RPC_QUERY_KIND) — a query template runs under \
        the CALLER's identity and cron has none. The target is \
        immutable — delete + create to retarget. payload_json (optional \
        JSON object as a string, <= 64 KiB): functions receive it as \
        event.payload, RPCs bind it as named params; omitted means a null \
        payload / no binds. Errors: CRON_INVALID_NAME, \
        CRON_INVALID_SCHEDULE, CRON_TARGET_NOT_FOUND, CRON_DUPLICATE, \
        CRON_JOB_LIMIT, CRON_PAYLOAD_TOO_LARGE, CRON_RPC_USER_ID, \
        CRON_RPC_QUERY_KIND."
    )]
    async fn create_cron_job(
        &self,
        Parameters(CreateCronJobArgs {
            name,
            schedule,
            target_kind,
            target_name,
            payload_json,
            active,
        }): Parameters<CreateCronJobArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::cron::create_cron_job(
            &self.state,
            &name,
            &schedule,
            &target_kind,
            &target_name,
            payload_json.as_deref(),
            active.unwrap_or(true),
        )
        .await
        {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(read_only_hint = true),
        description = "v1.48 — List this tenant's cron jobs (service-only): \
        name, schedule (5-field, UTC), target, payload, active flag, \
        last_run_at/last_status/last_error, and the computed next_fire. \
        Per-job run history has no MCP tool — read the last 20 outcomes via \
        REST GET /t/<tenant>/cron/<name>/runs with the service bearer."
    )]
    async fn list_cron_jobs(&self) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::cron::list_cron_jobs(&self.state).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = false, idempotent_hint = true),
        description = "v1.48 — Enable/disable a cron job without deleting \
        it (service-only). Disabled jobs keep their config and run history \
        and stop firing within the current minute. Errors: CRON_NOT_FOUND."
    )]
    async fn set_cron_job_active(
        &self,
        Parameters(SetCronJobActiveArgs { name, active }): Parameters<SetCronJobActiveArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::cron::set_cron_job_active(&self.state, &name, active).await {
            Ok(v) => json_content(v),
            Err(e) => bail_mcp(e),
        }
    }

    #[tool(
        annotations(destructive_hint = true),
        description = "v1.48 — Delete a cron job and its run history \
        (service-only, irreversible). Changing a job's target is delete + \
        create — the target is immutable on PATCH/update surfaces. \
        Errors: CRON_NOT_FOUND."
    )]
    async fn delete_cron_job(
        &self,
        Parameters(DeleteCronJobArgs { name }): Parameters<DeleteCronJobArgs>,
    ) -> Result<CallToolResult, McpError> {
        match crate::mcp::tools::cron::delete_cron_job(&self.state, &name).await {
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
    let bp = crate::base_path::base_path();
    format!(
        r#"drust multi-tenant SQLite BaaS — tenant '{tenant_id}'.

START HERE — make these two calls first, before anything else:
  1. `get_schema_overview` — everything this tenant has in ONE call: collections,
     fields, indexes, RPCs (with their params + callable contract), and each
     collection's access state (owner_field, anon_caps, realtime_enabled, vector
     dims, RLS policies). After this one call you know enough to act correctly on THIS tenant.
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
   RLS:      set_policy, get_policies, clear_policy — per-op (select|insert|update|
             delete) row filters as FilterAst; AND-compose ALONGSIDE owner_field
             (does NOT replace it); service tokens bypass. See each tool's description.

2. DATA (per-collection CRUD + search)
   Read:    list_records (default), query (raw SELECT, service-only) + explain,
            search_collection (vector)   — see CHOOSING A READ TOOL above
   Write:   insert_record, update_record, delete_record   (all accept dry_run: true)
   RPCs:    create_rpc, update_rpc, delete_rpc, list_rpc, call_rpc

3. STORAGE (per-tenant Garage buckets — public + private)
   Manage: list_files, delete_file, get_file_url, set_file_visibility  (get_file_url: pass download=true for attachment disposition)
   Files RLS (v1.63): set_file_policy, list_file_policies, clear_file_policy — per-PREFIX
     rules over each file's logical `path` ("avatars/", "" = tenant root); longest prefix
     wins; owner_scoped / select FilterAst / public_read compose. Second gate UNDER the
     per-verb file caps; service keys bypass. A rule that restricts nothing is refused
     (FILE_POLICY_OPEN_REQUIRES_FLAG) — say public_read: true to mean "open".
   HANDBOOK: read the resource drust://{tenant_id}/files-guide.md before uploading —
     upload endpoints, the public/private model, the per-prefix publish grant
     (public_upload_roles: which of anon/user may upload with visibility=public), the
     FILE_PUBLIC_UPLOAD_DENIED remedy, and this tenant's live grants.
   Upload (small): single request — MCP has no upload tool by design. Use REST:
     POST {base}{bp}/t/{tenant_id}/files
     Header: Authorization: Bearer $DRUST_TOKEN
     Body:   multipart/form-data
       file          (required — bytes)
       visibility    (optional — 'public' | 'private'; service omitting it gets 'public',
                      any other bearer gets 'private'. A non-service bearer may send
                      'public' only where a file-policy prefix grants its role
                      (public_upload_roles) — else 403 FILE_PUBLIC_UPLOAD_DENIED.
                      Full model: files-guide.md resource.)
       disposition   (optional — 'inline' | 'attachment', default 'inline')
       cache_control (optional — default 'public, max-age=86400' (public) / 'private, no-store' (private))
       meta          (optional — JSON object)
   Upload (large / resumable): when the file exceeds limits.max_upload_bytes
   (see whoami) or you need resume-on-disconnect, use the tus 1.0 protocol:
     POST {base}{bp}/t/{tenant_id}/uploads    (create session; 201 + Location)
       Header: Upload-Length, Upload-Metadata (tus); Authorization: Bearer $DRUST_TOKEN
     then PATCH each chunk per tus 1.0; HEAD to resume from the server offset.
     Send OPTIONS {base}{bp}/t/{tenant_id}/uploads to discover Tus-Max-Size
     and the per-chunk limit. Both upload paths accept any bearer holding the
     file.upload cap; the same public-visibility grant rule as the small
     upload applies (visibility is fixed at session create).

4. IDENTITY + INTEGRATIONS
   Users:    create_user, list_users, get_user, update_user, delete_user, revoke_user_sessions
   OAuth:    list_oauth_providers, set_oauth_provider, delete_oauth_provider, set_self_register
   Webhooks: create_webhook, list_webhooks, update_webhook, delete_webhook   (CRUD events fan out)
   Broadcast (v1.31+): broadcast — publish JSON to a WS room; fire-and-forget, no replay
   Publish policy (v1.32.5+): set_publish_policy — opt non-service tokens into WS/REST publish

5. OBSERVABILITY (service-only)
   recent_writes — last 100 mutations for THIS tenant. Use after a retry to see what the previous attempt wrote.

6. FUNCTIONS (v1.36+, service-only — edge functions: user-uploaded wasm triggered by record CRUD + file.uploaded)
   Manage:  list_functions, set_function_active, set_function_invoke_acl, delete_function
   Invoke ACL: set_function_invoke_acl — opt anon/user into self-identity invoke (default-deny; runs capability-gated, not god-mode)
   Run:     invoke_function (async — returns enqueue ack; read outcome via get_function_logs, trigger=manual)
   Logs:    get_function_logs
   Upload:  NO MCP upload tool by design. POST the .wasm via REST:
     POST {base}{bp}/t/{tenant_id}/functions   (multipart: name, wasm, triggers, description; service bearer)

7. CRON (v1.48+, service-only — schedule edge functions or stored RPCs)
   Manage:  create_cron_job, list_cron_jobs, set_cron_job_active, delete_cron_job
   Schedule: 5-field cron (minute hour day month weekday), UTC, minute resolution — no seconds, no @aliases
   Target:  target_kind 'function' | 'rpc' + target_name; immutable — delete + create to retarget
   Payload: optional JSON object string (<=64 KiB) — functions get it as event.payload,
            RPCs bind it as named params; omitted means null payload / no binds
   Jobs run at service (Privileged) identity; an RPC declaring :user_id is refused.
   Run history (last 20): REST GET {base}{bp}/t/{tenant_id}/cron/<name>/runs (service bearer)

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
  "Restrict who sees rows"→ set_policy (per-op FilterAst; layered on owner_field)

RECOVERY — experiment cheaply, you can always see and undo-plan:
  • Every destructive tool (delete_record, drop_collection, drop_index) accepts
    `dry_run: true` and returns would_* counts + blast radius WITHOUT mutating.
  • Every error JSON carries a `suggested_fix` hint tailored to the failure —
    read it before retrying.
  • `recent_writes` returns your last 100 mutations, so after a failed/retried
    attempt you can recover exactly what already changed.

NOTES
  • Schema drops and delete_file are irreversible (use dry_run first).
  • Call `tools/list` for the canonical input schema of every tool listed above.
  • RESOURCES + PROMPTS (v1.56): this endpoint also serves MCP Resources and
    Prompts. `resources/list` + `resources/templates/list` project this tenant's
    knowledge as `drust://{tenant_id}/…` URIs — `schema`, `schema.md`,
    `collections`, `openapi.json`, `types.ts`, `zod.ts`, plus templates like
    `collections/<c>/records/<id>` for a single row. `prompts/list` offers task
    recipes; start with the `bootstrap` prompt. (Read tools return a
    `resource_link` / `resource_uri_template` pointing back at these.)"#
    )
}

#[tool_handler]
impl ServerHandler for DrustMcpService {
    fn get_info(&self) -> ServerInfo {
        let tenant_id = self.state.tenant_id();
        let base = self.state.public_base_url();
        let instructions = build_instructions(tenant_id, base);
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new("drust", env!("CARGO_PKG_VERSION")))
        .with_instructions(instructions)
    }

    // --- MCP Resources (v1.56, M2). Hand-written (rmcp has no resource macro);
    // thin wrappers over `crate::mcp::resources` — the tenant comes from the
    // per-tenant `self.state`, role is always Service (mcp_dispatch-gated), so
    // no request-context plumbing is needed. See src/mcp/resources.rs.
    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, McpError> {
        Ok(rmcp::model::ListResourcesResult::with_all_items(
            crate::mcp::resources::static_resource_list(self.state.tenant_id()),
        ))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListResourceTemplatesResult, McpError> {
        Ok(rmcp::model::ListResourceTemplatesResult::with_all_items(
            crate::mcp::resources::resource_template_list(self.state.tenant_id()),
        ))
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResult, McpError> {
        use crate::mcp::resources;
        let uri = resources::parse_resource_uri(&request.uri, self.state.tenant_id())?;
        let (body, mime) = resources::render_resource(&self.state, &uri).await?;
        resources::audit_resource_read(&self.state, &request.uri);
        let contents = rmcp::model::ResourceContents::text(resources::cap_body(body), &request.uri)
            .with_mime_type(mime);
        Ok(rmcp::model::ReadResourceResult::new(vec![contents]))
    }

    // --- MCP Prompts (v1.56, M3). Hand-written (no prompt macro); thin wrappers
    // over `crate::mcp::prompts`. Tenant comes from `self.state`; role is always
    // Service (mcp_dispatch-gated). See src/mcp/prompts.rs.
    async fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, McpError> {
        Ok(rmcp::model::ListPromptsResult::with_all_items(
            crate::mcp::prompts::prompt_list(),
        ))
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::GetPromptResult, McpError> {
        crate::mcp::prompts::render_prompt(&self.state, &request.name, &request.arguments).await
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
        assert!(
            DrustMcpService::tool_count() > 0,
            "router must not be empty"
        );
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
        let t = tools
            .into_iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("tool {name:?} not in router"));
        t.description
            .unwrap_or_else(|| panic!("tool {name:?} has no description"))
            .to_string()
    }

    #[test]
    fn router_exposes_read_cluster_descriptions() {
        for name in ["list_records", "query", "search_collection"] {
            let d = desc_of(name);
            assert!(!d.is_empty(), "{name} description empty");
        }
    }

    #[test]
    fn router_exposes_set_redirect_uris() {
        let d = desc_of("set_redirect_uris");
        assert!(
            d.contains("redirect"),
            "description should mention redirect"
        );
        assert!(
            d.to_lowercase().contains("not touch"),
            "description must state it leaves credentials alone"
        );
    }

    #[test]
    fn list_records_description_disambiguates_siblings() {
        let d = desc_of("list_records");
        assert!(d.contains("USE WHEN"), "list_records missing USE WHEN line");
        assert!(d.contains("NOT WHEN"), "list_records missing NOT WHEN line");
        assert!(
            d.contains("query"),
            "list_records must name sibling `query`"
        );
        assert!(
            d.contains("search_collection"),
            "list_records must name sibling `search_collection`"
        );
        assert!(
            d.contains("total"),
            "list_records must mention it returns `total`"
        );
    }

    #[test]
    fn query_description_disambiguates_siblings() {
        let d = desc_of("query");
        assert!(d.contains("USE WHEN"), "query missing USE WHEN line");
        assert!(d.contains("NOT WHEN"), "query missing NOT WHEN line");
        assert!(
            d.contains("owner_field"),
            "query must warn it does NOT enforce owner_field"
        );
        assert!(
            d.contains("list_records"),
            "query must point at sibling `list_records`"
        );
    }

    #[test]
    fn search_collection_description_disambiguates_siblings() {
        let d = desc_of("search_collection");
        assert!(
            d.contains("USE WHEN"),
            "search_collection missing USE WHEN line"
        );
        assert!(
            d.contains("NOT WHEN"),
            "search_collection missing NOT WHEN line"
        );
        assert!(
            d.contains("list_records"),
            "search_collection must point at sibling `list_records`"
        );
    }

    #[test]
    fn list_records_description_has_filterast_example() {
        let d = desc_of("list_records");
        assert!(d.contains("EXAMPLE"), "list_records missing EXAMPLE block");
        assert!(d.contains("\"filter\""), "example must show `filter`");
        assert!(d.contains("\"and\""), "example must use an and/or/not node");
        assert!(d.contains("\"gte\""), "example must show an operator leaf");
        assert!(d.contains("\"sort\""), "example must show `sort`");
        assert!(d.contains("\"per_page\""), "example must show `per_page`");
    }

    #[test]
    fn create_collection_description_has_fieldspec_example() {
        let d = desc_of("create_collection");
        assert!(
            d.contains("EXAMPLE"),
            "create_collection missing EXAMPLE block"
        );
        assert!(
            d.contains("\"nullable\": false"),
            "example must show a required field"
        );
        assert!(
            d.contains("{\"sql\": \"datetime('now')\"}"),
            "example must show the allowlisted SQL default form"
        );
        assert!(
            d.contains("\"foreign_key\""),
            "example must show a foreign_key field"
        );
        assert!(
            d.contains("\"vector\""),
            "example must show a vector field type"
        );
        assert!(d.contains("\"dim\""), "example must show the vector dim");
    }

    #[test]
    fn search_collection_description_has_body_example() {
        let d = desc_of("search_collection");
        assert!(
            d.contains("EXAMPLE"),
            "search_collection missing EXAMPLE block"
        );
        for key in [
            "\"field\"",
            "\"vector\"",
            "\"k\"",
            "\"metric\"",
            "\"where\"",
            "\"select\"",
        ] {
            assert!(d.contains(key), "search example must show {key}");
        }
    }

    #[test]
    fn no_description_names_a_removed_tool() {
        let removed = [
            "sample_rows",
            "count_rows",
            "clear_owner_field",
            "set_field_description",
            "set_index_description",
        ];
        let tools = DrustMcpService::tool_router().list_all();
        for t in &tools {
            let d = t.description.as_deref().unwrap_or("");
            for r in removed {
                assert!(
                    !d.contains(r),
                    "tool {:?} description names removed tool {r:?}",
                    t.name
                );
            }
        }
    }

    #[test]
    fn list_records_description_keeps_ownerfield_framing() {
        // Prose must not drift into implying /list takes raw SQL: it stays
        // structured-only so owner_field is enforceable by construction.
        let d = desc_of("list_records");
        assert!(
            d.contains("owner_field"),
            "list_records must keep the owner_field-enforcement framing"
        );
        assert!(
            d.contains("rejects raw SQL") || d.contains("FilterAst") || d.contains("raw SQL"),
            "list_records must state it is structured-only / rejects raw SQL"
        );
    }

    /// #950 T6: the machine-readable `call_rpc` contract must document BOTH
    /// result envelopes, keyed by the stored `kind` — a query RPC returns the
    /// /list page, a sql RPC returns the columnar result. `mcp-surface.md` treats
    /// these descriptions as the contract, so the branch and both shapes are
    /// spelled out here for the model.
    #[test]
    fn call_rpc_description_documents_both_kind_envelopes() {
        let d = desc_of("call_rpc");
        assert!(
            d.contains("kind"),
            "call_rpc must name the kind branch: {d}"
        );
        // sql arm envelope keys.
        assert!(
            d.contains("column_names") && d.contains("row_count"),
            "call_rpc must document the sql envelope: {d}"
        );
        // query arm envelope keys.
        assert!(
            d.contains("records") && d.contains("perPage"),
            "call_rpc must document the query envelope: {d}"
        );
    }

    /// create_rpc / update_rpc descriptions must both point at the kind='query'
    /// path so a model discovers the structured-template surface.
    #[test]
    fn create_and_update_rpc_descriptions_mention_query_kind() {
        for name in ["create_rpc", "update_rpc"] {
            let d = desc_of(name);
            assert!(
                d.contains("query"),
                "{name} description must mention the kind='query' path: {d}"
            );
        }
    }
}

#[cfg(test)]
mod rpc_query_schema_tests {
    use super::{CreateRpcParams, UpdateRpcParams};

    /// #950 T6 anti-drift: the `query` template param is published by TWO tool
    /// faces (`create_rpc` and `update_rpc`), each via the SAME
    /// `#[schemars(with = "Option<QueryTemplate>")]` override. If one is edited
    /// and the other is not, MCP clients see two different shapes for the same
    /// concept. Pin them identical — both derive from `QueryTemplate`, so the
    /// generated `query` property (and the `QueryTemplate` `$defs` it pulls in)
    /// must match byte-for-byte.
    #[test]
    fn query_param_schema_is_identical_across_create_and_update() {
        let create = serde_json::to_value(schemars::schema_for!(CreateRpcParams)).unwrap();
        let update = serde_json::to_value(schemars::schema_for!(UpdateRpcParams)).unwrap();
        // The prose `description` is deliberately different (create says
        // "Validated at create time", update says "Refused on a kind=sql row");
        // everything STRUCTURAL — the `QueryTemplate` `$ref`, nullability,
        // default — must match, so the two faces can't grow different shapes.
        let mut cq = create["properties"]["query"].clone();
        let mut uq = update["properties"]["query"].clone();
        if let Some(o) = cq.as_object_mut() {
            o.remove("description");
        }
        if let Some(o) = uq.as_object_mut() {
            o.remove("description");
        }
        assert_eq!(
            cq, uq,
            "the `query` param STRUCTURE drifted between create_rpc and update_rpc"
        );
        // The pulled-in QueryTemplate definition must be identical too — this is
        // the actual template shape both faces publish.
        assert_eq!(
            create["$defs"]["QueryTemplate"], update["$defs"]["QueryTemplate"],
            "the QueryTemplate `$defs` drifted between the two publishing sites"
        );
        // And it must be the typed QueryTemplate, not schemars' untyped "any":
        // the template's filter override advertises the `$param`/`$auth`
        // operands, so their presence proves the real template shape is
        // published (the v1.58.6 bare-Value regression class).
        let create_str = serde_json::to_string(&create).unwrap();
        assert!(
            create_str.contains("collection") && create_str.contains("$param"),
            "create_rpc.query must publish the QueryTemplate shape, not `any`: {create_str}"
        );
    }
}

#[cfg(test)]
mod instructions_tests {
    use super::build_instructions;

    // Regression: a bare `serde_json::Value` MCP tool arg derives a schema that
    // strict MCP clients (Zod) reject — the per-tenant tools/list fails with
    // "Invalid input at properties.<x>" and the client fetches NO tools. Every
    // such arg must override its schema to an explicit type via
    // #[schemars(with = ...)]. (2026-06 prod incident. A tree sweep confirms the
    // only three bare-Value tool args are these; Option<Value> renders an
    // accepted `{description, default}` schema and needs no override.)
    #[test]
    fn bare_json_value_tool_args_render_typed_schema() {
        let cases = [
            (
                "event",
                "object",
                serde_json::to_value(schemars::schema_for!(super::InvokeFunctionArgs)).unwrap(),
            ),
            (
                "payload",
                "object",
                serde_json::to_value(schemars::schema_for!(super::BroadcastArgs)).unwrap(),
            ),
            (
                "vector",
                "array",
                serde_json::to_value(schemars::schema_for!(
                    crate::mcp::tools::vector::SearchInput
                ))
                .unwrap(),
            ),
        ];
        for (prop, want, schema) in cases {
            assert_eq!(
                schema["properties"][prop]["type"], want,
                "{prop} must render type={want} (bare serde_json::Value derives a \
                 schema strict clients reject), got: {}",
                schema["properties"][prop]
            );
        }
    }

    #[test]
    fn instructions_register_rls_policy_tools() {
        let s = build_instructions("test-tenant-abc", "https://example.test");
        for tool in ["set_policy", "get_policies", "clear_policy"] {
            assert!(
                s.contains(tool),
                "instructions prologue must register RLS tool: {tool}"
            );
        }
    }

    #[test]
    fn instructions_mention_resources_and_prompts() {
        // v1.56 — the prologue must point the model at the Resources + Prompts
        // surface (they add no tools, so tools/list alone wouldn't reveal them).
        let s = build_instructions("test-tenant-abc", "https://example.test");
        assert!(s.contains("resources/list"), "must point at resources/list");
        assert!(s.contains("prompts/list"), "must point at prompts/list");
        assert!(s.contains("bootstrap"), "must name the bootstrap prompt");
        assert!(s.contains("drust://"), "must show the resource URI scheme");
    }

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
        assert!(
            s.contains("get_schema_overview"),
            "must name get_schema_overview as a bootstrap call"
        );
        assert!(s.contains("whoami"), "must name whoami as a bootstrap call");
        let go = s
            .find("get_schema_overview")
            .expect("get_schema_overview present");
        let groups = s
            .find("CAPABILITY GROUPS")
            .expect("CAPABILITY GROUPS present");
        assert!(
            go < groups,
            "bootstrap calls must appear before the capability-group body"
        );

        // (b) The CHOOSING A READ TOOL disambiguation block exists and names all three.
        assert!(
            s.contains("CHOOSING A READ TOOL"),
            "missing CHOOSING A READ TOOL disambiguation block"
        );
        assert!(
            s.contains("list_records"),
            "read block must name list_records"
        );
        assert!(
            s.contains("search_collection"),
            "read block must name search_collection"
        );
        assert!(
            s.contains("does not enforce") || s.contains("does NOT enforce"),
            "read block must warn that query does not enforce owner_field"
        );

        // (c) Recovery affordances are stated by name (Lever 5).
        assert!(s.contains("dry_run"), "missing dry_run recovery affordance");
        assert!(
            s.contains("suggested_fix"),
            "missing suggested_fix recovery affordance"
        );
        assert!(
            s.contains("recent_writes"),
            "missing recent_writes recovery affordance"
        );

        // (d) Post-Lever-4 tool set: merged names present, removed names absent.
        assert!(
            s.contains("set_description"),
            "must advertise merged set_description"
        );
        assert!(
            s.contains("set_owner_field"),
            "must advertise set_owner_field"
        );
        for removed in &[
            "sample_rows",
            "count_rows",
            "set_collection_description",
            "set_field_description",
            "set_index_description",
            "clear_owner_field",
        ] {
            assert!(
                !s.contains(removed),
                "instructions still reference removed/merged tool: {removed}"
            );
        }
    }
}

#[cfg(test)]
mod annotation_tests {
    use super::*;

    // Wire name == fn name (no `name=` overrides). Buckets sum to 74; call_rpc &
    // invoke_function are special-cased below. Total must equal tool_count() (76).
    const READONLY: &[&str] = &[
        "list_collections",
        "whoami",
        "describe_collection",
        "get_schema_overview",
        "query",
        "explain",
        "get_record_history",
        "get_policies",
        "search_collection",
        "list_records",
        "aggregate",
        "list_files",
        "get_file_url",
        "list_rpc",
        "list_users",
        "get_user",
        "get_egress_allowlist",
        "list_oauth_providers",
        "list_webhooks",
        "recent_writes",
        "list_functions",
        "get_function_logs",
        "list_cron_jobs",
        "list_fts_indexes",
        "list_file_policies",
    ];
    const DESTRUCTIVE: &[&str] = &[
        "drop_field",
        "drop_collection",
        "drop_index",
        "drop_fts_index",
        "delete_record",
        "delete_file",
        "delete_rpc",
        "delete_user",
        "revoke_user_sessions",
        "clear_policy",
        "delete_oauth_provider",
        "delete_webhook",
        "delete_function",
        "delete_cron_job",
        "clear_file_policy",
    ];
    const IDEMPOTENT: &[&str] = &[
        "set_anon_caps",
        "set_user_caps",
        "set_realtime",
        "set_audit_enabled",
        "set_policy",
        "set_description",
        "set_file_visibility",
        "set_file_policy",
        "set_owner_field",
        "set_self_register",
        "set_publish_policy",
        "set_file_caps",
        "set_egress_allowlist",
        "set_oauth_provider",
        "set_redirect_uris",
        "set_function_active",
        "set_function_invoke_acl",
        "set_cron_job_active",
        "update_record",
        "upsert_records",
        "update_rpc",
        "update_user",
        "update_webhook",
    ];
    const ADDITIVE: &[&str] = &[
        "insert_record",
        "insert_records",
        "create_collection",
        "add_field",
        "create_index",
        "create_fts_index",
        "create_rpc",
        "create_user",
        "create_webhook",
        "create_cron_job",
        "broadcast",
    ];

    fn tools() -> Vec<rmcp::model::Tool> {
        DrustMcpService::tool_router().list_all()
    }
    fn ann(name: &str) -> rmcp::model::ToolAnnotations {
        tools()
            .into_iter()
            .find(|t| t.name.as_ref() == name)
            .unwrap_or_else(|| panic!("tool {name} not found"))
            .annotations
            .unwrap_or_else(|| panic!("tool {name} has no annotations"))
    }

    /// Completeness anchor: proves wire name == fn name, the count is 76, and the
    /// classification below covers EXACTLY the real tool set (catches renames/adds/typos).
    #[test]
    fn wire_names_match_classification_and_count_is_76() {
        let names: Vec<String> = tools().iter().map(|t| t.name.to_string()).collect();
        assert_eq!(
            names.len(),
            76,
            "tool count changed — update tool_count assertions too"
        );
        let mut covered: Vec<&str> = READONLY
            .iter()
            .chain(DESTRUCTIVE)
            .chain(IDEMPOTENT)
            .chain(ADDITIVE)
            .copied()
            .chain(["call_rpc", "invoke_function"])
            .collect();
        covered.sort_unstable();
        let mut actual: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        actual.sort_unstable();
        assert_eq!(
            covered, actual,
            "classification set != actual tool wire names"
        );
    }

    #[test]
    fn every_tool_is_annotated() {
        for t in tools() {
            assert!(
                t.annotations.is_some(),
                "tool {} has no annotations",
                t.name
            );
        }
    }

    #[test]
    fn readonly_tools_marked() {
        for &n in READONLY {
            assert_eq!(ann(n).read_only_hint, Some(true), "{n} should be read_only");
        }
    }

    #[test]
    fn destructive_tools_marked() {
        for &n in DESTRUCTIVE {
            let a = ann(n);
            assert_eq!(a.destructive_hint, Some(true), "{n} should be destructive");
            assert_ne!(
                a.read_only_hint,
                Some(true),
                "{n} destructive must not be read_only"
            );
        }
    }

    #[test]
    fn idempotent_tools_marked() {
        for &n in IDEMPOTENT {
            let a = ann(n);
            assert_eq!(a.idempotent_hint, Some(true), "{n} should be idempotent");
            assert_eq!(
                a.destructive_hint,
                Some(false),
                "{n} should be non-destructive"
            );
        }
    }

    #[test]
    fn additive_tools_marked() {
        for &n in ADDITIVE {
            let a = ann(n);
            assert_eq!(
                a.destructive_hint,
                Some(false),
                "{n} additive should be non-destructive"
            );
            assert_eq!(
                a.idempotent_hint,
                Some(false),
                "{n} additive should be non-idempotent"
            );
        }
    }

    #[test]
    fn open_world_only_invoke_function() {
        for t in tools() {
            let ow = t.annotations.as_ref().and_then(|a| a.open_world_hint);
            if t.name.as_ref() == "invoke_function" {
                assert_eq!(ow, Some(true), "invoke_function must be open_world");
            } else {
                assert_ne!(ow, Some(true), "{} must not be open_world", t.name);
            }
        }
    }
}

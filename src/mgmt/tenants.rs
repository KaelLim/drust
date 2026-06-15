use crate::auth::middleware::AdminSessionState;
use crate::storage::garage::GarageClient;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

pub(crate) mod common;
mod crud;
mod files_page;
mod oauth_page;
mod overview;
mod webhooks_page;

pub use crud::{
    PublishPolicyPatch, cmdk_tenants_json, create_tenant_form, create_tenant_json,
    get_publish_policy, list_page_axum, patch_publish_policy, soft_delete_tenant,
    soft_delete_tenant_form, toggle_self_register,
};
pub use files_page::tenant_files_admin_page;
pub use oauth_page::{
    tenant_oauth_provider_delete, tenant_oauth_provider_upsert, tenant_oauth_providers_page,
};
pub use overview::tenant_overview_page;
pub use webhooks_page::{
    tenant_webhook_create_form, tenant_webhook_delete_form, tenant_webhooks_page,
};

#[derive(Clone)]
pub struct TenantsState {
    pub session: AdminSessionState,
    pub data_dir: PathBuf,
    pub garage: Option<Arc<GarageClient>>,
    pub garage_client_key_id: String,
    /// Used by the admin tenant-files subpage to render disk banner + form cap.
    pub max_upload_bytes: usize,
    pub disk_min_free_pct: u8,
    pub public_base_url: String,
    /// Shared per-tenant pool registry. Admin handlers that mutate
    /// schema-cached state (e.g. the anon_caps editor) reach in here
    /// to invalidate the cache so REST/MCP requests pick up the change
    /// on the very next call.
    pub tenants: Arc<crate::storage::pool::TenantRegistry>,
    /// Per-tenant MCP service registry. Used by soft_delete_tenant to
    /// evict the cached `DrustMcpService` so in-flight sessions release.
    pub mcp: Arc<crate::mcp::http_registry::McpHttpRegistry>,
    /// SSE broadcast channels. Used by soft_delete_tenant to drop every
    /// channel keyed on the tenant.
    pub bus: crate::tenant::events::EventBus,
    /// v1.31 broadcast rooms bus. Mirrors `bus` for ad-hoc per-room
    /// WS multiplex channels. `soft_delete_tenant` evicts both.
    pub bus_rooms: crate::tenant::rooms::RoomBus,
    /// Directory containing `audit-YYYY-MM-DD.jsonl` files. Sourced from
    /// `$DRUST_LOG_DIR` at boot; consumed by the admin audit UI handlers
    /// mounted under tenants_router.
    pub log_dir: PathBuf,
    /// v1.24 — read-only connection to `meta_logs.sqlite`. Consumed by
    /// the admin audit UI (`audit_host_page` / `audit_tenant_page`) which
    /// now queries SQL directly instead of scanning JSONL.
    pub audit_meta_read: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    /// Row count threshold above which index creation is considered "large
    /// table" and returns `LARGE_TABLE` unless `force=true`. Sourced from
    /// `DRUST_INDEX_LARGE_TABLE_ROWS` (default 1 000 000).
    pub index_large_table_rows: u64,
    /// v1.35 — shared auth cache (same `Arc` as `TenantAuthState`/`MgmtState`).
    /// Admin write handlers invalidate it so a rerolled/revoked token misses
    /// on its next data-plane request. See `crate::tenant::auth_cache`.
    pub auth_cache: Arc<crate::tenant::auth_cache::AuthCache>,
    /// v1.36 — edge-function dispatcher. The `ƒ _functions` admin page calls
    /// `functions.bindings.invalidate(tenant)` after toggle/delete so the
    /// trigger-match cache picks up the change on the next event.
    pub functions: Arc<crate::functions::dispatcher::FunctionDispatcher>,
    /// v1.36 — executor handle for the admin page's synchronous test-invoke.
    pub functions_exec: Arc<crate::functions::executor::Executor>,
    /// v1.36 — artifact root (same dir the tenant pools use). The admin
    /// delete handler GCs the content-addressed `{sha}.wasm` blob from here.
    pub fn_data_root: PathBuf,
}

/// Test-only constructor available in debug builds.
///
/// Defaults:
/// - `garage`: `None` (no S3 client)
/// - `garage_client_key_id`: `""`
/// - `max_upload_bytes`: 1 MiB (1 048 576)
/// - `disk_min_free_pct`: 20
/// - `public_base_url`: `"http://localhost"`
/// - `log_dir`: `data_dir.join("logs")`
/// - `index_large_table_rows`: 1 000 000
///
/// `session` is derived from `meta` directly.
#[cfg(any(test, debug_assertions))]
impl TenantsState {
    pub fn test_default(
        meta: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
        data_dir: PathBuf,
        tenants: std::sync::Arc<crate::storage::pool::TenantRegistry>,
        mcp: std::sync::Arc<crate::mcp::http_registry::McpHttpRegistry>,
        bus: crate::tenant::events::EventBus,
        bus_rooms: crate::tenant::rooms::RoomBus,
    ) -> Self {
        use crate::auth::middleware::AdminSessionState;
        let log_dir = data_dir.join("logs");
        let fn_data_root = data_dir.clone();
        let audit_meta_read = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::safety::audit_db::open_audit_db_memory().expect("in-memory audit DB for tests"),
        ));
        let (functions, functions_exec, _cfg) = crate::functions::test_stack_parts(tenants.clone());
        Self {
            session: AdminSessionState { meta: meta.clone() },
            data_dir,
            garage: None,
            garage_client_key_id: String::new(),
            max_upload_bytes: 1024 * 1024,
            disk_min_free_pct: 20,
            public_base_url: "http://localhost".to_string(),
            tenants,
            mcp,
            bus,
            bus_rooms,
            log_dir,
            audit_meta_read,
            index_large_table_rows: 1_000_000,
            auth_cache: Arc::new(crate::tenant::auth_cache::AuthCache::new(
                std::time::Duration::from_secs(10),
                200_000,
            )),
            functions,
            functions_exec,
            fn_data_root,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantJson {
    /// Optional — auto-generated UUID v4 when omitted.
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub quota_db_mb: Option<i64>,
    #[serde(default)]
    pub quota_rows: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantForm {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreatedResp {
    pub tenant: TenantInfo,
    /// Both initial keys, shown once only.
    pub initial_tokens: InitialTokens,
    /// Back-compat field: equals `initial_tokens.service`.
    pub initial_token: String,
}

#[derive(Debug, Serialize)]
pub struct InitialTokens {
    pub anon: String,
    pub service: String,
}

#[derive(Debug, Serialize)]
pub struct TenantInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub quota_db_mb: i64,
    pub quota_rows: i64,
}

pub fn valid_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    if !(3..=40).contains(&bytes.len()) {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    let is_lead = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_lead(first) || !is_lead(last) {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

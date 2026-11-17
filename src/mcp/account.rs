//! The server handler behind the account-level MCP endpoint (`/mcp`).
//!
//! One handler serves every tenant an account may see; the tenant is a tool
//! argument, never part of the URL. The transport is stateless: every POST is
//! authorized on its own by the OAuth bearer layer in front of it, and no rmcp
//! session or GET stream exists. The handler holds no tenant state (only the
//! shared `McpRegistry`, which builds a tenant's server state on demand), and
//! it never pushes: no notification, no server-to-client request. HTTP, Host
//! and credential checks live in `mgmt::mcp_oauth`, not here.

use std::path::PathBuf;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, InitializeRequestParams,
    InitializeResult, ProtocolVersion, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use rusqlite::Connection;
use tokio::sync::Mutex;

use crate::mcp::handler::server_capabilities;
use crate::mcp::server::McpRegistry;
use crate::mgmt::mcp_oauth::config::McpOauthConfig;

/// The protocol revisions drust implements, oldest first. `initialize` echoes
/// a requested revision found here and answers the newest one otherwise. Never
/// derived from rmcp's own list, which names revisions drust does not
/// implement and moves with every rmcp upgrade.
pub(crate) const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] =
    ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];

/// The large-upload limits a ticket-bound upload is issued under, copied from
/// the management state when the router is built. Plain numbers, no
/// credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadLimits {
    pub storage_configured: bool,
    pub max_bytes: usize,
    pub chunk_max_bytes: usize,
    pub session_ttl_secs: u64,
}

/// What every request of the account-level server shares.
// Fields gain readers as the tool surface lands.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct AccountState {
    registry: Arc<McpRegistry>,
    meta: Arc<Mutex<Connection>>,
    cfg: Arc<McpOauthConfig>,
    uploads: UploadLimits,
    log_dir: PathBuf,
}

/// The account-level MCP server. No `Debug` and no `Default`: it is built only
/// by `new`, from the router that puts the entry gate, the bearer layer and
/// the body buffer in front of it.
#[derive(Clone)]
pub struct AccountMcp {
    // Allowed until a tool reads the shared state.
    #[cfg_attr(not(test), allow(dead_code))]
    inner: Arc<AccountState>,
}

impl AccountMcp {
    pub(crate) fn new(
        registry: Arc<McpRegistry>,
        meta: Arc<Mutex<Connection>>,
        cfg: Arc<McpOauthConfig>,
        uploads: UploadLimits,
        log_dir: PathBuf,
    ) -> Self {
        AccountMcp {
            inner: Arc::new(AccountState {
                registry,
                meta,
                cfg,
                uploads,
                log_dir,
            }),
        }
    }

    /// The requested revision when drust implements it, 2025-11-25 otherwise.
    pub(crate) fn negotiate(requested: &ProtocolVersion) -> ProtocolVersion {
        if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested.as_str()) {
            requested.clone()
        } else {
            ProtocolVersion::V_2025_11_25
        }
    }
}

impl ServerHandler for AccountMcp {
    /// The per-tenant server's capabilities (nothing that pushes), and no
    /// instructions yet.
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(server_capabilities())
            .with_server_info(Implementation::new("drust", env!("CARGO_PKG_VERSION")))
    }

    /// Answers with the negotiated revision. The request context is never
    /// touched: rmcp's default stores the client's info through it, and this
    /// stateless server has nowhere to keep it.
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self
            .get_info()
            .with_protocol_version(Self::negotiate(&request.protocol_version)))
    }

    /// No tool exists yet: the same error rmcp's own tool router gives for an
    /// unknown name.
    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        Err(McpError::invalid_params("tool not found", None))
    }
}

/// The revision a client asking for an unsupported one is answered with. The
/// fallback branch of `AccountMcp::negotiate` returns
/// `ProtocolVersion::V_2025_11_25` (its field is private, so it cannot be
/// built from this string); this is that branch's test oracle.
// Below every production item on purpose: source pins scan only the text
// above a file's first `#[cfg(test)]`.
#[cfg(test)]
pub(crate) const FALLBACK_PROTOCOL_VERSION: &str = "2025-11-25";

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::ServerHandler;

    fn pv(s: &str) -> ProtocolVersion {
        serde_json::from_value(serde_json::json!(s)).unwrap()
    }

    fn fixture(
        tmp: &tempfile::TempDir,
    ) -> (
        Arc<McpRegistry>,
        Arc<Mutex<Connection>>,
        Arc<McpOauthConfig>,
    ) {
        let tenants = Arc::new(crate::storage::pool::TenantRegistry::new(
            tmp.path().to_path_buf(),
            2,
        ));
        (
            Arc::new(McpRegistry::new(tenants)),
            Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            Arc::new(McpOauthConfig::disabled()),
        )
    }

    #[test]
    fn negotiate_echoes_a_supported_version_and_falls_back_otherwise() {
        for v in SUPPORTED_PROTOCOL_VERSIONS {
            assert_eq!(AccountMcp::negotiate(&pv(v)).as_str(), v, "{v}");
        }
        for v in ["2026-07-28", "1999-01-01", "", "2025-11-25 ", "latest"] {
            assert_eq!(
                AccountMcp::negotiate(&pv(v)).as_str(),
                FALLBACK_PROTOCOL_VERSION,
                "{v:?}"
            );
        }
    }

    #[test]
    fn fallback_is_the_newest_supported_and_no_unimplemented_revision_is_listed() {
        let mut sorted = SUPPORTED_PROTOCOL_VERSIONS;
        sorted.sort_unstable();
        assert_eq!(
            sorted, SUPPORTED_PROTOCOL_VERSIONS,
            "keep the list ascending"
        );
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[3], FALLBACK_PROTOCOL_VERSION);
        assert_eq!(
            FALLBACK_PROTOCOL_VERSION,
            ProtocolVersion::V_2025_11_25.as_str()
        );
        assert!(!SUPPORTED_PROTOCOL_VERSIONS.contains(&ProtocolVersion::V_2026_07_28.as_str()));
    }

    #[test]
    fn info_declares_the_tenant_server_capabilities_and_no_instructions() {
        let tmp = tempfile::tempdir().unwrap();
        let (r, m, c) = fixture(&tmp);
        let info = AccountMcp::new(
            r,
            m,
            c,
            UploadLimits {
                storage_configured: false,
                max_bytes: 1,
                chunk_max_bytes: 1,
                session_ttl_secs: 1,
            },
            PathBuf::from("/l"),
        )
        .get_info();
        assert_eq!(
            serde_json::to_value(&info.capabilities).unwrap(),
            serde_json::to_value(crate::mcp::handler::server_capabilities()).unwrap(),
        );
        assert!(info.instructions.is_none());
        assert_eq!(info.server_info.name, "drust");
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn new_keeps_every_field() {
        let tmp = tempfile::tempdir().unwrap();
        let (r, m, c) = fixture(&tmp);
        let u = UploadLimits {
            storage_configured: true,
            max_bytes: 7,
            chunk_max_bytes: 3,
            session_ttl_secs: 11,
        };
        let a = AccountMcp::new(r.clone(), m.clone(), c.clone(), u, PathBuf::from("/x/logs"));
        assert!(Arc::ptr_eq(&a.inner.registry, &r));
        assert!(Arc::ptr_eq(&a.inner.meta, &m));
        assert!(Arc::ptr_eq(&a.inner.cfg, &c));
        assert_eq!(a.inner.uploads, u);
        assert_eq!(a.inner.log_dir, PathBuf::from("/x/logs"));
    }
}

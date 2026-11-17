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
use crate::mcp::server::{DrustMcp, McpRegistry};
use crate::mgmt::mcp_oauth::caller::McpCaller;
use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::tenant_authz::{AdminTenantAccess, TenantIncarnation, tenant_access_for_admin};

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

/// Why an account-level call could not be pointed at a tenant. One value for
/// "not visible", "missing", "soft-deleted" and "not a valid id", so no
/// surface can tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denied {
    /// The `tenant` argument is absent, not a string, or empty.
    Required,
    NotFound,
    /// A meta query failed, or the request carries no caller.
    Internal,
}

/// Holds a DrustMcp, which carries the URL-signing secret: never derive Debug.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Resolved {
    pub mcp: DrustMcp,
    pub tenant_id: String,
    /// What the second visibility check saw.
    pub incarnation: TenantIncarnation,
}

/// The caller the OAuth bearer layer put on the HTTP request. rmcp hands the
/// handler the request's `Parts` inside its own extensions; a `McpCaller`
/// anywhere else (for instance at the top level of those extensions) does not
/// count.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn caller_from_extensions(ext: &rmcp::model::Extensions) -> Option<McpCaller> {
    ext.get::<axum::http::request::Parts>()?
        .extensions
        .get::<McpCaller>()
        .cloned()
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

    /// The request's caller (see [`caller_from_extensions`]). Reads only the
    /// context's extensions.
    #[allow(dead_code)]
    pub(crate) fn caller(ctx: &RequestContext<RoleServer>) -> Option<McpCaller> {
        caller_from_extensions(&ctx.extensions)
    }

    /// Every account-level call that targets a tenant must go through this
    /// function (tools, resources, prompts and the upload tool). Checks
    /// visibility first and opens the tenant only after that check passed, so a
    /// caller never makes the host open a tenant it cannot see; then checks
    /// again and requires the same (owner, created_at), so a soft delete or an
    /// id recycle by another owner between the two reads is refused. Each check
    /// holds the meta lock only inside its own block; nothing here holds it
    /// across an await. Not detectable here, by design: an old-incarnation pool
    /// still cached by the TenantRegistry (the residual window documented in
    /// .claude/rules/auth-tenancy.md).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn resolve_tenant(
        &self,
        caller: &McpCaller,
        raw: Option<&serde_json::Value>,
    ) -> Result<Resolved, Denied> {
        self.resolve_tenant_with_hook(caller, raw, || async {})
            .await
    }

    /// [`Self::resolve_tenant`] with `between_checks` run after the tenant was
    /// opened and before the second check (a no-op outside tests).
    async fn resolve_tenant_with_hook<F, Fut>(
        &self,
        caller: &McpCaller,
        raw: Option<&serde_json::Value>,
        between_checks: F,
    ) -> Result<Resolved, Denied>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        // The argument: no meta access, no case folding.
        let id = match raw {
            Some(serde_json::Value::String(s)) if !s.is_empty() => s.as_str(),
            _ => return Err(Denied::Required),
        };
        if crate::storage::tenant_db::validate_tenant_id(id).is_err() {
            return Err(Denied::NotFound);
        }
        // First check. Anything but Allow returns here, before the tenant is
        // opened.
        let first = {
            let c = self.inner.meta.lock().await;
            tenant_access_for_admin(&c, caller.grant_id(), caller.admin_id(), id)
        };
        let first = self.allowed(caller, first)?;
        let mcp = self
            .inner
            .registry
            .build_live(id, self.inner.meta.clone())
            .ok_or(Denied::NotFound)?;
        between_checks().await;
        // Second check: still visible, and still the same incarnation.
        let second = {
            let c = self.inner.meta.lock().await;
            tenant_access_for_admin(&c, caller.grant_id(), caller.admin_id(), id)
        };
        let second = self.allowed(caller, second)?;
        if second.owner != first.owner || second.created_at != first.created_at {
            return Err(Denied::NotFound);
        }
        Ok(Resolved {
            mcp,
            tenant_id: id.to_string(),
            incarnation: second,
        })
    }

    /// One visibility check's answer as `resolve_tenant` maps it.
    fn allowed(
        &self,
        caller: &McpCaller,
        access: rusqlite::Result<AdminTenantAccess>,
    ) -> Result<TenantIncarnation, Denied> {
        match access {
            Ok(AdminTenantAccess::Allow(inc)) => Ok(inc),
            Ok(AdminTenantAccess::Deny) => Err(Denied::NotFound),
            Err(e) => {
                tracing::warn!(
                    stage = "resolve_tenant",
                    grant_id = caller.grant_id(),
                    admin_id = caller.admin_id(),
                    error = %crate::error::sqlite_error_without_sql(&e),
                    "tenant visibility check failed"
                );
                Err(Denied::Internal)
            }
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

#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::mgmt::mcp_oauth::caller::McpCaller;
    use crate::mgmt::tenant_authz::TenantIncarnation;
    use crate::storage::pool::TenantRegistry;
    use rusqlite::{Connection, params};
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    struct Fx {
        acct: AccountMcp,
        meta: Arc<Mutex<Connection>>,
        tenants: Arc<TenantRegistry>,
        root: tempfile::TempDir,
        m: McpCaller,
        o: McpCaller,
        x: McpCaller,
        m_id: i64,
        o_id: i64,
        x_id: i64,
    }

    /// member M owns "blog" (real data.sqlite, pool cached); owner O; member X owns
    /// "other" (real data.sqlite, pool NOT cached).
    async fn fx() -> Fx {
        let root = tempfile::tempdir().unwrap();
        let conn = crate::storage::meta::open_meta(&root.path().join("meta.sqlite")).unwrap();
        crate::db::migrations::run_migrations(&conn, root.path()).unwrap();
        let mut ids = vec![];
        for (u, role) in [("m", "member"), ("o", "owner"), ("x", "member")] {
            conn.execute(
                "INSERT INTO admins (username, password_hash, role) VALUES (?1, '$oauth-only$', ?2)",
                params![u, role],
            )
            .unwrap();
            let a = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO _mcp_oauth_grants (admin_id, admin_created_at, client_id, redirect_host, \
                   idle_expires_at, absolute_expires_at) \
                 SELECT id, created_at, 'c', 'localhost', datetime('now', '+30 days'), \
                   datetime('now', '+90 days') FROM admins WHERE id = ?1",
                params![a],
            )
            .unwrap();
            ids.push((a, conn.last_insert_rowid()));
        }
        conn.execute(
            "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('blog', 'Blog', ?1)",
            params![ids[0].0],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('other', 'Other', ?1)",
            params![ids[2].0],
        )
        .unwrap();
        let tenants = Arc::new(TenantRegistry::new(root.path().to_path_buf(), 2));
        tenants.get_or_create("blog").unwrap();
        tenants.get_or_create("other").unwrap();
        tenants.evict("other"); // on disk, not in the pool cache
        let meta = Arc::new(Mutex::new(conn));
        let acct = AccountMcp::new(
            Arc::new(crate::mcp::server::McpRegistry::new(tenants.clone())),
            meta.clone(),
            Arc::new(crate::mgmt::mcp_oauth::config::McpOauthConfig::for_tests(
                "https://drust.test",
            )),
            UploadLimits {
                storage_configured: false,
                max_bytes: 0,
                chunk_max_bytes: 0,
                session_ttl_secs: 0,
            },
            root.path().join("logs"),
        );
        let c = |(a, g): (i64, i64)| McpCaller::for_tests(a, g);
        Fx {
            acct,
            meta,
            tenants,
            m: c(ids[0]),
            o: c(ids[1]),
            x: c(ids[2]),
            m_id: ids[0].0,
            o_id: ids[1].0,
            x_id: ids[2].0,
            root,
        }
    }

    async fn run(f: &Fx, who: &McpCaller, raw: serde_json::Value) -> Result<Resolved, Denied> {
        tokio::time::timeout(
            Duration::from_secs(5),
            f.acct.resolve_tenant(who, Some(&raw)),
        )
        .await
        .expect("resolve_tenant must not block")
    }

    #[tokio::test]
    async fn resolve_allows_the_owner_and_returns_the_incarnation() {
        let f = fx().await;
        let ca: String = f
            .meta
            .lock()
            .await
            .query_row(
                "SELECT created_at FROM tenants WHERE id = 'blog'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let r = run(&f, &f.m, json!("blog"))
            .await
            .expect("owner member is allowed");
        assert_eq!(r.tenant_id, "blog");
        assert_eq!(r.mcp.tenant_id(), "blog");
        assert_eq!(
            r.incarnation,
            TenantIncarnation {
                owner: Some(f.m_id),
                created_at: ca
            }
        );
        assert!(
            run(&f, &f.o, json!("blog")).await.is_ok(),
            "sees-all owner is allowed"
        );
    }

    #[tokio::test]
    async fn resolve_maps_tenant_arguments_without_touching_meta() {
        let f = fx().await;
        let _held = f.meta.lock().await; // any meta access below would hang until the timeout
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), f.acct.resolve_tenant(&f.m, None))
                .await
                .unwrap()
                .err(),
            Some(Denied::Required)
        );
        for raw in [json!(5), json!(null), json!({}), json!(["blog"]), json!("")] {
            let got = tokio::time::timeout(
                Duration::from_secs(1),
                f.acct.resolve_tenant(&f.m, Some(&raw)),
            )
            .await
            .expect("no meta access")
            .err();
            assert_eq!(got, Some(Denied::Required), "{raw}");
        }
        let long = "a".repeat(53);
        for raw in ["Blog", " blog", "../blog", "admin", long.as_str()] {
            let got = tokio::time::timeout(
                Duration::from_secs(1),
                f.acct.resolve_tenant(&f.m, Some(&json!(raw))),
            )
            .await
            .expect("no meta access")
            .err();
            assert_eq!(got, Some(Denied::NotFound), "{raw:?}");
        }
        // No directory was created for any of them. Compared by listing, not by
        // `exists()`: on a case-insensitive file system `tenants/Blog` "exists"
        // because `tenants/blog` does.
        let mut dirs: Vec<String> = std::fs::read_dir(f.root.path().join("tenants"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        dirs.sort();
        assert_eq!(dirs, ["blog", "other"]);
    }

    #[tokio::test]
    async fn resolve_hides_foreign_deleted_and_missing_tenants_identically() {
        let f = fx().await;
        assert_eq!(
            run(&f, &f.x, json!("blog")).await.err(),
            Some(Denied::NotFound),
            "foreign"
        );
        assert_eq!(
            run(&f, &f.m, json!("nope")).await.err(),
            Some(Denied::NotFound),
            "missing, member"
        );
        assert_eq!(
            run(&f, &f.o, json!("nope")).await.err(),
            Some(Denied::NotFound),
            "missing, sees-all"
        );
        f.meta
            .lock()
            .await
            .execute(
                "UPDATE tenants SET deleted_at = datetime('now') WHERE id = 'blog'",
                [],
            )
            .unwrap();
        assert_eq!(
            run(&f, &f.m, json!("blog")).await.err(),
            Some(Denied::NotFound),
            "soft-deleted, owner"
        );
        assert_eq!(
            run(&f, &f.o, json!("blog")).await.err(),
            Some(Denied::NotFound),
            "soft-deleted, sees-all"
        );
    }

    #[tokio::test]
    async fn resolve_denies_a_meta_row_without_a_database() {
        let f = fx().await;
        f.meta
            .lock()
            .await
            .execute(
                "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('ghost', 'G', ?1)",
                params![f.m_id],
            )
            .unwrap();
        assert_eq!(
            run(&f, &f.m, json!("ghost")).await.err(),
            Some(Denied::NotFound)
        );
        assert!(!crate::storage::tenant_db::tenant_dir(f.root.path(), "ghost").exists());
    }

    #[tokio::test]
    async fn resolve_denies_a_revoked_grant() {
        let f = fx().await;
        f.meta
            .lock()
            .await
            .execute(
                "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now') \
            WHERE id = ?1",
                params![f.m.grant_id()],
            )
            .unwrap();
        assert_eq!(
            run(&f, &f.m, json!("blog")).await.err(),
            Some(Denied::NotFound)
        );
    }

    #[tokio::test]
    async fn resolve_fails_closed_on_a_meta_error() {
        let f = fx().await;
        let broken = AccountMcp::new(
            f.acct.inner.registry.clone(),
            Arc::new(Mutex::new(Connection::open_in_memory().unwrap())), // no tables
            f.acct.inner.cfg.clone(),
            f.acct.inner.uploads,
            f.root.path().join("logs"),
        );
        assert_eq!(
            broken
                .resolve_tenant(&f.m, Some(&json!("blog")))
                .await
                .err(),
            Some(Denied::Internal)
        );
    }

    /// The first check runs BEFORE build_live: a refused call never makes the
    /// host open (catch-up, cache) a tenant the caller cannot see.
    #[tokio::test]
    async fn resolve_never_opens_a_pool_for_a_denied_tenant() {
        let f = fx().await;
        let n = f.tenants.cached_count(); // "blog" cached, "other" on disk only
        assert_eq!(
            run(&f, &f.m, json!("other")).await.err(),
            Some(Denied::NotFound),
            "foreign"
        );
        assert_eq!(
            f.tenants.cached_count(),
            n,
            "a foreign tenant must not be opened"
        );
        f.tenants.evict("blog");
        f.meta
            .lock()
            .await
            .execute(
                "UPDATE tenants SET deleted_at = datetime('now') WHERE id = 'blog'",
                [],
            )
            .unwrap();
        assert_eq!(
            run(&f, &f.o, json!("blog")).await.err(),
            Some(Denied::NotFound),
            "soft-deleted"
        );
        assert_eq!(
            f.tenants.cached_count(),
            n - 1,
            "a soft-deleted tenant must not be opened"
        );
        f.meta
            .lock()
            .await
            .execute(
                "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now') \
            WHERE id = ?1",
                params![f.x.grant_id()],
            )
            .unwrap();
        assert_eq!(
            run(&f, &f.x, json!("other")).await.err(),
            Some(Denied::NotFound),
            "revoked grant"
        );
        assert_eq!(
            f.tenants.cached_count(),
            n - 1,
            "a revoked grant must not open its own tenant"
        );
        // positive control: an allowed call does open the pool, so the probe above can see an open
        assert!(run(&f, &f.o, json!("other")).await.is_ok());
        assert_eq!(f.tenants.cached_count(), n);
    }

    /// Runs `sql` between the first check + build_live and the second check.
    async fn with_hook(f: &Fx, who: &McpCaller, sql: String) -> Result<Resolved, Denied> {
        let m = f.meta.clone();
        tokio::time::timeout(
            Duration::from_secs(5),
            f.acct
                .resolve_tenant_with_hook(who, Some(&json!("blog")), move || async move {
                    m.lock().await.execute_batch(&sql).unwrap();
                }),
        )
        .await
        .expect("the meta lock is free between the two checks")
    }

    #[tokio::test]
    async fn recycled_by_another_owner_between_the_checks_is_denied() {
        let f = fx().await;
        let recycle = |new_owner: i64| {
            format!(
                "DELETE FROM tenants WHERE id = 'blog'; \
             INSERT INTO tenants (id, name, owner_admin_id) VALUES ('blog', 'Blog2', {new_owner});"
            )
        };
        assert_eq!(
            with_hook(&f, &f.m, recycle(f.o_id)).await.err(),
            Some(Denied::NotFound),
            "member caller"
        );
        // sees-all caller: both checks Allow, but the owner differs (M, then X).
        // The first recycle left the row owned by O, so hand it back to M first.
        f.meta
            .lock()
            .await
            .execute(
                "UPDATE tenants SET owner_admin_id = ?1 WHERE id = 'blog'",
                params![f.m_id],
            )
            .unwrap();
        assert_eq!(
            with_hook(&f, &f.o, recycle(f.x_id)).await.err(),
            Some(Denied::NotFound),
            "sees-all caller"
        );
    }

    #[tokio::test]
    async fn soft_delete_between_the_checks_is_denied() {
        let f = fx().await;
        let sql = "UPDATE tenants SET deleted_at = datetime('now') WHERE id = 'blog';".to_string();
        assert_eq!(with_hook(&f, &f.m, sql).await.err(), Some(Denied::NotFound));
    }

    #[tokio::test]
    async fn demotion_between_the_checks_is_denied() {
        let f = fx().await;
        let sql = format!("UPDATE admins SET role = 'member' WHERE id = {};", f.o_id);
        assert_eq!(with_hook(&f, &f.o, sql).await.err(), Some(Denied::NotFound));
    }

    /// The second check re-validates the grant and its admin, not only the tenant row.
    #[tokio::test]
    async fn grant_or_admin_change_between_the_checks_is_denied() {
        for case in ["grant revoked", "admin recycled"] {
            let f = fx().await;
            let sql = match case {
                "grant revoked" => format!(
                    "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now') WHERE id = {};",
                    f.m.grant_id()
                ),
                _ => format!(
                    "UPDATE admins SET created_at = '2000-01-01 00:00:00' WHERE id = {};",
                    f.m_id
                ),
            };
            assert_eq!(
                with_hook(&f, &f.m, sql).await.err(),
                Some(Denied::NotFound),
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn owner_transfer_between_the_checks_is_denied() {
        for case in ["member caller", "sees-all caller"] {
            let f = fx().await;
            let who = if case == "member caller" {
                f.m.clone()
            } else {
                f.o.clone()
            };
            let sql = format!(
                "UPDATE tenants SET owner_admin_id = {} WHERE id = 'blog';",
                f.x_id
            );
            // member: the second check is Deny; sees-all: Allow, but the owner differs
            assert_eq!(
                with_hook(&f, &who, sql).await.err(),
                Some(Denied::NotFound),
                "{case}"
            );
        }
    }

    /// Owner unchanged, only the incarnation timestamp moves: the created_at arm alone refuses.
    #[tokio::test]
    async fn created_at_change_between_the_checks_is_denied() {
        let f = fx().await;
        let sql =
            "UPDATE tenants SET created_at = '2000-01-01 00:00:00' WHERE id = 'blog';".to_string();
        assert_eq!(with_hook(&f, &f.m, sql).await.err(), Some(Denied::NotFound));
    }

    #[tokio::test]
    async fn a_meta_error_on_the_second_check_is_internal() {
        let f = fx().await;
        let sql = "DROP TABLE _mcp_oauth_grants;".to_string();
        assert_eq!(with_hook(&f, &f.m, sql).await.err(), Some(Denied::Internal));
    }

    #[tokio::test]
    async fn resolve_releases_the_meta_lock_before_returning() {
        let f = fx().await;
        assert!(
            with_hook(&f, &f.m, String::new()).await.is_ok(),
            "a no-op hook keeps Allow"
        );
        assert!(run(&f, &f.m, json!("blog")).await.is_ok());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), f.meta.lock())
                .await
                .is_ok()
        );
    }

    #[test]
    fn caller_comes_only_from_the_http_parts() {
        let mut ext = rmcp::model::Extensions::new();
        assert!(caller_from_extensions(&ext).is_none(), "no Parts");
        ext.insert(McpCaller::for_tests(7, 9)); // outside Parts: must not count
        assert!(
            caller_from_extensions(&ext).is_none(),
            "caller outside Parts"
        );
        let (mut parts, ()) = axum::http::Request::new(()).into_parts();
        ext.insert(parts.clone());
        assert!(
            caller_from_extensions(&ext).is_none(),
            "Parts without a caller"
        );
        parts.extensions.insert(McpCaller::for_tests(7, 9));
        ext.insert(parts);
        let c = caller_from_extensions(&ext).expect("caller in Parts");
        assert_eq!((c.admin_id(), c.grant_id()), (7, 9));
    }
}

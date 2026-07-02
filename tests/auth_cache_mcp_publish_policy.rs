// tests/auth_cache_mcp_publish_policy.rs — hook 11 (MCP face).
//
// `patch_publish_policy` (REST admin) fires a tenant-scoped clear (hook 11),
// but the publish-policy flags have a SECOND production writer: the MCP
// `set_publish_policy` tool (src/mcp/tools/owner_field.rs). Same seam as the
// hooks 7/8 MCP tools: the tool fn takes `Option<&AuthCache>` and invalidates
// inside the fn, so the wiring is exercised directly here. Without the clear,
// a model flipping `allow_user_publish` via MCP leaves every cached entry
// serving the OLD policy for up to the safety TTL.
mod helpers;

use drust::storage::meta::open_meta;
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

fn bearer_entry(tenant: &str) -> CachedAuth {
    CachedAuth::Bearer {
        bound_tenant_id: tenant.to_string(),
        role: CachedRole::Service,
        publish_user_allowed: false,
        publish_anon_allowed: false,
        email_snapshot: None,
        file_caps: Default::default(),
        expires_at: None,
    }
}

fn user_entry(tenant: &str) -> CachedAuth {
    CachedAuth::User {
        tenant_id: tenant.to_string(),
        user_id: "u-1".to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        publish_user_allowed: false,
        publish_anon_allowed: false,
        file_caps: Default::default(),
    }
}

#[tokio::test]
async fn mcp_set_publish_policy_clears_tenant_scoped_entries() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    // migrations add tenants.allow_user_publish / allow_anon_publish
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-pp', 'x')", [])
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert("svc".to_string(), bearer_entry("t-pp"));
    cache.insert("usr".to_string(), user_entry("t-pp"));
    // A different tenant's entry must survive the tenant-scoped clear.
    cache.insert("other".to_string(), bearer_entry("t-other"));

    let v = drust::mcp::tools::owner_field::set_publish_policy(
        &meta,
        "t-pp",
        Some(true),
        None,
        Some(&*cache),
    )
    .await
    .unwrap();
    assert_eq!(v["allow_user_publish"], true);

    assert!(
        cache.get("svc").is_none() && cache.get("usr").is_none(),
        "MCP set_publish_policy must clear t-pp's cached entries (hook 11 MCP face)"
    );
    assert!(
        cache.get("other").is_some(),
        "tenant-scoped clear must spare other tenants' entries"
    );
}

#[tokio::test]
async fn mcp_set_publish_policy_noop_call_still_clears_nothing_foreign() {
    // A call that changes neither flag (both None) performs no UPDATE; it
    // must not clear anything (no auth state changed).
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    // migrations add tenants.allow_user_publish / allow_anon_publish
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-pp', 'x')", [])
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert("svc".to_string(), bearer_entry("t-pp"));

    let _ = drust::mcp::tools::owner_field::set_publish_policy(
        &meta,
        "t-pp",
        None,
        None,
        Some(&*cache),
    )
    .await
    .unwrap();
    assert!(
        cache.get("svc").is_some(),
        "a no-op policy call (no flag supplied) must not evict cached entries"
    );
}

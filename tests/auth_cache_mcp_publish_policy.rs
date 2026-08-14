// tests/auth_cache_mcp_publish_policy.rs — hook 11 (MCP face) + the #955
// rooms eviction on that same face.
//
// `patch_publish_policy` (REST admin) fires a tenant-scoped clear (hook 11),
// but the publish-policy flags have a SECOND production writer: the MCP
// `set_publish_policy` tool (src/mcp/tools/owner_field.rs). Same seam as the
// hooks 7/8 MCP tools: the tool fn takes `Option<&AuthCache>` and invalidates
// inside the fn, so the wiring is exercised directly here. Without the clear,
// a model flipping `allow_user_publish` via MCP leaves every cached entry
// serving the OLD policy for up to the safety TTL.
//
// #955 gave the SAME station a second obligation, and this file pins it on
// this face for the same reason it pins hook 11 here: a live rooms WS socket
// captures its `TenantPublishPolicy` once at upgrade, so turning
// `allow_anon_publish` OFF over `/t/<id>/mcp` — the natural way for a tenant
// to stop publish abuse — must close those sockets, exactly as the REST PATCH
// does (`tests/auth_cache_publish_policy.rs`).
mod helpers;

use drust::storage::meta::open_meta;
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use drust::tenant::rooms::RoomBus;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
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
        quota_tier: 1,
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
        quota_tier: 1,
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
        &RoomBus::new(),
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
        &RoomBus::new(),
    )
    .await
    .unwrap();
    assert!(
        cache.get("svc").is_some(),
        "a no-op policy call (no flag supplied) must not evict cached entries"
    );
}

/// #955 — the rooms half of this station, on the MCP face.
///
/// The REST PATCH's twin lives in `tests/auth_cache_publish_policy.rs`; both
/// are non-`#[ignore]`d and need no socket, because the whole behaviour is
/// visible as a per-tenant epoch bump. The evict lives in the TOOL FN rather
/// than in the `#[tool]` wrapper (where the #952 `delete_user` /
/// `revoke_user_sessions` evicts sit) for ONE reason: the change detection it
/// is conditional on can only be done under the meta lock the tool fn holds.
///
/// This test calls the tool fn DIRECTLY, and that is a harness limit, not a
/// statement about `#[tool]` reachability. `#[tool]` wrappers ARE reachable
/// from an integration test — `tests/admin_users.rs` drives
/// `revoke_user_sessions` over `/t/<id>/mcp` `tools/call`, and that tool's #952
/// evict lives in the wrapper arm. What stops the same shape here is that
/// `McpRegistry::with_bus` (every helper stack's MCP ctor) passes `meta: None`,
/// so the wrapper short-circuits before the fn below: measured, `tools/call
/// set_publish_policy` answers `-32603 "meta connection not available in this
/// context"` and leaves the epoch at 0. An earlier version of this comment said
/// no integration test could reach a `#[tool]` method at all; that was false
/// and is corrected here (#955 T3 round 2).
#[tokio::test]
async fn mcp_set_publish_policy_real_change_evicts_rooms_noop_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-pp', 'x')", [])
        .unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-other', 'y')", [])
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let bus = RoomBus::new();
    // Captured BEFORE the first call — the same handle a live WS socket holds
    // from its upgrade until it closes.
    let epoch = bus.tenant_epoch_handle("t-pp");
    let other = bus.tenant_epoch_handle("t-other");
    let e0 = epoch.load(SeqCst);

    let call =
        |u, a| drust::mcp::tools::owner_field::set_publish_policy(&meta, "t-pp", u, a, None, &bus);

    // false → true: a REAL change closes every socket holding the old policy.
    call(None, Some(true)).await.unwrap();
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a real flag change over MCP must evict the tenant's rooms (epoch +1)"
    );

    // Same value again — a model re-asserting the current policy must not
    // thunder-herd the tenant's subscribers.
    call(None, Some(true)).await.unwrap();
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a no-op MCP call must NOT evict (epoch unmoved)"
    );

    // A call supplying neither flag writes nothing at all.
    call(None, None).await.unwrap();
    assert_eq!(epoch.load(SeqCst), e0 + 1, "an empty call must not evict");

    // The OTHER flag moving is a real change too — the comparison is on the
    // effective (user, anon) PAIR, not on the field the args mention.
    call(Some(true), None).await.unwrap();
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 2,
        "moving the user flag is a real change as well"
    );

    assert_eq!(
        other.load(SeqCst),
        0,
        "eviction must stay scoped to the tenant that changed"
    );
}

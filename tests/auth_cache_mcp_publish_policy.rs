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
// `allow_anon_publish` OFF over the account-level `/mcp` — the natural way for a tenant
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
/// This test calls the tool fn DIRECTLY with a bus it owns, so it proves the
/// FN's behaviour and says nothing about which bus the `#[tool]` wrapper hands
/// it — that half is
/// `mcp_tools_call_set_publish_policy_evicts_the_stacks_own_bus` below, which
/// drives the wrapper over `tools/call`.
///
/// Driving the wrapper needs a `DrustMcp` built with `Some(meta)`: the
/// account-level endpoint builds one per call through `McpRegistry::build_live`,
/// which always passes the meta handle, so the wrapper test below runs on
/// `helpers::spin_up_account_mcp`. (The per-tenant helper ctor
/// `McpRegistry::with_bus` passes `meta: None`, under which `tools/call
/// set_publish_policy` short-circuits with "meta connection not available in
/// this context" and leaves the epoch at 0.)
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

// ═══ #955 — the `#[tool]` WRAPPER's bus, driven over the account-level `/mcp` ═
//
// Everything above calls `mcp::tools::owner_field::set_publish_policy`
// directly, handing it a `RoomBus` the test owns. That proves the FN evicts on
// a real change and not on a no-op — and proves NOTHING about the argument the
// `#[tool]` wrapper in `src/mcp/handler.rs` actually passes it. The wrapper
// forwards `&inner.bus_rooms` (the registry's bus, which production and
// `helpers::shared_bus_rooms` make the same instance the WS handler's sockets
// sit on). The #955 T3 round-3 review MEASURED what that gap cost: swapping
// that one expression for a fresh `RoomBus::new()` compiled and left the whole
// tree green, while silently turning the MCP face of #955 off in production —
// a tenant switching `allow_anon_publish` off over MCP would evict a bus no
// socket is on.
//
// The tests below close it by EXECUTION rather than by scanning source: each
// captures the epoch handle from the stack's own bus BEFORE the call, then
// drives `tools/call`. Under the mutant the wrapper bumps a bus that dies with
// the call and the captured handle never moves — re-measured for all three
// wrapper arms, one mutant at a time (`left: 0, right: 1`).

// The account harness hands ONE `RoomBus` to the stack, its auth state and
// the MCP registry whose `build_live` serves every call (`h.bus_rooms`), as
// `src/main.rs` wires it; the epoch handle is captured from that bus, the side
// a WS socket would read, never from anything the registry hands back.

/// #955, EXECUTED — the `#[tool]` wrapper hands the tool fn the STACK's bus.
///
/// The pair above pins `mcp::tools::owner_field::set_publish_policy`'s own
/// decision (evict on a real change, stay put on a no-op). This one pins the
/// wire between the wrapper and that fn: `&inner.bus_rooms` in
/// `src/mcp/handler.rs`. It is the only test in the tree that executes that
/// expression, and the one thing it asserts is that the epoch a WS socket
/// compares against — captured here from the bus the STACK holds, before the
/// call — is the epoch the tool moved.
///
/// What it does NOT cover: the #952 `delete_user` / `revoke_user_sessions`
/// wrapper evicts, which pass the same `inner.bus_rooms` from their own arms
/// and have no executed bus-identity pin of their own; and the `no matching
/// tenant` / error paths, which never reach the evict at all.
#[tokio::test]
async fn mcp_tools_call_set_publish_policy_evicts_the_stacks_own_bus() {
    let h = helpers::spin_up_account_mcp("t-ppwrap").await;

    // Captured BEFORE the call, from the stack's bus — the same handle a live
    // socket holds from its upgrade until it closes.
    let epoch = h.bus_rooms.tenant_epoch_handle(&h.tid);
    let e0 = epoch.load(SeqCst);

    let v = helpers::mcp_tool_json(
        &h.app,
        &h.access,
        &h.tid,
        "set_publish_policy",
        serde_json::json!({"allow_anon_publish": true}),
    )
    .await;
    assert_eq!(
        v["allow_anon_publish"], true,
        "the tool must really have flipped the flag: {v}"
    );
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a real flag change over `tools/call` must evict the bus the STACK is on — the wrapper \
         passes `&inner.bus_rooms`, and a default/private bus there would leave live sockets \
         holding the old publish policy"
    );

    // Same value again: the wrapper still forwards, the fn still declines.
    let v = helpers::mcp_tool_json(
        &h.app,
        &h.access,
        &h.tid,
        "set_publish_policy",
        serde_json::json!({"allow_anon_publish": true}),
    )
    .await;
    assert_eq!(v["allow_anon_publish"], true);
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a no-op `tools/call` must not thunder-herd the tenant's subscribers"
    );
}

/// #952, EXECUTED — the other two `#[tool]` wrapper arms on this same bus.
///
/// `delete_user` and `revoke_user_sessions` call `inner.bus_rooms.evict_tenant`
/// from their own arms (`src/mcp/handler.rs`), and until #955 T3 round 3 no
/// test executed those expressions either: `tests/admin_users.rs` drives both
/// tools over `tools/call` but asserts only their JSON, and the harness's
/// registry bus was a private one until T2 round 4. Same fixture, same
/// one-line-mutant question — is the bus these arms move the bus the stack's
/// sockets are on — so the answer belongs next to its twin above rather than in
/// a scan of the handler's source text.
#[tokio::test]
async fn mcp_tools_call_user_revocations_evict_the_stacks_own_bus() {
    let h = helpers::spin_up_account_mcp("t-ppwrap-users").await;
    helpers::account_allow_self_register(&h).await;

    let epoch = h.bus_rooms.tenant_epoch_handle(&h.tid);
    let e0 = epoch.load(SeqCst);

    // `revoke_user_sessions` is documented safe on an unknown user (revoked: 0)
    // and evicts on every Ok — the blunt tenant-wide evict #952 chose because
    // there is no per-user room index. No seeding needed.
    let v = helpers::mcp_tool_json(
        &h.app,
        &h.access,
        &h.tid,
        "revoke_user_sessions",
        serde_json::json!({"user_id": "u-nobody"}),
    )
    .await;
    assert_eq!(v["revoked"], 0, "unexpected revoke result: {v}");
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "revoke_user_sessions must evict the bus the STACK is on"
    );

    // `delete_user` evicts only on Ok, so it needs a real user.
    let u = helpers::mcp_tool_json(
        &h.app,
        &h.access,
        &h.tid,
        "create_user",
        serde_json::json!({"email": "w@x.com", "password": "longpassword"}),
    )
    .await;
    let uid = u["user_id"]
        .as_str()
        .unwrap_or_else(|| panic!("create_user returned no user_id: {u}"))
        .to_string();
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "creating a user revokes nothing and must not evict"
    );

    let v = helpers::mcp_tool_json(
        &h.app,
        &h.access,
        &h.tid,
        "delete_user",
        serde_json::json!({"user_id": uid}),
    )
    .await;
    assert!(
        v.get("deleted_records").is_some(),
        "unexpected delete_user result: {v}"
    );
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 2,
        "delete_user must evict the bus the STACK is on"
    );
}

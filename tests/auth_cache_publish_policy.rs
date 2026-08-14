// tests/auth_cache_publish_policy.rs — hook 11, plus the in-gate half of the
// #955 evict-on-change behaviour (see the second test).
mod helpers;

use axum::extract::{Path, State};
use axum::response::Response;
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

#[tokio::test]
async fn publish_policy_change_clears_tenant_entries() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert(
        "svc".to_string(),
        CachedAuth::Bearer {
            bound_tenant_id: "t1".to_string(),
            role: CachedRole::Service,
            publish_user_allowed: false, // stale: about to flip to true
            publish_anon_allowed: false,
            email_snapshot: None,
            file_caps: Default::default(),
            expires_at: None,
            quota_tier: 1,
        },
    );

    let (state, _dir) = helpers::tenants_state_with_cache("t1", cache.clone()).await;
    let body = drust::mgmt::tenants::PublishPolicyPatch {
        allow_user_publish: Some(true),
        allow_anon_publish: None,
    };
    let resp = drust::mgmt::tenants::patch_publish_policy(
        State(state),
        Path("t1".to_string()),
        axum::Extension(drust::auth::middleware::AdminId(0)),
        axum::Json(body),
    )
    .await;
    assert!(resp.status().is_success());
    assert_eq!(
        cache.len(),
        0,
        "hook 11 cleared t1's cached entry so flags refill"
    );
}

/// Drive the REAL admin handler against `state`.
async fn patch(
    state: &drust::mgmt::tenants::TenantsState,
    allow_user_publish: Option<bool>,
    allow_anon_publish: Option<bool>,
) -> Response {
    drust::mgmt::tenants::patch_publish_policy(
        State(state.clone()),
        Path("t1".to_string()),
        axum::Extension(drust::auth::middleware::AdminId(0)),
        axum::Json(drust::mgmt::tenants::PublishPolicyPatch {
            allow_user_publish,
            allow_anon_publish,
        }),
    )
    .await
}

/// #955 — the IN-GATE half of "a real publish-policy change evicts live rooms
/// sockets, a no-op PATCH does not".
///
/// The wire-level companion (`rooms_ws.rs::publish_policy_change_evicts_live_
/// socket_noop_does_not`) opens a real WS socket and is therefore `#[ignore]`d
/// under tokio/2374, so it runs in NO gate. Both of its load-bearing
/// assertions are epoch loads either side of the PATCH, and an epoch needs no
/// socket — so they belong here, where every `make test-all` and CI run
/// executes them. Measured red under both mutants: delete the `evict_tenant`
/// call in `crud::patch_publish_policy` and the first assert fails; make it
/// unconditional and the no-op assert fails.
#[tokio::test]
async fn publish_policy_real_change_bumps_rooms_epoch_noop_does_not() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    let (state, _dir) = helpers::tenants_state_with_cache("t1", cache).await;
    // Captured BEFORE any PATCH — this is the same handle a live WS
    // connection holds from its upgrade until it closes.
    let epoch = state.bus_rooms.tenant_epoch_handle("t1");
    let e0 = epoch.load(SeqCst);

    // false → true is a REAL change: every socket holding the old
    // TenantPublishPolicy must be closed.
    assert!(patch(&state, Some(true), None).await.status().is_success());
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a real flag change must evict the tenant's rooms (epoch +1)"
    );

    // Same value again — an admin page re-submitting unchanged checkboxes
    // must not thunder-herd the tenant's subscribers.
    assert!(patch(&state, Some(true), None).await.status().is_success());
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 1,
        "a no-op PATCH must NOT evict (epoch unmoved)"
    );

    // The OTHER flag still moving is a real change too — the comparison is on
    // the effective (user, anon) PAIR, not on the field the body mentions.
    assert!(patch(&state, None, Some(true)).await.status().is_success());
    assert_eq!(
        epoch.load(SeqCst),
        e0 + 2,
        "moving the anon flag is a real change as well"
    );
}

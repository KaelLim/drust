// tests/auth_cache_revoke_reroll.rs — Spec test 2 (hook 1).
mod helpers;

use axum::extract::{Path, State};
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn reroll_clears_cached_service_bearer() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    // Seed a cached service Bearer for tenant t1.
    cache.insert(
        "svc-hash".to_string(),
        CachedAuth::Bearer {
            bound_tenant_id: "t1".to_string(),
            role: CachedRole::Service,
            publish_user_allowed: false,
            publish_anon_allowed: false,
            email_snapshot: None,
            file_caps: Default::default(),
            expires_at: None,
            quota_tier: 1,
        },
    );
    assert_eq!(cache.len(), 1);

    let (state, _dir) = helpers::tenants_state_with_cache("t1", cache.clone()).await;

    // Fire the real reroll handler for (t1, service) — hook 1 must scan-clear.
    let resp = drust::mgmt::tokens::reroll_token_json(
        State(state),
        Path(("t1".to_string(), "service".to_string())),
    )
    .await;
    assert!(resp.status().is_success(), "reroll succeeded");

    // The cached service Bearer for t1 is gone.
    assert_eq!(
        cache.len(),
        0,
        "hook 1 scan-cleared the (t1, service) Bearer"
    );
}

/// task #934 MED #1 (invariant 5): rerolling a tenant token must evict
/// in-flight realtime subscribers — the revoked key must not keep streaming
/// until process restart. Subscribe to the bus (standing in for an in-flight
/// SSE subscriber), reroll, and assert the channel is closed.
#[tokio::test]
async fn reroll_evicts_in_flight_realtime_subscribers() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    let (state, _dir) = helpers::tenants_state_with_cache("t1", cache).await;

    // Stand in for an in-flight SSE subscriber connected before the reroll.
    let mut rx = state.bus.subscribe("t1", "posts");
    // Keepalive clone of the Arc-backed bus so consuming `state` into the
    // handler does NOT by itself drop the channel's Sender — only an explicit
    // evict must close `rx`. Without this the test would pass on state-drop
    // alone and never exercise the eviction it is meant to prove.
    let _bus = state.bus.clone();

    let resp = drust::mgmt::tokens::reroll_token_json(
        State(state),
        Path(("t1".to_string(), "service".to_string())),
    )
    .await;
    assert!(resp.status().is_success(), "reroll succeeded");

    // The bus channel must have been evicted → recv returns Closed (Err).
    // A never-published broadcast Receiver would BLOCK on recv() until evicted,
    // so make both states observable: pre-fix hangs → Err(Elapsed);
    // post-fix Closes promptly → Ok(Err(RecvError::Closed)).
    let recvd = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        matches!(recvd, Ok(Err(_))),
        "reroll must evict in-flight subscribers promptly (invariant 5); got {recvd:?}"
    );
}

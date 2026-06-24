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

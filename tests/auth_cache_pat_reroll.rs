// tests/auth_cache_pat_reroll.rs — hook 2.
mod helpers;

use axum::Extension;
use axum::extract::State;
use drust::auth::middleware::AdminId;
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn pat_reroll_clears_cached_admin_pat_bearers() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert(
        "pat-hash".to_string(),
        CachedAuth::Bearer {
            bound_tenant_id: "t1".to_string(),
            role: CachedRole::AdminPat { admin_id: 42 },
            publish_user_allowed: false,
            publish_anon_allowed: false,
            email_snapshot: Some("admin42@x".to_string()),
        },
    );
    // A different admin's PAT must survive.
    cache.insert(
        "other-pat".to_string(),
        CachedAuth::Bearer {
            bound_tenant_id: "t1".to_string(),
            role: CachedRole::AdminPat { admin_id: 99 },
            publish_user_allowed: false,
            publish_anon_allowed: false,
            email_snapshot: Some("admin99@x".to_string()),
        },
    );

    let (state, _dir) = helpers::mgmt_state_with_cache_and_admin(42, cache.clone()).await;
    let resp = drust::mgmt::admin_pat::reroll(State(state), Extension(AdminId(42))).await;
    assert!(resp.status().is_success(), "PAT reroll succeeded");

    // admin 42's cached PAT is gone; admin 99's survives.
    assert_eq!(cache.len(), 1, "only admin 42's PAT cleared");
    assert!(cache.get("other-pat").is_some());
}

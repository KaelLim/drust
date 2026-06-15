// tests/auth_cache_publish_policy.rs — hook 11.
mod helpers;

use axum::extract::{Path, State};
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use std::sync::Arc;
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

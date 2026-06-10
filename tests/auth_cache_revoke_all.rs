// tests/auth_cache_revoke_all.rs — Spec test 6 (hook 7, REST half).
mod helpers;

use axum::extract::{Path, State};
use drust::auth::middleware::ServiceTid;
use drust::tenant::auth_cache::{AuthCache, CachedAuth};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn revoke_all_sessions_clears_user_entries() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    for h in ["s1", "s2"] {
        cache.insert(
            h.to_string(),
            CachedAuth::User {
                tenant_id: "t1".to_string(),
                user_id: "u1".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(1),
                publish_user_allowed: false,
                publish_anon_allowed: false,
            },
        );
    }
    // A different user survives.
    cache.insert(
        "other".to_string(),
        CachedAuth::User {
            tenant_id: "t1".to_string(),
            user_id: "u2".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            publish_user_allowed: false,
            publish_anon_allowed: false,
        },
    );

    let (auth_state, _dir) = helpers::auth_state_with_cache("t1", cache.clone()).await;
    let mut params = HashMap::new();
    params.insert("tenant".to_string(), "t1".to_string());
    params.insert("uid".to_string(), "u1".to_string());

    let resp = drust::tenant::admin_user_routes::revoke_sessions_handler(
        State(auth_state),
        ServiceTid("t1".to_string()),
        Path(params),
    )
    .await;
    assert!(resp.status().is_success());

    assert_eq!(cache.len(), 1, "u1's two entries cleared, u2 survives");
    assert!(cache.get("other").is_some());
}

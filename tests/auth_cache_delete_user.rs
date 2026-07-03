// tests/auth_cache_delete_user.rs — Spec test 7a (hook 8, REST).
mod helpers;

use axum::Extension;
use axum::extract::{Path, State};
use drust::auth::middleware::{AuthCtx, ServiceTid};
use drust::tenant::auth_cache::CachedAuth;
use std::collections::HashMap;

#[tokio::test]
async fn delete_user_clears_cached_entry() {
    let (auth_state, _dir, uid) = helpers::auth_state_with_seeded_user("t1").await;
    let cache = auth_state.auth_cache.clone();
    cache.insert(
        "h".to_string(),
        CachedAuth::User {
            tenant_id: "t1".to_string(),
            user_id: uid.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            publish_user_allowed: false,
            publish_anon_allowed: false,
            file_caps: Default::default(),
        },
    );

    let mut params = HashMap::new();
    params.insert("tenant".to_string(), "t1".to_string());
    params.insert("uid".to_string(), uid.clone());
    let resp = drust::tenant::admin_user_routes::delete_user_handler(
        State(auth_state),
        ServiceTid("t1".to_string()),
        Extension(AuthCtx::Service { admin_id: None }),
        Path(params),
    )
    .await;
    assert!(resp.status().is_success());
    assert_eq!(
        cache.len(),
        0,
        "hook 8 cleared the deleted user's cached entry"
    );
}

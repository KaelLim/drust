// tests/auth_cache_tenant_lifecycle.rs — Spec test 5 (hooks 3 + 4).
mod helpers;

use axum::extract::{Path, State};
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn soft_delete_clears_tenant_scoped_entries() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert(
        "svc".to_string(),
        CachedAuth::Bearer {
            bound_tenant_id: "t1".to_string(),
            role: CachedRole::Service,
            publish_user_allowed: false,
            publish_anon_allowed: false,
            email_snapshot: None,
            file_caps: Default::default(),
            expires_at: None,
        },
    );
    cache.insert(
        "usr".to_string(),
        CachedAuth::User {
            tenant_id: "t1".to_string(),
            user_id: "u1".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            publish_user_allowed: false,
            publish_anon_allowed: false,
            file_caps: Default::default(),
        },
    );
    // An unrelated tenant's entry must survive.
    cache.insert(
        "other".to_string(),
        CachedAuth::Bearer {
            bound_tenant_id: "t2".to_string(),
            role: CachedRole::Service,
            publish_user_allowed: false,
            publish_anon_allowed: false,
            email_snapshot: None,
            file_caps: Default::default(),
            expires_at: None,
        },
    );

    let (state, _dir) = helpers::tenants_state_with_cache("t1", cache.clone()).await;
    let resp = drust::mgmt::tenants::soft_delete_tenant(State(state), Path("t1".to_string())).await;
    assert!(resp.status().is_success() || resp.status().is_redirection());

    assert_eq!(cache.len(), 1, "t1 entries cleared, t2 survives");
    assert!(cache.get("other").is_some());
}

#[tokio::test]
async fn create_recycling_id_clears_stale_entries() {
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert(
        "stale".to_string(),
        CachedAuth::Bearer {
            bound_tenant_id: "recy".to_string(),
            role: CachedRole::Service,
            publish_user_allowed: false,
            publish_anon_allowed: false,
            email_snapshot: None,
            file_caps: Default::default(),
            expires_at: None,
        },
    );
    let (state, _dir) = helpers::tenants_state_with_cache("recy", cache.clone()).await;
    // Soft-delete then recreate the same id.
    let _ =
        drust::mgmt::tenants::soft_delete_tenant(State(state.clone()), Path("recy".to_string()))
            .await;
    // Re-seed a stale entry as if a request raced in after soft-delete.
    cache.insert(
        "stale2".to_string(),
        CachedAuth::Bearer {
            bound_tenant_id: "recy".to_string(),
            role: CachedRole::Service,
            publish_user_allowed: false,
            publish_anon_allowed: false,
            email_snapshot: None,
            file_caps: Default::default(),
            expires_at: None,
        },
    );
    // CreateTenantJson derives only Deserialize (NOT Default), so every field
    // is written explicitly. `id: Some("recy".into())` makes the recycled id
    // deterministic — create_tenant_json uses the supplied id verbatim
    // (`form.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4())`), so the new
    // incarnation reuses "recy" and the stale "recy" cache entries are purged.
    let body = drust::mgmt::tenants::CreateTenantJson {
        id: Some("recy".to_string()),
        name: "recy".to_string(),
        quota_db_mb: None,
        quota_rows: None,
    };
    let resp = drust::mgmt::tenants::create_tenant_json(State(state), axum::Json(body)).await;
    assert!(resp.status().is_success(), "recycle-create succeeded");
    assert!(
        cache.get("stale2").is_none(),
        "hook 4 cleared the recycled id's stale entry"
    );
}

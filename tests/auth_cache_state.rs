// tests/auth_cache_state.rs — proves the cache field exists on TenantAuthState
// and that test_default seeds a fresh empty one with the prod safety_ttl.
mod helpers;

use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::router::TenantAuthState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_default_seeds_fresh_auth_cache() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(TenantRegistry::new(data, 2));
    let state = TenantAuthState::test_default(meta, tenants);
    assert_eq!(state.auth_cache.len(), 0);
    assert_eq!(state.auth_cache.safety_ttl(), Duration::from_secs(10));
}

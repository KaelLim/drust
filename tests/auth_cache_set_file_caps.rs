// tests/auth_cache_set_file_caps.rs — hook 12 (MCP face).
//
// The MCP `set_file_caps` tool (src/mcp/tools/owner_field.rs) writes
// tenants.{file_anon_caps_json, file_user_caps_json} and must drop the tenant's
// cached auth entries — file caps gate request handling on the hot path (like
// publish policy / hook 11). Without the clear, a model granting anon `upload`
// via MCP would leave every cached entry serving the OLD (empty) caps for up to
// the safety TTL.

use drust::storage::meta::open_meta;
use drust::storage::schema::FileVerb;
use drust::tenant::auth_cache::{AuthCache, CachedAuth, CachedRole};
use std::sync::Arc;
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
    }
}

#[tokio::test]
async fn mcp_set_file_caps_writes_and_clears_tenant_entries() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    // migrations add tenants.file_anon_caps_json / file_user_caps_json
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-fc', 'x')", [])
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert("svc".to_string(), bearer_entry("t-fc"));
    // A different tenant's entry must survive the tenant-scoped clear.
    cache.insert("other".to_string(), bearer_entry("t-other"));

    let v = drust::mcp::tools::owner_field::set_file_caps(
        &meta,
        "t-fc",
        Some(vec![FileVerb::Read, FileVerb::List]),
        None,
        Some(&*cache),
    )
    .await
    .unwrap();
    assert_eq!(v["file_anon_caps"], serde_json::json!(["read", "list"]));
    assert_eq!(v["file_user_caps"], serde_json::json!([]));

    // Persisted (canonical, sorted) on the tenants row.
    {
        let c = meta.lock().await;
        let stored: String = c
            .query_row(
                "SELECT file_anon_caps_json FROM tenants WHERE id='t-fc'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, r#"["read","list"]"#);
    }

    // Hook 12: t-fc cleared, the other tenant spared.
    assert!(
        cache.get("svc").is_none(),
        "set_file_caps must clear t-fc's cached entries (hook 12)"
    );
    assert!(
        cache.get("other").is_some(),
        "tenant-scoped clear must spare other tenants' entries"
    );
}

#[tokio::test]
async fn mcp_set_file_caps_noop_clears_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('t-fc', 'x')", [])
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert("svc".to_string(), bearer_entry("t-fc"));

    let _ =
        drust::mcp::tools::owner_field::set_file_caps(&meta, "t-fc", None, None, Some(&*cache))
            .await
            .unwrap();
    assert!(
        cache.get("svc").is_some(),
        "a no-op caps call (both args None) must not evict cached entries"
    );
}

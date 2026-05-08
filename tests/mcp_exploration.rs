mod helpers;
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::exploration::{
    count_rows, describe_collection, list_collections, sample_rows, whoami,
};
use drust::storage::pool::TenantRegistry;
use helpers::seed_tenant_fs;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    let svc = reg.get_or_create("blog").await.unwrap();
    let pool = svc.inner().pool.clone();
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            INSERT INTO posts (title) VALUES ('a'), ('b'), ('c');",
        )
    })
    .await
    .unwrap();
    svc
}

#[tokio::test]
async fn list() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = list_collections(&s).await.unwrap();
    assert_eq!(v["collections"][0]["name"], "posts");
}

#[tokio::test]
async fn describe() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = describe_collection(&s, "posts").await.unwrap();
    assert_eq!(v["name"], "posts");
    assert!(
        v["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "title")
    );
}

#[tokio::test]
async fn sample_5() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = sample_rows(&s, "posts", 5).await.unwrap();
    assert_eq!(v["rows"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn count_all() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = count_rows(&s, "posts", None).await.unwrap();
    assert_eq!(v["count"], 3);
    let v2 = count_rows(&s, "posts", Some("title='b'")).await.unwrap();
    assert_eq!(v2["count"], 1);
}

#[tokio::test]
async fn whoami_returns_tenant_tokens_and_endpoints() {
    use drust::storage::meta::open_meta;
    use drust::tenant::events::EventBus;
    use tokio::sync::Mutex;

    let d = tempfile::tempdir().unwrap();
    let data = d.path().to_path_buf();

    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params!["blog", "Blog Tenant"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role, plaintext) \
         VALUES (?1, ?2, 'service', ?3)",
        rusqlite::params!["blog", "hash-svc", "drust_svc_plain"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role, plaintext) \
         VALUES (?1, ?2, 'anon', ?3)",
        rusqlite::params!["blog", "hash-anon", "drust_anon_plain"],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let meta = Arc::new(Mutex::new(conn));

    let tr = Arc::new(TenantRegistry::new(data, 2));
    let reg = McpRegistry::with_bus_and_storage(
        tr,
        EventBus::new(),
        None,
        String::new(),
        Arc::new([0u8; 32]),
        Some(meta),
        12_345,
    );
    let svc = reg.get_or_create("blog").await.unwrap();

    let v = whoami(&svc).await.unwrap();
    assert_eq!(v["tenant_id"], "blog");
    assert_eq!(v["tenant_name"], "Blog Tenant");
    assert_eq!(v["tokens"]["service"]["plaintext"], "drust_svc_plain");
    assert_eq!(v["tokens"]["anon"]["plaintext"], "drust_anon_plain");
    assert_eq!(v["endpoints"]["mcp"], "/drust/t/blog/mcp");
    assert_eq!(v["endpoints"]["files_upload"], "/drust/t/blog/files");
    assert_eq!(v["endpoints"]["rest_base"], "/drust/t/blog/");
    assert_eq!(v["endpoints"]["rpc"], "/drust/t/blog/rpc/<name>");
    assert_eq!(v["limits"]["max_upload_bytes"], 12_345);
}

#[tokio::test]
async fn whoami_bails_when_meta_unavailable() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await; // built via McpRegistry::new (meta is None)
    let err = whoami(&s).await.unwrap_err();
    assert!(
        err.to_string().contains("META_UNAVAILABLE"),
        "expected META_UNAVAILABLE error, got: {err}"
    );
}

mod helpers;
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::exploration::{
    WhoamiView, describe_collection, get_schema_overview, list_collections, whoami,
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

/// A tenant `blog` with a meta connection holding one service and one anon
/// token, so `whoami` has both to report. Returns the meta handle too, so a
/// test can change the token rows.
async fn whoami_fixture(
    d: &tempfile::TempDir,
) -> (
    drust::mcp::server::DrustMcp,
    Arc<tokio::sync::Mutex<rusqlite::Connection>>,
) {
    use drust::storage::meta::open_meta;
    use drust::tenant::events::EventBus;
    use tokio::sync::Mutex;

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
        tr.clone(),
        EventBus::new(),
        drust::tenant::WebhookDispatcher::new(tr.clone(), None),
        None,
        String::new(),
        Arc::new([0u8; 32]),
        Some(meta.clone()),
        12_345,
        1_000_000,
        Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        drust::tenant::rooms::RoomBus::new(),
        drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        drust::tenant::rooms::RoomsConfig::test_defaults(),
        Arc::new(drust::tenant::auth_cache::AuthCache::new(
            std::time::Duration::from_secs(10),
            200_000,
        )),
        drust::functions::dispatcher::FunctionDispatcher::new(
            tr.clone(),
            tokio::sync::mpsc::channel(8).0,
            drust::functions::FnConfig::test_default(),
        ),
    );
    let svc = reg.get_or_create("blog").await.unwrap();
    (svc, meta)
}

#[tokio::test]
async fn whoami_returns_tenant_tokens_and_endpoints() {
    let d = tempfile::tempdir().unwrap();
    let (svc, _meta) = whoami_fixture(&d).await;

    // v1.64 (#974): one granted prefix, so the `file_upload` block has something
    // live to report.
    let row = drust::storage::file_policy::FilePolicyRow {
        prefix: "avatars/".to_string(),
        owner_scoped: true,
        public_read: false,
        select_policy: None,
        delete_policy: None,
        public_upload_roles: Some(vec!["user".to_string()]),
    };
    svc.inner()
        .pool
        .with_writer(move |c| drust::storage::file_policy::upsert_file_policy(c, &row))
        .await
        .unwrap();

    let v = whoami(&svc, account_view()).await.unwrap();
    assert_eq!(v["tenant_id"], "blog");
    assert_eq!(v["tenant_name"], "Blog Tenant");
    assert_eq!(v["tokens"]["service"]["redacted"], true);
    assert_eq!(v["tokens"]["anon"]["plaintext"], "drust_anon_plain");
    assert_eq!(v["endpoints"]["mcp"], MCP_URL);
    assert!(v["endpoints"]["files_upload"].is_null());
    assert_eq!(
        v["endpoints"]["files_upload_resumable"],
        "/drust/t/blog/uploads"
    );
    assert_eq!(v["endpoints"]["rest_base"], "/drust/t/blog/");
    assert_eq!(v["endpoints"]["rpc"], "/drust/t/blog/rpc/<name>");
    assert_eq!(v["limits"]["max_upload_bytes"], 12_345);

    // v1.64 (#974) — a SIGNPOST, not a manual. The user rejected a whoami that
    // grows a paragraph per feature: this block may only name the guide resource
    // and this tenant's live grants, and the rules stay in the guide.
    let fu = &v["file_upload"];
    assert_eq!(
        fu["guide_resource"], "drust://blog/files-guide.md",
        "whoami must point at the files handbook: {fu}"
    );
    assert_eq!(
        fu["granted_prefixes"],
        serde_json::json!([{ "prefix": "avatars/", "roles": ["user"] }]),
        "the live grant list is the other half of the signpost: {fu}"
    );
    let keys: Vec<&String> = fu.as_object().unwrap().keys().collect();
    assert_eq!(
        keys.len(),
        2,
        "the block stays two keys — rules belong in the guide, not here: {keys:?}"
    );
    // Prose-heaviness is what was rejected, so pin it as a size: the whole block
    // must stay far smaller than one paragraph of rules.
    let rendered = fu.to_string();
    assert!(
        rendered.len() < 300,
        "file_upload must stay lean ({} bytes): {rendered}",
        rendered.len()
    );

    // An unreadable registry reports `null`, never `[]`: "nobody may publish"
    // and "I could not find out" are different facts, and the second one also
    // means every non-service file READ is currently being denied.
    svc.inner()
        .pool
        .with_writer(|c| c.execute_batch("DROP TABLE \"_system_file_policy\""))
        .await
        .unwrap();
    let v = whoami(&svc, account_view()).await.unwrap();
    assert!(
        v["file_upload"]["granted_prefixes"].is_null(),
        "an unreadable registry must not render as the empty (healthy) list: {v}"
    );
    assert_eq!(
        v["file_upload"]["guide_resource"], "drust://blog/files-guide.md",
        "…and the signpost still points somewhere useful"
    );
    assert_eq!(
        v["tokens"]["service"]["redacted"], true,
        "whoami's own job must survive a broken file registry"
    );
}

#[tokio::test]
async fn whoami_bails_when_meta_unavailable() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await; // built via McpRegistry::new (meta is None)
    let err = whoami(&s, account_view()).await.unwrap_err();
    assert!(
        err.to_string().contains("META_UNAVAILABLE"),
        "expected META_UNAVAILABLE error, got: {err}"
    );
}

const MCP_URL: &str = "https://mcp.example.test/drust/mcp";
const KEYS_URL: &str = "https://mcp.example.test/drust/admin/tenants/blog/_api_keys";

fn account_view() -> WhoamiView {
    WhoamiView::Account {
        mcp_url: MCP_URL.into(),
        api_keys_url: KEYS_URL.into(),
        grant_id: 7,
    }
}

#[tokio::test]
async fn whoami_key_order_is_fixed() {
    let d = tempfile::tempdir().unwrap();
    let (svc, _meta) = whoami_fixture(&d).await;
    let v = whoami(&svc, account_view()).await.unwrap();
    let keys = |v: &serde_json::Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(
        keys(&v),
        [
            "tenant_id",
            "tenant_name",
            "tenant_created_at",
            "tokens",
            "endpoints",
            "limits",
            "file_upload",
            "broadcast",
            "caller"
        ]
    );
    assert_eq!(
        keys(&v["tokens"]["service"]),
        ["redacted", "id", "created_at", "how_to_get"]
    );
    assert_eq!(
        keys(&v["endpoints"]),
        [
            "rest_base",
            "mcp",
            "files_upload_resumable",
            "rpc",
            "realtime_ws",
            "rooms_publish_rest"
        ]
    );
}

/// The newest live service row of `blog`, read straight from meta.
async fn service_row(meta: &tokio::sync::Mutex<rusqlite::Connection>) -> (i64, String) {
    meta.lock()
        .await
        .query_row(
            "SELECT id, created_at FROM tokens WHERE tenant_id='blog' AND role='service' \
             AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

#[tokio::test]
async fn whoami_account_masks_the_service_key() {
    let d = tempfile::tempdir().unwrap();
    let (svc, meta) = whoami_fixture(&d).await;
    let (id, created_at) = service_row(&meta).await;
    let v = whoami(&svc, account_view()).await.unwrap();
    // The exact-equality assertions below are the masking guarantee: they fail
    // on any extra field and on any partial character of the key. The
    // `contains` checks only give a readable failure message; never replace
    // the equality checks with them.
    let s = &v["tokens"]["service"];
    assert_eq!(
        s,
        &serde_json::json!({
            "redacted": true,
            "id": id,
            "created_at": created_at,
            "how_to_get": KEYS_URL,
        })
    );
    assert!(
        !v.to_string().contains("drust_svc_plain"),
        "service plaintext leaked"
    );
    assert!(
        !s.to_string().contains("drust_"),
        "no character of the service key may appear: {s}"
    );
    assert_eq!(v["tokens"]["anon"]["plaintext"], "drust_anon_plain");
    assert_eq!(
        v["caller"],
        serde_json::json!({"kind": "oauth", "grant_id": 7})
    );
    assert_eq!(v["endpoints"]["mcp"], MCP_URL);
    assert_eq!(
        v.as_object()
            .unwrap()
            .keys()
            .next_back()
            .map(String::as_str),
        Some("caller")
    );

    assert_eq!(v["tenant_id"], "blog");
    assert_eq!(v["tenant_name"], "Blog Tenant");
    assert_eq!(v["limits"]["max_upload_bytes"], 12_345);
    assert_eq!(
        v["file_upload"]["guide_resource"],
        "drust://blog/files-guide.md"
    );
}

#[tokio::test]
async fn whoami_account_without_a_live_service_key_reports_null() {
    let d = tempfile::tempdir().unwrap();
    let (svc, meta) = whoami_fixture(&d).await;
    meta.lock()
        .await
        .execute(
            "UPDATE tokens SET revoked_at = datetime('now') WHERE role = 'service'",
            [],
        )
        .unwrap();
    let v = whoami(&svc, account_view()).await.unwrap();
    assert!(
        v["tokens"]["service"].is_null(),
        "{}",
        v["tokens"]["service"]
    );
    assert_eq!(v["caller"]["grant_id"], 7);
}

#[tokio::test]
async fn whoami_account_legacy_null_plaintext_keeps_the_same_shape() {
    let d = tempfile::tempdir().unwrap();
    let (svc, meta) = whoami_fixture(&d).await;
    meta.lock()
        .await
        .execute(
            "UPDATE tokens SET plaintext = NULL WHERE role = 'service'",
            [],
        )
        .unwrap();
    let v = whoami(&svc, account_view()).await.unwrap();
    let keys: Vec<&String> = v["tokens"]["service"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["redacted", "id", "created_at", "how_to_get"]);
}

#[tokio::test]
async fn whoami_account_reports_the_newest_service_row() {
    let d = tempfile::tempdir().unwrap();
    let (svc, meta) = whoami_fixture(&d).await;
    meta.lock()
        .await
        .execute(
            "INSERT INTO tokens (tenant_id, token_hash, role, plaintext, created_at) \
             VALUES ('blog', 'hash-svc-2', 'service', 'drust_svc_plain_second', '2099-01-01 00:00:00')",
            [],
        )
        .unwrap();
    let (id, _) = service_row(&meta).await;
    let v = whoami(&svc, account_view()).await.unwrap();
    assert_eq!(v["tokens"]["service"]["id"], id);
    let text = v.to_string();
    assert!(
        !text.contains("drust_svc_plain"),
        "neither service plaintext may appear"
    );
}

#[tokio::test]
async fn overview_rpc_surfaces_params_anon_callable_and_user_id_autobound() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let pool = s.inner().pool.clone();
    // RPC 1: declares a `user_id` param → must auto-bind.
    // RPC 2: declares only `limit`, no user_id → must NOT auto-bind.
    pool.with_writer(|c| {
        c.execute_batch(
            "INSERT INTO _system_rpc \
             (name, sql, params_json, description, anon_callable, \
              anon_calls, service_calls, last_called_at, created_at, updated_at) \
             VALUES \
             ('my_posts', 'SELECT * FROM posts WHERE author = :user_id', \
              '[{\"name\":\"user_id\",\"type\":\"text\"}]', 'mine', 1, \
              0, 0, NULL, datetime('now'), datetime('now')), \
             ('recent', 'SELECT * FROM posts LIMIT :limit', \
              '[{\"name\":\"limit\",\"type\":\"integer\"}]', 'recent', 0, \
              0, 0, NULL, datetime('now'), datetime('now'))",
        )
    })
    .await
    .unwrap();

    let v = get_schema_overview(&s).await.unwrap();
    let rpcs = v["rpcs"].as_array().expect("rpcs array");
    let my_posts = rpcs
        .iter()
        .find(|r| r["name"] == "my_posts")
        .expect("my_posts rpc present");
    let recent = rpcs
        .iter()
        .find(|r| r["name"] == "recent")
        .expect("recent rpc present");

    assert_eq!(my_posts["params"][0]["name"], "user_id");
    assert_eq!(recent["params"][0]["name"], "limit");
    assert_eq!(my_posts["anon_callable"], true);
    assert_eq!(recent["anon_callable"], false);
    // NEW: derived user_id_autobound — true only when a `user_id` param is declared.
    assert_eq!(
        my_posts["user_id_autobound"], true,
        "rpc declaring a user_id param must be flagged auto-bound"
    );
    assert_eq!(
        recent["user_id_autobound"], false,
        "rpc with no user_id param must not be flagged auto-bound"
    );
}

#[tokio::test]
async fn overview_collections_always_surface_access_state() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await; // svc() seeds `posts` (no owner field)
    let pool = s.inner().pool.clone();
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE docs (\
                id INTEGER PRIMARY KEY AUTOINCREMENT,\
                author TEXT NOT NULL,\
                title TEXT\
             );\
             INSERT INTO _system_collection_meta \
               (collection_name, anon_caps_json, owner_field, read_scope, updated_at) \
             VALUES ('docs', '[\"select\"]', 'author', 'own', datetime('now'));",
        )
    })
    .await
    .unwrap();

    let v = get_schema_overview(&s).await.unwrap();
    let cols = v["collections"].as_array().expect("collections array");
    let posts = cols
        .iter()
        .find(|c| c["name"] == "posts")
        .expect("posts present");
    let docs = cols
        .iter()
        .find(|c| c["name"] == "docs")
        .expect("docs present");

    assert!(posts["anon_caps"].is_array(), "anon_caps always present");
    assert!(
        posts["realtime_enabled"].is_boolean(),
        "realtime_enabled always present"
    );
    // NEW: non-owner-scoped collection emits explicit null (not an absent key).
    assert!(
        posts
            .get("owner_field")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "posts.owner_field must be present and null, got {:?}",
        posts.get("owner_field")
    );
    assert!(
        posts
            .get("read_scope")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "posts.read_scope must be present and null, got {:?}",
        posts.get("read_scope")
    );
    assert!(
        posts["vector_fields"].is_array(),
        "vector_fields always present as array, got {:?}",
        posts.get("vector_fields")
    );
    assert_eq!(docs["owner_field"], "author");
    assert_eq!(docs["read_scope"], "own");
}

/// Recursively collect every object key in a JSON Value (lowercased).
fn all_keys(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                out.push(k.to_ascii_lowercase());
                all_keys(val, out);
            }
        }
        serde_json::Value::Array(a) => {
            for val in a {
                all_keys(val, out);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn overview_flags_vector_fields_with_dim() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let pool = s.inner().pool.clone();
    pool.with_writer(|c| {
        c.execute_batch(
            "ALTER TABLE posts ADD COLUMN embedding BLOB;\
             INSERT INTO _system_collection_meta \
               (collection_name, anon_caps_json, vector_fields_json, updated_at) \
             VALUES ('posts', '[\"select\"]', \
                     '[{\"name\":\"embedding\",\"dim\":8,\"metric\":\"cosine\"}]', \
                     datetime('now')) \
             ON CONFLICT(collection_name) DO UPDATE SET \
               vector_fields_json = excluded.vector_fields_json;",
        )
    })
    .await
    .unwrap();

    let v = get_schema_overview(&s).await.unwrap();
    let posts = v["collections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "posts")
        .expect("posts present");
    let vf = posts["vector_fields"]
        .as_array()
        .expect("vector_fields array");
    let emb = vf
        .iter()
        .find(|f| f["name"] == "embedding")
        .expect("embedding vector field present");
    assert_eq!(emb["dim"], 8, "vector field must be flagged with its dim");
}

#[tokio::test]
async fn overview_never_leaks_tokens_or_secrets() {
    let d = tempfile::tempdir().unwrap();
    seed_tenant_fs(&d, "blog");
    let s = svc(&d).await;
    let v = get_schema_overview(&s).await.unwrap();
    let mut keys = Vec::new();
    all_keys(&v, &mut keys);
    for forbidden in [
        "plaintext",
        "token",
        "token_hash",
        "secret",
        "password",
        "password_hash",
    ] {
        assert!(
            !keys.iter().any(|k| k.contains(forbidden)),
            "get_schema_overview must not expose `{forbidden}`-shaped keys; got keys: {keys:?}"
        );
    }
    assert!(keys.iter().any(|k| k == "collections"));
    assert!(keys.iter().any(|k| k == "rpcs"));
}

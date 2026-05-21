use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::session::create_session;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn app() -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let mut conn = open_meta(&data.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    let tok = create_session(&mut conn, 1, 3600).unwrap();
    conn.execute("INSERT INTO tenants (id, name) VALUES ('blog', 'b')", [])
        .unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        session_ttl_days: 7,
        garage: None,
        public_base_url: "http://localhost:8793".to_string(),
        max_upload_bytes: 52_428_800,
        garage_client_key_id: String::new(),
        disk_min_free_pct: 20,
        log_dir: dir.path().join("audit"),
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: String::new(),
        oauth_registry: Arc::new(drust::oauth::ProviderRegistry::from_env_empty()),
        oauth_allowlist: Arc::new(std::collections::HashSet::new()),
        admin_login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, std::time::Duration::from_secs(60), 4096)),
        admin_oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, std::time::Duration::from_secs(60), 4096)),
    };
    (state.with_data_dir(data.clone()), tok, dir)
}

#[tokio::test]
async fn reroll_anon_on_empty_slot_creates_first() {
    let (app, tok, _d) = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants/blog/tokens/anon/reroll")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["role"], "anon");
    assert!(v["token"].as_str().unwrap().starts_with("drust_"));
    assert_eq!(v["revoked_legacy_count"], 0);
}

#[tokio::test]
async fn reroll_service_revokes_old_and_returns_new() {
    let (app, tok, _d) = app().await;
    let r1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants/blog/tokens/service/reroll")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b1 = axum::body::to_bytes(r1.into_body(), 65_536).await.unwrap();
    let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
    let first_token = v1["token"].as_str().unwrap().to_string();
    let first_id = v1["id"].as_i64().unwrap();

    let r2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants/blog/tokens/service/reroll")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b2 = axum::body::to_bytes(r2.into_body(), 65_536).await.unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    assert_eq!(v2["role"], "service");
    assert_ne!(v2["token"].as_str().unwrap(), first_token);
    assert_ne!(v2["id"].as_i64().unwrap(), first_id);
    assert_eq!(v2["revoked_legacy_count"], 1);
}

#[tokio::test]
async fn reroll_invalid_role() {
    let (app, tok, _d) = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants/blog/tokens/admin/reroll")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reroll_unknown_tenant() {
    let (app, tok, _d) = app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants/ghost/tokens/anon/reroll")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

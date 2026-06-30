//! Integration test: PAT (drust_pat_*) bearer path in bearer_auth_layer.
//! Verifies end-to-end: PAT → service context with admin_id → audit attribution.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token;
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::{
    TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus, router::TenantAuthState,
};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Spin up an app with a single tenant; admin row and PAT inserted directly.
/// Returns (app, plaintext_pat, admin_id, dir).
async fn app_with_pat(tenant: &str) -> (axum::Router, String, i64, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();

    // Insert admin
    conn.execute(
        "INSERT INTO admins (username, password_hash, email) VALUES ('tester', '$argon2id$v=19$m=19456,t=2,p=1$x$x', 'pat-tester@example.com')",
        [],
    ).unwrap();
    let admin_id: i64 = conn.last_insert_rowid();

    // Insert tenant
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'acme')",
        params![tenant],
    )
    .unwrap();

    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    // Soft-revoke any PAT the v1.29.3 migration backfill created for this
    // admin so we can insert a known plaintext (uniq_admin_tokens_active
    // forbids two active rows per admin).
    conn.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') WHERE admin_id = ?1 AND revoked_at IS NULL",
        params![admin_id],
    ).unwrap();

    // Mint a PAT and insert its hash (must come after run_migrations creates _admin_tokens)
    let plaintext = admin_token::generate_token();
    let hash = admin_token::hash_token(&plaintext);
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (?1, ?2)",
        params![admin_id, hash],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let app = build_tenant_router(TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cors_origins: Vec::new(),
    });

    (app, plaintext, admin_id, dir)
}

/// Initialize the process-wide SQLite audit writer once and return the
/// audit DB path so each test can read its own rows. Writer runs on a
/// dedicated std::thread with its own tokio runtime so its task
/// outlives individual #[tokio::test] runtimes (each gets a fresh
/// runtime that drops at the end of the test).
fn ensure_global_audit_writer() -> &'static PathBuf {
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_audit_pat_bearer.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-audit-pat-bearer-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    drust::safety::audit_db::init_globals(writer);
                    let _ = tx_ready.send(());
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

/// Read every audit row whose tenant matches `tenant`. Polls briefly
/// because the SQLite writer drains in 100ms batches.
async fn read_audit_rows_for_tenant(tenant: &str) -> Vec<serde_json::Value> {
    let path = ensure_global_audit_writer();
    for _ in 0..50 {
        let r = open_audit_db_read(path).unwrap();
        let mut stmt = r
            .prepare(
                "SELECT op, status, actor_admin_id, actor_email_snapshot \
                 FROM audit WHERE tenant = ?1 ORDER BY id ASC",
            )
            .unwrap();
        let rows: Vec<serde_json::Value> = stmt
            .query_map(rusqlite::params![tenant], |r| {
                Ok(serde_json::json!({
                    "op":                    r.get::<_, String>(0)?,
                    "status":                r.get::<_, String>(1)?,
                    "actor_admin_id":        r.get::<_, Option<i64>>(2)?,
                    "actor_email_snapshot":  r.get::<_, Option<String>>(3)?,
                }))
            })
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        if !rows.is_empty() {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no audit rows for tenant {tenant} after 1s");
}

#[tokio::test]
async fn pat_bearer_returns_200_for_tenant_route() {
    let (app, plaintext, _admin_id, _dir) = app_with_pat("pat-t1").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/pat-t1/collections")
                .header(header::AUTHORIZATION, format!("Bearer {plaintext}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PAT should resolve to service, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn pat_bearer_audit_row_carries_actor_admin_id() {
    ensure_global_audit_writer();
    let (app, plaintext, admin_id, _dir) = app_with_pat("pat-t2").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/pat-t2/collections")
                .header(header::AUTHORIZATION, format!("Bearer {plaintext}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = read_audit_rows_for_tenant("pat-t2").await;
    let entry = rows
        .iter()
        .find(|l| {
            l["op"]
                .as_str()
                .is_some_and(|op| op.contains("collections"))
        })
        .expect("no audit entry for collections route");

    let got_admin_id = entry["actor_admin_id"]
        .as_i64()
        .expect("actor_admin_id should be present as an integer in audit row");
    assert_eq!(
        got_admin_id, admin_id,
        "audit actor_admin_id should match the inserted admin"
    );

    let email = entry["actor_email_snapshot"]
        .as_str()
        .expect("actor_email_snapshot should be present");
    assert_eq!(email, "pat-tester@example.com");
}

#[tokio::test]
async fn expired_cli_pat_is_rejected_on_data_plane() {
    let (app, _ui_pat, admin_id, dir) = app_with_pat("pat-exp").await;
    // Mint an EXPIRED CLI PAT for the same admin (relaxed index permits coexistence).
    let cli = drust::auth::admin_token::generate_cli_token();
    let h = drust::auth::admin_token::hash_token(&cli);
    {
        let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext, label, expires_at) \
             VALUES (?1, ?2, ?3, 'cli:laptop', datetime('now','-1 hour'))",
            params![admin_id, h, cli],
        )
        .unwrap();
    }
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/t/pat-exp/collections")
                .header(header::AUTHORIZATION, format!("Bearer {cli}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired CLI PAT must 401"
    );
}

#[tokio::test]
async fn unexpired_cli_pat_resolves_on_data_plane() {
    let (app, _ui_pat, admin_id, dir) = app_with_pat("pat-ok").await;
    // A future-expiry CLI PAT resolves to Service { admin_id }, like the UI PAT.
    let cli = drust::auth::admin_token::generate_cli_token();
    let h = drust::auth::admin_token::hash_token(&cli);
    {
        let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext, label, expires_at) \
             VALUES (?1, ?2, ?3, 'cli:laptop', datetime('now','+1 hour'))",
            params![admin_id, h, cli],
        )
        .unwrap();
    }
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/t/pat-ok/collections")
                .header(header::AUTHORIZATION, format!("Bearer {cli}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "unexpired CLI PAT resolves to Service"
    );
}

#[tokio::test]
async fn non_pat_bearer_does_not_pollute_pat_path() {
    // A regular shared service token should still resolve to Service { admin_id: None }
    // and NOT get actor_admin_id in the audit row.
    let (app, tok, _dir) = helpers::spin_up_tenant("pat-t3").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/pat-t3/collections")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

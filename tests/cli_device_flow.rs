use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn app() -> (
    axum::Router,
    tempfile::TempDir,
    Arc<Mutex<rusqlite::Connection>>,
) {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let mut conn = open_meta(&data.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let meta = Arc::new(Mutex::new(conn));
    let mut state = MgmtState::test_default(
        meta.clone(),
        data.clone(),
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = std::env::temp_dir();
    (state.with_data_dir(data), dir, meta)
}

async fn login(app: &axum::Router) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=root&password=hunter2"))
                .unwrap(),
        )
        .await
        .unwrap();
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    sc.split(';').next().unwrap().to_string()
}

async fn post_json(
    app: &axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn jbody(r: axum::http::Response<Body>) -> serde_json::Value {
    let b = axum::body::to_bytes(r.into_body(), 1_000_000)
        .await
        .unwrap();
    serde_json::from_slice(&b).unwrap()
}

/// F1: the approval CSRF token is HMAC-bound to `user_code`, so a test must read
/// the real value the server bakes into the page's `drust_cli_csrf` cookie.
async fn fetch_csrf(app: &axum::Router, cookie: &str, uc: &str) -> String {
    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/cli/device?user_code={uc}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    page.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find_map(|c| c.strip_prefix("drust_cli_csrf="))
        .map(|c| c.split(';').next().unwrap().to_string())
        .expect("csrf cookie set on page")
}

#[tokio::test]
async fn start_issues_codes_and_stores_hash_only() {
    let (app, _dir, meta) = app().await;
    let r = post_json(
        &app,
        "/auth/cli/device/start",
        serde_json::json!({"client_name":"lappy"}),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let v = jbody(r).await;
    let dc = v["device_code"].as_str().unwrap();
    assert_eq!(v["interval"], 5);
    assert_eq!(v["expires_in"], 900);
    // plaintext device_code is NOT in the table; only its hash is.
    let c = meta.lock().await;
    let stored_plain: i64 = c
        .query_row(
            "SELECT count(*) FROM _cli_device_codes WHERE device_code_hash = ?1",
            rusqlite::params![dc],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        stored_plain, 0,
        "raw device_code must never be a stored hash"
    );
    let by_hash: i64 = c
        .query_row(
            "SELECT count(*) FROM _cli_device_codes WHERE device_code_hash = ?1",
            rusqlite::params![drust::auth::admin_token::hash_token(dc)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(by_hash, 1);
}

#[tokio::test]
async fn poll_pending_then_expired_and_denied() {
    let (app, _dir, meta) = app().await;
    let v = jbody(post_json(&app, "/auth/cli/device/start", serde_json::json!({})).await).await;
    let dc = v["device_code"].as_str().unwrap().to_string();
    // first poll -> pending
    let p = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":dc}),
        )
        .await,
    )
    .await;
    assert_eq!(p["status"], "pending");
    // flip to denied out-of-band -> poll denied
    meta.lock()
        .await
        .execute("UPDATE _cli_device_codes SET status='denied'", [])
        .unwrap();
    let d = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":dc}),
        )
        .await,
    )
    .await;
    assert_eq!(d["status"], "denied");
    // unknown code -> expired (no enumeration signal)
    let u = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":"nope"}),
        )
        .await,
    )
    .await;
    assert_eq!(u["status"], "expired");
}

#[tokio::test]
async fn poll_approved_returns_token_once() {
    // Standalone (no T4): seed an _admin_tokens plaintext row + an approved device row.
    let (app, _dir, meta) = app().await;
    let v = jbody(post_json(&app, "/auth/cli/device/start", serde_json::json!({})).await).await;
    let dc = v["device_code"].as_str().unwrap().to_string();
    {
        let c = meta.lock().await;
        // The migration backfilled an active UI PAT for admin 1; revoke it so the
        // seeded PAT is the sole active row (pre-T4 the unique index forbids two).
        c.execute(
            "UPDATE _admin_tokens SET revoked_at=datetime('now') WHERE admin_id=1 AND revoked_at IS NULL",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (1,'th','drust_pat_cli_SEED')",
            [],
        )
        .unwrap();
        let tid: i64 = c
            .query_row(
                "SELECT id FROM _admin_tokens WHERE plaintext='drust_pat_cli_SEED'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        c.execute(
            "UPDATE _cli_device_codes SET status='approved', admin_id=1, minted_token_id=?1",
            rusqlite::params![tid],
        )
        .unwrap();
    }
    let a = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":dc}),
        )
        .await,
    )
    .await;
    assert_eq!(a["status"], "approved");
    assert_eq!(a["access_token"], "drust_pat_cli_SEED");
    // consume-once: second poll -> expired
    let again = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":dc}),
        )
        .await,
    )
    .await;
    assert_eq!(again["status"], "expired");
}

#[tokio::test]
async fn poll_slow_down_on_too_fast_repoll() {
    let (app, _dir, _meta) = app().await;
    let v = jbody(post_json(&app, "/auth/cli/device/start", serde_json::json!({})).await).await;
    let dc = v["device_code"].as_str().unwrap().to_string();
    let p1 = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":dc}),
        )
        .await,
    )
    .await;
    assert_eq!(p1["status"], "pending");
    let p2 = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":dc}),
        )
        .await,
    )
    .await;
    assert_eq!(p2["status"], "slow_down");
}

#[tokio::test]
async fn start_rate_limited() {
    let (app, _dir, _meta) = app().await;
    let mk = || {
        Request::builder()
            .method("POST")
            .uri("/auth/cli/device/start")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", "9.9.9.9, 10.0.0.1")
            .body(Body::from("{}"))
            .unwrap()
    };
    for _ in 0..5 {
        let r = app.clone().oneshot(mk()).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
    let sixth = app.clone().oneshot(mk()).await.unwrap();
    assert_eq!(sixth.status(), StatusCode::TOO_MANY_REQUESTS);
    let v = jbody(sixth).await;
    assert_eq!(v["error_code"], "RATE_LIMITED_IP");
}

#[tokio::test]
async fn start_approve_poll_full_happy_path() {
    let (app, _d, _m) = app().await;
    let v = jbody(
        post_json(
            &app,
            "/auth/cli/device/start",
            serde_json::json!({"client_name":"lappy"}),
        )
        .await,
    )
    .await;
    let dc = v["device_code"].as_str().unwrap().to_string();
    let uc = v["user_code"].as_str().unwrap().to_string();
    let cookie = login(&app).await;
    let csrf = fetch_csrf(&app, &cookie, &uc).await;
    let combined = format!("{cookie}; drust_cli_csrf={csrf}");
    let appr = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/cli/device/approve")
                .header(header::COOKIE, combined)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("user_code={uc}&csrf={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(appr.status().is_success());
    let got = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":dc}),
        )
        .await,
    )
    .await;
    assert_eq!(got["status"], "approved");
    assert!(
        got["access_token"]
            .as_str()
            .unwrap()
            .starts_with("drust_pat_cli_")
    );
    // bootstrap_admin sets username+password only (no email), so admins.email is
    // NULL → admin.email is null. Assert the admin identity via the deterministic id.
    assert_eq!(got["admin"]["id"], 1);
}

#[tokio::test]
async fn migrations_twice_then_full_flow_keeps_ui_pat() {
    // v1.41.5 regression guard, extended: a second boot's run_migrations is a pure
    // no-op (UI PAT not rerolled), and the CLI approve flow mints a LABELED PAT
    // that coexists under the relaxed unique index without touching the UI PAT.
    let (app, dir, meta) = app().await;
    {
        let conn = meta.lock().await;
        drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    }
    let ui_before: i64 = meta
        .lock()
        .await
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens \
             WHERE admin_id=1 AND label IS NULL AND revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ui_before, 1, "exactly one unlabeled UI PAT after two boots");

    let v = jbody(
        post_json(
            &app,
            "/auth/cli/device/start",
            serde_json::json!({"client_name":"lappy"}),
        )
        .await,
    )
    .await;
    let dc = v["device_code"].as_str().unwrap().to_string();
    let uc = v["user_code"].as_str().unwrap().to_string();
    let cookie = login(&app).await;
    let csrf = fetch_csrf(&app, &cookie, &uc).await;
    let combined = format!("{cookie}; drust_cli_csrf={csrf}");
    let appr = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/cli/device/approve")
                .header(header::COOKIE, combined)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("user_code={uc}&csrf={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(appr.status().is_success());
    let got = jbody(
        post_json(
            &app,
            "/auth/cli/device/poll",
            serde_json::json!({"device_code":dc}),
        )
        .await,
    )
    .await;
    assert_eq!(got["status"], "approved");
    assert!(
        got["access_token"]
            .as_str()
            .unwrap()
            .starts_with("drust_pat_cli_")
    );

    let ui_after: i64 = meta
        .lock()
        .await
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens \
             WHERE admin_id=1 AND label IS NULL AND revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        ui_after, 1,
        "the unlabeled UI PAT is untouched by the CLI approve flow"
    );
    let cli_active: i64 = meta
        .lock()
        .await
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens \
             WHERE admin_id=1 AND label IS NOT NULL AND revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        cli_active, 1,
        "exactly one labeled CLI PAT minted by approve"
    );
}

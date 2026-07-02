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
async fn page_redirects_without_session() {
    // browser invariant preserved
    let (app, _d, _m) = app().await;
    let r = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/cli/device?user_code=ABCD-2345")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(
        r.headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with("/login")
    );
}

#[tokio::test]
async fn page_renders_and_sets_csrf_cookie_when_logged_in() {
    let (app, _d, meta) = app().await;
    let user_code = {
        let v = jbody(
            post_json(
                &app,
                "/auth/cli/device/start",
                serde_json::json!({"client_name":"lappy"}),
            )
            .await,
        )
        .await;
        v["user_code"].as_str().unwrap().to_string()
    };
    let cookie = login(&app).await; // POST /login -> drust_session=...
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/cli/device?user_code={user_code}"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        r.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|c| c.to_str().unwrap().starts_with("drust_cli_csrf="))
    );
    let body = String::from_utf8(
        axum::body::to_bytes(r.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("lappy")); // client_name shown for confirmation
    let _ = meta;
}

#[tokio::test]
async fn deny_requires_csrf_then_flips_status() {
    let (app, _d, meta) = app().await;
    let uc = jbody(post_json(&app, "/auth/cli/device/start", serde_json::json!({})).await).await
        ["user_code"]
        .as_str()
        .unwrap()
        .to_string();
    let cookie = login(&app).await;
    // bad/absent CSRF -> 403
    let bad = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/cli/device/deny")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("user_code={uc}&csrf=WRONG")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::FORBIDDEN);
    // good CSRF: the server-issued token is HMAC-bound to user_code (F1). Fetch
    // the approval page to obtain the real drust_cli_csrf cookie value, then
    // double-submit it.
    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/cli/device?user_code={uc}"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csrf = page
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find_map(|c| c.strip_prefix("drust_cli_csrf="))
        .map(|c| c.split(';').next().unwrap().to_string())
        .expect("csrf cookie set on page");
    let combined = format!("{cookie}; drust_cli_csrf={csrf}");
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/cli/device/deny")
                .header(header::COOKIE, combined)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("user_code={uc}&csrf={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(ok.status().is_success());
    let s: String = meta
        .lock()
        .await
        .query_row(
            "SELECT status FROM _cli_device_codes WHERE user_code=?1",
            rusqlite::params![uc],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(s, "denied");
}

#[tokio::test]
#[serial_test::serial(env_cli_pat_ttl)]
async fn approve_honors_pat_ttl_env() {
    // F9: the minted CLI PAT honors DRUST_CLI_PAT_TTL_SECS, not the 24h const.
    // SAFETY: the serial wrapper ensures no concurrent env access.
    unsafe {
        std::env::set_var("DRUST_CLI_PAT_TTL_SECS", "300");
    }
    let (app, _d, meta) = app().await;
    let v = jbody(
        post_json(
            &app,
            "/auth/cli/device/start",
            serde_json::json!({"client_name":"lappy"}),
        )
        .await,
    )
    .await;
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
    let secs: i64 = meta
        .lock()
        .await
        .query_row(
            "SELECT CAST((julianday(expires_at) - julianday('now')) * 86400 AS INTEGER) \
             FROM _admin_tokens WHERE admin_id=1 AND label IS NOT NULL AND revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    unsafe {
        std::env::remove_var("DRUST_CLI_PAT_TTL_SECS");
    }
    assert!(
        (200..400).contains(&secs),
        "expires_at should be ~300s out (DRUST_CLI_PAT_TTL_SECS), got {secs}"
    );
}

#[tokio::test]
async fn approve_postconditions_atomic() {
    // F10: after a successful approve, the device row is `approved` with a
    // non-null minted_token_id AND exactly one labeled PAT exists — the mint and
    // the row-flip commit together (one tx) or neither.
    let (app, _d, meta) = app().await;
    let v = jbody(
        post_json(
            &app,
            "/auth/cli/device/start",
            serde_json::json!({"client_name":"lappy"}),
        )
        .await,
    )
    .await;
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
    let c = meta.lock().await;
    let (status, minted): (String, Option<i64>) = c
        .query_row(
            "SELECT status, minted_token_id FROM _cli_device_codes WHERE user_code=?1",
            rusqlite::params![uc],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "approved");
    let minted = minted.expect("minted_token_id must be set");
    let labeled: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens \
             WHERE admin_id=1 AND label IS NOT NULL AND revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(labeled, 1);
    let exists: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens WHERE id=?1 AND revoked_at IS NULL",
            rusqlite::params![minted],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(exists, 1, "device row references the minted PAT");
}

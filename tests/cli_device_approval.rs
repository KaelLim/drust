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
    let b = axum::body::to_bytes(r.into_body(), 1_000_000).await.unwrap();
    serde_json::from_slice(&b).unwrap()
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
    // good CSRF (cookie value == form value) -> status denied
    let csrf = "tok123";
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

//! v1.58 P1-11 — the admin plane must refuse to be framed.
//!
//! `/admin/*` has destructive one-click actions (reroll a service token, delete
//! a tenant), and until now sent neither `X-Frame-Options` nor a CSP
//! `frame-ancestors`, so any site could iframe it and harvest a click.
//!
//! Scope matters: the guard is admin-plane only. Tenant data routes are an API
//! for third-party frontends, the tenant half of the signed-bytes pair
//! (`/s/t/{tenant}/{key}`) is a delivery surface a tenant frontend may embed,
//! and `/public/*` never reaches drust at all.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::files::SANDBOX_CSP;
use drust::storage::garage::GarageClient;
use drust::storage::meta::{bootstrap_admin, open_meta};
use object_store::memory::InMemory;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

const BYTES_TENANT: &str = "frameguard-tenant";
const BOUNDARY: &str = "drustframeboundary";

/// The PRODUCTION mgmt router — `MgmtState::with_data_dir`, the one `main.rs`
/// merges. Deliberately not `build_mgmt_router`, which is a three-route
/// unauthenticated mini-router that no deployment ever serves: guarding it
/// would prove nothing about `/admin/*`.
///
/// `with_garage` wires an in-memory object store plus a tenant row, so the
/// admin byte route `/admin/tenants/{id}/files/{key}/bytes` is reachable.
async fn mgmt_app_inner(with_garage: bool) -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    if with_garage {
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
            rusqlite::params![BYTES_TENANT],
        )
        .unwrap();
        drust::storage::tenant_db::open_write(&data_dir, BYTES_TENANT).unwrap();
    }
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    // #955 — one bus per fixture: the admin-plane state and the MCP registry
    // it mounts must evict the same instance.
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir.clone(),
        tenants.clone(),
        helpers::test_mcp_http(tenants, bus.clone(), bus_rooms.clone()),
        bus,
        bus_rooms,
    );
    if with_garage {
        state.garage = Some(Arc::new(GarageClient::from_store(
            Arc::new(InMemory::new()),
            "public",
        )));
        state.disk_min_free_pct = 0; // CI disk is frequently <20% free
    }
    (state.with_data_dir(data_dir), dir)
}

async fn mgmt_app() -> (axum::Router, tempfile::TempDir) {
    mgmt_app_inner(false).await
}

/// Log in as the bootstrap admin and return the session cookie pair.
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
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login failed");
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("no Set-Cookie on login")
        .to_str()
        .unwrap();
    sc.split(';').next().unwrap().to_string()
}

/// Assert both anti-framing headers on a response, naming the route so a
/// failure says which one regressed.
fn assert_frame_denied(res: &axum::response::Response, route: &str) {
    assert_eq!(
        res.headers()
            .get("x-frame-options")
            .map(|v| v.to_str().unwrap()),
        Some("DENY"),
        "{route} must send X-Frame-Options: DENY"
    );
    let csp = res
        .headers()
        .get("content-security-policy")
        .unwrap_or_else(|| panic!("{route} must carry a CSP"))
        .to_str()
        .unwrap();
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "{route} CSP must deny framing, got: {csp}"
    );
}

#[tokio::test]
async fn login_page_refuses_framing() {
    let (app, _dir) = mgmt_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_frame_denied(&res, "/login");
}

/// The authenticated plane, reached unauthenticated: the session layer answers
/// with a redirect to `/login`, and that redirect is itself framed-clickable
/// bait, so it must carry the guard too. Also proves the guard sits OUTSIDE
/// `admin_session_layer` rather than only on the public sub-router.
#[tokio::test]
async fn admin_plane_refuses_framing_even_on_the_login_redirect() {
    let (app, _dir) = mgmt_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/admin/tenants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res.status().is_redirection(),
        "expected the unauthenticated /admin/tenants redirect, got {}",
        res.status()
    );
    assert_frame_denied(&res, "/admin/tenants");
}

/// The frame-guard CSP is `if_not_present`, so it must NOT clobber the
/// `SANDBOX_CSP` that `insert_content_type_headers` puts on a markup byte
/// response. Losing that sandbox would reopen the same-origin stored-XSS hole,
/// which is a far worse trade than a byte response missing `frame-ancestors`.
///
/// `tests/upload_content_type_safety.rs` cannot prove this: it mounts the byte
/// handlers on a bespoke two-route router and never touches the mgmt router,
/// so no frame guard is in its stack at all. This drives the production router.
#[tokio::test]
async fn admin_byte_route_keeps_its_sandbox_csp() {
    let (app, _dir) = mgmt_app_inner(true).await;
    let cookie = login(&app).await;

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"x.html\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: text/html\r\n\r\n<script>1</script>\r\n");
    for (name, value) in [("visibility", "public"), ("disposition", "inline")] {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/tenants/{BYTES_TENANT}/files/upload"))
                .header(header::COOKIE, &cookie)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "admin upload should succeed");
    let raw = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let key = v["key"].as_str().expect("upload response carries a key");

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/admin/tenants/{BYTES_TENANT}/files/{key}/bytes"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "bytes fetch should succeed");
    assert_eq!(
        resp.headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap(),
        SANDBOX_CSP,
        "the frame guard must not clobber the stored-XSS sandbox CSP"
    );
    // X-Frame-Options is `overriding`, so byte responses still refuse framing.
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
}

/// The signed-bytes pair is split across the guard boundary: `/s/admin/{key}`
/// is admin-owned and stays inside, `/s/t/{tenant}/{key}` is a tenant delivery
/// surface and stays outside — a tenant frontend may legitimately `<iframe>` a
/// signed asset of its own, and `X-Frame-Options: DENY` would break that.
///
/// Both are driven with a deliberately bogus token: the 403 comes from the
/// handler, which proves the route matched (a 404 would satisfy the header
/// assertions without ever entering the route), and the response layer runs on
/// the error path exactly as it does on the success path.
async fn signed_bytes_probe(app: &axum::Router, uri: &str) -> axum::response::Response {
    let e = chrono::Utc::now().timestamp() + 600;
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{uri}?e={e}&t=not-a-real-token&d=0"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "{uri} should reach the signature check, got {}",
        res.status()
    );
    res
}

#[tokio::test]
async fn admin_signed_bytes_refuses_framing() {
    let (app, _dir) = mgmt_app().await;
    let res = signed_bytes_probe(&app, "/s/admin/somekey").await;
    assert_frame_denied(&res, "/s/admin/{key}");
}

#[tokio::test]
async fn tenant_signed_bytes_is_not_frame_guarded() {
    let (app, _dir) = mgmt_app().await;
    let res = signed_bytes_probe(&app, "/s/t/t1/somekey").await;
    assert!(
        res.headers().get("x-frame-options").is_none(),
        "/s/t/{{tenant}}/{{key}} is a tenant delivery surface and must not be frame-guarded"
    );
    assert!(
        res.headers().get("content-security-policy").is_none(),
        "/s/t/{{tenant}}/{{key}} must not inherit the admin frame-ancestors CSP"
    );
}

#[tokio::test]
async fn tenant_data_plane_is_not_frame_guarded() {
    let (app, token, _dir) = helpers::spin_up_tenant("t1").await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/t/t1/collections")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 200 matters: a 404 from an unmatched route would pass the header
    // assertions below without ever entering the data plane.
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get("x-frame-options").is_none(),
        "the tenant data plane is a third-party API and must not be frame-guarded"
    );
    assert!(
        res.headers().get("content-security-policy").is_none(),
        "the tenant data plane must not inherit the admin frame-ancestors CSP"
    );
}

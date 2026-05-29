//! T8: admin-UI handlers for `_system_webhooks` virtual sidebar entry.
//!
//! Mirrors the `admin_oauth_provider_handlers.rs` `build_app()` shape — a
//! local fixture that mounts the 3 new admin routes without the admin
//! session middleware. We assert sidebar inclusion, empty-state rendering,
//! and the create → list flow (including secret-once cookie surfacing).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use drust::mgmt::tenants::{
    tenant_oauth_provider_delete, tenant_oauth_provider_upsert, tenant_oauth_providers_page,
    tenant_webhook_create_form, tenant_webhook_delete_form, tenant_webhooks_page, TenantsState,
};
use drust::storage::meta::open_meta;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

/// Build a minimal `axum::Router` with the webhook + api-keys + oauth admin
/// handlers mounted (no admin-session middleware — tests assert handler-
/// level behaviour, not auth gate). A tenant row is pre-seeded so the
/// `ensure_tenant_exists` guard lets requests through; the tenant's
/// `data.sqlite` is materialised by `open_write` so its schema is in place.
async fn build_app(tenant_id: &str) -> (Router, std::path::PathBuf, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant_id],
    )
    .unwrap();
    // Materialise the tenant's data.sqlite so _system_webhooks exists.
    let _ = drust::storage::tenant_db::open_write(&data_dir, tenant_id).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let state = TenantsState::test_default(meta, data_dir.clone(), tenants, mcp, bus, bus_rooms);
    let app = Router::new()
        .route(
            "/admin/tenants/{id}/_api_keys",
            get(drust::mgmt::tokens::api_keys_page),
        )
        .route(
            "/admin/tenants/{id}/_oauth_providers",
            get(tenant_oauth_providers_page).post(tenant_oauth_provider_upsert),
        )
        .route(
            "/admin/tenants/{id}/_oauth_providers/{provider}/delete",
            post(tenant_oauth_provider_delete),
        )
        .route(
            "/admin/tenants/{id}/_webhooks",
            get(tenant_webhooks_page).post(tenant_webhook_create_form),
        )
        .route(
            "/admin/tenants/{id}/_webhooks/{wid}/delete",
            post(tenant_webhook_delete_form),
        )
        .with_state(state);
    (app, data_dir, dir)
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn sidebar_includes_webhooks_entry() {
    let tid = "00000000-0000-4000-8000-000000000001";
    let (app, _data_dir, _td) = build_app(tid).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/tenants/{tid}/_api_keys"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "api_keys page should render");
    let body = body_text(resp).await;
    assert!(
        body.contains("_webhooks"),
        "sidebar must contain '_webhooks' entry; body excerpt:\n{}",
        &body.chars().take(800).collect::<String>()
    );
    // The 🔔 emoji icon was replaced by an inline SVG during the v1.15
    // design overhaul. Anchor on the link's title attribute instead — it
    // is the stable semantic identifier for this sidebar entry.
    assert!(
        body.contains("outbound webhook subscriptions"),
        "sidebar must carry the _webhooks entry's title attribute"
    );
}

#[tokio::test]
async fn empty_state_renders_with_add_form() {
    let tid = "00000000-0000-4000-8000-000000000002";
    let (app, _data_dir, _td) = build_app(tid).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/tenants/{tid}/_webhooks"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    // Empty-state hint (case-insensitive search for "no webhook")
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("no webhook"),
        "page should show empty-state hint; body excerpt:\n{}",
        &body.chars().take(800).collect::<String>()
    );
    // Add-form: must POST to the same URL and accept collection/events/url
    assert!(
        body.contains(&format!(
            "action=\"/drust/admin/tenants/{tid}/_webhooks\""
        )) || body.contains(&format!("/admin/tenants/{tid}/_webhooks")),
        "page must render a form pointing at the create endpoint"
    );
    assert!(body.contains("name=\"collection\""), "form needs collection input");
    assert!(body.contains("name=\"events\""), "form needs events input");
    assert!(body.contains("name=\"url\""), "form needs url input");
    // active_coll highlight should be `_webhooks`
    assert!(
        body.contains("_webhooks"),
        "active_coll _webhooks must be referenced"
    );
}

#[tokio::test]
async fn create_then_list_shows_row_and_surfaces_secret_once() {
    let tid = "00000000-0000-4000-8000-000000000003";
    let (app, _data_dir, _td) = build_app(tid).await;

    // POST create
    let form_body =
        "collection=notes&events=created&url=https%3A%2F%2Fexample.com%2Fone";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/tenants/{tid}/_webhooks"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "create form should 303 back to the list"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(
        loc.ends_with(&format!("/admin/tenants/{tid}/_webhooks")),
        "redirect target should be the list page, got: {loc}"
    );
    // Secret-once mechanism: a Set-Cookie or query-param carries the secret
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    // Cookie route: must be HttpOnly + short-lived
    assert!(
        set_cookie.contains("drust_webhook_secret_once"),
        "create response must set the secret-once cookie; got: {set_cookie:?}"
    );
    assert!(
        set_cookie.to_lowercase().contains("httponly"),
        "secret-once cookie must be HttpOnly; got: {set_cookie}"
    );

    // Follow the redirect with the cookie attached — the page should
    // surface the raw secret exactly once and then the cookie must be
    // cleared by the response (Max-Age=0 / expired).
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/tenants/{tid}/_webhooks"))
                .header(header::COOKIE, set_cookie.split(';').next().unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let clear = resp2
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let body = body_text(resp2).await;

    // The page must list the new webhook row.
    assert!(
        body.contains("https://example.com/one"),
        "list page must show the created webhook url"
    );
    assert!(
        body.contains("notes"),
        "list page must show the collection name"
    );
    assert!(
        body.contains("created"),
        "list page must show the event name"
    );

    // The raw secret should appear in the rendered page once (banner). It's
    // 64 hex chars from generate_secret() — we can't predict it, but the
    // banner ought to flag it as "save this now" or include a copy button.
    // A loose check: cookie cleared on this response means the handler did
    // pop the value.
    assert!(
        clear.contains("drust_webhook_secret_once")
            && (clear.contains("Max-Age=0") || clear.to_lowercase().contains("expires=")),
        "secret-once cookie should be cleared after one render; got: {clear}"
    );
}

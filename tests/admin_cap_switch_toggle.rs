//! Regression tests for the two cap-switch toggle bugs on
//! `GET /admin/tenants/{id}/_api_keys` (self-register + publish-policy tiles).
//!
//! Bug 1 — sticky toggle / needs refresh: each `.cap-tile` is a `<label>`
//! wrapping a `display:none` checkbox. The click handlers manually flip
//! `cb.checked` but never call `e.preventDefault()`, so the browser's native
//! label→control activation toggles the checkbox a SECOND time and desyncs it
//! from the visual switch — after one flip the toggle sticks until a page
//! refresh re-reads the server truth. Fix: each cap-tile click handler must
//! cancel the native toggle with `e.preventDefault()`.
//!
//! Bug 2 — English "enabled" on a zh-TW page: `_setSelfRegPill` hardcoded the
//! literals `'enabled'`/`'disabled'` instead of the localized strings, so the
//! initial server render showed 已啟用/已停用 but flipping the toggle rewrote
//! the pill to English. Fix: emit `t.s("common.pill.enabled")` /
//! `t.s("common.state.disabled")`.
//!
//! Both are JS-in-template bugs and this repo has no JS test harness, so the
//! guard is render-level: window on the relevant inline-JS region and require
//! the fixed tokens. Locale is forced to zh-TW via `Extension(Locale::ZhTw)`
//! because the English bundle renders "enabled"/"disabled" — byte-identical to
//! the buggy hardcode — and could not distinguish fixed from broken.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use drust::auth::middleware::AdminId;
use drust::mgmt::admin_profile::AdminProfileExt;
use drust::mgmt::i18n::{Locale, init_bundles};
use drust::mgmt::tenants::TenantsState;
use drust::mgmt::tokens::api_keys_page;
use drust::storage::meta::open_meta;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

const TID: &str = "tenant-cap-0001";

/// Build an app with `api_keys_page` mounted directly, forced to zh-TW so the
/// localized pill strings differ from the buggy English literals. Seeds one
/// tenant with `allow_self_register=1` + a plaintext service token.
async fn build_zhtw_app() -> Router {
    init_bundles();
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    // Production boots `open_meta` then `run_migrations` (main.rs) — the latter
    // adds the later `tenants` columns (allow_self_register / allow_user_publish
    // / allow_anon_publish) the api_keys handler SELECTs. open_meta alone omits
    // them, so mirror the full boot sequence here.
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name, created_at, allow_self_register) \
         VALUES (?1, 'alpha', '2026-01-01T00:00:00Z', 1)",
        rusqlite::params![TID],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, role, token_hash, plaintext) \
         VALUES (?1, 'service', 'hash_s', 'drust_service_alpha_PLAINTEXT')",
        rusqlite::params![TID],
    )
    .unwrap();

    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let bus = drust::tenant::events::EventBus::new();
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let state = TenantsState::test_default(meta, data_dir.clone(), tenants, mcp, bus, bus_rooms);

    Router::new()
        .route("/drust/admin/tenants/{id}/_api_keys", get(api_keys_page))
        .with_state(state)
        .layer(axum::Extension(AdminProfileExt::placeholder()))
        .layer(axum::Extension(AdminId(1)))
        .layer(axum::Extension(Locale::ZhTw))
}

async fn render_page() -> String {
    let app = build_zhtw_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/drust/admin/tenants/{TID}/_api_keys"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "api_keys page should render 200"
    );
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Bug 2: on a zh-TW page the pill-setter JS must emit the localized strings,
/// not the hardcoded English literals.
#[tokio::test]
async fn self_reg_pill_js_uses_localized_strings() {
    let html = render_page().await;
    let start = html
        .find("function _setSelfRegPill")
        .expect("_setSelfRegPill function missing from rendered page");
    // Window forward over the function body (it is ~6 lines).
    let body = &html[start..(start + 400).min(html.len())];
    assert!(
        body.contains("已啟用"),
        "pill-setter must emit the localized enabled string (已啟用), not the \
         hardcoded English literal — function window:\n{body}"
    );
    assert!(
        body.contains("已停用"),
        "pill-setter must emit the localized disabled string (已停用) — function \
         window:\n{body}"
    );
}

/// Bug 1: both cap-tile click handlers must call `preventDefault()` to cancel
/// the native label→checkbox toggle (otherwise it double-fires and the switch
/// sticks until refresh).
#[tokio::test]
async fn cap_tile_handlers_call_preventdefault() {
    let html = render_page().await;
    // The inline JS references each form by id with single quotes
    // (`getElementById('self-reg-form')`); the HTML elements use double quotes
    // (`id="self-reg-form"`), so the single-quoted form pins the JS handler.
    let selfreg = html
        .find("'self-reg-form'")
        .expect("self-reg IIFE marker missing");
    let pubpolicy = html
        .find("'pub-policy-form'")
        .expect("pub-policy IIFE marker missing");
    let reroll = html
        .find("form.reroll-form")
        .expect("reroll handler marker missing (region delimiter)");
    assert!(
        selfreg < pubpolicy && pubpolicy < reroll,
        "unexpected inline-JS ordering: self-reg={selfreg}, pub-policy={pubpolicy}, reroll={reroll}"
    );

    let selfreg_region = &html[selfreg..pubpolicy];
    let pubpolicy_region = &html[pubpolicy..reroll];
    assert!(
        selfreg_region.contains("preventDefault"),
        "self-register cap-tile handler must call e.preventDefault() to stop the \
         native label double-toggle"
    );
    assert!(
        pubpolicy_region.contains("preventDefault"),
        "publish-policy cap-tile handler must call e.preventDefault() to stop the \
         native label double-toggle"
    );
}

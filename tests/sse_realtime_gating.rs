//! Integration tests for v1.16 per-collection SSE realtime toggle.
//! Additional tests for the SSE gate and PUT endpoint added in
//! later tasks.

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir, tenant: &str) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create(tenant).await.unwrap()
}

#[tokio::test]
async fn create_collection_defaults_realtime_enabled_to_zero() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d, "rt").await;
    create_collection(
        &s,
        "events",
        &[FieldSpec {
            name: "label".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
        }],
    )
    .await
    .unwrap();

    // Read the meta row directly through the pool. McpRegistry has a
    // tenant pool — reach it via the same path the production handler
    // uses (s.inner().pool).
    let pool = s.inner().pool.clone();
    let v: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT realtime_enabled FROM _system_collection_meta WHERE collection_name='events'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(
        v, 0,
        "new collections should be opt-in (realtime_enabled=0)"
    );
}

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tests_helpers::{grab_pool, spin_up_dual_role_self_register, spin_up_tenant};
use tower::ServiceExt;

#[path = "helpers.rs"]
mod tests_helpers;

async fn seed_with_realtime(dir: &tempfile::TempDir, tenant: &str, enabled: bool) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(move |c| {
        c.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);",
        )?;
        drust::storage::schema::write_realtime_enabled(c, "posts", enabled)?;
        Ok::<_, rusqlite::Error>(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn service_subscribes_when_realtime_enabled() {
    let (app, tok, d) = spin_up_tenant("svc-on").await;
    seed_with_realtime(&d, "svc-on", true).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/svc-on/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn service_blocked_when_realtime_disabled() {
    let (app, tok, d) = spin_up_tenant("svc-off").await;
    seed_with_realtime(&d, "svc-off", false).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/svc-off/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "REALTIME_DISABLED");
}

#[tokio::test]
async fn anon_subscribes_when_enabled_and_can_select() {
    let (app, _tid, _svc, anon, d) = spin_up_dual_role_self_register("anon-ok").await;
    seed_with_realtime(&d, "anon-ok", true).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/anon-ok/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn anon_blocked_when_realtime_disabled() {
    let (app, _tid, _svc, anon, d) = spin_up_dual_role_self_register("anon-off").await;
    seed_with_realtime(&d, "anon-off", false).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/anon-off/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "REALTIME_DISABLED");
}

#[tokio::test]
async fn anon_blocked_without_select_cap() {
    let (app, _tid, _svc, anon, d) = spin_up_dual_role_self_register("anon-nosel").await;
    seed_with_realtime(&d, "anon-nosel", true).await;
    // Strip the default select cap so the composed gate fails on caps.
    let pool = grab_pool("anon-nosel", &d).await;
    pool.with_writer(|c| {
        drust::storage::schema::write_anon_caps(
            c,
            "posts",
            &std::collections::BTreeSet::new(),
        )
    })
    .await
    .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/anon-nosel/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "REALTIME_ANON_DENIED");
}

#[tokio::test]
async fn system_collection_subscribe_returns_404() {
    let (app, tok, _d) = spin_up_tenant("sys-coll").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/sys-coll/records/_system_users/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

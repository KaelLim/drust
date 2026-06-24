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
            description: None,
            ..Default::default()
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

#[path = "helpers.rs"]
mod tests_helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tests_helpers::{grab_pool, spin_up_dual_role_self_register, spin_up_tenant};
use tower::ServiceExt;

async fn seed_with_realtime(dir: &tempfile::TempDir, tenant: &str, enabled: bool) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(move |c| {
        c.execute_batch("CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);")?;
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
    // Note: bypasses the production DDL path, which would call
    // schema_cache.invalidate. Safe here because the schema cache for
    // `posts` is still cold — no prior subscribe has populated it.
    let pool = grab_pool("anon-nosel", &d).await;
    pool.with_writer(|c| {
        drust::storage::schema::write_anon_caps(c, "posts", &std::collections::BTreeSet::new())
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

#[tokio::test]
async fn put_realtime_enable_then_disable_round_trip() {
    let (app, tok, d) = spin_up_tenant("rt-put").await;
    seed_with_realtime(&d, "rt-put", false).await;
    // 0 → 1
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/t/rt-put/collections/posts/realtime")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(v["realtime_enabled"], true);

    // Subscribe now succeeds.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/rt-put/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 1 → 0
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/t/rt-put/collections/posts/realtime")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(v["realtime_enabled"], false);

    // Fresh subscribe now 403's — the disable half landed in the cache.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/rt-put/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(v["error_code"], "REALTIME_DISABLED");
}

#[tokio::test]
async fn put_realtime_disable_evicts_existing_subscribers() {
    let (app, tok, d) = spin_up_tenant("rt-evict").await;
    seed_with_realtime(&d, "rt-evict", true).await;

    // Open SSE first.
    let sub = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/rt-evict/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sub.status(), StatusCode::OK);
    let mut stream = sub.into_body().into_data_stream();

    // Toggle off.
    let off = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/t/rt-evict/collections/posts/realtime")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(off.status(), StatusCode::OK);

    // Stream must terminate (next chunk returns None) within 1s.
    let done = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        use futures::StreamExt;
        loop {
            match stream.next().await {
                None => return true,
                Some(Err(_)) => return true,
                Some(Ok(_)) => continue, // keep-alive comment, ignore
            }
        }
    })
    .await;
    assert!(done.is_ok(), "stream did not terminate within 1s of evict");
}

#[tokio::test]
async fn put_realtime_rejects_anon() {
    let (app, _tid, _svc, anon, d) = spin_up_dual_role_self_register("rt-anon-rej").await;
    seed_with_realtime(&d, "rt-anon-rej", false).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/t/rt-anon-rej/collections/posts/realtime")
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(v["error_code"], "WRITE_DENIED");
}

#[tokio::test]
async fn put_realtime_rejects_protected_collection() {
    let (app, tok, _d) = spin_up_tenant("rt-prot").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/t/rt-prot/collections/_system_users/realtime")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(v["error_code"], "PROTECTED_COLLECTION");
}

#[tokio::test]
async fn put_realtime_unknown_collection_404() {
    let (app, tok, _d) = spin_up_tenant("rt-ghost").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/t/rt-ghost/collections/ghost/realtime")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(v["error_code"], "COLLECTION_NOT_FOUND");
}

#[tokio::test]
async fn user_token_denied_regardless_of_toggle() {
    use tests_helpers::register_and_login_via_app;
    let (app, tid, _svc, _anon, d) = spin_up_dual_role_self_register("rt-user").await;
    seed_with_realtime(&d, "rt-user", true).await;
    let user_tok = register_and_login_via_app(&app, &tid, "u@e.com", "passpass").await;
    // realtime_enabled=true should still 403 user
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/rt-user/records/posts/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(v["error_code"], "SSE_USER_DENIED");
}

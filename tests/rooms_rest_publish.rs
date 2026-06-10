//! v1.31 REST publish integration tests for POST /t/{tenant}/rooms/{room}.
//!
//! Exercises full per-tenant router (bearer_auth_layer → publish_handler).
//! Uses helpers::spin_up_tenant_with_role to mint service / anon variants
//! and a local helper for tests that need a custom RoomsConfig override.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

mod helpers;

const TENANT: &str = "ab10b1a4-0000-0000-0000-000000000001";

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!(null))
}

#[tokio::test]
async fn publish_with_service_key_returns_200_and_zero_delivered_when_no_subscribers() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "service").await;
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{TENANT}/rooms/notif"))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"hello":"world"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["ok"], true);
    assert_eq!(v["delivered_to"], 0);
}

#[tokio::test]
async fn publish_anon_returns_403_anon_denied_by_default() {
    // v1.32.5 — anon publish is opt-in. The default (allow_anon_publish=0)
    // returns 403 with the role-specific primary code and the legacy
    // `WRITE_DENIED` retained as an alias for backwards-compat.
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{TENANT}/rooms/notif"))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"x":1}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v = body_json(resp).await;
    assert_eq!(v["error_code"], "PUBLISH_ANON_DENIED");
    let aliases = v["error_aliases"].as_array().expect("error_aliases array");
    assert!(
        aliases.iter().any(|x| x == "WRITE_DENIED"),
        "v1.32.5 must keep WRITE_DENIED as a legacy alias; got {:?}",
        aliases,
    );
    let fix = v["suggested_fix"].as_str().unwrap_or_default();
    assert!(
        fix.contains("allow_anon_publish"),
        "suggested_fix should mention the opt-in flag; got {fix:?}",
    );
}

#[tokio::test]
async fn publish_protected_room_returns_403_protected_room() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "service").await;
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{TENANT}/rooms/_system_evil"))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"x":1}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v = body_json(resp).await;
    assert_eq!(v["error_code"], "PROTECTED_ROOM");
}

#[tokio::test]
async fn publish_invalid_room_name_returns_400() {
    // axum decodes the path: %20 → ' '. validate_room_name rejects spaces.
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role(TENANT, "service").await;
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{TENANT}/rooms/has%20space"))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"x":1}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert_eq!(v["error_code"], "ROOM_NAME_INVALID");
}

#[tokio::test]
async fn publish_zero_qps_rate_limited() {
    // Override DRUST_BROADCAST_PUBLISH_QPS=1 via inline helper; second publish
    // within 1 second must 429.
    // (We don't use process env here — global state would race other tests.
    //  Instead build a tenant stack with a custom RoomsConfig.)
    use drust::auth::middleware::AuthCtx;
    use drust::tenant::rooms;
    let pc = rooms::PublishCtx {
        bus: rooms::RoomBus::new(),
        bucket: std::sync::Arc::new(rooms::PublishBucket::new(1)), // 1 QPS
        cfg: rooms::RoomsConfig {
            publish_qps: 1,
            payload_max_bytes: 65_536,
            room_subscriber_max: 1_000,
            client_room_max: 100,
            sweeper_interval_secs: 0,
        },
    };
    // First publish OK.
    let r1 = rooms::publish_into_bus(&pc, TENANT, "rl", serde_json::json!({"x":1}), "rest");
    assert!(r1.is_ok(), "first publish should succeed");
    // Second publish should rate-limit.
    let r2 = rooms::publish_into_bus(&pc, TENANT, "rl", serde_json::json!({"x":2}), "rest");
    assert!(matches!(r2, Err(rooms::PublishError::RateLimited(_))));
    // AuthCtx is referenced so the type-check covers the import; unused here.
    let _ = AuthCtx::Anon;
}

#[tokio::test]
async fn publish_payload_too_large_at_helper_layer() {
    // Direct helper-layer test for payload cap (cap = 100 bytes).
    use drust::tenant::rooms;
    let pc = rooms::PublishCtx {
        bus: rooms::RoomBus::new(),
        bucket: std::sync::Arc::new(rooms::PublishBucket::new(0)),
        cfg: rooms::RoomsConfig {
            publish_qps: 0,
            payload_max_bytes: 100,
            room_subscriber_max: 1_000,
            client_room_max: 100,
            sweeper_interval_secs: 0,
        },
    };
    let huge = serde_json::json!({"big": "x".repeat(500)});
    let r = rooms::publish_into_bus(&pc, TENANT, "huge", huge, "rest");
    assert!(matches!(r, Err(rooms::PublishError::PayloadTooLarge)));
}

#[tokio::test]
async fn publish_into_bus_delivers_to_one_subscriber() {
    use drust::tenant::rooms;
    let bus = rooms::RoomBus::new();
    let mut rx = bus.subscribe(TENANT, "delivery");
    let pc = rooms::PublishCtx {
        bus: bus.clone(),
        bucket: std::sync::Arc::new(rooms::PublishBucket::new(0)),
        cfg: rooms::RoomsConfig::test_defaults(),
    };
    let n = rooms::publish_into_bus(&pc, TENANT, "delivery", serde_json::json!({"k":1}), "rest")
        .unwrap();
    assert_eq!(n, 1);
    let got = rx.recv().await.unwrap();
    assert_eq!(got.payload["k"], 1);
}

// ─── v1.32.5 publish-policy gating ───────────────────────────────────────────

/// Helper: flip allow_user_publish / allow_anon_publish in the test tenant's
/// meta.sqlite. Returns once the UPDATE has been issued. The next REST
/// request through bearer_auth_layer will pick up the new value via the CTE.
fn flip_publish_flag(dir: &tempfile::TempDir, tenant: &str, col: &str, on: bool) {
    let path = dir.path().join("meta.sqlite");
    let c = rusqlite::Connection::open(path).unwrap();
    let sql = format!("UPDATE tenants SET {col} = ?1 WHERE id = ?2");
    c.execute(&sql, rusqlite::params![on as i64, tenant])
        .unwrap();
}

#[tokio::test]
async fn publish_anon_succeeds_once_allow_anon_publish_is_on() {
    let (app, tok, dir) = helpers::spin_up_tenant_with_role(TENANT, "anon").await;
    flip_publish_flag(&dir, TENANT, "allow_anon_publish", true);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{TENANT}/rooms/chat"))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"hi":true}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["ok"], true);
}

#[tokio::test]
async fn publish_user_denied_when_flag_off_and_allowed_when_on() {
    // Anon flag stays off — opening anon publish must NOT open user publish.
    let tenant = "ab10b1a4-0000-0000-0000-000000000099";
    let (app, _svc_tok, cache, dir) =
        helpers::spin_up_tenant_with_role_cached(tenant, "service").await;
    // Mint a user session directly in the tenant DB so bearer_auth_layer
    // resolves AuthCtx::User. Schema lives in src/auth/user_session.rs.
    use drust::auth::user_session;
    let conn = drust::storage::tenant_db::open_write(dir.path(), tenant).unwrap();
    // _system_users + _system_sessions are auto-created by open_write. Seed
    // one row so the session can reference a real user_id.
    conn.execute(
        "INSERT INTO _system_users (id, email, password_hash, verified, profile, created_at, updated_at) \
         VALUES ('u-1','u1@x','$oauth-only$',1,'{}','2026-01-01','2026-01-01')",
        [],
    )
    .unwrap();
    let session_tok = user_session::create_session(&conn, "u-1", None, 1).unwrap();
    drop(conn);
    // Default: user publish denied.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{tenant}/rooms/chat"))
        .header("authorization", format!("Bearer {session_tok}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"x":1}"#))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v = body_json(resp).await;
    assert_eq!(v["error_code"], "PUBLISH_USER_DENIED");
    let aliases = v["error_aliases"].as_array().expect("aliases");
    assert!(aliases.iter().any(|x| x == "WRITE_DENIED"));
    // Flip user flag, leave anon off. User publish must now succeed.
    // The flip is an OUT-OF-BAND raw-SQL write (no production handler runs,
    // so no v1.35 auth-cache hook fires) — mirror what every production
    // writer (REST patch_publish_policy / MCP set_publish_policy) does and
    // drop the tenant's cached entries so the next request re-reads the CTE.
    flip_publish_flag(&dir, tenant, "allow_user_publish", true);
    cache.clear_tenant(tenant);
    let req2 = Request::builder()
        .method("POST")
        .uri(format!("/t/{tenant}/rooms/chat"))
        .header("authorization", format!("Bearer {session_tok}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"x":2}"#))
        .unwrap();
    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
}

#[tokio::test]
async fn publish_service_unaffected_by_publish_policy_flags() {
    // Service key must publish whether the two flags are off, on, or mixed.
    let tenant = "ab10b1a4-0000-0000-0000-000000000010";
    let (app, tok, dir) = helpers::spin_up_tenant_with_role(tenant, "service").await;
    flip_publish_flag(&dir, tenant, "allow_user_publish", false);
    flip_publish_flag(&dir, tenant, "allow_anon_publish", false);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/t/{tenant}/rooms/notif"))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"x":1}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

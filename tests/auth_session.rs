use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

mod helpers;

fn post_json(tid: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_bearer(tid: &str, path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn get_bearer(tid: &str, path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn register_and_login(app: &axum::Router, tid: &str, email: &str) -> String {
    let _ = app
        .clone()
        .oneshot(post_json(
            tid,
            "/auth/register",
            json!({"email": email, "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(post_json(
            tid,
            "/auth/login",
            json!({"email": email, "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    v["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn logout_invalidates_only_that_session() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-sess1").await;
    let t1 = register_and_login(&app, "t-sess1", "a@b.com").await;
    // Second login → second session
    let resp = app
        .clone()
        .oneshot(post_json(
            "t-sess1",
            "/auth/login",
            json!({"email": "a@b.com", "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    let t2 = v["token"].as_str().unwrap().to_string();

    let r = app
        .clone()
        .oneshot(post_bearer("t-sess1", "/auth/logout", &t1))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // t1 invalid — collections call now 401
    let r1 = app
        .clone()
        .oneshot(get_bearer("t-sess1", "/collections", &t1))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::UNAUTHORIZED);
    // t2 still valid — collections returns 200
    let r2 = app
        .oneshot(get_bearer("t-sess1", "/collections", &t2))
        .await
        .unwrap();
    assert!(r2.status().is_success(), "got {}", r2.status());
}

#[tokio::test]
async fn logout_all_invalidates_every_session() {
    let (app, _svc_tok, _dir) = helpers::spin_up_tenant_self_register("t-sess2").await;
    let t1 = register_and_login(&app, "t-sess2", "a@b.com").await;
    let resp = app
        .clone()
        .oneshot(post_json(
            "t-sess2",
            "/auth/login",
            json!({"email": "a@b.com", "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let v = read_json(resp).await;
    let t2 = v["token"].as_str().unwrap().to_string();

    let r = app
        .clone()
        .oneshot(post_bearer("t-sess2", "/auth/logout-all", &t1))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = read_json(r).await;
    assert_eq!(body["revoked"].as_i64().unwrap(), 2);

    for t in [&t1, &t2] {
        let r = app
            .clone()
            .oneshot(get_bearer("t-sess2", "/collections", t))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn janitor_deletes_expired_sessions_past_grace() {
    let (app, _svc_tok, dir) = helpers::spin_up_tenant_self_register("t-jan1").await;
    let _ =
        helpers::register_and_login_via_app(&app, "t-jan1", "a@b.com", "longpassword").await;
    // Backdate the session row by ~2 days
    let p = dir.path().join("tenants").join("t-jan1").join("data.sqlite");
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute("UPDATE _system_sessions SET expires_at = '2025-01-01'", [])
        .unwrap();
    drop(c);

    let deleted = drust::storage::janitor::sweep_expired_sessions(dir.path(), 1).unwrap();
    assert!(deleted >= 1, "should delete at least 1 expired session, got {}", deleted);

    let c = rusqlite::Connection::open(&p).unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM _system_sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn janitor_keeps_active_sessions() {
    let (app, _svc_tok, dir) = helpers::spin_up_tenant_self_register("t-jan2").await;
    let _ =
        helpers::register_and_login_via_app(&app, "t-jan2", "a@b.com", "longpassword").await;
    // Sessions default to 30d expiry — sweep with 1d grace should leave them.
    let deleted = drust::storage::janitor::sweep_expired_sessions(dir.path(), 1).unwrap();
    assert_eq!(deleted, 0);

    let p = dir.path().join("tenants").join("t-jan2").join("data.sqlite");
    let c = rusqlite::Connection::open(&p).unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM _system_sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn janitor_skips_soft_deleted_tenants() {
    let (app, _svc_tok, dir) = helpers::spin_up_tenant_self_register("t-jan3").await;
    let _ =
        helpers::register_and_login_via_app(&app, "t-jan3", "a@b.com", "longpassword").await;
    // Mark tenant soft-deleted in meta
    let meta = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    meta.execute(
        "UPDATE tenants SET deleted_at = '2026-01-01' WHERE id = ?1",
        rusqlite::params!["t-jan3"],
    )
    .unwrap();
    drop(meta);
    // Even though the session would be active, janitor should skip the tenant entirely
    let deleted = drust::storage::janitor::sweep_expired_sessions(dir.path(), 1).unwrap();
    assert_eq!(deleted, 0, "soft-deleted tenants must be skipped");
}

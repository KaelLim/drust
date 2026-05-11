use axum::body::Body;
use axum::http::{Request, header};
use serde_json::json;
use tower::ServiceExt;

mod helpers;

fn read_audit_lines(dir: &std::path::Path) -> Vec<serde_json::Value> {
    let mut out = vec![];
    let audit_dir = dir.join("audit");
    if let Ok(rd) = std::fs::read_dir(&audit_dir) {
        for e in rd.flatten() {
            if let Ok(s) = std::fs::read_to_string(e.path()) {
                for l in s.lines() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
                        out.push(v);
                    }
                }
            }
        }
    }
    out
}

async fn flush_audit() {
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

fn post_json(tid: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn login_audit_records_email_and_auth_user_id() {
    let (app, tid, _svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-aud1").await;
    let _ = app
        .clone()
        .oneshot(post_json(
            &tid,
            "/auth/register",
            json!({"email":"a@b.com","password":"longpassword"}),
        ))
        .await
        .unwrap();
    let _ = app
        .oneshot(post_json(
            &tid,
            "/auth/login",
            json!({"email":"a@b.com","password":"longpassword"}),
        ))
        .await
        .unwrap();
    flush_audit().await;
    let lines = read_audit_lines(dir.path());
    let login = lines
        .iter()
        .find(|l| l["op"].as_str().unwrap_or("").contains("/auth/login"))
        .expect("audit must record /auth/login");
    assert_eq!(
        login["email"].as_str().unwrap(),
        "a@b.com",
        "login row must carry email: {login}"
    );
    assert!(
        login["auth_user_id"].as_str().is_some(),
        "login success must record the resolved user id: {login}"
    );
}

#[tokio::test]
async fn audit_never_records_password() {
    let secret = "BoldenburgRedAxiom77";
    let (app, tid, _svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-aud2").await;
    let _ = app
        .clone()
        .oneshot(post_json(
            &tid,
            "/auth/register",
            json!({"email":"a@b.com","password":secret}),
        ))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(post_json(
            &tid,
            "/auth/login",
            json!({"email":"a@b.com","password":secret}),
        ))
        .await
        .unwrap();
    let _ = app
        .oneshot(post_json(
            &tid,
            "/auth/login",
            json!({"email":"a@b.com","password":"WRONG"}),
        ))
        .await
        .unwrap();
    flush_audit().await;
    let lines = read_audit_lines(dir.path());
    for l in &lines {
        let s = serde_json::to_string(l).unwrap();
        assert!(
            !s.contains(secret),
            "S6 violation: password leaked in audit row: {s}"
        );
        assert!(
            !s.contains("WRONG"),
            "S6 violation: failed-login password leaked: {s}"
        );
    }
}

#[tokio::test]
async fn authed_request_carries_auth_kind() {
    let (app, tid, svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-aud3").await;
    // service token request → audit row should have auth_kind=service
    let _ = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    flush_audit().await;
    let lines = read_audit_lines(dir.path());
    assert!(
        lines.iter().any(|l| l["op"].as_str().unwrap_or("").contains("/collections")
            && l["auth_kind"] == "service"),
        "audit row must carry auth_kind=service: lines={:?}",
        lines
    );
}

#[tokio::test]
async fn user_request_carries_auth_user_id() {
    let (app, tid, _svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-aud4").await;
    let tok =
        helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let _ = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/me"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    flush_audit().await;
    let lines = read_audit_lines(dir.path());
    let me = lines
        .iter()
        .find(|l| l["op"].as_str().unwrap_or("").contains("/me"))
        .expect("audit must record /me");
    assert_eq!(me["auth_kind"], "user");
    assert!(
        me["auth_user_id"].as_str().unwrap_or("").starts_with("u-"),
        "user request must carry auth_user_id: {me}"
    );
}

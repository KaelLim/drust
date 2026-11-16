//! `POST /login` refuses a browser-declared cross-site submission.
//!
//! A cross-site page can make a victim's browser POST `/login` with
//! credentials the page author holds; `SameSite=Lax` does not stop the
//! response from setting the session cookie. `login_submit` now refuses
//! `Sec-Fetch-Site: cross-site` with 403 `LOGIN_CROSS_SITE` — before the
//! per-IP limiter, the meta lock and argon2. Everything else (same-origin,
//! same-site, none, no header at all — every script and test) must behave
//! exactly as before, and the admin OAuth callback, which is cross-site by
//! construction, must not be touched — on its full success path, not only
//! its first branch. Production router (`with_data_dir`), not
//! `build_mgmt_router`.

mod helpers;

use crate::common;
use common::oauth_helpers::{assert_redirect_contains, extract_set_cookie, spawn_fake_google};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower::ServiceExt;

const USER: &str = "root";
const PASS: &str = "hunter2";

struct Fx {
    app: axum::Router,
    meta: Arc<Mutex<rusqlite::Connection>>,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, USER, PASS).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let state = MgmtState::test_default(
        meta.clone(),
        data_dir.clone(),
        tenants.clone(),
        helpers::test_mcp_http(tenants, bus.clone(), bus_rooms.clone()),
        bus,
        bus_rooms,
    );
    Fx {
        app: state.with_data_dir(data_dir),
        meta,
        _dir: dir,
    }
}

fn login_req(sec_fetch_site: Option<&str>, user: &str, pass: &str) -> Request<Body> {
    login_req_multi(sec_fetch_site.as_slice(), user, pass)
}

/// One `sec-fetch-site` header line per element of `values`, in order
/// (`Request::builder().header` appends).
fn login_req_multi(values: &[&str], user: &str, pass: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for v in values {
        b = b.header("sec-fetch-site", *v);
    }
    b.body(Body::from(format!("username={user}&password={pass}")))
        .unwrap()
}

async fn send(app: &axum::Router, req: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(req).await.unwrap()
}

fn sessions(meta: &rusqlite::Connection) -> i64 {
    meta.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap()
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let b = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&b).unwrap()
}

/// Asserts the exact refusal shape and returns nothing else to look at.
async fn assert_refused(resp: axum::response::Response, what: &str) {
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{what}");
    let body = json(resp).await;
    assert_eq!(body["error_code"], "LOGIN_CROSS_SITE", "{what}");
}

// T1
#[tokio::test]
async fn cross_site_login_is_refused_with_403_json_and_no_cookie() {
    let fx = fixture().await;
    assert_eq!(sessions(&*fx.meta.lock().await), 0);
    let resp = send(&fx.app, login_req(Some("cross-site"), USER, PASS)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        ct.starts_with("application/json"),
        "content-type was {ct:?}"
    );
    assert!(
        resp.headers().get(header::SET_COOKIE).is_none(),
        "a refused login must not set any cookie"
    );
    assert!(resp.headers().get(header::LOCATION).is_none());
    let body = json(resp).await;
    assert_eq!(body["error_code"], "LOGIN_CROSS_SITE");
    assert_eq!(body["message"], "cross-site login refused");
    assert_eq!(
        sessions(&*fx.meta.lock().await),
        0,
        "a refused login must not create a session row"
    );
}

// T2
#[tokio::test]
async fn cross_site_refusal_ignores_case_and_surrounding_space() {
    // One fixture: refused requests do not spend the 5/min login budget.
    let fx = fixture().await;
    for v in ["Cross-Site", "CROSS-SITE", " cross-site "] {
        let resp = send(&fx.app, login_req(Some(v), USER, PASS)).await;
        assert_refused(resp, &format!("sec-fetch-site {v:?}")).await;
    }
}

// T3
#[tokio::test]
async fn cross_site_refusal_precedes_credential_check() {
    let fx = fixture().await;
    let wrong_pass = send(&fx.app, login_req(Some("cross-site"), USER, "nope")).await;
    assert_refused(wrong_pass, "wrong password").await;
    let no_user = send(&fx.app, login_req(Some("cross-site"), "ghost", PASS)).await;
    assert_refused(no_user, "unknown user").await;
}

// T4
#[tokio::test]
async fn cross_site_attempts_do_not_spend_the_login_budget() {
    // Depends on `MgmtState::test_default`'s `admin_login_rl` = 5 per 60 s;
    // change this test if that capacity changes. Every request here comes
    // from the same fallback client IP, so they all share one bucket.
    let fx = fixture().await;
    for i in 1..=6 {
        let resp = send(&fx.app, login_req(Some("cross-site"), USER, "nope")).await;
        assert_refused(resp, &format!("cross-site attempt {i}")).await;
    }
    let ok = send(&fx.app, login_req(None, USER, PASS)).await;
    assert_eq!(
        ok.status(),
        StatusCode::SEE_OTHER,
        "the full budget must remain after 6 cross-site refusals"
    );
    for i in 2..=5 {
        let resp = send(&fx.app, login_req(None, USER, "nope")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    let sixth = send(&fx.app, login_req(None, USER, "nope")).await;
    assert_eq!(
        sixth.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the limiter itself must still trip on the 6th counted attempt"
    );
}

// T5
#[tokio::test]
async fn cross_site_refusal_does_not_wait_on_meta() {
    let fx = fixture().await;
    let guard = fx.meta.lock().await;
    let refused = tokio::time::timeout(
        Duration::from_secs(5),
        send(&fx.app, login_req(Some("cross-site"), USER, PASS)),
    )
    .await
    .expect("cross-site refusal must not wait on the meta lock");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    // Control: the same held lock DOES block an ordinary login, so this test
    // can tell "touched meta" from "did not".
    let control = tokio::time::timeout(
        Duration::from_millis(300),
        send(&fx.app, login_req(None, USER, PASS)),
    )
    .await;
    assert!(
        control.is_err(),
        "control: an ordinary login must block on the held meta lock"
    );
    drop(guard);
}

// T6
#[tokio::test]
async fn non_cross_site_logins_behave_as_before() {
    for v in [None, Some("same-origin"), Some("same-site"), Some("none")] {
        let fx = fixture().await;
        let resp = send(&fx.app, login_req(v, USER, PASS)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{v:?}");
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/drust/admin/tenants",
            "{v:?}"
        );
        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|c| c.to_str().ok())
            .unwrap_or_default();
        assert!(cookie.starts_with("drust_session="), "{v:?}: {cookie:?}");
        assert!(cookie.contains("HttpOnly"), "{v:?}");
        assert_eq!(sessions(&*fx.meta.lock().await), 1, "{v:?}");
    }
}

// T7
#[tokio::test]
async fn unknown_or_empty_values_are_not_refused() {
    let fx = fixture().await;
    for v in ["", "cross-sitex"] {
        let resp = send(&fx.app, login_req(Some(v), USER, PASS)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{v:?}");
    }
}

// T8
#[tokio::test]
async fn any_cross_site_among_repeated_headers_refuses() {
    let fx = fixture().await;
    for order in [["same-origin", "cross-site"], ["cross-site", "same-origin"]] {
        let resp = send(&fx.app, login_req_multi(&order, USER, PASS)).await;
        assert_refused(resp, &format!("{order:?}")).await;
    }
}

// T9 — the callback's first branch (no provider registered) answers the same
// with or without `cross-site`: a check added at the top of the callback
// would turn this into a 403.
#[tokio::test]
async fn admin_oauth_callback_misconfigured_branch_is_not_gated() {
    let fx = fixture().await;
    let cb = |xs: bool| {
        let mut b = Request::builder().uri("/admin/oauth/google/callback?code=x&state=y");
        if xs {
            b = b.header("sec-fetch-site", "cross-site");
        }
        b.body(Body::empty()).unwrap()
    };
    let plain = send(&fx.app, cb(false)).await;
    let xs = send(&fx.app, cb(true)).await;
    assert_eq!(plain.status(), StatusCode::FOUND);
    assert_eq!(xs.status(), plain.status());
    let want = "/drust/login?oauth_error=oauth_misconfigured";
    assert_eq!(plain.headers().get(header::LOCATION).unwrap(), want);
    assert_eq!(xs.headers().get(header::LOCATION).unwrap(), want);
}

// T10 — the admin OAuth callback's FULL success path is not gated. A real IdP
// redirect always arrives as `Sec-Fetch-Site: cross-site`; T9 (empty registry)
// only reaches the first branch, so a check added after the provider lookup,
// the state compare or the exchange would slip past it but not past this.
#[tokio::test]
async fn admin_oauth_callback_success_path_ignores_cross_site() {
    let fake = spawn_fake_google().await; // FakeScript::default() = kael@example.com
    let (app, _dir, _log) = crate::admin_oauth::spin_up_admin_with_google_fake(&fake).await;
    let start = send(
        &app,
        Request::builder()
            .uri("/admin/oauth/google/start")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(start.status(), StatusCode::FOUND);
    let st = extract_set_cookie(&start, "drust_oauth_state").expect("state cookie set");
    let pk = extract_set_cookie(&start, "drust_oauth_pkce").expect("pkce cookie set");
    let resp = send(
        &app,
        Request::builder()
            .uri(format!(
                "/admin/oauth/google/callback?code=CODE-XS&state={st}"
            ))
            .header(
                header::COOKIE,
                format!("drust_oauth_state={st}; drust_oauth_pkce={pk}"),
            )
            .header("sec-fetch-site", "cross-site")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_redirect_contains(&resp, "/drust/admin/tenants");
    let session = extract_set_cookie(&resp, "drust_session").expect("session cookie set");
    assert!(!session.is_empty());
}

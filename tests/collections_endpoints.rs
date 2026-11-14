use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::tenant::router::TenantRef;
use tower::ServiceExt;

mod helpers;
use helpers::{
    create_collection_via_pool, grab_pool, register_and_login_via_app,
    spin_up_dual_role_self_register, spin_up_tenant,
};

#[tokio::test]
async fn list_collections_empty() {
    let (app, tok, _d) = spin_up_tenant("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/collections")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["collections"], serde_json::json!([]));
    let _: TenantRef; // keep import
}

#[tokio::test]
async fn describe_after_manual_create() {
    let (app, tok, _d) = spin_up_tenant("blog").await;
    // Manually create a table on the writer conn
    let pool = helpers::grab_pool("blog", &_d).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT NOT NULL);
             INSERT INTO posts (title) VALUES ('a');",
        )
    })
    .await
    .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/collections/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["name"], "posts");
    assert_eq!(v["row_count"], 1);
}

#[tokio::test]
async fn describe_missing_404() {
    let (app, tok, _d) = spin_up_tenant("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/collections/ghost")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── E8 (S-08): anon / user cannot describe `_system_*` / `sqlite_*` ──────────

/// oneshot GET with a bearer; returns status + raw bytes (describe's own
/// miss is plain text, so the body cannot always be parsed as JSON).
async fn e8_get(app: &axum::Router, uri: &str, tok: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, body.to_vec())
}

struct E8Fixture {
    app: axum::Router,
    svc: String,
    anon: String,
    user: String,
    _dir: tempfile::TempDir,
}

/// Tenant `e8` with service + anon keys, self-register on, a `posts`
/// collection holding one row (creating it also creates `sqlite_sequence`,
/// since the table is AUTOINCREMENT), and one registered user — so
/// `_system_users` holds exactly one row.
async fn e8_fixture() -> E8Fixture {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("e8").await;
    let pool = grab_pool(&tid, &dir).await;
    create_collection_via_pool(&pool, "posts", &[("title", "text")]).await;
    pool.with_writer(|c| c.execute_batch("INSERT INTO posts (title) VALUES ('a');"))
        .await
        .unwrap();
    let user = register_and_login_via_app(&app, &tid, "u@e8.test", "pw_long_enough").await;
    E8Fixture {
        app,
        svc,
        anon,
        user,
        _dir: dir,
    }
}

fn e8_assert_protected_404(status: StatusCode, body: &[u8], what: &str) {
    assert_eq!(status, StatusCode::NOT_FOUND, "{what}: expected 404");
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|_| {
        panic!(
            "{what}: body is not JSON: {}",
            String::from_utf8_lossy(body)
        )
    });
    assert_eq!(v["error_code"], "NOT_FOUND", "{what}: body was {v}");
    let s = String::from_utf8_lossy(body);
    assert!(!s.contains("password_hash"), "{what}: leaked a column: {s}");
    assert!(!s.contains("row_count"), "{what}: leaked row_count: {s}");
}

#[tokio::test]
async fn e8_anon_describe_system_users_is_404_not_found() {
    let f = e8_fixture().await;
    let (st, body) = e8_get(&f.app, "/t/e8/collections/_system_users", &f.anon).await;
    e8_assert_protected_404(st, &body, "anon _system_users");
}

#[tokio::test]
async fn e8_user_describe_system_users_is_404_not_found() {
    let f = e8_fixture().await;
    let (st, body) = e8_get(&f.app, "/t/e8/collections/_system_users", &f.user).await;
    e8_assert_protected_404(st, &body, "user _system_users");
}

#[tokio::test]
async fn e8_anon_describe_every_protected_shape_is_404() {
    let f = e8_fixture().await;
    // The last two prove the decision happens BEFORE any DB read: inside the
    // protected namespace a case variant and a missing name answer exactly
    // like an existing table.
    for name in [
        "_system_sessions",
        "_system_record_history",
        "_system_webhooks",
        "sqlite_sequence",
        "_System_Users",
        "_system_does_not_exist",
    ] {
        let (st, body) = e8_get(&f.app, &format!("/t/e8/collections/{name}"), &f.anon).await;
        e8_assert_protected_404(st, &body, &format!("anon {name}"));
    }
}

#[tokio::test]
async fn e8_user_describe_sqlite_sequence_is_404() {
    let f = e8_fixture().await;
    let (st, body) = e8_get(&f.app, "/t/e8/collections/sqlite_sequence", &f.user).await;
    e8_assert_protected_404(st, &body, "user sqlite_sequence");
}

#[tokio::test]
async fn e8_service_describe_system_users_unchanged() {
    let f = e8_fixture().await;
    let (st, body) = e8_get(&f.app, "/t/e8/collections/_system_users", &f.svc).await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["name"], "_system_users");
    assert_eq!(v["row_count"], 1);
    let fields = v["fields"].as_array().expect("fields array");
    assert!(
        fields.iter().any(|x| x["name"] == "email"),
        "service describe should list `email`; got {v}"
    );
}

#[tokio::test]
async fn e8_service_describe_sqlite_sequence_unchanged() {
    let f = e8_fixture().await;
    let (st, _body) = e8_get(&f.app, "/t/e8/collections/sqlite_sequence", &f.svc).await;
    assert_eq!(st, StatusCode::OK);
}

async fn e8_assert_posts_describable(app: &axum::Router, tok: &str, who: &str) {
    let (st, body) = e8_get(app, "/t/e8/collections/posts", tok).await;
    assert_eq!(st, StatusCode::OK, "{who}: describe posts");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["row_count"], 1, "{who}: {v}");
    let fields = v["fields"].as_array().expect("fields array");
    assert!(
        fields.iter().any(|x| x["name"] == "title"),
        "{who}: describe posts should list `title`; got {v}"
    );
}

#[tokio::test]
async fn e8_anon_describe_regular_collection_unchanged() {
    let f = e8_fixture().await;
    e8_assert_posts_describable(&f.app, &f.anon, "anon").await;
}

#[tokio::test]
async fn e8_user_describe_regular_collection_unchanged() {
    let f = e8_fixture().await;
    e8_assert_posts_describable(&f.app, &f.user, "user").await;
}

/// NOT a security pin. It pins that E8 did not also change describe's own
/// error envelope for ordinary names (still plain text). When S-39 error
/// envelope unification or P3′ `decide_describe` turns this miss into JSON,
/// flipping this assertion is expected.
#[tokio::test]
async fn e8_anon_describe_missing_regular_collection_unchanged() {
    let f = e8_fixture().await;
    let (st, body) = e8_get(&f.app, "/t/e8/collections/ghost", &f.anon).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body.as_slice(), b"collection not found");
}

#[tokio::test]
async fn e8_anon_list_collections_still_hides_system() {
    let f = e8_fixture().await;
    let (st, body) = e8_get(&f.app, "/t/e8/collections", &f.anon).await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let list = v["collections"].as_array().expect("collections array");
    for c in list {
        let name = c["name"].as_str().unwrap_or_default().to_ascii_lowercase();
        assert!(
            !name.starts_with("_system_") && !name.starts_with("sqlite_"),
            "list leaked an internal table: {c}"
        );
    }
    let posts = list
        .iter()
        .find(|c| c["name"] == "posts")
        .expect("posts listed");
    assert_eq!(posts["row_count"], 1, "posts row_count: {posts}");
}

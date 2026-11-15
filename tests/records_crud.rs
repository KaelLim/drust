mod helpers;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use helpers::{grab_pool, spin_up_tenant};
use tower::ServiceExt;

async fn seed_posts(dir: &tempfile::TempDir) {
    let pool = grab_pool("blog", dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                views INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn create_then_list() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    // Create
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"hello","views":5}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    // List
    let r2 = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r2.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 1);
    assert_eq!(v["total"], 1);
}

#[tokio::test]
async fn update_then_get() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"a"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let id = v["id"].as_i64().unwrap();
    let r2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"b"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let r3 = app
        .oneshot(
            Request::builder()
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r3.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["record"]["title"], "b");
}

#[tokio::test]
async fn delete_record() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"x"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let id = v["id"].as_i64().unwrap();
    let r2 = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn list_with_filter() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    for t in ["a", "b", "c"] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/t/blog/records/posts")
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"data":{{"title":"{t}"}}}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let r = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts?filter=title='b'")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 1);
    assert_eq!(v["records"][0]["title"], "b");
}

// H5-1 phase 1: legacy ?filter / ?sort must emit Deprecation + Sunset +
// Link headers with the EXACT values the server is supposed to advertise.
// v1.29.7 C2 — content assertions (not just is_some()) so a day-of-week
// regression (the v1.29.6 Wed/Fri bug) or a wrong Link target cannot ship
// past `cargo test`.
#[tokio::test]
async fn legacy_filter_emits_deprecation_headers() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;

    // ?filter= present → Deprecation: true + Sunset (Fri) + Link (GitHub
    // blob URL) all with exact values.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts?filter=title='x'")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.headers().get("deprecation").map(|v| v.as_bytes()),
        Some(b"true".as_ref()),
        "Deprecation header value"
    );
    assert_eq!(
        r.headers().get("sunset").and_then(|v| v.to_str().ok()),
        Some("Fri, 01 Jan 2027 00:00:00 GMT"),
        "Sunset must be RFC 7231 IMF-fixdate with correct day-of-week"
    );
    assert_eq!(
        r.headers().get("link").and_then(|v| v.to_str().ok()),
        Some(
            "<https://github.com/KaelLim/drust/blob/main/docs/migration/list-filter.md>; rel=\"deprecation\""
        ),
        "Link must be the GitHub blob URL (the canonical, dereferenceable migration doc)"
    );

    // ?sort= present → same three headers.
    let r2 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts?sort=-created_at")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(
        r2.headers().get("deprecation").map(|v| v.as_bytes()),
        Some(b"true".as_ref()),
    );
    assert_eq!(
        r2.headers().get("sunset").and_then(|v| v.to_str().ok()),
        Some("Fri, 01 Jan 2027 00:00:00 GMT"),
    );

    // No legacy params → no deprecation headers.
    let r3 = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r3.status(), StatusCode::OK);
    assert!(
        r3.headers().get("deprecation").is_none(),
        "no Deprecation on clean request"
    );
    assert!(
        r3.headers().get("sunset").is_none(),
        "no Sunset on clean request"
    );
    assert!(
        r3.headers().get("link").is_none(),
        "no Link on clean request"
    );
}

// --- Unknown body key → 400 FIELD_NOT_FOUND (smoke fix, rest-errors-audit) ---

async fn send_json(
    app: &axum::Router,
    method: Method,
    uri: &str,
    tok: &str,
    body: &str,
) -> (StatusCode, String, bytes::Bytes) {
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let ct = r
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (status, ct, b)
}

fn json_of(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap_or_else(|_| {
        panic!("not JSON: {}", String::from_utf8_lossy(b));
    })
}

async fn post_count(dir: &tempfile::TempDir) -> i64 {
    grab_pool("blog", dir)
        .await
        .with_writer(|c| c.query_row("SELECT COUNT(*) FROM posts", [], |r| r.get(0)))
        .await
        .unwrap()
}

/// One row through the app (also warms the app pool's schema cache); returns its id.
async fn insert_one(app: &axum::Router, tok: &str) -> i64 {
    let (s, _, b) = send_json(
        app,
        Method::POST,
        "/t/blog/records/posts",
        tok,
        r#"{"data":{"title":"a","views":1}}"#,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    json_of(&b)["id"].as_i64().unwrap()
}

fn assert_field_not_found(status: StatusCode, ct: &str, b: &[u8], key: &str) -> serde_json::Value {
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(b)
    );
    assert!(ct.starts_with("application/json"), "content-type {ct}");
    let v = json_of(b);
    assert_eq!(v["error_code"], "FIELD_NOT_FOUND", "{v}");
    assert!(v["message"].as_str().unwrap().contains(key), "{v}");
    v
}

#[tokio::test]
async fn insert_unknown_field_answers_400_field_not_found_json() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let (s, ct, b) = send_json(
        &app,
        Method::POST,
        "/t/blog/records/posts",
        &tok,
        r#"{"data":{"title":"x","nope":1}}"#,
    )
    .await;
    let v = assert_field_not_found(s, &ct, &b, "nope");
    let fix = v["suggested_fix"].as_str().unwrap();
    assert!(fix.contains("`nope`"), "{fix}");
    assert!(fix.contains("title"), "{fix}");
    assert_eq!(post_count(&d).await, 0);
}

#[tokio::test]
async fn patch_unknown_field_answers_400_field_not_found_json() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let id = insert_one(&app, &tok).await;
    let (s, ct, b) = send_json(
        &app,
        Method::PATCH,
        &format!("/t/blog/records/posts/{id}"),
        &tok,
        r#"{"data":{"title":"changed","nope":1}}"#,
    )
    .await;
    let v = assert_field_not_found(s, &ct, &b, "nope");
    let fix = v["suggested_fix"].as_str().unwrap();
    assert!(fix.contains("`nope`") && fix.contains("title"), "{fix}");
    // The row is unchanged.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let got = json_of(&axum::body::to_bytes(r.into_body(), 65_536).await.unwrap());
    let title = got["record"]["title"]
        .as_str()
        .or_else(|| got["title"].as_str())
        .unwrap_or_default()
        .to_string();
    assert_eq!(title, "a", "{got}");
}

#[tokio::test]
async fn insert_unknown_key_named_like_an_error_code_answers_field_not_found() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    for key in ["TENANT_QUOTA_EXCEEDED", "POLICY_CHECK_FAILED"] {
        let (s, ct, b) = send_json(
            &app,
            Method::POST,
            "/t/blog/records/posts",
            &tok,
            &format!(r#"{{"data":{{"title":"x","{key}":1}}}}"#),
        )
        .await;
        assert_ne!(s, StatusCode::INSUFFICIENT_STORAGE, "{key}");
        assert_ne!(s, StatusCode::FORBIDDEN, "{key}");
        assert_field_not_found(s, &ct, &b, key);
    }
    assert_eq!(post_count(&d).await, 0);
}

#[tokio::test]
async fn patch_unknown_key_named_like_an_error_code_answers_field_not_found() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let id = insert_one(&app, &tok).await;
    let (s, ct, b) = send_json(
        &app,
        Method::PATCH,
        &format!("/t/blog/records/posts/{id}"),
        &tok,
        r#"{"data":{"TENANT_QUOTA_EXCEEDED":1}}"#,
    )
    .await;
    assert_ne!(s, StatusCode::INSUFFICIENT_STORAGE);
    assert_ne!(s, StatusCode::NOT_FOUND);
    assert_field_not_found(s, &ct, &b, "TENANT_QUOTA_EXCEEDED");
}

#[tokio::test]
async fn oversized_unknown_key_is_truncated_in_the_response() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let key = "k".repeat(4096);
    let (s, ct, b) = send_json(
        &app,
        Method::POST,
        "/t/blog/records/posts",
        &tok,
        &format!(r#"{{"data":{{"title":"x","{key}":1}}}}"#),
    )
    .await;
    assert_field_not_found(s, &ct, &b, &"k".repeat(128));
    assert!(b.len() < 2048, "response is {} bytes", b.len());
}

#[tokio::test]
async fn anon_insert_unknown_field_answers_field_not_found() {
    use drust::storage::schema::{DmlVerb, write_anon_caps};
    let (app, tok, d) = helpers::spin_up_tenant_with_role("blog", "anon").await;
    seed_posts(&d).await;
    grab_pool("blog", &d)
        .await
        .with_writer(|c| write_anon_caps(c, "posts", &[DmlVerb::Insert].into_iter().collect()))
        .await
        .unwrap();
    // Control: the cap gate admits anon here, so the refusal below is the
    // field check, not a cap deny.
    let (s, _, b) = send_json(
        &app,
        Method::POST,
        "/t/blog/records/posts",
        &tok,
        r#"{"data":{"title":"ok"}}"#,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&b));
    let (s, ct, b) = send_json(
        &app,
        Method::POST,
        "/t/blog/records/posts",
        &tok,
        r#"{"data":{"title":"x","nope":1}}"#,
    )
    .await;
    assert_field_not_found(s, &ct, &b, "nope");
}

#[tokio::test]
async fn insert_into_collection_dropped_behind_the_schema_cache_answers_404_not_found() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    insert_one(&app, &tok).await;
    // A separate pool (its own registry) — the app's schema cache still holds `posts`.
    grab_pool("blog", &d)
        .await
        .with_writer(|c| c.execute_batch("DROP TABLE posts"))
        .await
        .unwrap();
    let (s, ct, b) = send_json(
        &app,
        Method::POST,
        "/t/blog/records/posts",
        &tok,
        r#"{"data":{"title":"x"}}"#,
    )
    .await;
    assert_ne!(&b[..], b"Query is not read-only");
    assert_eq!(s, StatusCode::NOT_FOUND, "{}", String::from_utf8_lossy(&b));
    assert!(ct.starts_with("application/json"), "content-type {ct}");
    assert_eq!(json_of(&b)["error_code"], "NOT_FOUND");
}

#[tokio::test]
async fn patch_field_dropped_behind_the_schema_cache_names_that_field() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let id = insert_one(&app, &tok).await;
    grab_pool("blog", &d)
        .await
        .with_writer(|c| c.execute_batch("ALTER TABLE posts DROP COLUMN views"))
        .await
        .unwrap();
    let (s, ct, b) = send_json(
        &app,
        Method::PATCH,
        &format!("/t/blog/records/posts/{id}"),
        &tok,
        r#"{"data":{"views":1}}"#,
    )
    .await;
    let v = assert_field_not_found(s, &ct, &b, "views");
    let fix = v["suggested_fix"].as_str().unwrap();
    assert!(fix.contains("`views`"), "{fix}");
    let existing = fix.split("Existing fields:").nth(1).unwrap_or_default();
    assert!(existing.contains("title"), "{fix}");
    assert!(!existing.contains("views"), "{fix}");
}

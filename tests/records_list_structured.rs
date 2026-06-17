//! v1.21 — `POST /t/<id>/collections/<c>/list` structured list endpoint.
//!
//! Covers spec §4.2: happy paths × callers, owner_field strict
//! enforcement, owner-field bypass attempts, SQL-injection attempts in
//! filter/sort, vector-field blocks, _system_* 404, anon_caps denial,
//! ANON_FORBIDDEN_OWNER_SCOPED, /list/explain smoke, page/per_page bounds.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use helpers::{
    grab_pool, register_and_login_via_app, spin_up_dual_role_self_register,
    spin_up_tenant_with_role,
};
use serde_json::{Value, json};
use tower::ServiceExt;

// ── Test-only fixture helpers ─────────────────────────────────────────

async fn seed_plain_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json)
                  VALUES ('posts', '[\"select\"]')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '[\"select\"]';",
        )
    })
    .await
    .unwrap();
}

async fn seed_owner_scoped_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                owner_id TEXT REFERENCES _system_users(id),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json, owner_field, read_scope)
                  VALUES ('posts', '[\"select\"]', 'owner_id', 'own')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    owner_field = 'owner_id',
                    read_scope = 'own',
                    anon_caps_json = '[\"select\"]';",
        )
    })
    .await
    .unwrap();
}

async fn seed_posts_with_vector(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE docs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                embedding BLOB,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json, vector_fields_json)
                  VALUES ('docs', '[\"select\"]',
                          '[{\"name\":\"embedding\",\"dim\":3}]');",
        )
    })
    .await
    .unwrap();
}

async fn set_anon_caps_empty(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute(
            "UPDATE _system_collection_meta SET anon_caps_json = '[]' \
             WHERE collection_name = 'posts'",
            [],
        )
        .map(|_| ())
    })
    .await
    .unwrap();
}

async fn insert_post(app: &axum::Router, tid: &str, tok: &str, title: &str, score: i64) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"data": {"title": title, "score": score}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert {title} failed");
}

async fn post_list(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    coll: &str,
    body: Value,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/collections/{coll}/list"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn post_list_explain(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    coll: &str,
    body: Value,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/collections/{coll}/list/explain"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

// ──────────────────────────────────────────────────────────────────────
// Group 1 — Happy paths × callers
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn service_token_empty_body_returns_all_rows() {
    let (app, tok, dir) = spin_up_tenant_with_role("svc-empty", "service").await;
    seed_plain_posts(&dir, "svc-empty").await;
    insert_post(&app, "svc-empty", &tok, "first", 1).await;
    insert_post(&app, "svc-empty", &tok, "second", 2).await;
    let (status, v) = post_list(&app, "svc-empty", &tok, "posts", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["total"], 2);
    assert_eq!(v["records"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn service_token_with_filter_returns_matching_rows() {
    let (app, tok, dir) = spin_up_tenant_with_role("svc-filter", "service").await;
    seed_plain_posts(&dir, "svc-filter").await;
    insert_post(&app, "svc-filter", &tok, "alpha", 5).await;
    insert_post(&app, "svc-filter", &tok, "beta", 10).await;
    insert_post(&app, "svc-filter", &tok, "gamma", 15).await;
    let (status, v) = post_list(
        &app,
        "svc-filter",
        &tok,
        "posts",
        json!({"filter": {"score": {"gt": 5}}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["total"], 2);
    let rows = v["records"].as_array().unwrap();
    let titles: Vec<&str> = rows.iter().map(|r| r["title"].as_str().unwrap()).collect();
    assert!(titles.contains(&"beta"));
    assert!(titles.contains(&"gamma"));
    assert!(!titles.contains(&"alpha"));
}

#[tokio::test]
async fn service_token_with_sort_asc_orders_rows() {
    let (app, tok, dir) = spin_up_tenant_with_role("svc-sort", "service").await;
    seed_plain_posts(&dir, "svc-sort").await;
    insert_post(&app, "svc-sort", &tok, "z", 1).await;
    insert_post(&app, "svc-sort", &tok, "a", 2).await;
    insert_post(&app, "svc-sort", &tok, "m", 3).await;
    let (status, v) = post_list(
        &app,
        "svc-sort",
        &tok,
        "posts",
        json!({"sort": {"field": "title", "dir": "asc"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = v["records"].as_array().unwrap();
    let titles: Vec<&str> = rows.iter().map(|r| r["title"].as_str().unwrap()).collect();
    assert_eq!(titles, vec!["a", "m", "z"]);
}

#[tokio::test]
async fn anon_with_cap_can_list() {
    // dual-role tenant: anon token has anon_caps_json='[\"select\"]'.
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("anon-list").await;
    seed_plain_posts(&dir, &tid).await;
    insert_post(&app, &tid, &_svc, "anon-1", 1).await;
    let (status, v) = post_list(&app, &tid, &anon, "posts", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["total"], 1);
}

#[tokio::test]
async fn user_on_owner_scoped_sees_only_own_rows() {
    // User-A creates two rows; user-B creates one. User-A's POST /list
    // must return exactly two.
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("user-owner-list").await;
    seed_owner_scoped_posts(&dir, &tid).await;
    let _ = svc; // unused — we use user tokens
    let user_a = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let user_b = register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;
    insert_post(&app, &tid, &user_a, "a-1", 1).await;
    insert_post(&app, &tid, &user_a, "a-2", 2).await;
    insert_post(&app, &tid, &user_b, "b-1", 1).await;
    let (status, v) = post_list(&app, &tid, &user_a, "posts", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["total"], 2, "user A should see 2 own rows: {v:?}");
    for row in v["records"].as_array().unwrap() {
        let title = row["title"].as_str().unwrap();
        assert!(title.starts_with("a-"), "leaked foreign row: {row:?}");
    }
}

#[tokio::test]
async fn user_on_non_owner_scoped_governed_by_user_caps() {
    // v1.41: plain (non-owner-scoped) `posts` with no explicit user_caps →
    // default user_caps=[select] lets the User /list (no longer "inherits anon").
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("user-non-owner").await;
    seed_plain_posts(&dir, &tid).await;
    let user_a = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    insert_post(&app, &tid, &svc, "row-1", 1).await;
    let (status, v) = post_list(&app, &tid, &user_a, "posts", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["total"], 1);
}

#[tokio::test]
async fn happy_path_select_projects_columns() {
    let (app, tok, dir) = spin_up_tenant_with_role("svc-select", "service").await;
    seed_plain_posts(&dir, "svc-select").await;
    insert_post(&app, "svc-select", &tok, "x", 1).await;
    let (status, v) = post_list(
        &app,
        "svc-select",
        &tok,
        "posts",
        json!({"select": ["id", "title"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let row = &v["records"][0];
    assert!(row["id"].is_i64());
    assert!(row["title"].is_string());
    assert!(row.get("score").is_none(), "score not in select: {row:?}");
    assert!(row.get("created_at").is_none(), "created_at not in select");
}

#[tokio::test]
async fn happy_path_filter_and_sort_combined() {
    let (app, tok, dir) = spin_up_tenant_with_role("svc-combo", "service").await;
    seed_plain_posts(&dir, "svc-combo").await;
    insert_post(&app, "svc-combo", &tok, "alpha", 5).await;
    insert_post(&app, "svc-combo", &tok, "beta", 10).await;
    insert_post(&app, "svc-combo", &tok, "gamma", 15).await;
    let (status, v) = post_list(
        &app,
        "svc-combo",
        &tok,
        "posts",
        json!({
            "filter": {"score": {"gte": 10}},
            "sort": {"field": "score", "dir": "desc"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let titles: Vec<&str> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, vec!["gamma", "beta"]);
}

// ──────────────────────────────────────────────────────────────────────
// Group 2 — owner_field strict enforcement
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_filter_without_owner_clause_still_scoped() {
    let (app, tid, _svc, _anon, dir) = spin_up_dual_role_self_register("owner-strict").await;
    seed_owner_scoped_posts(&dir, &tid).await;
    let user_a = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let user_b = register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;
    insert_post(&app, &tid, &user_a, "a-low", 1).await;
    insert_post(&app, &tid, &user_a, "a-high", 100).await;
    insert_post(&app, &tid, &user_b, "b-high", 100).await;
    // User A filters by score ≥ 100 — should still see only a-high, NOT b-high.
    let (status, v) = post_list(
        &app,
        &tid,
        &user_a,
        "posts",
        json!({"filter": {"score": {"gte": 100}}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["total"], 1, "owner scope must hold: {v:?}");
    assert_eq!(v["records"][0]["title"], "a-high");
}

// ──────────────────────────────────────────────────────────────────────
// Group 3 — owner_field bypass attempt
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_filter_targeting_owner_field_yields_empty_intersection() {
    let (app, tid, _svc, _anon, dir) = spin_up_dual_role_self_register("owner-bypass").await;
    seed_owner_scoped_posts(&dir, &tid).await;
    let user_a = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let user_b = register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;
    insert_post(&app, &tid, &user_a, "a-1", 1).await;
    insert_post(&app, &tid, &user_b, "b-1", 1).await;
    // User A explicitly filters owner_id = "u-anything"; the auto-appended
    // AND owner_id = <user_a's id> clause means the conjunction can only
    // be non-empty for user_a's own id. If they put a foreign id, the
    // intersection is empty — they cannot escape the gate.
    let (status, v) = post_list(
        &app,
        &tid,
        &user_a,
        "posts",
        json!({"filter": {"owner_id": "u-not-real"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["total"], 0, "bypass attempt must yield empty: {v:?}");
}

// ──────────────────────────────────────────────────────────────────────
// Group 4 — SQL-injection attempts in filter
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn filter_inj_double_dash_returns_unknown_field() {
    let (app, tok, dir) = spin_up_tenant_with_role("inj-dash", "service").await;
    seed_plain_posts(&dir, "inj-dash").await;
    let (status, v) = post_list(
        &app,
        "inj-dash",
        &tok,
        "posts",
        json!({"filter": {"--": 1}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "FILTER_UNKNOWN_FIELD");
}

#[tokio::test]
async fn filter_inj_semicolon_drop_returns_unknown_field() {
    let (app, tok, dir) = spin_up_tenant_with_role("inj-drop", "service").await;
    seed_plain_posts(&dir, "inj-drop").await;
    let (status, v) = post_list(
        &app,
        "inj-drop",
        &tok,
        "posts",
        json!({"filter": {";DROP": 1}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "FILTER_UNKNOWN_FIELD");
}

#[tokio::test]
async fn filter_inj_quote_or_returns_unknown_field() {
    let (app, tok, dir) = spin_up_tenant_with_role("inj-quote", "service").await;
    seed_plain_posts(&dir, "inj-quote").await;
    let (status, v) = post_list(
        &app,
        "inj-quote",
        &tok,
        "posts",
        json!({"filter": {"\"OR 1=1": 1}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "FILTER_UNKNOWN_FIELD");
}

// ──────────────────────────────────────────────────────────────────────
// Group 5 — SQL-injection attempts in sort
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sort_inj_drop_returns_sort_field_unknown() {
    let (app, tok, dir) = spin_up_tenant_with_role("sort-inj", "service").await;
    seed_plain_posts(&dir, "sort-inj").await;
    let (status, v) = post_list(
        &app,
        "sort-inj",
        &tok,
        "posts",
        json!({"sort": {"field": "id; DROP TABLE posts", "dir": "asc"}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "SORT_FIELD_UNKNOWN");
}

// ──────────────────────────────────────────────────────────────────────
// Group 6 — Vector field blocks
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn filter_on_vector_field_returns_filter_vector_field() {
    let (app, tok, dir) = spin_up_tenant_with_role("vec-filter", "service").await;
    seed_posts_with_vector(&dir, "vec-filter").await;
    let (status, v) = post_list(
        &app,
        "vec-filter",
        &tok,
        "docs",
        json!({"filter": {"embedding": [0.0, 0.0, 0.0]}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "FILTER_VECTOR_FIELD");
}

#[tokio::test]
async fn sort_on_vector_field_returns_sort_vector_field() {
    let (app, tok, dir) = spin_up_tenant_with_role("vec-sort", "service").await;
    seed_posts_with_vector(&dir, "vec-sort").await;
    let (status, v) = post_list(
        &app,
        "vec-sort",
        &tok,
        "docs",
        json!({"sort": {"field": "embedding", "dir": "asc"}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "SORT_VECTOR_FIELD");
}

#[tokio::test]
async fn select_with_vector_drops_silently_from_response() {
    let (app, tok, dir) = spin_up_tenant_with_role("vec-select", "service").await;
    seed_posts_with_vector(&dir, "vec-select").await;
    // Insert a row WITHOUT touching the embedding column (set_realtime is
    // off by default but that doesn't affect /list).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/vec-select/records/docs")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"data": {"title": "x"}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let (status, v) = post_list(
        &app,
        "vec-select",
        &tok,
        "docs",
        json!({"select": ["id", "title", "embedding"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let row = &v["records"][0];
    assert!(
        row.get("embedding").is_none(),
        "vector must be dropped: {row:?}"
    );
    assert_eq!(row["title"], "x");
}

// ──────────────────────────────────────────────────────────────────────
// Group 7 — _system_* → 404 for every caller
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn system_collection_404_for_service() {
    let (app, tok, dir) = spin_up_tenant_with_role("sys-svc", "service").await;
    seed_plain_posts(&dir, "sys-svc").await;
    let (status, v) = post_list(&app, "sys-svc", &tok, "_system_users", json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error_code"], "COLLECTION_NOT_FOUND");
}

#[tokio::test]
async fn system_collection_404_for_anon() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("sys-anon").await;
    seed_plain_posts(&dir, &tid).await;
    let (status, v) = post_list(&app, &tid, &anon, "_system_users", json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error_code"], "COLLECTION_NOT_FOUND");
}

#[tokio::test]
async fn system_collection_404_for_user() {
    let (app, tid, _svc, _anon, dir) = spin_up_dual_role_self_register("sys-user").await;
    seed_plain_posts(&dir, &tid).await;
    let user_a = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let (status, v) = post_list(&app, &tid, &user_a, "_system_users", json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error_code"], "COLLECTION_NOT_FOUND");
}

// ──────────────────────────────────────────────────────────────────────
// Group 8 — anon_caps=[] → 403 ANON_CAP_DENIED
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn anon_empty_caps_returns_anon_cap_denied() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("anon-nocap").await;
    seed_plain_posts(&dir, &tid).await;
    set_anon_caps_empty(&dir, &tid).await;
    let (status, v) = post_list(&app, &tid, &anon, "posts", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(v["error_code"], "ANON_CAP_DENIED");
}

// ──────────────────────────────────────────────────────────────────────
// Group 9 — ANON_FORBIDDEN_OWNER_SCOPED
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn anon_on_owner_scoped_returns_owner_scoped_anon_denied() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("anon-owner").await;
    seed_owner_scoped_posts(&dir, &tid).await;
    let (status, v) = post_list(&app, &tid, &anon, "posts", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(v["error_code"], "ANON_FORBIDDEN_OWNER_SCOPED");
}

// ──────────────────────────────────────────────────────────────────────
// Group 10 — /list/explain smoke
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn explain_service_returns_plan() {
    let (app, tok, dir) = spin_up_tenant_with_role("explain-svc", "service").await;
    seed_plain_posts(&dir, "explain-svc").await;
    let (status, v) = post_list_explain(&app, "explain-svc", &tok, "posts", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(v["plan"].is_array(), "plan must be array: {v:?}");
    assert!(!v["plan"].as_array().unwrap().is_empty(), "plan empty");
}

#[tokio::test]
async fn explain_anon_returns_explain_requires_service() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("explain-anon").await;
    seed_plain_posts(&dir, &tid).await;
    let (status, v) = post_list_explain(&app, &tid, &anon, "posts", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(v["error_code"], "EXPLAIN_REQUIRES_SERVICE");
}

// ──────────────────────────────────────────────────────────────────────
// Group 11 — page/per_page bounds
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn per_page_zero_returns_page_range_invalid() {
    let (app, tok, dir) = spin_up_tenant_with_role("pp-zero", "service").await;
    seed_plain_posts(&dir, "pp-zero").await;
    let (status, v) = post_list(&app, "pp-zero", &tok, "posts", json!({"per_page": 0})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error_code"], "PAGE_RANGE_INVALID");
}

#[tokio::test]
async fn per_page_over_500_returns_page_range_invalid() {
    let (app, tok, dir) = spin_up_tenant_with_role("pp-501", "service").await;
    seed_plain_posts(&dir, "pp-501").await;
    let (status, v) = post_list(&app, "pp-501", &tok, "posts", json!({"per_page": 501})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error_code"], "PAGE_RANGE_INVALID");
}

#[tokio::test]
async fn page_zero_returns_page_range_invalid() {
    let (app, tok, dir) = spin_up_tenant_with_role("page-zero", "service").await;
    seed_plain_posts(&dir, "page-zero").await;
    let (status, v) = post_list(&app, "page-zero", &tok, "posts", json!({"page": 0})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error_code"], "PAGE_RANGE_INVALID");
}

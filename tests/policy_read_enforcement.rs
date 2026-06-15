//! RLS Phase 4 (Read) — explicit-policy USING enforcement on `/list` and
//! `/search`.
//!
//! A `select` policy `{"using":{"status":"published"}}` must filter the
//! `POST /t/<id>/collections/<c>/list` result for non-service callers
//! (anon / user) while the service token bypasses it entirely. The USING
//! AND-composes alongside the (here absent) owner clause; owner_field
//! behaviour is unchanged.
//!
//! Until Task 17 (the REST `set_policy`) lands, policies are written
//! directly via `storage::schema::write_policy` + `schema_cache.invalidate`
//! per the plan's Test Harness appendix.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::storage::schema::DmlVerb;
use helpers::{grab_pool, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use tower::ServiceExt;

// ── Fixtures ──────────────────────────────────────────────────────────

/// `posts(status TEXT, body TEXT)` with anon select cap, no owner_field.
async fn seed_status_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                body TEXT,
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

/// Write a select-policy USING directly (pre-Task-17) + invalidate cache.
async fn set_select_using(dir: &tempfile::TempDir, tenant: &str, coll: &str, policy_json: Value) {
    let pool = grab_pool(tenant, dir).await;
    let policy: drust::query::policy::Policy = serde_json::from_value(policy_json).unwrap();
    let coll_owned = coll.to_string();
    pool.with_writer(move |c| {
        drust::storage::schema::write_policy(c, &coll_owned, DmlVerb::Select, Some(&policy))
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate(coll);
}

async fn insert_post(app: &axum::Router, tid: &str, tok: &str, status: &str, body: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"data": {"status": status, "body": body}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert {status} failed");
}

/// `POST /t/<id>/records/posts` → the new row's `id` from the 201 body.
async fn insert_post_returning_id(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    status: &str,
    body: &str,
) -> i64 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"data": {"status": status, "body": body}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert {status} failed");
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["id"].as_i64().expect("create body has numeric id")
}

/// `GET /t/<id>/records/<coll>/<row_id>` → just the HTTP status.
async fn get_one_status(app: &axum::Router, tid: &str, tok: &str, coll: &str, row_id: i64) -> u16 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/{coll}/{row_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

/// Bare `GET /t/<id>/records/<coll>` (legacy list path, no query string) →
/// the `records` array. Asserts 200.
async fn get_list_records(app: &axum::Router, tid: &str, tok: &str, coll: &str) -> Vec<Value> {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/{coll}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET list {coll} non-OK");
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["records"].as_array().cloned().unwrap_or_default()
}

/// `GET /t/<id>/records/<coll>?<query>` → just the HTTP status code.
async fn get_list_status(app: &axum::Router, tid: &str, tok: &str, coll: &str, query: &str) -> u16 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/{coll}?{query}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

/// `POST /t/<id>/collections/posts/list` → the `records` array.
async fn list_records(app: &axum::Router, tid: &str, tok: &str, coll: &str) -> Vec<Value> {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/collections/{coll}/list"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "list {coll} non-OK");
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["records"].as_array().cloned().unwrap_or_default()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn anon_list_filtered_by_select_policy() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("rls-read-list").await;
    seed_status_posts(&dir, &tid).await;
    // Set the policy BEFORE any router read so the router's own per-pool
    // schema_cache never caches a policy-free view (the test harness pool
    // from grab_pool is a SEPARATE registry/cache instance).
    set_select_using(
        &dir,
        &tid,
        "posts",
        json!({"using": {"status": "published"}}),
    )
    .await;

    // Service inserts both rows.
    insert_post(&app, &tid, &svc, "published", "a").await;
    insert_post(&app, &tid, &svc, "draft", "b").await;

    // Anon: only the published row.
    let anon_rows = list_records(&app, &tid, &anon, "posts").await;
    assert_eq!(anon_rows.len(), 1, "anon should see only published");
    assert_eq!(anon_rows[0]["status"], "published");

    // Service bypasses the policy: both rows.
    let svc_rows = list_records(&app, &tid, &svc, "posts").await;
    assert_eq!(svc_rows.len(), 2, "service bypasses the select policy");
}

#[tokio::test]
async fn anon_search_filtered_by_select_policy() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("rls-read-search").await;
    // posts with a vector field so /search has something to scan.
    let pool = grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                embedding BLOB,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json, vector_fields_json)
                  VALUES ('posts', '[\"select\"]',
                          '[{\"name\":\"embedding\",\"dim\":3}]');",
        )
    })
    .await
    .unwrap();
    drop(pool);

    // Set the policy BEFORE any router read (see the list test for why).
    set_select_using(
        &dir,
        &tid,
        "posts",
        json!({"using": {"status": "published"}}),
    )
    .await;

    // Insert two rows with embeddings (service token).
    for (status, vec) in [("published", [1.0, 0.0, 0.0]), ("draft", [0.0, 1.0, 0.0])] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/t/{tid}/records/posts"))
                    .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"data": {"status": status, "embedding": vec}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "insert {status} failed");
    }

    let search = |tok: String| {
        let app = app.clone();
        let tid = tid.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/t/{tid}/collections/posts/search"))
                        .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({"field": "embedding", "vector": [1.0, 0.0, 0.0], "k": 10})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "search non-OK");
            let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            v["rows"].as_array().cloned().unwrap_or_default()
        }
    };

    let anon_hits = search(anon.clone()).await;
    assert_eq!(anon_hits.len(), 1, "anon search filtered to published");
    assert_eq!(anon_hits[0]["status"], "published");

    let svc_hits = search(svc.clone()).await;
    assert_eq!(svc_hits.len(), 2, "service search bypasses select policy");
}

#[tokio::test]
async fn anon_get_one_blocked_by_select_policy() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("rls-read-getone").await;
    seed_status_posts(&dir, &tid).await;
    // Policy must be set before any router read caches a policy-free view.
    set_select_using(
        &dir,
        &tid,
        "posts",
        json!({"using": {"status": "published"}}),
    )
    .await;

    // Service inserts both rows and records their ids.
    let draft_id = insert_post_returning_id(&app, &tid, &svc, "draft", "b").await;
    let published_id = insert_post_returning_id(&app, &tid, &svc, "published", "a").await;

    // Anon: the draft is invisible under the published-only USING → 404.
    let draft_status = get_one_status(&app, &tid, &anon, "posts", draft_id).await;
    assert_eq!(
        draft_status, 404,
        "anon must not see a draft under a published-only policy"
    );

    // Anon: the published row passes the USING → 200.
    let published_status = get_one_status(&app, &tid, &anon, "posts", published_id).await;
    assert_eq!(
        published_status, 200,
        "anon may see the published row under the policy"
    );

    // Service bypasses the policy → the draft is visible (200).
    let svc_status = get_one_status(&app, &tid, &svc, "posts", draft_id).await;
    assert_eq!(
        svc_status, 200,
        "service bypasses the select policy on GET-one"
    );
}

// ── H1: legacy GET-list must enforce the select-policy USING ────────────

/// H1 (a) + (b): the legacy bare `GET /records/<coll>` list path must apply
/// the explicit select-policy USING for non-service callers (it previously
/// applied only the owner clause), and the service token must bypass it.
#[tokio::test]
async fn anon_get_list_filtered_by_select_policy() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("rls-getlist-policy").await;
    seed_status_posts(&dir, &tid).await;
    // Policy set before any router read caches a policy-free view.
    set_select_using(
        &dir,
        &tid,
        "posts",
        json!({"using": {"status": "published"}}),
    )
    .await;

    // Service inserts both rows.
    insert_post(&app, &tid, &svc, "published", "a").await;
    insert_post(&app, &tid, &svc, "draft", "b").await;

    // (a) Anon bare GET-list: only the published row passes the USING.
    let anon_rows = get_list_records(&app, &tid, &anon, "posts").await;
    assert_eq!(
        anon_rows.len(),
        1,
        "anon GET-list should see only the published row under the policy"
    );
    assert_eq!(anon_rows[0]["status"], "published");

    // (b) Service bypasses the policy on the same GET-list path: both rows.
    let svc_rows = get_list_records(&app, &tid, &svc, "posts").await;
    assert_eq!(
        svc_rows.len(),
        2,
        "service GET-list bypasses the select policy"
    );
}

/// H1 (c): raw `?filter` / `?sort` on a policy-protected collection must be
/// refused for anon (those interpolate verbatim and a trailing `--` could
/// comment the AND-ed policy clause away) → 403 `ANON_QUERY_DENIED_ON_POLICY`.
#[tokio::test]
async fn anon_get_list_raw_filter_sort_denied_on_policy() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("rls-getlist-rawdeny").await;
    seed_status_posts(&dir, &tid).await;
    set_select_using(
        &dir,
        &tid,
        "posts",
        json!({"using": {"status": "published"}}),
    )
    .await;

    let filter_status = get_list_status(&app, &tid, &anon, "posts", "filter=status='draft'").await;
    assert_eq!(
        filter_status, 403,
        "anon raw ?filter on a policy collection must be 403"
    );

    let sort_status = get_list_status(&app, &tid, &anon, "posts", "sort=-status").await;
    assert_eq!(
        sort_status, 403,
        "anon raw ?sort on a policy collection must be 403"
    );
}

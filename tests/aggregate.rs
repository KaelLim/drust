//! v1.54 — REST `POST /aggregate` tests (SQLite Wave 1 M1).
//!
//! `/aggregate` reuses `records_list::compute_read_auth` +
//! `list_builder::build_where_clause` verbatim with `/list`, so its
//! owner/policy/cap row-authorization is in lockstep by construction. These
//! tests pin that: a User only aggregates their own rows, anon on an
//! owner-scoped collection is denied, anon obeys `anon_caps` on a plain
//! collection, and the service key aggregates everything.

#[path = "helpers.rs"]
mod helpers;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::storage::schema::{DmlVerb, write_anon_caps};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use tempfile::TempDir;
use tower::ServiceExt;

fn req(method: &str, tid: &str, path: &str, body: Option<Value>, token: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(
        body.map(|v| Body::from(v.to_string()))
            .unwrap_or(Body::empty()),
    )
    .unwrap()
}

async fn read_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn agg(app: &Router, tid: &str, body: Value, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(req(
            "POST",
            tid,
            "/collections/posts/aggregate",
            Some(body),
            token,
        ))
        .await
        .unwrap()
}

async fn create_row(app: &Router, tid: &str, data: Value, token: &str) {
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            tid,
            "/records/posts",
            Some(json!({ "data": data })),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "insert should 201, got {}",
        r.status()
    );
}

/// Plain (non-owner) `posts(status TEXT, score INTEGER)`. anon_caps default is
/// `[select]` (no meta row ⇒ default), so anon may read/aggregate by default.
async fn setup_plain(tname: &str) -> (Router, String, TempDir, String, String) {
    let (app, tid, svc, anon, dir) = helpers::spin_up_dual_role_self_register(tname).await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    helpers::create_collection_via_pool(
        &pool,
        "posts",
        &[("status", "text"), ("score", "integer")],
    )
    .await;
    (app, tid, dir, svc, anon)
}

/// Owner-scoped `posts(user_id FK, title, score)` with `read_scope="own"` and
/// two registered users. Mirrors `audit3_readscope_all_caps::setup_all`.
async fn setup_owner_own(tname: &str) -> (Router, String, TempDir, String, String, String, String) {
    let (app, tid, svc, anon, dir) = helpers::spin_up_dual_role_self_register(tname).await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE posts (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id    TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                 title      TEXT,
                 score      INTEGER,
                 created_at TEXT DEFAULT (datetime('now')),
                 updated_at TEXT DEFAULT (datetime('now'))
             );",
        )
    })
    .await
    .unwrap();
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": "own"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "set owner-field failed");
    let ta = helpers::register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let tb = helpers::register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;
    (app, tid, dir, svc, anon, ta, tb)
}

async fn set_anon_caps(dir: &TempDir, tid: &str, verbs: &[DmlVerb]) {
    let pool = helpers::grab_pool(tid, dir).await;
    let caps: BTreeSet<DmlVerb> = verbs.iter().copied().collect();
    pool.with_writer(move |c| write_anon_caps(c, "posts", &caps))
        .await
        .unwrap();
    pool.schema_cache.invalidate("posts");
}

async fn create_post(app: &Router, tid: &str, title: &str, score: i64, token: &str) {
    create_row(app, tid, json!({"title": title, "score": score}), token).await;
}

// ── service happy path ─────────────────────────────────────────────────────

#[tokio::test]
async fn service_count_group_by_and_filter() {
    let (app, tid, _dir, svc, _anon) = setup_plain("t-agg-svc").await;
    for (status, score) in &[("published", 10i64), ("published", 30), ("draft", 5)] {
        create_row(&app, &tid, json!({"status": status, "score": score}), &svc).await;
    }

    // count(*) over all rows
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"count","as":"n"}]}),
        &svc,
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(read_json(r).await["rows"][0]["n"], 3);

    // group_by status + sum(score), sorted by total desc
    let r = agg(
        &app,
        &tid,
        json!({
            "group_by": ["status"],
            "metrics": [{"op":"count","as":"n"}, {"op":"sum","field":"score","as":"total"}],
            "sort": {"field":"total","dir":"desc"}
        }),
        &svc,
    )
    .await;
    let v = read_json(r).await;
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "two status groups");
    assert_eq!(rows[0]["status"], "published");
    assert_eq!(rows[0]["n"], 2);
    assert_eq!(rows[0]["total"], 40);
    assert_eq!(rows[1]["status"], "draft");
    assert_eq!(rows[1]["total"], 5);

    // filter narrows the aggregate set
    let r = agg(
        &app,
        &tid,
        json!({"filter":{"score":{"gte":10}},"metrics":[{"op":"count","as":"n"}]}),
        &svc,
    )
    .await;
    assert_eq!(read_json(r).await["rows"][0]["n"], 2);
}

#[tokio::test]
async fn no_metrics_is_400() {
    let (app, tid, _dir, svc, _anon) = setup_plain("t-agg-nometrics").await;
    let r = agg(&app, &tid, json!({"metrics": []}), &svc).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(read_json(r).await.to_string().contains("AGG_NO_METRICS"));
}

#[tokio::test]
async fn missing_metrics_key_is_400_not_422() {
    // `metrics` carries #[serde(default)], so an omitted key deserializes to an
    // empty Vec and reaches the typed AGG_NO_METRICS 400 (not a generic 422).
    let (app, tid, _dir, svc, _anon) = setup_plain("t-agg-nokey").await;
    let r = agg(&app, &tid, json!({}), &svc).await;
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "missing metrics key must be a typed 400, not a serde 422"
    );
    assert!(read_json(r).await.to_string().contains("AGG_NO_METRICS"));
}

#[tokio::test]
async fn duplicate_output_column_is_400() {
    // Two metrics sharing an alias → AGG_ALIAS_DUPLICATE, never a silently
    // last-wins-overwritten row.
    let (app, tid, _dir, svc, _anon) = setup_plain("t-agg-dupcol").await;
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"count","as":"x"},{"op":"sum","field":"score","as":"x"}]}),
        &svc,
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(
        read_json(r)
            .await
            .to_string()
            .contains("AGG_ALIAS_DUPLICATE")
    );
}

// ── owner/user lockstep ─────────────────────────────────────────────────────

#[tokio::test]
async fn user_only_aggregates_own_rows() {
    let (app, tid, _dir, svc, _anon, ta, tb) = setup_owner_own("t-agg-own").await;
    create_post(&app, &tid, "a1", 10, &ta).await;
    create_post(&app, &tid, "a2", 20, &ta).await;
    create_post(&app, &tid, "b1", 100, &tb).await;

    // Alice → only her 2 rows (sum 30)
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"count","as":"n"},{"op":"sum","field":"score","as":"total"}]}),
        &ta,
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(v["rows"][0]["n"], 2, "alice sees only her rows");
    assert_eq!(v["rows"][0]["total"], 30);

    // Bob → only his row (sum 100)
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"sum","field":"score","as":"total"}]}),
        &tb,
    )
    .await;
    assert_eq!(read_json(r).await["rows"][0]["total"], 100);

    // Service → all 3 rows (sum 130), bypassing owner scope
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"count","as":"n"},{"op":"sum","field":"score","as":"total"}]}),
        &svc,
    )
    .await;
    let v = read_json(r).await;
    assert_eq!(v["rows"][0]["n"], 3, "service bypasses owner scope");
    assert_eq!(v["rows"][0]["total"], 130);
}

#[tokio::test]
async fn lockstep_list_total_equals_aggregate_count_for_user() {
    let (app, tid, _dir, _svc, _anon, ta, tb) = setup_owner_own("t-agg-lockstep").await;
    create_post(&app, &tid, "a1", 1, &ta).await;
    create_post(&app, &tid, "a2", 2, &ta).await;
    create_post(&app, &tid, "b1", 3, &tb).await;

    // /list total for Alice (owner clause → her rows only)
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/collections/posts/list",
            Some(json!({})),
            &ta,
        ))
        .await
        .unwrap();
    let list_total = read_json(r).await["total"].as_i64().unwrap();

    // /aggregate count for Alice must equal /list total — lockstep proof.
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"count","as":"n"}]}),
        &ta,
    )
    .await;
    let agg_count = read_json(r).await["rows"][0]["n"].as_i64().unwrap();

    assert_eq!(
        list_total, agg_count,
        "aggregate count must equal /list total (owner lockstep)"
    );
    assert_eq!(agg_count, 2);
}

#[tokio::test]
async fn anon_on_owner_scoped_is_denied() {
    let (app, tid, _dir, _svc, anon, _ta, _tb) = setup_owner_own("t-agg-anondeny").await;
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"count","as":"n"}]}),
        &anon,
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(
        read_json(r)
            .await
            .to_string()
            .contains("ANON_FORBIDDEN_OWNER_SCOPED")
    );
}

// ── anon cap gating (non-owner) ─────────────────────────────────────────────
//
// NOTE: these are two separate tests, each on a fresh app, because
// `set_anon_caps` writes through a *separate* `grab_pool` handle whose
// `schema_cache.invalidate` does not reach the app's in-memory cache (see the
// `grab_pool` note in helpers.rs). So a cap change must be observed on an app
// whose `posts` schema is NOT yet cached — the deny test avoids any prior
// request (the cap check fires before the SQL runs, so no row is needed), and
// the allow test relies on the meta-less default `[select]`.

#[tokio::test]
async fn anon_with_select_cap_can_aggregate() {
    // Meta-less collection ⇒ anon_caps default `[select]` ⇒ anon may aggregate.
    let (app, tid, _dir, svc, anon) = setup_plain("t-agg-anonallow").await;
    create_row(&app, &tid, json!({"status":"a","score":1}), &svc).await;
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"count","as":"n"}]}),
        &anon,
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "anon WITH default select cap may aggregate"
    );
    assert_eq!(read_json(r).await["rows"][0]["n"], 1);
}

#[tokio::test]
async fn anon_without_select_cap_is_denied() {
    // anon_caps=[] set BEFORE any request populates the app's schema cache, so
    // the aggregate reads the fresh `[]` from disk and the cap gate fires.
    let (app, tid, dir, _svc, anon) = setup_plain("t-agg-anondeny-cap").await;
    set_anon_caps(&dir, &tid, &[]).await;
    let r = agg(
        &app,
        &tid,
        json!({"metrics":[{"op":"count","as":"n"}]}),
        &anon,
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "anon WITHOUT select cap must be denied"
    );
    assert!(read_json(r).await.to_string().contains("ANON_CAP_DENIED"));
}

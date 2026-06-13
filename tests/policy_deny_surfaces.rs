//! RLS Phase 6 (Deny) — Task 15.
//!
//! drust cannot row-filter raw SQL (`/query`, `/query/explain`) or the legacy
//! `GET /records/<coll>?filter=…&sort=…` path (those interpolate verbatim and
//! are un-rewritable). So once a tenant adopts ANY row-level rule (an
//! `owner_field` OR any explicit per-op policy), the anon caller is denied on
//! those surfaces tenant-wide, pointed at `POST /collections/<c>/list` (or
//! `/search`) where drust builds the SQL with `?` binds. Service keeps full
//! access; the deny is anon-only.
//!
//! Until Task 17 (the REST `set_policy`) lands, policies are written directly
//! via `storage::schema::write_policy` + `schema_cache.invalidate` per the
//! plan's Test Harness appendix.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, header};
use drust::storage::schema::DmlVerb;
use helpers::{grab_pool, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use tower::ServiceExt;

// ── Fixtures ──────────────────────────────────────────────────────────

/// `posts(status TEXT)` with a `_system_collection_meta` row (default
/// `["select"]` anon caps), no owner_field, no policy.
async fn seed_status_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
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

/// Write a policy for `op` directly (pre-Task-17) + invalidate the cache.
async fn set_policy(
    dir: &tempfile::TempDir,
    tenant: &str,
    coll: &str,
    op: DmlVerb,
    policy_json: Value,
) {
    let pool = grab_pool(tenant, dir).await;
    let policy: drust::query::policy::Policy = serde_json::from_value(policy_json).unwrap();
    let coll_owned = coll.to_string();
    pool.with_writer(move |c| {
        drust::storage::schema::write_policy(c, &coll_owned, op, Some(&policy))
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate(coll);
}

/// Set `owner_field` directly (pre-Task-17) + invalidate the cache.
async fn set_owner(dir: &tempfile::TempDir, tenant: &str, coll: &str, field: &str) {
    let pool = grab_pool(tenant, dir).await;
    let coll_owned = coll.to_string();
    let field_owned = field.to_string();
    pool.with_writer(move |c| {
        drust::storage::schema::set_owner_field(c, &coll_owned, Some(&field_owned), Some("own"))
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate(coll);
}

// ── Drivers ───────────────────────────────────────────────────────────

/// `POST /t/<id>/query` → just the HTTP status.
async fn query_status(app: &axum::Router, tid: &str, tok: &str, sql: &str) -> u16 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/query"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::from(json!({"sql": sql}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

/// `POST /t/<id>/query/explain` → just the HTTP status.
async fn explain_status(app: &axum::Router, tid: &str, tok: &str, sql: &str) -> u16 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/query/explain"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::from(json!({"sql": sql}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

/// `GET /t/<id>/records/posts?<qs>` → just the HTTP status.
async fn list_legacy_status(app: &axum::Router, tid: &str, tok: &str, qs: &str) -> u16 {
    let uri = if qs.is_empty() {
        format!("/t/{tid}/records/posts")
    } else {
        format!("/t/{tid}/records/posts?{qs}")
    };
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn anon_query_denied_when_tenant_has_policy() {
    let tenant = "t-deny1";
    let (app, _tid, svc_tok, anon_tok, dir) = spin_up_dual_role_self_register(tenant).await;
    seed_status_posts(&dir, tenant).await;

    // No policy yet → anon /query works.
    assert_eq!(
        query_status(&app, tenant, &anon_tok, "SELECT * FROM posts").await,
        200,
        "anon /query should work before any policy"
    );

    set_policy(
        &dir,
        tenant,
        "posts",
        DmlVerb::Select,
        json!({"using": {"status": "published"}}),
    )
    .await;

    // Now anon /query is denied tenant-wide.
    assert_eq!(
        query_status(&app, tenant, &anon_tok, "SELECT * FROM posts").await,
        403,
        "anon /query should be denied once the tenant has a policy"
    );
    // Service /query still works.
    assert_eq!(
        query_status(&app, tenant, &svc_tok, "SELECT * FROM posts").await,
        200,
        "service /query must keep full access"
    );
}

#[tokio::test]
async fn anon_query_denied_when_tenant_has_owner_field() {
    let tenant = "t-deny2";
    let (app, _tid, svc_tok, anon_tok, dir) = spin_up_dual_role_self_register(tenant).await;
    seed_status_posts(&dir, tenant).await;

    assert_eq!(
        query_status(&app, tenant, &anon_tok, "SELECT * FROM posts").await,
        200
    );
    set_owner(&dir, tenant, "posts", "owner").await;
    assert_eq!(
        query_status(&app, tenant, &anon_tok, "SELECT * FROM posts").await,
        403,
        "owner_field alone must also gate anon /query"
    );
    assert_eq!(
        query_status(&app, tenant, &svc_tok, "SELECT * FROM posts").await,
        200
    );
}

#[tokio::test]
async fn anon_explain_denied_when_tenant_has_policy() {
    let tenant = "t-deny3";
    let (app, _tid, svc_tok, anon_tok, dir) = spin_up_dual_role_self_register(tenant).await;
    seed_status_posts(&dir, tenant).await;

    assert_eq!(
        explain_status(&app, tenant, &anon_tok, "SELECT * FROM posts").await,
        200
    );
    set_policy(
        &dir,
        tenant,
        "posts",
        DmlVerb::Select,
        json!({"using": {"status": "published"}}),
    )
    .await;
    assert_eq!(
        explain_status(&app, tenant, &anon_tok, "SELECT * FROM posts").await,
        403,
        "anon /query/explain should be denied once the tenant has a policy"
    );
    assert_eq!(
        explain_status(&app, tenant, &svc_tok, "SELECT * FROM posts").await,
        200,
        "service /query/explain must keep full access"
    );
}

/// Baseline: with NO policy/owner anywhere, anon legacy `?filter` works.
/// (Separate tenant so the schema cache is never warmed with a policy — the
/// test `grab_pool` uses a separate registry/cache and cannot invalidate the
/// running app's cache, so the policy must be on disk before the first app
/// load of that collection; mixing both phases on one collection is unsafe.)
#[tokio::test]
async fn anon_legacy_filter_allowed_without_policy() {
    let tenant = "t-deny4a";
    let (app, _tid, _svc_tok, anon_tok, dir) = spin_up_dual_role_self_register(tenant).await;
    seed_status_posts(&dir, tenant).await;

    assert_eq!(
        list_legacy_status(&app, tenant, &anon_tok, "filter=status%3D%27x%27").await,
        200,
        "anon legacy ?filter should work when no policy/owner is set"
    );
}

#[tokio::test]
async fn anon_legacy_filter_denied_on_policy_collection() {
    let tenant = "t-deny4";
    let (app, _tid, svc_tok, anon_tok, dir) = spin_up_dual_role_self_register(tenant).await;
    seed_status_posts(&dir, tenant).await;
    // Write the policy to disk BEFORE the first app call touches `posts`, so
    // the running app's schema_cache picks it up on first load (grab_pool's
    // cache is a separate instance and cannot invalidate the app's cache).
    set_policy(
        &dir,
        tenant,
        "posts",
        DmlVerb::Select,
        json!({"using": {"status": "published"}}),
    )
    .await;

    // ?filter is denied for anon on the policy-protected collection.
    assert_eq!(
        list_legacy_status(&app, tenant, &anon_tok, "filter=status%3D%27x%27").await,
        403,
        "anon ?filter on a policy-protected collection must be denied"
    );
    // ?sort is denied too.
    assert_eq!(
        list_legacy_status(&app, tenant, &anon_tok, "sort=-created_at").await,
        403,
        "anon ?sort on a policy-protected collection must be denied"
    );
    // A plain list with no filter/sort still works for anon (select cap).
    assert_eq!(
        list_legacy_status(&app, tenant, &anon_tok, "").await,
        200,
        "anon plain list (no filter/sort) must still work"
    );
    // Service keeps raw filter access.
    assert_eq!(
        list_legacy_status(&app, tenant, &svc_tok, "filter=status%3D%27x%27").await,
        200,
        "service ?filter must keep full access"
    );
}

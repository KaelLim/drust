//! v1.58 P1-8 — an UPDATE may not grow a tenant past its hard cap, but must
//! never block a shrink.
//!
//! Every update path was exempt from quota. The documented reason was that a
//! shrink or recovery write must never be blocked — which justifies "do not
//! reject a smaller row", not "accept unbounded growth". Repeatedly overwriting
//! one row with a larger payload could exceed the cap without limit.
//!
//! Four cells, and the two that must stay OPEN are the point of these tests:
//! a shrink from over the cap (the recovery write) and growth that stays under
//! the cap. A fix that closes either of those is worse than the bug.
//!
//! The pure matrix pins the decision. The end-to-end half then pins it at all
//! THREE wired update sites — MCP/edge, REST, and the upsert conflict branch —
//! because this is an enumeration invariant: a site that forgets the gate looks
//! locally correct.

mod helpers;

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::batch::batch_upsert;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::write::{insert_record, update_record};
use drust::storage::pool::TenantRegistry;
use drust::storage::quota::{QuotaError, decide_update_growth};
use drust::storage::record_history::AuditActor;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// The pure four-cell matrix
// ---------------------------------------------------------------------------

/// tier 1 = 10 GiB, and `check_tenant_quota` clamps tier to a minimum of 1.
const TIER: i64 = 1;
const CAP: u64 = 10 * 1024 * 1024 * 1024;

#[test]
fn shrink_while_over_cap_is_allowed() {
    // The recovery case: already over the cap, and this write makes it smaller.
    // Blocking it would strand the tenant with no way back under.
    assert!(decide_update_growth(CAP + 5_000, CAP + 1_000, TIER).is_ok());
}

#[test]
fn a_no_op_update_while_over_cap_is_allowed() {
    assert!(decide_update_growth(CAP + 5_000, CAP + 5_000, TIER).is_ok());
}

#[test]
fn growth_that_stays_under_cap_is_allowed() {
    assert!(decide_update_growth(1_000, 2_000, TIER).is_ok());
}

#[test]
fn growth_that_crosses_the_cap_is_refused() {
    let r = decide_update_growth(CAP - 1_000, CAP + 1, TIER);
    assert!(
        matches!(r, Err(QuotaError::TenantQuotaExceeded { .. })),
        "an update that grows past the cap must be refused, got {r:?}"
    );
}

#[test]
fn growth_while_already_over_cap_is_refused() {
    // Distinct from the shrink case above: over the cap AND getting bigger.
    let r = decide_update_growth(CAP + 1_000, CAP + 9_000, TIER);
    assert!(matches!(r, Err(QuotaError::TenantQuotaExceeded { .. })));
}

#[test]
fn growth_exactly_to_the_cap_is_allowed() {
    // The hard cap rejects the write that PASSES it, not the one that reaches
    // it exactly — same boundary `check_tenant_quota` already documents.
    assert!(decide_update_growth(CAP - 1, CAP, TIER).is_ok());
}

// ---------------------------------------------------------------------------
// End-to-end: the same four cells at each of the three wired update sites.
//
// Pushing a tenant over the tier-1 cap without materialising 10 GiB is the
// established trick from tests/tenant_quota_db.rs: one oversized
// `_system_files` metadata row, which `usage_on_conn` sums verbatim. A record
// UPDATE cannot change `files_bytes`, so the growth the gate sees is purely the
// tenant db's page-count delta — exactly what the production check measures.
// ---------------------------------------------------------------------------

/// 11 GiB of pretend uploaded bytes — over the tier-1 (10 GiB) cap on its own.
const OVER_CAP_FILLER: i64 = 11 * 1024 * 1024 * 1024;

fn tf(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: true,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

fn tfu(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        unique: true,
        ..tf(name, ty)
    }
}

async fn svc(dir: &tempfile::TempDir) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    McpRegistry::new(tr).get_or_create("blog").await.unwrap()
}

/// Inflate `_system_files` so the tenant reads as over its tier-1 cap.
async fn push_over_cap(dir: &tempfile::TempDir, tenant: &str) {
    let pool = helpers::grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute(
            "INSERT INTO \"_system_files\" (key, original_name, size_bytes, uploader) \
             VALUES ('quota-filler', 'filler', ?1, 'service')",
            rusqlite::params![OVER_CAP_FILLER],
        )
    })
    .await
    .unwrap();
}

/// Big enough that writing it must allocate pages beyond anything the earlier
/// value freed, so `page_count` genuinely grows inside the tx.
fn huge(tag: char) -> String {
    tag.to_string().repeat(4 * 1024 * 1024)
}

fn medium(tag: char) -> String {
    tag.to_string().repeat(200 * 1024)
}

// ---------------------------------------------------------------------------
// The same-length overwrite (adversarial review of the first cut).
//
// `huge('a')` and `huge('b')` differ in every byte and are byte-for-byte the
// same LENGTH, so the UPDATE frees exactly the overflow pages it re-allocates
// and `page_count` does not move. The growth is entirely the history row, which
// stores the full old AND new image (audit defaults on) — roughly twice the
// payload per request, forever, if the gate is measured before `capture`.
//
// Verified directly against sqlite3 before the fix: at the pre-capture
// measurement point `after == before` on every iteration (1028 → 1028), while
// the committed database grew 2050 pages (~8 MiB) each time.
// ---------------------------------------------------------------------------

// --- Site 1: MCP / edge (`update_record_checked`) --------------------------

#[tokio::test]
async fn mcp_update_over_cap_allows_shrink_but_refuses_growth() {
    let dir = tempfile::tempdir().unwrap();
    let s = svc(&dir).await;
    create_collection(&s, "blobs", &[tf("v", "text")])
        .await
        .unwrap();
    let rec = insert_record(&s, "blobs", serde_json::json!({ "v": medium('a') }))
        .await
        .unwrap();
    let id = rec["id"].as_i64().unwrap();

    push_over_cap(&dir, "blog").await;

    // OPEN: shrinking while over the cap is the recovery write.
    update_record(&s, "blobs", id, serde_json::json!({ "v": "x" }))
        .await
        .expect("a shrinking update must never be blocked, even over the cap");

    // CLOSED: growing while over the cap.
    let err = update_record(&s, "blobs", id, serde_json::json!({ "v": huge('b') }))
        .await
        .expect_err("an update that grows a tenant past its cap must be refused");
    assert!(
        err.to_string().contains("TENANT_QUOTA_EXCEEDED"),
        "expected the quota sentinel, got: {err}"
    );

    // The refused update must have rolled back — the row still holds "x".
    let after: String = helpers::grab_pool("blog", &dir)
        .await
        .with_reader(move |c| c.query_row("SELECT v FROM blobs WHERE id = ?1", [id], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(after, "x", "a quota-refused update must roll back");
}

#[tokio::test]
async fn mcp_same_length_overwrite_over_cap_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let s = svc(&dir).await;
    create_collection(&s, "blobs", &[tf("v", "text")])
        .await
        .unwrap();
    let rec = insert_record(&s, "blobs", serde_json::json!({ "v": huge('a') }))
        .await
        .unwrap();
    let id = rec["id"].as_i64().unwrap();

    push_over_cap(&dir, "blog").await;

    let err = update_record(&s, "blobs", id, serde_json::json!({ "v": huge('b') }))
        .await
        .expect_err(
            "a same-length overwrite still commits ~2x the payload as history \
             and must be refused over the cap",
        );
    assert!(
        err.to_string().contains("TENANT_QUOTA_EXCEEDED"),
        "expected the quota sentinel, got: {err}"
    );

    // Rolled back: neither the row nor a history row survives.
    let (v0, hist): (char, i64) = helpers::grab_pool("blog", &dir)
        .await
        .with_reader(move |c| {
            let v: String = c.query_row("SELECT v FROM blobs WHERE id = ?1", [id], |r| r.get(0))?;
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM _system_record_history WHERE op = 'update'",
                [],
                |r| r.get(0),
            )?;
            Ok((v.chars().next().unwrap(), n))
        })
        .await
        .unwrap();
    assert_eq!(v0, 'a', "a quota-refused overwrite must roll back");
    assert_eq!(hist, 0, "a rolled-back update must leave no history row");
}

#[tokio::test]
async fn mcp_update_growth_under_cap_is_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let s = svc(&dir).await;
    create_collection(&s, "blobs", &[tf("v", "text")])
        .await
        .unwrap();
    let rec = insert_record(&s, "blobs", serde_json::json!({ "v": "seed" }))
        .await
        .unwrap();
    let id = rec["id"].as_i64().unwrap();

    // OPEN: growth well under the 10 GiB cap is not the gate's business.
    update_record(&s, "blobs", id, serde_json::json!({ "v": huge('c') }))
        .await
        .expect("growth under the cap must not be blocked");
    update_record(&s, "blobs", id, serde_json::json!({ "v": "small again" }))
        .await
        .expect("shrink under the cap must not be blocked");
}

// --- Site 2: REST (`update_handler`) ---------------------------------------

#[tokio::test]
async fn rest_update_over_cap_allows_shrink_but_refuses_growth() {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use tower::ServiceExt;

    let (app, tok, dir) = helpers::spin_up_tenant("blog").await;
    let pool = helpers::grab_pool("blog", &dir).await;
    let seed = medium('a');
    let id: i64 = pool
        .with_writer(move |c| {
            c.execute_batch(
                "CREATE TABLE posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );",
            )?;
            c.execute("INSERT INTO posts (title) VALUES (?1)", [&seed])?;
            Ok(c.last_insert_rowid())
        })
        .await
        .unwrap();

    push_over_cap(&dir, "blog").await;

    let patch = |body: String| {
        app.clone().oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
    };

    // OPEN: the recovery write.
    let r = patch(serde_json::json!({ "data": { "title": "x" } }).to_string())
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "a shrinking update must be allowed over the cap, got {}",
        r.status()
    );

    // CLOSED: growth past the cap → 507.
    let r = patch(serde_json::json!({ "data": { "title": huge('b') } }).to_string())
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "an update that grows past the cap must be 507"
    );
    let bytes = axum::body::to_bytes(r.into_body(), 1_048_576)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "TENANT_QUOTA_EXCEEDED", "body: {v}");
}

#[tokio::test]
async fn rest_same_length_overwrite_over_cap_is_refused() {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use tower::ServiceExt;

    let (app, tok, dir) = helpers::spin_up_tenant("blog").await;
    let pool = helpers::grab_pool("blog", &dir).await;
    let seed = huge('a');
    let id: i64 = pool
        .with_writer(move |c| {
            c.execute_batch(
                "CREATE TABLE posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );",
            )?;
            c.execute("INSERT INTO posts (title) VALUES (?1)", [&seed])?;
            Ok(c.last_insert_rowid())
        })
        .await
        .unwrap();

    push_over_cap(&dir, "blog").await;

    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "data": { "title": huge('b') } }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "a same-length overwrite over the cap must be 507 — the history row is the growth"
    );
}

#[tokio::test]
async fn rest_update_growth_under_cap_is_untouched() {
    use axum::body::Body;
    use axum::http::{Method, Request, header};
    use tower::ServiceExt;

    let (app, tok, dir) = helpers::spin_up_tenant("blog").await;
    let pool = helpers::grab_pool("blog", &dir).await;
    let id: i64 = pool
        .with_writer(|c| {
            c.execute_batch(
                "CREATE TABLE posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );",
            )?;
            c.execute("INSERT INTO posts (title) VALUES ('seed')", [])?;
            Ok(c.last_insert_rowid())
        })
        .await
        .unwrap();

    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "data": { "title": medium('c') } }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "growth under the cap must not be blocked, got {}",
        r.status()
    );
}

// --- Site 3: the upsert conflict-UPDATE branch -----------------------------

#[tokio::test]
async fn upsert_conflict_update_over_cap_allows_shrink_but_refuses_growth() {
    let dir = tempfile::tempdir().unwrap();
    let s = svc(&dir).await;
    create_collection(&s, "products", &[tfu("sku", "text"), tf("name", "text")])
        .await
        .unwrap();

    let up = |rows: Vec<serde_json::Value>| {
        batch_upsert(
            &s,
            "products",
            rows,
            vec!["sku".into()],
            AuditActor::service(),
        )
    };

    // Insert branch, still under the cap.
    up(vec![
        serde_json::json!({ "sku": "s1", "name": medium('a') }),
    ])
    .await
    .unwrap();

    push_over_cap(&dir, "blog").await;

    // OPEN: the conflict-UPDATE branch shrinking while over the cap.
    up(vec![serde_json::json!({ "sku": "s1", "name": "x" })])
        .await
        .expect("a shrinking upsert-update must never be blocked, even over the cap");

    // CLOSED: the conflict-UPDATE branch growing past the cap.
    let err = up(vec![serde_json::json!({ "sku": "s1", "name": huge('b') })])
        .await
        .expect_err("an upsert-update that grows past the cap must be refused");
    assert!(
        err.to_string().contains("TENANT_QUOTA_EXCEEDED"),
        "expected the quota sentinel, got: {err}"
    );
}

#[tokio::test]
async fn upsert_same_length_overwrite_over_cap_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let s = svc(&dir).await;
    create_collection(&s, "products", &[tfu("sku", "text"), tf("name", "text")])
        .await
        .unwrap();

    let up = |rows: Vec<serde_json::Value>| {
        batch_upsert(
            &s,
            "products",
            rows,
            vec!["sku".into()],
            AuditActor::service(),
        )
    };

    up(vec![serde_json::json!({ "sku": "s1", "name": huge('a') })])
        .await
        .unwrap();

    push_over_cap(&dir, "blog").await;

    let err = up(vec![serde_json::json!({ "sku": "s1", "name": huge('b') })])
        .await
        .expect_err("a same-length conflict-UPDATE over the cap must be refused");
    assert!(
        err.to_string().contains("TENANT_QUOTA_EXCEEDED"),
        "expected the quota sentinel, got: {err}"
    );
}

#[tokio::test]
async fn upsert_conflict_update_growth_under_cap_is_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let s = svc(&dir).await;
    create_collection(&s, "products", &[tfu("sku", "text"), tf("name", "text")])
        .await
        .unwrap();

    batch_upsert(
        &s,
        "products",
        vec![serde_json::json!({ "sku": "s1", "name": "seed" })],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();

    let out = batch_upsert(
        &s,
        "products",
        vec![serde_json::json!({ "sku": "s1", "name": huge('c') })],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .expect("growth under the cap must not be blocked");
    assert_eq!(out["results"][0]["op"], "updated", "out: {out}");
}

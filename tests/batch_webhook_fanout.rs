//! v1.58 P1-7 — a batch write resolves webhook subscriptions ONCE, not once
//! per row.
//!
//! The post-commit loop called `webhooks.dispatch` per row, and each call
//! unconditionally opened the tenant pool, listed subscriptions and opened a
//! NEW meta.sqlite connection (the egress-allowlist read). A 1000-row batch
//! meant 1000 connections and a saturated reader semaphore, even for zero
//! deliveries.
//!
//! `meta_connections_opened()` is the load-bearing oracle here: it counts the
//! egress-allowlist opens, which is exactly the per-row cost the change
//! removes. Each subscribed test asserts an EXACT delta, because that delta is
//! the only thing that distinguishes the batch entry point from the reverted
//! per-row loop — a delivery-count assertion alone passes under either, since
//! both produce one delivery per (subscription, event).
//!
//! What each test pins:
//!
//! 1. zero subscriptions — the dispatcher's early return, no meta open at all.
//! 2. subscribed insert — ONE allowlist read for the whole batch.
//! 3. subscribed but event-filtered — ONE read at 200 rows, and no delivery.
//! 4. subscribed upsert — ONE read per upsert CALL, with the per-row
//!    Created/Updated granularity preserved.

use crate::webhooks_common;

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::batch::{batch_insert, batch_upsert};
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use drust::storage::record_history::AuditActor;
use drust::tenant::webhook_dispatcher::meta_connections_opened;
use std::sync::Arc;
use webhooks_common::FakeHook;

/// Every test reads the process-wide `meta_connections_opened` counter (and
/// perturbs it), so they must not overlap inside this binary. Each test holds
/// the gate until its fan-out has finished reading the allowlist, so no
/// straggler open can land inside the next test's measurement window.
static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

fn tf(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: false,
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

/// Subscribe `collection` to `events` (a JSON array literal) at `url`.
/// Loopback target: `is_loopback_dev_url` bypasses the egress allowlist and the
/// pinned resolver in a debug build, so no meta/egress setup is needed — but
/// the allowlist is still READ before the gate, which is what we count.
async fn subscribe(s: &drust::mcp::server::DrustMcp, collection: &str, events: &str, url: &str) {
    let (collection, events, url) = (collection.to_string(), events.to_string(), url.to_string());
    s.inner()
        .pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_webhooks
                    (collection, events, url, secret, active, created_at)
                 VALUES (?1, ?2, ?3, 'topsecret', 1, '2026-01-01T00:00:00Z')",
                rusqlite::params![collection, events, url],
            )
            .map(|_| ())
        })
        .await
        .unwrap();
}

/// Poll until the hook has received `want` requests (or ~5 s elapses).
async fn wait_for(hook: &FakeHook, want: usize) -> Vec<webhooks_common::Received> {
    let mut received = Vec::new();
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        received = hook.requests().await;
        if received.len() >= want {
            break;
        }
    }
    received
}

#[tokio::test]
async fn batch_insert_with_no_subscriptions_does_not_fan_out_per_row() {
    let _gate = GATE.lock().await;
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "rows", &[tf("v", "text")])
        .await
        .unwrap();

    let before = meta_connections_opened();
    let rows: Vec<serde_json::Value> = (0..200)
        .map(|i| serde_json::json!({ "v": format!("r{i}") }))
        .collect();
    batch_insert(&s, "rows", rows, AuditActor::service())
        .await
        .expect("batch insert");
    // Let any spawned dispatch tasks run.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let after = meta_connections_opened();

    // This pins the dispatcher's `subs.is_empty()` early return, which sits
    // BEFORE the allowlist read — it is satisfied by the per-row loop too, so
    // it is NOT the guard on the batch entry point. Tests 2-4 are.
    assert_eq!(
        after - before,
        0,
        "zero subscriptions must not open meta at all, saw {} new connections",
        after - before
    );
}

#[tokio::test]
async fn batch_insert_still_delivers_one_post_per_row_when_subscribed() {
    let _gate = GATE.lock().await;
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "rows", &[tf("v", "text")])
        .await
        .unwrap();

    let hook = FakeHook::start().await;
    subscribe(&s, "rows", r#"["created"]"#, hook.url()).await;

    let before = meta_connections_opened();
    let rows: Vec<serde_json::Value> = (0..5)
        .map(|i| serde_json::json!({ "v": format!("r{i}") }))
        .collect();
    batch_insert(&s, "rows", rows, AuditActor::service())
        .await
        .expect("batch insert");

    // Deliveries are spawned tasks; poll rather than sleeping a fixed budget.
    let received = wait_for(&hook, 5).await;
    assert_eq!(
        received.len(),
        5,
        "one `created` delivery per batched row must still be sent"
    );
    let bodies: Vec<serde_json::Value> = received
        .iter()
        .map(|r| serde_json::from_str(&r.body_text).expect("json body"))
        .collect();
    for i in 0..5 {
        assert!(
            bodies
                .iter()
                .any(|b| b["event"] == "created" && b["record"]["v"] == format!("r{i}")),
            "missing delivery for row r{i}: {bodies:?}"
        );
    }

    // The guard on `batch_insert_core`: subscriptions and the egress allowlist
    // are resolved ONCE for the batch. Every delivery has landed, so every
    // allowlist read that was going to happen has happened — the per-row loop
    // would read 5 times here, one before each delivery.
    assert_eq!(
        meta_connections_opened() - before,
        1,
        "a subscribed batch insert must read the egress allowlist exactly once"
    );
}

#[tokio::test]
async fn batch_insert_reads_allowlist_once_even_when_the_event_filter_excludes_every_row() {
    let _gate = GATE.lock().await;
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "rows", &[tf("v", "text")])
        .await
        .unwrap();

    // Subscribed to the collection, but only to `deleted` — so the fan-out
    // task runs past the empty-subscription early return and reaches the
    // allowlist read, then drops every event at the filter. This is the
    // 200-row shape the change exists for, and the non-zero delta proves the
    // fan-out actually ran (test 1's zero cannot).
    let hook = FakeHook::start().await;
    subscribe(&s, "rows", r#"["deleted"]"#, hook.url()).await;

    let before = meta_connections_opened();
    let rows: Vec<serde_json::Value> = (0..200)
        .map(|i| serde_json::json!({ "v": format!("r{i}") }))
        .collect();
    batch_insert(&s, "rows", rows, AuditActor::service())
        .await
        .expect("batch insert");

    // Wait for the fan-out to reach the allowlist read, then give the per-row
    // loop's remaining 199 reads room to land before asserting the exact count.
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if meta_connections_opened() > before {
            break;
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    assert_eq!(
        meta_connections_opened() - before,
        1,
        "200 rows against one subscription must cost ONE allowlist read"
    );
    assert!(
        hook.requests().await.is_empty(),
        "a `created` batch must not deliver to a `deleted`-only subscription"
    );
}

#[tokio::test]
async fn batch_upsert_resolves_subscriptions_once_per_call_and_keeps_per_row_events() {
    let _gate = GATE.lock().await;
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "products", &[tfu("sku", "text"), tf("name", "text")])
        .await
        .unwrap();

    let hook = FakeHook::start().await;
    subscribe(&s, "products", r#"["created","updated"]"#, hook.url()).await;

    let before = meta_connections_opened();

    // Round 1: five new skus → five `created`.
    let rows: Vec<serde_json::Value> = (0..5)
        .map(|i| serde_json::json!({ "sku": format!("s{i}"), "name": format!("n{i}") }))
        .collect();
    batch_upsert(
        &s,
        "products",
        rows,
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .expect("batch upsert (insert round)");
    assert_eq!(wait_for(&hook, 5).await.len(), 5, "5 `created` deliveries");

    // Round 2: same five skus, new names → five `updated`.
    let rows: Vec<serde_json::Value> = (0..5)
        .map(|i| serde_json::json!({ "sku": format!("s{i}"), "name": format!("m{i}") }))
        .collect();
    batch_upsert(
        &s,
        "products",
        rows,
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .expect("batch upsert (update round)");
    let received = wait_for(&hook, 10).await;
    assert_eq!(received.len(), 10, "5 more `updated` deliveries");

    // Per-row Created/Updated granularity survives the batched fan-out.
    let bodies: Vec<serde_json::Value> = received
        .iter()
        .map(|r| serde_json::from_str(&r.body_text).expect("json body"))
        .collect();
    for i in 0..5 {
        assert!(
            bodies
                .iter()
                .any(|b| b["event"] == "created" && b["record"]["name"] == format!("n{i}")),
            "missing `created` for s{i}: {bodies:?}"
        );
        assert!(
            bodies
                .iter()
                .any(|b| b["event"] == "updated" && b["record"]["name"] == format!("m{i}")),
            "missing `updated` for s{i}: {bodies:?}"
        );
    }

    // The guard on `batch_upsert_core`: one allowlist read per upsert CALL, not
    // per row. Both rounds have fully delivered, so the count is final — the
    // per-row loop would read 10 times.
    assert_eq!(
        meta_connections_opened() - before,
        2,
        "two upsert calls must read the egress allowlist twice, not ten times"
    );
}

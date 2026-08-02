//! v1.58 P1-7 — a batch insert with no webhook subscriptions must not open one
//! meta connection per row.
//!
//! The post-commit loop called `webhooks.dispatch` per row, and each call
//! unconditionally opened the tenant pool, opened a NEW meta.sqlite connection
//! (the egress-allowlist read) and listed subscriptions before discovering
//! there were none. A 1000-row batch meant 1000 connections and a saturated
//! reader semaphore for zero deliveries.
//!
//! The second test is the counterweight: resolving subscriptions once must not
//! cost a single delivery — a subscribed collection still gets one POST per
//! row.

#[path = "webhooks_common/mod.rs"]
mod webhooks_common;

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::batch::batch_insert;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use drust::storage::record_history::AuditActor;
use drust::tenant::webhook_dispatcher::meta_connections_opened;
use std::sync::Arc;
use webhooks_common::FakeHook;

/// Both tests read the process-wide `meta_connections_opened` counter (or
/// perturb it), so they must not overlap inside this binary.
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

    assert!(
        after - before <= 2,
        "zero subscriptions must cost at most one subscription lookup, saw {} new meta connections",
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

    // Loopback target: `is_loopback_dev_url` bypasses the egress allowlist and
    // the pinned resolver in a debug build, so no meta/egress setup is needed.
    let hook = FakeHook::start().await;
    let url = hook.url().to_string();
    s.inner()
        .pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_webhooks
                    (collection, events, url, secret, active, created_at)
                 VALUES ('rows', '[\"created\"]', ?1, 'topsecret', 1,
                         '2026-01-01T00:00:00Z')",
                rusqlite::params![url],
            )
            .map(|_| ())
        })
        .await
        .unwrap();

    let rows: Vec<serde_json::Value> = (0..5)
        .map(|i| serde_json::json!({ "v": format!("r{i}") }))
        .collect();
    batch_insert(&s, "rows", rows, AuditActor::service())
        .await
        .expect("batch insert");

    // Deliveries are spawned tasks; poll rather than sleeping a fixed budget.
    let mut received = Vec::new();
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        received = hook.requests().await;
        if received.len() >= 5 {
            break;
        }
    }
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
}

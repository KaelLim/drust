//! v1.58 P1-12 — the egress allowlist gates every webhook ATTEMPT, not just
//! the fan-out.
//!
//! `CLAUDE.md` invariant 6 states the rule as "per attempt, fail-closed", but
//! the dispatcher read the allowlist once per fan-out and then handed the row
//! to a four-attempt schedule spanning ~36 s. An origin removed from the
//! allowlist while that chain was in flight still received up to three more
//! POSTs. A revocation must take effect on the NEXT attempt.
//!
//! Attempt 1 is covered by the fan-out gate in `dispatch_many`, which reads the
//! allowlist immediately before spawning the delivery; attempts 2..n are
//! covered by the re-read inside the retry loop. Between them every attempt is
//! preceded by a live check — and the fan-out read stays a single read per
//! batch, which `tests/batch_webhook_fanout.rs` pins with an exact
//! meta-connection count.
//!
//! Non-loopback URL hosts are used for the deny/allow cases on purpose:
//! `dispatch_egress_allowed` carves loopback out (dev scaffolds live there), so
//! a `127.0.0.1` target could never be denied and would prove nothing. The dial
//! is pinned back to the local `FakeHook` with an injected resolver, the same
//! trick `tests/webhook_dns_rebind.rs` case 2 uses.

mod webhooks_common;
use webhooks_common::FakeHook;

use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::WebhookDispatcher;
use drust::tenant::events::Event;
use drust::tenant::webhook_dispatcher::{
    DeliverySchedule, PreCheckResolveFn, WebhookRow, deliver_for_test_with_egress,
    meta_connections_opened,
};
use futures::future::BoxFuture;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::sync::Arc;
use std::time::Duration;

/// A non-loopback origin so the egress gate actually applies. It never
/// resolves — the injected resolver pins every dial to the local FakeHook.
const ORIGIN: &str = "http://hook.example.test";
const URL: &str = "http://hook.example.test/hook";

/// `meta_connections_opened()` is a process-wide counter, so the test that
/// asserts a delta on it must not overlap the ones that also open meta.
static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn sample_row(url: &str) -> WebhookRow {
    WebhookRow {
        id: 1,
        collection: "notes".into(),
        events: r#"["created"]"#.into(),
        url: url.into(),
        secret: "topsecret".into(),
        active: 1,
    }
}

/// Pins every DNS name at `127.0.0.1:<FakeHook port>` so a non-loopback URL
/// host still lands on the local scaffold.
struct PinTo127 {
    port: u16,
}
impl Resolve for PinTo127 {
    fn resolve(&self, _name: Name) -> Resolving {
        let port = self.port;
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = vec![([127, 0, 0, 1], port).into()];
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Wrap-first resolve always succeeds — the point of these tests is the egress
/// gate, not the private-IP filter.
fn pre_check_ok() -> PreCheckResolveFn {
    Arc::new(|_h, _p| -> BoxFuture<'static, Result<(), String>> { Box::pin(async { Ok(()) }) })
}

/// A data root with `meta.sqlite`, one tenant row, and that tenant's SQLite
/// file on disk, so `TenantRegistry` treats it as live.
fn live_tenant(tenant: &str) -> (Arc<TenantRegistry>, std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let meta_path = data.join("meta.sqlite");
    let conn = open_meta(&meta_path).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    drop(conn);
    drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    (Arc::new(TenantRegistry::new(data, 2)), meta_path, dir)
}

/// Whole-list replace of the tenant's egress allowlist, straight into
/// `meta.sqlite` — the same column the dispatcher's live read consults.
fn set_allowlist(meta_path: &std::path::Path, tenant: &str, json: &str) {
    let conn = rusqlite::Connection::open(meta_path).unwrap();
    conn.execute(
        "UPDATE tenants SET egress_allowlist_json = ?2 WHERE id = ?1",
        rusqlite::params![tenant, json],
    )
    .unwrap();
}

fn webhook_entry(origin: &str) -> String {
    serde_json::json!([{ "system": "webhook", "uri": origin }]).to_string()
}

// ─── (a) revoked mid-retry → terminal, no further POSTs ─────────────────────

#[tokio::test]
async fn revoking_the_origin_mid_retry_stops_further_posts() {
    let _gate = GATE.lock().await;
    let tenant = "t-egress-per-attempt";
    let hook = FakeHook::start_scripted(vec![500, 500, 500, 500]).await;
    let port = reqwest::Url::parse(hook.url()).unwrap().port().unwrap();
    let (registry, meta_path, _dir) = live_tenant(tenant);
    set_allowlist(&meta_path, tenant, &webhook_entry(ORIGIN));

    let row = sample_row(URL);
    // A 2 s gap after attempt 1 is the mid-flight window the revocation lands
    // in; production's is 1 s and then 5 s.
    let sched = DeliverySchedule {
        backoffs: [0, 2, 2, 2],
        per_attempt_timeout_secs: 2,
    };

    let revoke = async {
        for _ in 0..200 {
            if !hook.requests().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        set_allowlist(&meta_path, tenant, "[]");
    };
    let deliver = deliver_for_test_with_egress(
        Arc::new(PinTo127 { port }),
        Some(pre_check_ok()),
        Some((registry.as_ref(), tenant)),
        &row,
        b"{}".to_vec(),
        "delivery-1".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        sched,
    );
    let (outcome, ()) = tokio::join!(deliver, revoke);

    let err = outcome.expect_err("a revoked origin must end the retry chain");
    let msg = err.to_string();
    assert!(
        msg.contains("egress_not_allowlisted"),
        "the terminal reason must name the egress gate, got: {msg}"
    );

    // Past where attempts 3 and 4 would have landed under this schedule.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        hook.requests().await.len(),
        1,
        "attempts after the origin was removed must not be sent"
    );
}

// ─── (b) still-allowlisted origin keeps its full retry schedule ─────────────

#[tokio::test]
async fn an_allowlisted_origin_still_gets_every_retry() {
    let _gate = GATE.lock().await;
    let tenant = "t-egress-still-allowed";
    let hook = FakeHook::start_scripted(vec![500, 500, 500, 500]).await;
    let port = reqwest::Url::parse(hook.url()).unwrap().port().unwrap();
    let (registry, meta_path, _dir) = live_tenant(tenant);
    set_allowlist(&meta_path, tenant, &webhook_entry(ORIGIN));

    let row = sample_row(URL);
    let outcome = deliver_for_test_with_egress(
        Arc::new(PinTo127 { port }),
        Some(pre_check_ok()),
        Some((registry.as_ref(), tenant)),
        &row,
        b"{}".to_vec(),
        "delivery-2".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;

    assert!(
        matches!(
            outcome,
            Err(drust::tenant::webhook_dispatcher::DeliveryError::Exhausted { .. })
        ),
        "four 500s must exhaust the schedule, got: {outcome:?}"
    );
    assert_eq!(
        hook.requests().await.len(),
        4,
        "an origin that stays allowlisted must keep all four attempts"
    );
}

// ─── (c) the production dispatch path re-reads per retry ────────────────────

/// The two cases above drive `deliver_for_test_with_egress`. This one drives
/// the real `WebhookDispatcher::dispatch` → `deliver` path and proves it wires
/// the live re-read in, using the `meta_connections_opened` counter as the
/// oracle (the same oracle `tests/batch_webhook_fanout.rs` relies on).
///
/// A loopback target is unavoidable here — production passes no pre-check, so a
/// non-resolving host would be killed by `resolve_public` before any attempt —
/// and loopback bypasses the allowlist VERDICT. It does not bypass the READ,
/// which is what this counts: one fan-out read plus one read per retry.
#[tokio::test]
async fn production_dispatch_rereads_the_allowlist_per_retry() {
    let _gate = GATE.lock().await;
    let tenant = "t-egress-prod-reread";
    let hook = FakeHook::start_scripted(vec![500, 500, 500, 500]).await;
    let (registry, meta_path, _dir) = live_tenant(tenant);
    set_allowlist(&meta_path, tenant, &webhook_entry(ORIGIN));

    let pool = registry.get_or_create(tenant).unwrap();
    let url = hook.url().to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_webhooks(collection,events,url,secret,active,created_at)
             VALUES('notes','[\"created\"]',?1,'topsecret',1,'2026-01-01T00:00:00Z')",
            rusqlite::params![url],
        )?;
        Ok(())
    })
    .await
    .unwrap();

    let before = meta_connections_opened();
    let dispatcher = WebhookDispatcher::new(registry.clone(), None);
    dispatcher.dispatch(
        tenant,
        "notes",
        Event::Created {
            record: serde_json::json!({"id": 1}),
        },
    );

    // Production backoffs are 0/1/5/30 s — wait past attempt 2 only.
    tokio::time::sleep(Duration::from_millis(3500)).await;

    let attempts = hook.requests().await.len();
    assert!(
        attempts >= 2,
        "the 500 must have been retried at least once, saw {attempts} attempt(s)"
    );
    let delta = meta_connections_opened() - before;
    assert!(
        delta >= 2,
        "one fan-out read plus one live re-read per retry: expected >= 2 meta reads, saw {delta}"
    );
}

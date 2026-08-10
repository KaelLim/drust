//! v1.58 P1-12 — the egress allowlist gates every webhook ATTEMPT, not just
//! the fan-out.
//!
//! `CLAUDE.md` invariant 6 states the rule as "per attempt, fail-closed", but
//! the dispatcher read the allowlist once per fan-out and then handed the row
//! to a four-attempt schedule spanning ~36 s. An origin removed from the
//! allowlist while that chain was in flight still received up to three more
//! POSTs. A revocation must take effect on the NEXT attempt.
//!
//! Attempts 2..n are covered by the live re-read inside the retry loop.
//! Attempt 1 is covered only by the fan-out SNAPSHOT `dispatch_many` takes
//! before spawning the delivery — a deliberate trade, since a per-delivery read
//! would cost one meta open per ROW of a batch (`tests/batch_webhook_fanout.rs`
//! pins that count). Case (g) below pins the one part of attempt 1's window
//! that IS free to remove.
//!
//! The live read is three-way, not two-way: a denial ends the chain, an
//! unreadable `meta.sqlite` does not — cases (e) and (f).
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
    DeliverySchedule, PreCheckResolveFn, WebhookRow, bump_egress_allowlist_version,
    deliver_for_test_with_egress, deliver_for_test_with_egress_ver, egress_allowlist_version,
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

// ─── review follow-up fixtures ──────────────────────────────────────────────

/// Soft-delete the tenant the way `soft_delete_tenant` does: the `tenants` row
/// SURVIVES with `deleted_at` set and `egress_allowlist_json` untouched.
fn soft_delete(meta_path: &std::path::Path, tenant: &str) {
    let conn = rusqlite::Connection::open(meta_path).unwrap();
    let n = conn
        .execute(
            "UPDATE tenants SET deleted_at = datetime('now') WHERE id = ?1",
            rusqlite::params![tenant],
        )
        .unwrap();
    assert_eq!(n, 1, "the soft-delete must hit the tenant row");
}

/// The three files a WAL-mode SQLite database can occupy on disk.
fn meta_files(meta_path: &std::path::Path) -> [std::path::PathBuf; 3] {
    let s = meta_path.as_os_str().to_string_lossy().to_string();
    [
        meta_path.to_path_buf(),
        std::path::PathBuf::from(format!("{s}-wal")),
        std::path::PathBuf::from(format!("{s}-shm")),
    ]
}

/// Make `meta.sqlite` unreadable by moving it (and its WAL sidecars) aside —
/// the cheapest faithful stand-in for the transient open/read failures the
/// dispatcher must NOT mistake for a revocation (EMFILE, EIO, a volume that
/// briefly went away). `restore_meta` puts it back.
fn hide_meta(meta_path: &std::path::Path, suffix: &str) {
    for f in meta_files(meta_path) {
        if f.exists() {
            let away =
                std::path::PathBuf::from(format!("{}{suffix}", f.as_os_str().to_string_lossy()));
            std::fs::rename(&f, &away).unwrap();
        }
    }
    assert!(!meta_path.exists(), "meta.sqlite must be gone");
}

fn restore_meta(meta_path: &std::path::Path, suffix: &str) {
    for f in meta_files(meta_path) {
        let away = std::path::PathBuf::from(format!("{}{suffix}", f.as_os_str().to_string_lossy()));
        if away.exists() {
            std::fs::rename(&away, &f).unwrap();
        }
    }
    assert!(meta_path.exists(), "meta.sqlite must be back");
}

// ─── (d) soft-deleting the tenant mid-retry is a revocation ─────────────────

/// A soft-delete leaves the `tenants` row in place with its allowlist intact,
/// so a reader without a `deleted_at IS NULL` predicate keeps authorizing
/// outbound POSTs for a tenant an admin has just deleted — for the rest of the
/// ~36 s schedule. `dispatch_many` already refuses to START a fan-out for a
/// non-live tenant (`get_if_live`); the per-attempt gate must agree.
#[tokio::test]
async fn soft_deleting_the_tenant_mid_retry_stops_further_posts() {
    let _gate = GATE.lock().await;
    let tenant = "t-egress-soft-deleted";
    let hook = FakeHook::start_scripted(vec![500, 500, 500, 500]).await;
    let port = reqwest::Url::parse(hook.url()).unwrap().port().unwrap();
    let (registry, meta_path, _dir) = live_tenant(tenant);
    set_allowlist(&meta_path, tenant, &webhook_entry(ORIGIN));

    let row = sample_row(URL);
    let sched = DeliverySchedule {
        backoffs: [0, 2, 2, 2],
        per_attempt_timeout_secs: 2,
    };

    let delete = async {
        for _ in 0..200 {
            if !hook.requests().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        soft_delete(&meta_path, tenant);
    };
    let deliver = deliver_for_test_with_egress(
        Arc::new(PinTo127 { port }),
        Some(pre_check_ok()),
        Some((registry.as_ref(), tenant)),
        &row,
        b"{}".to_vec(),
        "delivery-soft-delete".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        sched,
    );
    let (outcome, ()) = tokio::join!(deliver, delete);

    let msg = outcome
        .expect_err("a soft-deleted tenant must not keep its retry chain")
        .to_string();
    assert!(
        msg.contains("egress_not_allowlisted"),
        "a soft-deleted tenant is an authoritative deny, got: {msg}"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        hook.requests().await.len(),
        1,
        "no attempt may be sent after the tenant was soft-deleted"
    );
}

// ─── (e) an unreadable meta is NOT a revocation ─────────────────────────────

/// The gate must tell "the tenant revoked this origin" apart from "meta could
/// not be read". Both collapse to the deny-all `"[]"` in the fail-closed
/// convenience reader, and treating the second as the first turns a transient
/// infrastructure error into PERMANENT event loss plus a `last_failure_reason`
/// that accuses the tenant of a misconfiguration it does not have.
///
/// Fail-closed still holds: nothing is POSTed while meta is unreadable. What
/// must not happen is the chain ending, or the reason naming the allowlist.
#[tokio::test]
async fn an_unreadable_meta_is_not_a_revocation() {
    let _gate = GATE.lock().await;
    let tenant = "t-egress-meta-gone";
    let hook = FakeHook::start_scripted(vec![500, 500, 500, 500]).await;
    let port = reqwest::Url::parse(hook.url()).unwrap().port().unwrap();
    let (registry, meta_path, _dir) = live_tenant(tenant);
    set_allowlist(&meta_path, tenant, &webhook_entry(ORIGIN));
    // Attempt 1 consults the fan-out snapshot, never meta — so hiding meta up
    // front reproduces "the open fails at the first re-read" deterministically.
    hide_meta(&meta_path, ".away");

    let row = sample_row(URL);
    let outcome = deliver_for_test_with_egress(
        Arc::new(PinTo127 { port }),
        Some(pre_check_ok()),
        Some((registry.as_ref(), tenant)),
        &row,
        b"{}".to_vec(),
        "delivery-meta-gone".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule {
            backoffs: [0, 1, 1, 1],
            per_attempt_timeout_secs: 2,
        },
    )
    .await;

    let msg = outcome.expect_err("four 500s cannot succeed").to_string();
    assert!(
        !msg.contains("egress_not_allowlisted"),
        "an unreadable meta must never be reported as an allowlist revocation, got: {msg}"
    );
    assert!(
        msg.contains("all 4 attempts failed"),
        "the schedule must run to exhaustion, got: {msg}"
    );
    assert_eq!(
        hook.requests().await.len(),
        1,
        "fail-closed: no POST may be sent while the allowlist cannot be read"
    );
}

// ─── (f) a transient meta failure lets a later attempt through ──────────────

#[tokio::test]
async fn a_transient_meta_failure_still_lets_a_later_attempt_succeed() {
    let _gate = GATE.lock().await;
    let tenant = "t-egress-meta-flaps";
    // Attempt 1 → 500; whichever attempt lands after meta comes back → 200.
    let hook = FakeHook::start_scripted(vec![500]).await;
    let port = reqwest::Url::parse(hook.url()).unwrap().port().unwrap();
    let (registry, meta_path, _dir) = live_tenant(tenant);
    set_allowlist(&meta_path, tenant, &webhook_entry(ORIGIN));
    hide_meta(&meta_path, ".flap");

    let row = sample_row(URL);
    let sched = DeliverySchedule {
        backoffs: [0, 1, 4, 4],
        per_attempt_timeout_secs: 2,
    };
    let heal = async {
        tokio::time::sleep(Duration::from_millis(2500)).await;
        restore_meta(&meta_path, ".flap");
    };
    let deliver = deliver_for_test_with_egress(
        Arc::new(PinTo127 { port }),
        Some(pre_check_ok()),
        Some((registry.as_ref(), tenant)),
        &row,
        b"{}".to_vec(),
        "delivery-meta-flaps".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        sched,
    );
    let (outcome, ()) = tokio::join!(deliver, heal);

    assert!(
        outcome.is_ok(),
        "attempt 3 runs at t~5 s, well after meta returned at t~2.5 s: {outcome:?}"
    );
    assert_eq!(
        hook.requests().await.len(),
        2,
        "attempt 2 is skipped (meta unreadable), attempt 3 delivers"
    );
}

// ─── #953: a version bump before attempt 1 forces a live re-read ─────────────

/// The v1.61 delivery semaphore can park a task before attempt 1; a de-allowlist
/// landing in that window is invisible to the fan-out snapshot that gates
/// attempt 1. #953 gives attempt 1 a cheap version compare: when the tenant's
/// allowlist version moved since the snapshot, attempt 1 re-reads the allowlist
/// live and terminates if the origin is now denied — WITHOUT the one POST the
/// stale snapshot would otherwise have sent. The SSRF-IP filter was always safe;
/// this closes the same-tenant "de-allowlisted origin gets one more POST" gap.
#[tokio::test]
async fn a_version_bump_before_attempt_1_forces_a_live_reread() {
    let _gate = GATE.lock().await;
    let tenant = "t-egress-953-stale";
    // 200s would succeed if a POST were ever sent — the assertion below proves
    // none is, because attempt 1's re-read denies first.
    let hook = FakeHook::start_scripted(vec![200, 200, 200, 200]).await;
    let port = reqwest::Url::parse(hook.url()).unwrap().port().unwrap();
    let (registry, meta_path, _dir) = live_tenant(tenant);
    // The meta allowlist does NOT authorize the delivery URL's origin — models
    // the tenant having de-allowlisted it during the pre-attempt-1 window.
    set_allowlist(
        &meta_path,
        tenant,
        &webhook_entry("http://other.example.test"),
    );

    // Capture the version, then bump it as `egress_config::set_allowlist` would
    // on that de-allowlist write, so attempt 1 sees its snapshot as stale.
    let snapshot_ver = egress_allowlist_version(tenant);
    bump_egress_allowlist_version(tenant);

    let row = sample_row(URL);
    let outcome = deliver_for_test_with_egress_ver(
        Arc::new(PinTo127 { port }),
        Some(pre_check_ok()),
        Some((registry.as_ref(), tenant)),
        Some(snapshot_ver),
        &row,
        b"{}".to_vec(),
        "delivery-953-stale".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule {
            backoffs: [0, 1, 1, 1],
            per_attempt_timeout_secs: 2,
        },
    )
    .await;

    let msg = outcome
        .expect_err("a stale snapshot over a de-allowlisted origin must be terminal")
        .to_string();
    assert!(
        msg.contains("egress_not_allowlisted"),
        "attempt 1 must re-read and deny on a stale version, got: {msg}"
    );
    assert!(
        hook.requests().await.is_empty(),
        "no POST may be sent — attempt 1's re-read denied before the request"
    );
}

// ─── (g) a denied subscription must not delay the allowed ones ──────────────

/// The fan-out snapshot is what gates ATTEMPT 1, so the window between taking
/// it and that attempt is the residual staleness of the whole design. Awaiting
/// `record_failure` for a DENIED subscription inside the spawn loop put the
/// per-tenant writer mutex — held for seconds by any concurrent batch write —
/// directly inside that window, for every subscription queued behind it.
/// Recording the denials AFTER the allowed deliveries are spawned removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_denied_subscription_does_not_delay_the_allowed_ones() {
    let _gate = GATE.lock().await;
    let tenant = "t-egress-fanout-order";
    let hook = FakeHook::start().await;
    let (registry, meta_path, _dir) = live_tenant(tenant);
    // Deny-all: the loopback FakeHook is carved out, TEST-NET-1 is not.
    set_allowlist(&meta_path, tenant, "[]");

    let pool = registry.get_or_create(tenant).unwrap();
    let allowed_url = hook.url().to_string();
    pool.with_writer(move |c| {
        // Lower rowid first, so the denied subscription is the one the fan-out
        // loop reaches before the allowed one.
        c.execute(
            "INSERT INTO _system_webhooks(collection,events,url,secret,active,created_at)
             VALUES('notes','[\"created\"]','https://192.0.2.1/hook','s',1,'2026-01-01T00:00:00Z')",
            [],
        )?;
        c.execute(
            "INSERT INTO _system_webhooks(collection,events,url,secret,active,created_at)
             VALUES('notes','[\"created\"]',?1,'s',1,'2026-01-01T00:00:00Z')",
            rusqlite::params![allowed_url],
        )?;
        Ok(())
    })
    .await
    .unwrap();

    // Hold the per-tenant writer mutex the way a large batch write does.
    let holder_pool = pool.clone();
    let holder = tokio::spawn(async move {
        holder_pool
            .with_writer(|_c| {
                std::thread::sleep(Duration::from_secs(4));
                Ok(())
            })
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(250)).await;

    let dispatcher = WebhookDispatcher::new(registry.clone(), None);
    dispatcher.dispatch(
        tenant,
        "notes",
        Event::Created {
            record: serde_json::json!({"id": 1}),
        },
    );

    let mut delivered = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if !hook.requests().await.is_empty() {
            delivered = true;
            break;
        }
    }
    assert!(
        delivered,
        "the allowed delivery must not wait on the denied subscription's \
         record_failure write, which is blocked on the writer mutex"
    );

    holder.await.unwrap();
    // The denial is still recorded, just after the spawns.
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let reason: Option<String> = pool
            .with_reader(|c| {
                c.query_row(
                    "SELECT last_failure_reason FROM _system_webhooks WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
            })
            .await
            .unwrap_or(None);
        if reason.is_some_and(|r| r.contains("egress_not_allowlisted")) {
            return;
        }
    }
    panic!("the denied subscription's failure must still be recorded");
}

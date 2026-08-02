//! Retention for the admin-plane request queues in `meta.sqlite`.
//!
//! There are TWO of them and they are the same shape — a member asks, an owner
//! decides, the closed row stays as a record:
//!
//! | Table | Subject | Filed by | Reviewed at |
//! |---|---|---|---|
//! | `tenant_cap_requests` | an admin's tenant allowance | `tenant_cap::create_cap_request` | `/admin/tenant-cap-requests` |
//! | `quota_requests` | a tenant's storage tier | `quota_admin::create_quota_request` | `/admin/quota-requests` |
//!
//! One task sweeps both, deliberately. The first version of this shipped as
//! `tenant_cap::spawn_request_retention_task` and pruned only the cap queue; the
//! quota queue — older, and the one the cap queue was modelled on — was left
//! unbounded (2026-08-02 adversarial review). A janitor named after one table is
//! how the other gets forgotten, so this module is named after the *category*
//! and a new queue joins the loop below.
//!
//! Each queue keeps its own knob and its own DELETE (the SQL lives with the
//! table's module); this file only decides *when*.

use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::Mutex;

/// Prune both request queues once, returning `(cap_rows, quota_rows)`.
///
/// Split out from the loop so a test can drive a pass without a runtime clock.
/// Each queue is independent: a failure on one is logged and the other still
/// runs — a broken `quota_requests` must not leave `tenant_cap_requests`
/// growing forever.
pub fn prune_once(conn: &Connection) -> (usize, usize) {
    let cap_days = crate::mgmt::tenant_cap::request_retention_days();
    let quota_days = crate::mgmt::quota_admin::request_retention_days();

    let cap = match crate::mgmt::tenant_cap::prune_decided_requests(conn, cap_days) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = ?e, "tenant-cap request prune failed");
            0
        }
    };
    let quota = match crate::mgmt::quota_admin::prune_decided_requests(conn, quota_days) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = ?e, "quota request prune failed");
            0
        }
    };
    (cap, quota)
}

/// Daily prune of decided rows in both request queues, plus one pass at boot.
///
/// Anchored to 03:00 UTC like the other `meta.sqlite` retention passes
/// (`audit_db`, `record_history`). The boot pass exists for the same reason the
/// `_trash` janitor has one: a deployment that restarts more often than daily
/// would otherwise never reach its tick.
///
/// Deliberately its OWN task rather than a call inside
/// `record_history::spawn_retention_task`: that task returns early when
/// `DRUST_AUDIT_HISTORY_RETENTION_DAYS=0`, so hanging this off it would let one
/// operator knob silently disable an unrelated retention. For the same reason
/// the loop keeps running when ONE queue's knob is `0` — `prune_decided_requests`
/// is a no-op at `0`, so "keep cap requests forever" must not also mean "keep
/// quota requests forever".
///
/// `tokio::spawn(request_janitor::spawn_request_retention_task(meta))`.
pub async fn spawn_request_retention_task(meta: Arc<Mutex<Connection>>) {
    let cap_days = crate::mgmt::tenant_cap::request_retention_days();
    let quota_days = crate::mgmt::quota_admin::request_retention_days();
    if cap_days == 0 && quota_days == 0 {
        tracing::info!(
            "admin request-queue retention disabled (DRUST_TENANT_CAP_REQUEST_RETENTION_DAYS=0 and DRUST_QUOTA_REQUEST_RETENTION_DAYS=0); keeping decided requests forever"
        );
        return;
    }
    loop {
        {
            let conn = meta.lock().await;
            let (cap, quota) = prune_once(&conn);
            if cap > 0 || quota > 0 {
                tracing::info!(
                    tenant_cap_requests = cap,
                    quota_requests = quota,
                    cap_days,
                    quota_days,
                    "admin request queues pruned"
                );
            }
        }
        let now = chrono::Utc::now();
        let next = crate::safety::audit_db::next_0300_utc(now);
        let dur = (next - now)
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(60));
        tokio::time::sleep(dur).await;
    }
}

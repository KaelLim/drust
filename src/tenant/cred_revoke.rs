//! E2′ — per-ADMIN revocation signal for the SSE streams an admin PAT opened.
//!
//! An SSE stream opened with an admin PAT resolves to `AuthCtx::Service`, so
//! its event filter is `PassAll`; the only things that ever ended it were the
//! client, a channel drop (`EventBus::evict_tenant` / `evict_collection`) and,
//! for a PAT carrying `expires_at`, its `PatDeadline` (#976 F2). A UI PAT has
//! no `expires_at`, so a stream opened before a revocation kept receiving
//! every row event of its collection indefinitely. The PAT-revocation family
//! (the seven sites pinned in `mgmt::pat_evict_pin`) now sends
//! [`CredRevocations::revoke_admin`] after its auth-cache clear, and the stream
//! ends on it.
//!
//! ## Shape
//!
//! - One global, monotonic GENERATION ([`CredRevocations::current_gen`]).
//!   `ws_router` reads it as `g0` BEFORE bearer auth (`ws_auth::pat_gen_capture`)
//!   and carries it as [`PatGen0`].
//! - One `watch` per admin id, whose value is the generation of that admin's
//!   most recent revocation. `ws_auth::ws_baseline_capture` subscribes it AFTER
//!   auth, for requests carrying `AdminId` only, and inserts [`PatRevocation`].
//! - The stream ends once the admin's value exceeds `g0`. Because `g0` predates
//!   every auth read (cache or CTE), a revocation landing between the
//!   generation read and the subscription is still seen — the watch keeps the
//!   value, not an edge. An older revocation (before `g0`) never fires, so a
//!   reconnect after a revocation — or a recycled `admins` rowid — is not
//!   killed by history.
//!
//! The granularity is the ADMIN, not the token: revoking one CLI PAT ends that
//! admin's other PAT streams too, and they reconnect with the still-valid key.
//! Per-token signalling would need the token id in `CachedRole::AdminPat` and
//! a change to `bearer_auth_layer`, which this design deliberately leaves alone.
//!
//! Anon and tenant-key streams carry no `AdminId`, so they never subscribe and
//! pay nothing. Rooms WS sockets get the extension too but do not consume it;
//! their eviction stays reach-based (`mgmt::pat_evict::evict_reach`).
//!
//! ## Memory
//!
//! Keys come only from an authenticated `AdminId` or from a revocation site
//! that read the id out of `meta`, so the map is bounded by the `admins` table
//! and is never reclaimed — the same never-reclaim rule as the rooms `epochs`
//! map (a reclaimed and rebuilt entry would leave live receivers on a sender
//! nobody signals any more).

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use tokio::sync::watch;

/// The per-admin revocation registry. Cheap to clone; every clone shares one
/// state, which is what lets it ride on `RoomBus` (already one instance across
/// `TenantAuthState`, `MgmtState` and `TenantsState`) with zero extra wiring.
#[derive(Clone, Default)]
pub struct CredRevocations {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Global monotonic generation; bumped once per revocation.
    generation: AtomicU64,
    /// Value = the generation of that admin's latest revocation (0 = never).
    by_admin: DashMap<i64, watch::Sender<u64>>,
}

impl CredRevocations {
    /// The generation as of now. Read as `g0` before auth.
    pub fn current_gen(&self) -> u64 {
        self.inner.generation.load(SeqCst)
    }

    /// Subscribe to `admin_id`'s revocations. Creates the entry (at 0) when
    /// absent, so a later [`revoke_admin`](Self::revoke_admin) always lands on
    /// the SAME sender this receiver watches.
    pub fn subscribe_admin(&self, admin_id: i64) -> watch::Receiver<u64> {
        self.inner
            .by_admin
            .entry(admin_id)
            .or_insert_with(|| watch::Sender::new(0))
            .subscribe()
    }

    /// Revoke every PAT-backed SSE stream `admin_id` currently holds: bump the
    /// global generation and publish it as that admin's value. Creates the
    /// entry when absent, so a subscriber arriving AFTER this call (but whose
    /// `g0` predates it) still sees it — `send_if_modified` stores the value
    /// with or without receivers.
    pub fn revoke_admin(&self, admin_id: i64) {
        let g = self.inner.generation.fetch_add(1, SeqCst) + 1;
        self.bump_to(admin_id, g);
    }

    /// Raise `admin_id`'s value to `g`, never lower it: two revocations racing
    /// on different threads may publish out of order, and the later-numbered
    /// one must win.
    fn bump_to(&self, admin_id: i64, g: u64) {
        let tx = self
            .inner
            .by_admin
            .entry(admin_id)
            .or_insert_with(|| watch::Sender::new(0));
        tx.send_if_modified(|v| {
            if g > *v {
                *v = g;
                true
            } else {
                false
            }
        });
    }
}

/// The generation `ws_router` read BEFORE bearer auth (`ws_auth::pat_gen_capture`).
/// Server-side request state — a client cannot set a request extension.
#[derive(Clone, Copy, Debug)]
pub struct PatGen0(pub u64);

/// Inserted by `ws_auth::ws_baseline_capture` (after auth) on requests whose
/// credential is an admin PAT (`AdminId` present). Consumed by the SSE handler.
#[derive(Clone)]
pub struct PatRevocation {
    rx: watch::Receiver<u64>,
    g0: u64,
}

impl PatRevocation {
    pub fn new(rx: watch::Receiver<u64>, g0: u64) -> Self {
        Self { rx, g0 }
    }

    /// Resolves once this admin was revoked at a generation newer than `g0`.
    ///
    /// Checks the CURRENT value first (a revocation that landed before the
    /// subscription is still seen), then waits for each change. Written as a
    /// `borrow_and_update` + `changed` loop rather than `wait_for` because
    /// tokio asserts `Send` only for `changed()`'s future, and this one is
    /// boxed as `dyn Future + Send`. All senders gone ⇒ treated as revoked
    /// (fail-closed: the stream ends, the client reconnects through auth).
    pub async fn revoked(mut self) {
        loop {
            // The `Ref` is a temporary dropped at the end of this statement,
            // so no lock guard is held across the await below.
            if *self.rx.borrow_and_update() > self.g0 {
                return;
            }
            if self.rx.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn fires_within(r: PatRevocation, ms: u64) -> bool {
        tokio::time::timeout(Duration::from_millis(ms), r.revoked())
            .await
            .is_ok()
    }

    /// The window `pat_gen_capture` exists to close: `g0` taken, THEN the
    /// revocation, THEN the subscription. The value must still be seen.
    #[tokio::test]
    async fn a_revocation_before_subscribe_is_seen_by_the_later_subscriber() {
        let c = CredRevocations::default();
        let g0 = c.current_gen();
        c.revoke_admin(7);
        let rx = c.subscribe_admin(7);
        assert!(
            fires_within(PatRevocation::new(rx, g0), 100).await,
            "a revocation between g0 and the subscription was missed"
        );
    }

    #[tokio::test]
    async fn a_revocation_after_subscribe_wakes_the_waiter() {
        let c = CredRevocations::default();
        let g0 = c.current_gen();
        let rx = c.subscribe_admin(7);
        let waiter = tokio::spawn(PatRevocation::new(rx, g0).revoked());
        tokio::time::sleep(Duration::from_millis(20)).await;
        c.revoke_admin(7);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .is_ok(),
            "a live waiter did not wake on its admin's revocation"
        );
    }

    #[tokio::test]
    async fn another_admins_revocation_does_not_fire() {
        let c = CredRevocations::default();
        let g0 = c.current_gen();
        let rx = c.subscribe_admin(7);
        c.revoke_admin(8);
        assert!(
            !fires_within(PatRevocation::new(rx, g0), 200).await,
            "admin 8's revocation ended admin 7's stream"
        );
    }

    /// A reconnect after a revocation (or a recycled `admins` rowid) takes a
    /// `g0` at or past that revocation, so history must not kill it.
    #[tokio::test]
    async fn a_revocation_older_than_g0_does_not_fire() {
        let c = CredRevocations::default();
        c.revoke_admin(7);
        let g0 = c.current_gen();
        let rx = c.subscribe_admin(7);
        assert!(
            !fires_within(PatRevocation::new(rx, g0), 200).await,
            "a revocation older than g0 ended a fresh stream"
        );
    }

    #[tokio::test]
    async fn out_of_order_sends_keep_the_value_monotonic() {
        let c = CredRevocations::default();
        c.bump_to(7, 6);
        c.bump_to(7, 5);
        let rx = c.subscribe_admin(7);
        assert_eq!(*rx.borrow(), 6, "a lower generation overwrote a higher one");
        assert!(fires_within(PatRevocation::new(rx, 5), 100).await);
    }

    #[tokio::test]
    async fn clones_share_one_registry() {
        let c = CredRevocations::default();
        let c2 = c.clone();
        let g0 = c.current_gen();
        let rx = c.subscribe_admin(7);
        c2.revoke_admin(7);
        assert!(fires_within(PatRevocation::new(rx, g0), 100).await);
    }

    #[tokio::test]
    async fn a_room_bus_clone_shares_the_registry() {
        let b = crate::tenant::rooms::RoomBus::new();
        let b2 = b.clone();
        let g0 = b.cred().current_gen();
        let rx = b.cred().subscribe_admin(7);
        b2.cred().revoke_admin(7);
        assert!(fires_within(PatRevocation::new(rx, g0), 100).await);
    }

    #[tokio::test]
    async fn a_dropped_registry_ends_the_wait_fail_closed() {
        let c = CredRevocations::default();
        let g0 = c.current_gen();
        let rx = c.subscribe_admin(7);
        drop(c);
        assert!(
            fires_within(PatRevocation::new(rx, g0), 100).await,
            "every sender is gone, so the wait must end rather than park forever"
        );
    }

    #[test]
    fn current_gen_is_monotonic() {
        let c = CredRevocations::default();
        c.revoke_admin(1);
        let first = c.current_gen();
        c.revoke_admin(1);
        assert!(c.current_gen() > first);
    }
}

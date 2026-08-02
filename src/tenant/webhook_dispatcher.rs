//! WebhookDispatcher — record-CRUD event → subscribed URLs.
//!
//! Public API:
//!   WebhookDispatcher::new(
//!       pool: Arc<TenantRegistry>,
//!       resolver_override: Option<Arc<dyn reqwest::dns::Resolve + Send + Sync>>,
//!   ) -> Arc<Self>
//!   WebhookDispatcher::dispatch(&self, tenant: &str, collection: &str, event: Event)
//!   WebhookDispatcher::dispatch_many(&self, tenant, collection, events: Vec<Event>)
//!
//! `dispatch` is a one-element `dispatch_many`; batch writers call
//! `dispatch_many` so the subscription lookup and the egress-allowlist read
//! happen once per batch instead of once per row.
//!
//! Production passes `None` for `resolver_override` so dispatch uses
//! `webhook_resolver::PinnedPublicResolver`. Tests inject an
//! `AllowAllResolver` to bypass the public-IP filter.
//!
//! Internal: pure helpers below (HMAC, payload, event filter) are
//! `pub(crate)` to keep them testable from the integration suite.

use crate::storage::pool::TenantRegistry;
use crate::tenant::events::Event;
use futures::future::BoxFuture;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookRow {
    pub id: i64,
    pub collection: String,
    pub events: String, // JSON array as text
    pub url: String,
    pub secret: String,
    pub active: i64,
}

/// Optional pre-check resolver. Production passes `None` and lets
/// `deliver_for_test` fall through to `webhook_resolver::resolve_public`
/// (real stdlib DNS + public-IP filter). Tests pass `Some(f)` to inject
/// a synthetic pass/fail outcome at the wrap-first stage so IPv6 literal,
/// NXDOMAIN, and mixed-resolve cases stay deterministic.
///
/// The function takes `(host, port)` and returns `Ok(())` when the host
/// would resolve to at least one public IP, or `Err(reason)` when the
/// wrap-first short-circuit should fire. `reason` is logged only; the
/// user-visible `body` stays "host_now_private_or_unresolvable" so the
/// existing assertion contract from v1.21 (cases 1 and 3) keeps holding.
pub type PreCheckResolveFn =
    std::sync::Arc<dyn Fn(String, u16) -> BoxFuture<'static, Result<(), String>> + Send + Sync>;

/// Returns true if `events_json` (a serialized JSON array of event-name
/// strings) contains the given event name.
pub(crate) fn events_contains(events_json: &str, name: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Vec<String>>(events_json) else {
        return false;
    };
    v.iter().any(|s| s == name)
}

/// HMAC-SHA256 over `body` keyed by `secret`, hex-encoded, prefixed
/// `sha256=`. Matches GitHub-webhook signature convention.
pub fn compute_signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(7 + bytes.len() * 2);
    hex.push_str("sha256=");
    for b in bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

/// Build the JSON body that goes in the outbound POST. `delivery_id` and
/// `timestamp` are passed in so retries reuse them deterministically.
pub(crate) fn build_payload(
    tenant: &str,
    collection: &str,
    event: &Event,
    delivery_id: &str,
    timestamp: &str,
) -> Value {
    let ev = event.name();
    let rec = match event {
        Event::Created { record } | Event::Updated { record } => record.clone(),
        Event::Deleted { id } => json!({"id": id}),
    };
    json!({
        "tenant":      tenant,
        "collection":  collection,
        "event":       ev,
        "record":      rec,
        "delivery_id": delivery_id,
        "timestamp":   timestamp,
    })
}

/// True iff `url`'s host is a dev-loopback host (`127.0.0.1` / `localhost` /
/// `::1`) AND loopback is allowed for this build/env. This is the shared
/// predicate behind the resolver bypass in `deliver_inner` and the egress
/// dispatch gate below — kept in one place so the two never diverge. In a
/// release build with no `DRUST_WEBHOOK_ALLOW_LOOPBACK` this is always false,
/// so loopback is treated like any other host (egress-denied AND
/// resolver-denied). reqwest returns `[::1]` (bracketed) for IPv6 literals —
/// accept both forms, same as `check_url`.
pub(crate) fn is_loopback_dev_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1" | "[::1]")
        && crate::tenant::webhook_resolver::webhook_loopback_allowed(
            cfg!(debug_assertions),
            std::env::var("DRUST_WEBHOOK_ALLOW_LOOPBACK").is_ok(),
        )
}

/// The webhook DISPATCH egress gate (v1.49) — the THIRD gate, ADDED alongside
/// `check_url` (registration) and the `PinnedPublicResolver` (per-attempt DNS
/// filter); never a replacement. Returns true iff the subscriber `url` may
/// receive a delivery:
///   * a dev-loopback target bypasses the allowlist (the SAME carve-out the
///     resolver applies — Caddy / test scaffolds live on loopback; a release
///     build with no opt-in falls through to the allowlist below), OR
///   * the tenant's `system=webhook` allowlist contains its normalized origin.
/// Fail-closed: an empty allowlist, or an unparsable / non-origin URL, denies.
pub(crate) fn dispatch_egress_allowed(allowlist_json: &str, url: &str) -> bool {
    if is_loopback_dev_url(url) {
        return true;
    }
    crate::tenant::egress::check_egress(
        allowlist_json,
        crate::tenant::egress::EgressSystem::Webhook,
        url,
    )
}

/// Registration-side webhook egress gate (v1.49) — the SAME policy as
/// `dispatch_egress_allowed`, but reads the allowlist from a live meta handle
/// (registration paths hold `Arc<Mutex<Connection>>`; dispatch opens its own
/// read-only conn). Returns true iff `url` may be REGISTERED as a webhook
/// target for `tenant`. Wired into EVERY registration surface (REST
/// create/patch, MCP create/update, admin UI) so the register-time gate is
/// consistent: a non-allowlisted origin is rejected at registration, never
/// merely at delivery — which also prevents a persisted non-allowlisted row
/// from silently going live if an admin later allowlists that origin for an
/// unrelated reason. Fail-closed (empty/unreadable allowlist denies).
pub(crate) async fn registration_egress_allowed(
    meta: &Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    tenant: &str,
    url: &str,
) -> bool {
    let allowlist = {
        let conn = meta.lock().await;
        crate::tenant::egress::read_egress_allowlist(&conn, tenant)
            .unwrap_or_else(|_| "[]".to_string())
    };
    dispatch_egress_allowed(&allowlist, url)
}

/// Count of meta.sqlite connections the webhook dispatch path has opened (or
/// attempted to open) in this process — the cost the batch entry point exists
/// to bound. Incremented before the open so a failed open still counts: the
/// syscall is paid either way. Read it with [`meta_connections_opened`].
///
/// Observability hook for `tests/batch_webhook_fanout.rs`; a relaxed atomic
/// increment next to a SQLite file open is not measurable, so it is compiled
/// unconditionally (integration tests link the lib without `cfg(test)`).
#[doc(hidden)]
pub static META_CONNECTIONS_OPENED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Current value of [`META_CONNECTIONS_OPENED`]. Tests assert on a DELTA around
/// one operation, never on the absolute value.
#[doc(hidden)]
pub fn meta_connections_opened() -> u64 {
    META_CONNECTIONS_OPENED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Read a tenant's egress allowlist JSON from `meta.sqlite` for the dispatch
/// gate. Opens a short-lived READ-ONLY connection (dispatch runs on a spawned,
/// off-hot-path task, so a per-fan-out open is acceptable — a per-ROW one is
/// not, which is why `dispatch_many` calls this once per batch and only when
/// the collection actually has subscriptions). Fail-CLOSED: any open/read
/// failure yields the deny-all `"[]"`, so a transient meta hiccup denies
/// delivery to non-loopback hosts rather than opening egress.
fn read_tenant_egress_allowlist(registry: &TenantRegistry, tenant: &str) -> String {
    META_CONNECTIONS_OPENED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let meta_path = registry.data_root().join("meta.sqlite");
    match rusqlite::Connection::open_with_flags(
        &meta_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(conn) => crate::tenant::egress::read_egress_allowlist(&conn, tenant)
            .unwrap_or_else(|_| "[]".to_string()),
        Err(_) => "[]".to_string(),
    }
}

#[derive(Clone)]
pub struct WebhookDispatcher {
    pool: Arc<TenantRegistry>,
    /// Test-only injection point for `reqwest::dns::Resolve`. Production
    /// passes `None`; the dispatch path then falls back to
    /// `webhook_resolver::PinnedPublicResolver` per attempt so a host that
    /// rebinds mid-flight cannot win against the resolver cache. The
    /// per-attempt client is built inside `deliver_for_test` so no Client
    /// state is reused across attempts. See spec §1.
    resolver_override: Option<Arc<dyn reqwest::dns::Resolve + Send + Sync>>,
    /// v1.32.4 D10 — pre-built reqwest::Client reused across the dispatch
    /// fan-out. Pre-D10 each attempt rebuilt a Client (rustls context +
    /// resolver wiring + connection pool state, ~5-20ms cold per build).
    /// At N webhooks × 4 attempts that was 4N constructions per CRUD
    /// event. DNS-rebind defense preserved by:
    ///   * `pool_max_idle_per_host(0)` — disables keep-alive, every
    ///     request opens a fresh TCP connection → fresh DNS lookup →
    ///     `dns_resolver` called every time.
    ///   * `dns_resolver(PinnedPublicResolver)` (or the resolver_override
    ///     captured at construction) — rejects RFC1918/loopback/CGNAT
    ///     at every call.
    /// Research note: docs/superpowers/notes/2026-05-30-reqwest-resolver-lifecycle.md.
    /// Loopback-dev hosts (127.0.0.1, localhost, ::1) bypass this client
    /// and fall back to per-attempt build with no custom resolver — see
    /// `deliver_inner`.
    cached_client: Arc<reqwest::Client>,
}

impl WebhookDispatcher {
    pub fn new(
        pool: Arc<TenantRegistry>,
        resolver_override: Option<Arc<dyn reqwest::dns::Resolve + Send + Sync>>,
    ) -> Arc<Self> {
        use std::time::Duration;
        let resolver_for_cache: Arc<dyn reqwest::dns::Resolve + Send + Sync> = resolver_override
            .clone()
            .unwrap_or_else(|| Arc::new(crate::tenant::webhook_resolver::PinnedPublicResolver));
        let cached_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("drust-webhook/1.21.0")
            .pool_max_idle_per_host(0)
            .dns_resolver(Arc::new(crate::tenant::webhook_resolver::ResolverHandle(
                resolver_for_cache,
            )))
            .build()
            .expect("build cached webhook reqwest client");
        Arc::new(Self {
            pool,
            resolver_override,
            cached_client: Arc::new(cached_client),
        })
    }

    /// Fan out `event` to every active subscriber for `(tenant, collection)`.
    /// A one-element call into [`WebhookDispatcher::dispatch_many`], so there is
    /// exactly ONE delivery implementation. Returns immediately — the callers
    /// are on the hot REST/MCP path and must not block.
    pub fn dispatch(&self, tenant: &str, collection: &str, event: Event) {
        self.dispatch_many(tenant, collection, vec![event]);
    }

    /// Fan out many events for one collection, resolving subscriptions ONCE.
    ///
    /// Spawns a Tokio task per delivery; errors are silently swallowed at the
    /// dispatch level (individual delivery failures are recorded via
    /// `record_failure`). Returns immediately.
    ///
    /// v1.58 P1-7 — the per-row caller used to invoke `dispatch` once per row,
    /// and every call opened the tenant pool, listed subscriptions, and opened
    /// a fresh meta.sqlite connection for the egress allowlist. A 1000-row
    /// batch therefore cost 1000 meta connections and saturated the tenant's
    /// reader semaphore even when the collection had no subscriptions at all.
    /// Here the lookup happens once and an empty subscription set returns
    /// BEFORE the allowlist read, so the zero-subscriber case (the common one)
    /// costs one reader acquisition for the whole batch and no meta connection.
    ///
    /// Event granularity is unchanged — one delivery per (subscription, event),
    /// because collapsing them into an aggregate payload would break every
    /// existing consumer. The loop is subscription-major rather than
    /// event-major so the per-subscription decisions (event filter, egress
    /// gate) are made once per batch instead of once per row; deliveries are
    /// spawned concurrently either way, so no ordering guarantee changes.
    pub fn dispatch_many(&self, tenant: &str, collection: &str, events: Vec<Event>) {
        if events.is_empty() {
            return;
        }
        let pool = self.pool.clone();
        let tenant = tenant.to_string();
        let collection = collection.to_string();
        // Pin a resolver for this dispatch fan-out: tests inject their own
        // via `resolver_override`; production uses the wrap-first
        // PinnedPublicResolver so private/loopback addresses never reach
        // reqwest's dial step. The resolver is consulted on the loopback
        // fallback path inside `deliver_inner`; the production fast path
        // uses `client` (built at construction with this same resolver).
        let resolver: Arc<dyn reqwest::dns::Resolve + Send + Sync> = self
            .resolver_override
            .clone()
            .unwrap_or_else(|| Arc::new(crate::tenant::webhook_resolver::PinnedPublicResolver));
        let client = self.cached_client.clone();
        tokio::spawn(async move {
            // Spawned fan-out: `get_if_live` so a tenant soft-deleted between
            // the emitting write and this dispatch is skipped, not recreated.
            let tenant_pool = match pool.get_if_live(&tenant) {
                Some(p) => p,
                None => {
                    tracing::debug!(tenant = %tenant, "webhook dispatch: tenant not live, skipping");
                    return;
                }
            };
            let subs = match tenant_pool
                .with_reader(|conn| list_subscriptions(conn, &collection))
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = ?e, tenant = %tenant, collection = %collection, "webhook dispatch: list_subscriptions failed");
                    return;
                }
            };
            // Nothing subscribed: return BEFORE the meta open below. This is
            // the case a batch hits N times, and it must cost nothing.
            if subs.is_empty() {
                return;
            }
            // v1.49 egress third gate — read the tenant's allowlist ONCE per
            // fan-out (fresh from meta, so a just-removed origin is honored;
            // a batch's deliveries are all spawned within the same instant, so
            // reading it once per batch is as fresh as once per row was). This
            // read gates ATTEMPT 1 of every delivery it spawns; attempts 2..n
            // are gated by the live re-read inside the retry loop (v1.58
            // P1-12), so the pair covers every attempt without paying a
            // meta.sqlite open per row.
            let allowlist_json = read_tenant_egress_allowlist(&pool, &tenant);
            for sub in subs {
                // Which of this fan-out's events this subscription wants.
                let matching: Vec<&Event> = events
                    .iter()
                    .filter(|e| events_contains(&sub.events, e.name()))
                    .collect();
                if matching.is_empty() {
                    continue;
                }
                // Egress third gate: deny delivery to any origin not on the
                // tenant's system=webhook allowlist (loopback dev targets keep
                // the resolver's carve-out). A denial records a failure and
                // skips — no POST, no retry. check_url (registration) + the
                // PinnedPublicResolver (per attempt) remain; this is an ADDED
                // gate, never a replacement. The failure is recorded ONCE per
                // subscription per fan-out: `record_failure` overwrites one
                // row with a reason that does not depend on the event, so N
                // identical writes under the writer lock leave exactly the
                // state a single write leaves.
                if !dispatch_egress_allowed(&allowlist_json, &sub.url) {
                    let id = sub.id;
                    let reason = format!("egress_not_allowlisted: {}", sub.url);
                    let _ = tenant_pool
                        .with_writer(move |c| record_failure(c, id, &reason))
                        .await;
                    continue;
                }
                for event in matching {
                    let delivery_id = uuid::Uuid::new_v4().to_string();
                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let body_bytes = match serde_json::to_vec(&build_payload(
                        &tenant,
                        &collection,
                        event,
                        &delivery_id,
                        &timestamp,
                    )) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(error = ?e, tenant = %tenant, collection = %collection, "webhook dispatch: serialize payload failed");
                            continue;
                        }
                    };
                    let resolver2 = resolver.clone();
                    let pool2 = pool.clone();
                    let tenant2 = tenant.clone();
                    let delivery_id2 = delivery_id.clone();
                    let timestamp2 = timestamp.clone();
                    let client2 = client.clone();
                    let sub2 = sub.clone();
                    tokio::spawn(async move {
                        if let Err(e) = deliver(
                            client2,
                            resolver2,
                            &sub2,
                            body_bytes,
                            delivery_id2,
                            timestamp2,
                            DeliverySchedule::default(),
                            &pool2,
                            &tenant2,
                        )
                        .await
                        {
                            tracing::warn!(error = ?e, tenant = %tenant2, webhook_id = %sub2.id, "webhook deliver: final failure");
                        }
                    });
                }
            }
        });
    }
}

/// Pull every active subscription whose `collection` matches. The
/// per-event filter happens in Rust (`events_contains`) on the small
/// result set rather than in SQL.
pub(crate) fn list_subscriptions(
    conn: &Connection,
    collection: &str,
) -> rusqlite::Result<Vec<WebhookRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, collection, events, url, secret, active
           FROM _system_webhooks
          WHERE collection = ?1 AND active = 1",
    )?;
    let rows = stmt
        .query_map([collection], |r| {
            Ok(WebhookRow {
                id: r.get(0)?,
                collection: r.get(1)?,
                events: r.get(2)?,
                url: r.get(3)?,
                secret: r.get(4)?,
                active: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Mark a subscription's last failure. Called once after all retries
/// exhaust (or after a non-retryable 4xx on the first attempt).
pub(crate) fn record_failure(conn: &Connection, id: i64, reason: &str) -> rusqlite::Result<()> {
    let truncated: String = reason.chars().take(200).collect();
    conn.execute(
        "UPDATE _system_webhooks
            SET last_failure_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                last_failure_reason = ?2
          WHERE id = ?1",
        rusqlite::params![id, truncated],
    )?;
    Ok(())
}

/// Backoff schedule for `deliver()`. Production uses `default()`
/// (0/1/5/30 s). Tests override to skip waits.
#[derive(Clone, Copy)]
pub struct DeliverySchedule {
    pub backoffs: [u64; 4], // seconds, 4 total attempts
    pub per_attempt_timeout_secs: u64,
}

impl Default for DeliverySchedule {
    fn default() -> Self {
        Self {
            backoffs: [0, 1, 5, 30],
            per_attempt_timeout_secs: 10,
        }
    }
}

impl DeliverySchedule {
    pub const fn fast_for_tests() -> Self {
        Self {
            backoffs: [0, 0, 0, 0],
            per_attempt_timeout_secs: 2,
        }
    }
}

#[derive(Debug)]
pub enum DeliveryError {
    /// 4xx response — terminal, no retry attempted.
    NonRetryable { status: u16, body: String },
    /// All retries exhausted on retryable errors (5xx / network / timeout).
    Exhausted { last_error: String, attempts: usize },
    /// The tenant's egress allowlist stopped covering this origin BETWEEN
    /// attempts — terminal, the remaining attempts are abandoned. Its
    /// `Display` is byte-identical to the reason the fan-out gate records, so
    /// `last_failure_reason` reads the same whichever gate fired.
    EgressRevoked { url: String },
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliveryError::NonRetryable { status, body } => {
                write!(f, "4xx {} from subscriber: {}", status, body)
            }
            DeliveryError::Exhausted {
                last_error,
                attempts,
            } => {
                write!(f, "all {} attempts failed: {}", attempts, last_error)
            }
            DeliveryError::EgressRevoked { url } => {
                write!(f, "egress_not_allowlisted: {}", url)
            }
        }
    }
}

/// Live inputs for the per-attempt egress re-check inside the retry loop:
/// the registry that owns `meta.sqlite` and the tenant whose allowlist to
/// read. `deliver` always supplies one; `deliver_for_test` supplies `None`
/// (its callers assert on the resolver/pre-check gates, not this one).
pub type EgressRecheck<'a> = (&'a TenantRegistry, &'a str);

/// Production entry: one delivery, 4 attempts, fail-then-record_failure.
/// Uses the shared `TenantRegistry` pool so failure writes go through the
/// per-tenant writer mutex — same serialization guarantee as all other writes.
///
/// v1.32.4 D10: `shared_client` is the dispatcher's `cached_client` —
/// passed down here so the per-attempt fast path can reuse one
/// `reqwest::Client` across the full retry chain (and across deliveries).
/// Loopback-dev hosts inside `deliver_inner` ignore `shared_client` and
/// build per-attempt — see field doc on `WebhookDispatcher.cached_client`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn deliver(
    shared_client: Arc<reqwest::Client>,
    resolver: Arc<dyn reqwest::dns::Resolve + Send + Sync>,
    row: &WebhookRow,
    body_bytes: Vec<u8>,
    delivery_id: String,
    timestamp: String,
    sched: DeliverySchedule,
    pool: &TenantRegistry,
    tenant_id: &str,
) -> Result<(), DeliveryError> {
    let outcome = deliver_inner(
        Some(shared_client),
        resolver,
        None,
        // v1.58 P1-12 — the retry loop re-reads this tenant's allowlist before
        // every attempt after the first, so a revocation lands on the NEXT
        // attempt rather than after the ~36 s schedule finishes.
        Some((pool, tenant_id)),
        row,
        body_bytes,
        delivery_id,
        timestamp,
        sched,
    )
    .await;
    // v1.32 C1 — webhook attempt counter
    {
        let result_label = match &outcome {
            Ok(()) => "success",
            Err(DeliveryError::NonRetryable { status, .. }) if *status == 0 => "network",
            Err(DeliveryError::NonRetryable { status, .. }) if (400..500).contains(status) => "4xx",
            Err(DeliveryError::NonRetryable { .. }) => "5xx",
            Err(DeliveryError::EgressRevoked { .. }) => "egress_denied",
            Err(DeliveryError::Exhausted { last_error, .. }) => {
                if last_error.contains("timeout") || last_error.contains("timed out") {
                    "timeout"
                } else {
                    "network"
                }
            }
        };
        crate::mgmt::metrics::metrics()
            .webhook_attempts_total
            .with_label_values(&[result_label])
            .inc();
    }
    if let Err(ref e) = outcome {
        let reason = e.to_string();
        let id = row.id;
        // Retry bookkeeping after an awaited delivery: never create a tenant
        // just to record a failure against it.
        match pool.get_if_live(tenant_id) {
            Some(tenant_pool) => {
                let _ = tenant_pool
                    .with_writer(move |conn| record_failure(conn, id, &reason))
                    .await;
            }
            None => {
                tracing::debug!(tenant = %tenant_id, "deliver: tenant not live, skipping record_failure");
            }
        }
    }
    outcome
}

/// Exposed only for integration tests in `tests/`. Production code
/// uses `deliver()` (which wraps this + calls `record_failure` on
/// failure). Do NOT call from the dispatch path.
///
/// v1.21: wrap-first standalone resolve via `webhook_resolver::resolve_public`
/// short-circuits the entire attempt loop if the host now resolves only to
/// private/loopback/link-local IPs (or fails resolution outright). On dev
/// loopback hosts (`127.0.0.1` / `localhost` / `::1`) the pre-check and the
/// reqwest-level resolver are both bypassed — Caddy & test scaffolds live
/// on loopback. Every other host gets a fresh, single-shot reqwest::Client
/// per attempt wired to the injected resolver so no DNS cache survives an
/// attempt boundary.
///
/// v1.28.7: the new `pre_check` argument is `None` in production —
/// `deliver()` always passes `None` so the path is bit-for-bit unchanged
/// (`resolve_public` via stdlib DNS as above). Tests pass `Some(f)` to
/// inject a deterministic pass/fail outcome at the wrap-first stage
/// without touching real DNS — see `PreCheckResolveFn` for the contract.
/// `delivery_id` and `timestamp` are caller-supplied (also v1.28.7) so
/// the HMAC-signed body and the `x-drust-delivery-id` / `x-drust-timestamp`
/// headers agree for the same logical delivery.
pub async fn deliver_for_test(
    resolver: Arc<dyn reqwest::dns::Resolve + Send + Sync>,
    pre_check: Option<PreCheckResolveFn>,
    row: &WebhookRow,
    body_bytes: Vec<u8>,
    delivery_id: String,
    timestamp: String,
    sched: DeliverySchedule,
) -> Result<(), DeliveryError> {
    // v1.32.4 D10 — public test entry. Passes `None` for shared_client so
    // every attempt builds a fresh `reqwest::Client` (legacy behaviour;
    // tests rely on the per-attempt Client to scope the injected
    // `resolver` and pre_check). Production uses [`deliver`] which feeds
    // the dispatcher's `cached_client` into [`deliver_inner`] directly.
    deliver_inner(
        None,
        resolver,
        pre_check,
        None,
        row,
        body_bytes,
        delivery_id,
        timestamp,
        sched,
    )
    .await
}

/// [`deliver_for_test`] plus the per-attempt egress re-check the production
/// [`deliver`] wires in (v1.58 P1-12). Exposed separately so the existing
/// `deliver_for_test` call sites keep their signature; pass the same
/// `(registry, tenant)` pair `deliver` builds and the loop consults the REAL
/// `read_tenant_egress_allowlist` + `dispatch_egress_allowed` pair, so a test
/// can revoke an origin in `meta.sqlite` mid-flight and observe the effect.
#[allow(clippy::too_many_arguments)]
pub async fn deliver_for_test_with_egress(
    resolver: Arc<dyn reqwest::dns::Resolve + Send + Sync>,
    pre_check: Option<PreCheckResolveFn>,
    egress: Option<EgressRecheck<'_>>,
    row: &WebhookRow,
    body_bytes: Vec<u8>,
    delivery_id: String,
    timestamp: String,
    sched: DeliverySchedule,
) -> Result<(), DeliveryError> {
    deliver_inner(
        None,
        resolver,
        pre_check,
        egress,
        row,
        body_bytes,
        delivery_id,
        timestamp,
        sched,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn deliver_inner(
    shared_client: Option<Arc<reqwest::Client>>,
    resolver: Arc<dyn reqwest::dns::Resolve + Send + Sync>,
    pre_check: Option<PreCheckResolveFn>,
    egress: Option<EgressRecheck<'_>>,
    row: &WebhookRow,
    body_bytes: Vec<u8>,
    delivery_id: String,
    timestamp: String,
    sched: DeliverySchedule,
) -> Result<(), DeliveryError> {
    use std::time::Duration;

    // Parse once at the top — we need host/port for the wrap-first
    // standalone resolve and for the dev-loopback bypass.
    let parsed = reqwest::Url::parse(&row.url).map_err(|e| DeliveryError::NonRetryable {
        status: 0,
        body: format!("url parse: {e}"),
    })?;
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    let port = parsed.port_or_known_default().unwrap_or(443);
    // reqwest::Url returns `[::1]` (with brackets) for IPv6 literals — accept
    // both forms here, same as `check_url`.
    let is_loopback_dev = matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1" | "[::1]")
        && crate::tenant::webhook_resolver::webhook_loopback_allowed(
            cfg!(debug_assertions),
            std::env::var("DRUST_WEBHOOK_ALLOW_LOOPBACK").is_ok(),
        );

    // Wrap-first standalone resolve: BEFORE any attempt, confirm the
    // host still maps to at least one public IP. A rebinding between
    // registration and dispatch hits here as a terminal NonRetryable.
    if !is_loopback_dev {
        let pre_check_result = match &pre_check {
            Some(f) => f(host.clone(), port).await,
            None => crate::tenant::webhook_resolver::resolve_public(host.clone(), port)
                .await
                .map(|_| ()),
        };
        if let Err(reason) = pre_check_result {
            tracing::warn!(
                webhook_id = %row.id,
                url = %row.url,
                error = %reason,
                "deliver: wrap-first resolve rejected — terminal"
            );
            return Err(DeliveryError::NonRetryable {
                status: 0,
                body: "host_now_private_or_unresolvable".to_string(),
            });
        }
    }

    let sig = compute_signature(&row.secret, &body_bytes);
    let mut last_err = String::new();
    for (attempt_idx, wait_secs) in sched.backoffs.iter().enumerate() {
        if *wait_secs > 0 {
            tokio::time::sleep(Duration::from_secs(*wait_secs)).await;
        }
        // v1.58 P1-12 — egress is checked per ATTEMPT, fail-closed, which is
        // how CLAUDE.md invariant 6 states the rule. Attempt 1 is already
        // covered: the fan-out gate in `dispatch_many` reads the allowlist
        // immediately before spawning this delivery, so re-reading here would
        // only duplicate it — and would cost one meta.sqlite open per ROW on a
        // batch, which is exactly what the per-batch read exists to avoid.
        // Attempts 2..n are the gap this closes: the schedule spans ~36 s, and
        // an origin removed from the allowlist mid-flight used to keep
        // receiving POSTs until it ran out. The read is live by construction —
        // a fresh read-only connection, nothing cached — and a denial is
        // TERMINAL: `deliver` records the failure and no further attempt runs.
        if attempt_idx > 0
            && let Some((registry, tenant)) = egress
        {
            let allowlist_now = read_tenant_egress_allowlist(registry, tenant);
            if !dispatch_egress_allowed(&allowlist_now, &row.url) {
                tracing::warn!(
                    webhook_id = %row.id,
                    url = %row.url,
                    attempt = attempt_idx + 1,
                    "deliver: origin left the egress allowlist mid-retry — terminal"
                );
                return Err(DeliveryError::EgressRevoked {
                    url: row.url.clone(),
                });
            }
        }
        // v1.32.4 D10 — production fast path: reuse the dispatcher's
        // `cached_client` (built once at construction with
        // `pool_max_idle_per_host(0)` + the resolver baked in). Loopback
        // dev hosts skip the shared client and rebuild per attempt with
        // no custom resolver — same as pre-D10 behavior, so the dev
        // bypass for 127.0.0.1 / localhost / ::1 stays intact.
        let client: Arc<reqwest::Client> =
            if let Some(shared) = shared_client.as_ref().filter(|_| !is_loopback_dev) {
                shared.clone()
            } else {
                let mut b = reqwest::Client::builder()
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(10))
                    .redirect(reqwest::redirect::Policy::none())
                    .user_agent("drust-webhook/1.21.0");
                if !is_loopback_dev {
                    // Wrap the `dyn` resolver in a sized handle — reqwest's
                    // `dns_resolver` takes `Arc<R: Resolve + 'static + Sized>`,
                    // and `dyn Resolve` is not `Sized`.
                    b = b.dns_resolver(Arc::new(crate::tenant::webhook_resolver::ResolverHandle(
                        resolver.clone(),
                    )));
                }
                match b.build() {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        return Err(DeliveryError::NonRetryable {
                            status: 0,
                            body: format!("client build: {e}"),
                        });
                    }
                }
            };
        let req = client
            .post(&row.url)
            .header("content-type", "application/json")
            .header("x-drust-signature", &sig)
            .header("x-drust-delivery-id", &delivery_id)
            .header("x-drust-timestamp", &timestamp)
            .timeout(Duration::from_secs(sched.per_attempt_timeout_secs))
            .body(body_bytes.clone());
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if (200..300).contains(&status) {
                    return Ok(());
                }
                if (400..500).contains(&status) {
                    let body = resp.text().await.unwrap_or_default();
                    let truncated: String = body.chars().take(200).collect();
                    return Err(DeliveryError::NonRetryable {
                        status,
                        body: truncated,
                    });
                }
                last_err = format!("attempt {} got status {}", attempt_idx + 1, status);
            }
            Err(e) => {
                last_err = format!("attempt {} network err: {}", attempt_idx + 1, e);
            }
        }
    }
    Err(DeliveryError::Exhausted {
        last_error: last_err,
        attempts: sched.backoffs.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn events_contains_matches_each_name() {
        let s = r#"["created","updated"]"#;
        assert!(events_contains(s, "created"));
        assert!(events_contains(s, "updated"));
        assert!(!events_contains(s, "deleted"));
        assert!(!events_contains("not json", "created"));
        assert!(!events_contains("[]", "created"));
    }

    #[test]
    fn compute_signature_matches_known_vector() {
        // HMAC-SHA256("topsecret", "hello") verified via:
        // python3 -c "import hmac,hashlib; print(hmac.new(b'topsecret',b'hello',hashlib.sha256).hexdigest())"
        let sig = compute_signature("topsecret", b"hello");
        assert_eq!(
            sig,
            "sha256=ed76fd36523b8becda5a3b36d0e3737e8ae5111f55e26c7c3a455a3ce29636d2"
        );
    }

    #[test]
    fn build_payload_shape_created_event() {
        let ev = Event::Created {
            record: json!({"id":7,"title":"hi"}),
        };
        let v = build_payload("tA", "videos", &ev, "del-1", "2026-01-01T00:00:00Z");
        assert_eq!(v["tenant"], "tA");
        assert_eq!(v["collection"], "videos");
        assert_eq!(v["event"], "created");
        assert_eq!(v["record"]["title"], "hi");
        assert_eq!(v["delivery_id"], "del-1");
    }

    #[test]
    fn build_payload_deleted_event_has_id_only() {
        let ev = Event::Deleted { id: 99 };
        let v = build_payload("tA", "videos", &ev, "del-2", "2026-01-01T00:00:00Z");
        assert_eq!(v["event"], "deleted");
        assert_eq!(v["record"], json!({"id": 99}));
    }

    #[test]
    fn record_failure_truncates_to_200_chars() {
        let dir = tempfile::tempdir().unwrap();
        let tid = "t-rf";
        let _ = crate::storage::tenant_db::open_write(dir.path(), tid).unwrap();
        let p = dir.path().join("tenants").join(tid).join("data.sqlite");
        let conn = Connection::open(&p).unwrap();
        conn.execute(
            "INSERT INTO _system_webhooks
                (collection,events,url,secret,active,created_at)
             VALUES ('c','[]','https://x','s',1,'2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        let long = "x".repeat(500);
        record_failure(&conn, 1, &long).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT last_failure_reason FROM _system_webhooks WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored.len(), 200);
        assert!(stored.chars().all(|c| c == 'x'));
    }
}

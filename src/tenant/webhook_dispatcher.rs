//! WebhookDispatcher — record-CRUD event → subscribed URLs.
//!
//! Public API:
//!   WebhookDispatcher::new(
//!       pool: Arc<TenantRegistry>,
//!       resolver_override: Option<Arc<dyn reqwest::dns::Resolve + Send + Sync>>,
//!   ) -> Arc<Self>
//!   WebhookDispatcher::dispatch(&self, tenant: &str, collection: &str, event: Event)
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

/// Read a tenant's egress allowlist JSON from `meta.sqlite` for the dispatch
/// gate. Opens a short-lived READ-ONLY connection (dispatch runs on a spawned,
/// off-hot-path task, so a per-event open is acceptable). Fail-CLOSED: any
/// open/read failure yields the deny-all `"[]"`, so a transient meta hiccup
/// denies delivery to non-loopback hosts rather than opening egress.
fn read_tenant_egress_allowlist(registry: &TenantRegistry, tenant: &str) -> String {
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
    /// Spawns a Tokio task per delivery; errors are silently swallowed at the
    /// dispatch level (individual delivery failures are recorded via
    /// `record_failure`). Returns immediately — the callers are on the hot
    /// REST/MCP path and must not block.
    pub fn dispatch(&self, tenant: &str, collection: &str, event: Event) {
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
            let tenant_pool = match pool.get_or_open(&tenant) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = ?e, tenant = %tenant, "webhook dispatch: get_or_open failed");
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
            // v1.49 egress third gate — read the tenant's allowlist ONCE per
            // event (fresh from meta, so a just-removed origin is honored).
            let allowlist_json = read_tenant_egress_allowlist(&pool, &tenant);
            let event_name = event.name();
            for sub in subs {
                if !events_contains(&sub.events, event_name) {
                    continue;
                }
                // Egress third gate: deny delivery to any origin not on the
                // tenant's system=webhook allowlist (loopback dev targets keep
                // the resolver's carve-out). A denial records a failure and
                // skips — no POST, no retry. check_url (registration) + the
                // PinnedPublicResolver (per attempt) remain; this is an ADDED
                // gate, never a replacement.
                if !dispatch_egress_allowed(&allowlist_json, &sub.url) {
                    let id = sub.id;
                    let reason = format!("egress_not_allowlisted: {}", sub.url);
                    let _ = tenant_pool
                        .with_writer(move |c| record_failure(c, id, &reason))
                        .await;
                    continue;
                }
                let delivery_id = uuid::Uuid::new_v4().to_string();
                let timestamp = chrono::Utc::now().to_rfc3339();
                let body_bytes = match serde_json::to_vec(&build_payload(
                    &tenant,
                    &collection,
                    &event,
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
                tokio::spawn(async move {
                    if let Err(e) = deliver(
                        client2,
                        resolver2,
                        &sub,
                        body_bytes,
                        delivery_id2,
                        timestamp2,
                        DeliverySchedule::default(),
                        &pool2,
                        &tenant2,
                    )
                    .await
                    {
                        tracing::warn!(error = ?e, tenant = %tenant2, webhook_id = %sub.id, "webhook deliver: final failure");
                    }
                });
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
        }
    }
}

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
        match pool.get_or_open(tenant_id) {
            Ok(tenant_pool) => {
                let _ = tenant_pool
                    .with_writer(move |conn| record_failure(conn, id, &reason))
                    .await;
            }
            Err(err) => {
                tracing::warn!(error = ?err, tenant = %tenant_id, "deliver: get_or_open failed, skipping record_failure");
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

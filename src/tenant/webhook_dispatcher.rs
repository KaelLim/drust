//! WebhookDispatcher — record-CRUD event → subscribed URLs.
//!
//! Public API:
//!   WebhookDispatcher::new(tenants_root: PathBuf) -> Arc<Self>
//!   WebhookDispatcher::dispatch(&self, tenant: &str, collection: &str, event: Event)
//!
//! Internal: pure helpers below (HMAC, payload, event filter) are
//! `pub(crate)` to keep them testable from the integration suite.

use crate::tenant::events::Event;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::path::PathBuf;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookRow {
    pub id: i64,
    pub collection: String,
    pub events: String,    // JSON array as text
    pub url: String,
    pub secret: String,
    pub active: i64,
}

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
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(7 + bytes.len() * 2);
    hex.push_str("sha256=");
    for b in bytes { hex.push_str(&format!("{:02x}", b)); }
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
    let (ev, rec) = match event {
        Event::Created { record } => ("created", record.clone()),
        Event::Updated { record } => ("updated", record.clone()),
        Event::Deleted { id }     => ("deleted", json!({"id": id})),
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

#[derive(Clone)]
pub struct WebhookDispatcher {
    tenants_root: PathBuf,
    http: reqwest::Client,
}

impl WebhookDispatcher {
    pub fn new(tenants_root: PathBuf) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .pool_max_idle_per_host(8)
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("drust-webhook/1.13.0")
            .build()
            .expect("reqwest client builds");
        Arc::new(Self { tenants_root, http })
    }

    /// Public dispatch entry — see Task 5 wiring + Task 4 delivery.
    /// Currently a no-op stub so this task's tests still compile.
    pub fn dispatch(&self, _tenant: &str, _collection: &str, _event: Event) {
        // intentionally empty for Task 2; Task 5 fills in.
    }
}

/// Open a fresh read+write connection to a tenant's `data.sqlite`. The
/// dispatcher owns connections only for the duration of one subscription
/// query — no pooling needed at v1.13 scale.
pub(crate) fn open_tenant_conn(
    tenants_root: &std::path::Path,
    tenant: &str,
) -> rusqlite::Result<Connection> {
    let p = tenants_root.join("tenants").join(tenant).join("data.sqlite");
    Connection::open(p)
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
pub(crate) fn record_failure(
    conn: &Connection,
    id: i64,
    reason: &str,
) -> rusqlite::Result<()> {
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
        Self { backoffs: [0, 1, 5, 30], per_attempt_timeout_secs: 10 }
    }
}

impl DeliverySchedule {
    pub const fn fast_for_tests() -> Self {
        Self { backoffs: [0, 0, 0, 0], per_attempt_timeout_secs: 2 }
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
            DeliveryError::Exhausted { last_error, attempts } => {
                write!(f, "all {} attempts failed: {}", attempts, last_error)
            }
        }
    }
}

/// Production entry: one delivery, 4 attempts, fail-then-record_failure.
pub(crate) async fn deliver(
    http: &reqwest::Client,
    row: &WebhookRow,
    body_bytes: Vec<u8>,
    sched: DeliverySchedule,
    tenants_root: &std::path::Path,
    tenant_id: &str,
) -> Result<(), DeliveryError> {
    let outcome = deliver_for_test(http, row, body_bytes, sched).await;
    if let Err(ref e) = outcome {
        if let Ok(conn) = open_tenant_conn(tenants_root, tenant_id) {
            let _ = record_failure(&conn, row.id, &e.to_string());
        }
    }
    outcome
}

/// Pure HTTP-only entry — does NOT touch the DB. Exposed for the
/// integration tests so they can assert signature / retry shape without
/// spinning up a tenant DB.
pub async fn deliver_for_test(
    http: &reqwest::Client,
    row: &WebhookRow,
    body_bytes: Vec<u8>,
    sched: DeliverySchedule,
) -> Result<(), DeliveryError> {
    let sig = compute_signature(&row.secret, &body_bytes);
    let delivery_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut last_err = String::new();
    for (attempt_idx, wait_secs) in sched.backoffs.iter().enumerate() {
        if *wait_secs > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(*wait_secs)).await;
        }
        let req = http
            .post(&row.url)
            .header("content-type", "application/json")
            .header("x-drust-signature", &sig)
            .header("x-drust-delivery-id", &delivery_id)
            .header("x-drust-timestamp", &timestamp)
            .timeout(std::time::Duration::from_secs(sched.per_attempt_timeout_secs))
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
                    return Err(DeliveryError::NonRetryable { status, body: truncated });
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
        let ev = Event::Created { record: json!({"id":7,"title":"hi"}) };
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

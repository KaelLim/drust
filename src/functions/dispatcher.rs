//! `FunctionDispatcher` — mirrors `WebhookDispatcher.dispatch(&self, tenant,
//! collection, event)` (src/tenant/webhook_dispatcher.rs:161) but takes
//! `&Event` (callers keep ownership for the webhook move) and enqueues onto
//! the global bounded mpsc instead of spawning HTTP tasks.
//!
//! Hot-path cost per CRUD: one `Event` clone (full record JSON), six Arc
//! clones, and one unconditional `tokio::spawn` — the binding-cache DashMap
//! get happens inside the spawned task, off the caller's thread. Same shape
//! as the webhook precedent (spec §4); revisit with a sync cached-empty
//! fast-path on `BindingCache` if the spawn-per-CRUD ever shows up in a
//! profile against the 13k-rps positioning.

use crate::functions::FnConfig;
use crate::functions::bindings::BindingCache;
use crate::functions::executor::Invocation;
use crate::storage::pool::TenantRegistry;
use crate::tenant::events::Event;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::mpsc;

pub struct FunctionDispatcher {
    tenants: Arc<TenantRegistry>,
    pub bindings: Arc<BindingCache>,
    tx: mpsc::Sender<Invocation>,
    cfg: FnConfig,
    /// Per-tenant queued+running counter (shared Arc with the Executor,
    /// which decrements on completion).
    pub depth: Arc<DashMap<String, Arc<AtomicUsize>>>,
    /// Total invocations dropped at the queue-depth cap. `Arc` so the
    /// fire-and-forget dispatch tasks can record drops without borrowing
    /// `self`.
    pub dropped_total: Arc<AtomicU64>,
}

impl FunctionDispatcher {
    pub fn new(
        tenants: Arc<TenantRegistry>,
        tx: mpsc::Sender<Invocation>,
        cfg: FnConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            tenants,
            bindings: Arc::new(BindingCache::new()),
            tx,
            cfg,
            depth: Arc::new(DashMap::new()),
            dropped_total: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Record-CRUD entry point — call beside the existing
    /// `bus.publish` + `webhooks.dispatch` pairs at all SIX emission sites.
    /// Borrow-only for the caller; the spawned task builds the payload once
    /// the tenant has any binding (before the per-binding trigger filter).
    pub fn dispatch(&self, tenant: &str, collection: &str, event: &Event) {
        let me_tenant = tenant.to_string();
        let me_coll = collection.to_string();
        let ev = event.clone();
        let tenants = self.tenants.clone();
        let bindings = self.bindings.clone();
        let tx = self.tx.clone();
        let depth = self.depth.clone();
        let queue_depth = self.cfg.queue_depth;
        let dropped = self.dropped_total.clone();
        // Fire-and-forget — hot path must not await.
        tokio::spawn(async move {
            let pool = match tenants.get_or_open(&me_tenant) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = ?e, tenant = %me_tenant, "function dispatch: get_or_open failed");
                    return;
                }
            };
            let binds = bindings.get_or_load(&me_tenant, &pool).await;
            if binds.is_empty() {
                return;
            }
            let ev_name = ev.name(); // "created" | "updated" | "deleted"
            let payload = match &ev {
                Event::Created { record } => serde_json::json!({
                    "trigger": "record.created",
                    "collection": me_coll, "record": record }),
                Event::Updated { record } => serde_json::json!({
                    "trigger": "record.updated",
                    "collection": me_coll, "record": record }),
                Event::Deleted { id } => serde_json::json!({
                    "trigger": "record.deleted",
                    "collection": me_coll, "id": id }),
            }
            .to_string();
            for b in binds.iter().filter(|b| b.matches_record(&me_coll, ev_name)) {
                enqueue(
                    &tx,
                    &depth,
                    queue_depth,
                    &tenants,
                    &dropped,
                    Invocation {
                        tenant_id: me_tenant.clone(),
                        function_name: b.function_name.clone(),
                        trigger: format!("record.{ev_name}:{me_coll}"),
                        event_json: payload.clone(),
                    },
                )
                .await;
            }
        });
    }

    /// Manual (test-invoke) enqueue — same depth accounting as event dispatch.
    pub async fn enqueue_manual(&self, tenant: &str, function_name: &str, event_json: String) {
        enqueue(
            &self.tx,
            &self.depth,
            self.cfg.queue_depth,
            &self.tenants,
            &self.dropped_total,
            Invocation {
                tenant_id: tenant.to_string(),
                function_name: function_name.to_string(),
                trigger: "manual".into(),
                event_json,
            },
        )
        .await;
    }

    /// file.uploaded entry point — called at Mode A / Mode B completion.
    /// Deliberately NOT an `Event` variant (spec §4: file events must not
    /// leak into SSE/webhooks).
    pub fn dispatch_file(
        &self,
        tenant: &str,
        key: &str,
        size_bytes: i64,
        visibility: &str,
        content_type: &str,
    ) {
        let me_tenant = tenant.to_string();
        let payload = serde_json::json!({
            "trigger": "file.uploaded",
            "key": key, "size_bytes": size_bytes,
            "visibility": visibility, "content_type": content_type,
        })
        .to_string();
        let tenants = self.tenants.clone();
        let bindings = self.bindings.clone();
        let tx = self.tx.clone();
        let depth = self.depth.clone();
        let queue_depth = self.cfg.queue_depth;
        let dropped = self.dropped_total.clone();
        tokio::spawn(async move {
            let pool = match tenants.get_or_open(&me_tenant) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = ?e, tenant = %me_tenant, "function dispatch: get_or_open failed");
                    return;
                }
            };
            let binds = bindings.get_or_load(&me_tenant, &pool).await;
            for b in binds.iter().filter(|b| b.matches_file_uploaded()) {
                enqueue(
                    &tx,
                    &depth,
                    queue_depth,
                    &tenants,
                    &dropped,
                    Invocation {
                        tenant_id: me_tenant.clone(),
                        function_name: b.function_name.clone(),
                        trigger: "file.uploaded".to_string(),
                        event_json: payload.clone(),
                    },
                )
                .await;
            }
        });
    }
}

/// Enqueue with per-tenant depth accounting. Overflow ⇒ drop + `dropped`
/// log row + sampled warn (spec §8).
async fn enqueue(
    tx: &mpsc::Sender<Invocation>,
    depth: &DashMap<String, Arc<AtomicUsize>>,
    cap: usize,
    tenants: &Arc<TenantRegistry>,
    dropped: &AtomicU64,
    inv: Invocation,
) {
    let counter = depth
        .entry(inv.tenant_id.clone())
        .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
        .clone();
    let prev = counter.fetch_add(1, Ordering::Relaxed);
    if prev >= cap {
        counter.fetch_sub(1, Ordering::Relaxed);
        let n = dropped.fetch_add(1, Ordering::Relaxed) + 1;
        // Sampled WARN (spec §8) — sustained overflow would otherwise emit
        // one identical line per drop and drown the journal. Same threshold
        // idiom as audit_db.rs::try_send_inner.
        if n == 1 || n.is_multiple_of(10_000) {
            tracing::warn!(
                tenant = %inv.tenant_id, function = %inv.function_name,
                total_dropped = n,
                "function queue full — invocation dropped (rate-limited log)"
            );
        }
        if let Ok(pool) = tenants.get_or_open(&inv.tenant_id) {
            let _ = crate::functions::schema::insert_log(
                &pool,
                crate::functions::schema::LogRow {
                    invocation_id: uuid::Uuid::new_v4().to_string(),
                    function_name: inv.function_name.clone(),
                    trigger: inv.trigger.clone(),
                    status: "dropped".into(),
                    duration_ms: 0,
                    log_text: String::new(),
                    result_json: Some(format!(r#"{{"reason":"queue depth {cap} exceeded"}}"#)),
                },
            )
            .await;
        }
        return;
    }
    if tx.send(inv).await.is_err() {
        counter.fetch_sub(1, Ordering::Relaxed);
        tracing::warn!("function queue receiver gone — invocation lost");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::schema::{self, CreateFunctionParams};

    async fn tenant_with_fn(
        dir: &std::path::Path,
        triggers: &str,
    ) -> (Arc<TenantRegistry>, crate::storage::pool::SharedTenantPool) {
        let reg = Arc::new(TenantRegistry::new(dir.to_path_buf(), 2));
        let pool = reg.get_or_open("t-d").unwrap();
        schema::create_function(
            &pool,
            CreateFunctionParams {
                name: "f".into(),
                wasm_sha256: "00".repeat(32),
                size_bytes: 1,
                triggers_json: triggers.into(),
                description: String::new(),
            },
            10,
        )
        .await
        .unwrap();
        (reg, pool)
    }

    #[tokio::test]
    async fn record_event_enqueues_matching_only() {
        let dir = tempfile::tempdir().unwrap();
        let (reg, _pool) =
            tenant_with_fn(dir.path(), r#"[{"collection":"posts","events":["created"]}]"#).await;
        let (tx, mut rx) = mpsc::channel(8);
        let d = FunctionDispatcher::new(reg, tx, FnConfig::test_default());

        d.dispatch("t-d", "posts", &Event::Created { record: serde_json::json!({"id":1}) });
        let inv = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("enqueued")
            .expect("some");
        assert_eq!(inv.function_name, "f");
        assert_eq!(inv.trigger, "record.created:posts");
        assert!(inv.event_json.contains(r#""trigger":"record.created""#));

        // non-matching: wrong event + wrong collection ⇒ nothing arrives
        d.dispatch("t-d", "posts", &Event::Deleted { id: 1 });
        d.dispatch("t-d", "other", &Event::Created { record: serde_json::json!({}) });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "no enqueue for non-matching events"
        );
    }

    #[tokio::test]
    async fn file_event_enqueues() {
        let dir = tempfile::tempdir().unwrap();
        let (reg, _pool) = tenant_with_fn(dir.path(), r#"[{"file_uploaded":true}]"#).await;
        let (tx, mut rx) = mpsc::channel(8);
        let d = FunctionDispatcher::new(reg, tx, FnConfig::test_default());
        d.dispatch_file("t-d", "t-d/x.jpg", 123, "private", "image/jpeg");
        let inv = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("enqueued")
            .expect("some");
        assert_eq!(inv.trigger, "file.uploaded");
        assert!(inv.event_json.contains(r#""size_bytes":123"#));
    }

    #[tokio::test]
    async fn overflow_drops_with_log_row() {
        let dir = tempfile::tempdir().unwrap();
        let (reg, pool) = tenant_with_fn(dir.path(), r#"[{"file_uploaded":true}]"#).await;
        let mut cfg = FnConfig::test_default();
        cfg.queue_depth = 2;
        // receiver exists but nobody drains — fill to cap then overflow
        let (tx, _rx) = mpsc::channel(64);
        let d = FunctionDispatcher::new(reg, tx, cfg);
        for _ in 0..5 {
            d.dispatch_file("t-d", "k", 1, "private", "x");
        }
        // poll for the dropped rows (3 of 5 must drop at depth cap 2)
        for _ in 0..100 {
            let logs = schema::list_logs(&pool, "f", 100).await.unwrap();
            if logs.iter().filter(|l| l.status == "dropped").count() == 3 {
                assert_eq!(d.dropped_total.load(Ordering::Relaxed), 3);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("expected exactly 3 dropped log rows");
    }
}

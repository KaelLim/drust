//! v1.32 C1 — Prometheus metrics endpoint.
//!
//! Mounted at `GET /admin/_metrics`, admin-session-gated.
//! Five counters; passive — only the scrape consumes them. Closes
//! the ISO/IEC 27001 A.8.16 (Monitoring) gap surfaced in the v1.31.9
//! code review.
//!
//! Counter wiring:
//!   - `drust_audit_drops_total`       — incremented in `safety::audit_db`
//!                                       at every channel-full drop.
//!   - `drust_bearer_denied_total`     — incremented in `tenant::router`
//!                                       bearer_auth_layer denial branches.
//!   - `drust_webhook_attempts_total`  — incremented in `tenant::webhook_dispatcher`
//!                                       after each delivery attempt.
//!   - `drust_ws_connections_active`   — inc/dec in `tenant::rooms::ws`.
//!   - `drust_tenant_db_bytes`         — refreshed at scrape time from
//!                                       meta.sqlite `tenants.db_bytes`.

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, TextEncoder, register_int_counter,
    register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
};
use std::sync::OnceLock;

use crate::mgmt::routes::MgmtState;

pub struct Metrics {
    pub audit_drops_total: IntCounter,
    pub bearer_denied_total: IntCounterVec,
    pub webhook_attempts_total: IntCounterVec,
    pub ws_connections_active: IntGauge,
    pub tenant_db_bytes: IntGaugeVec,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(|| {
        let m = Metrics {
            audit_drops_total: register_int_counter!(
                "drust_audit_drops_total",
                "Total audit rows dropped due to channel full"
            )
            .expect("register audit_drops_total"),
            bearer_denied_total: register_int_counter_vec!(
                "drust_bearer_denied_total",
                "Bearer auth denials by role and HTTP status",
                &["role", "status"]
            )
            .expect("register bearer_denied_total"),
            webhook_attempts_total: register_int_counter_vec!(
                "drust_webhook_attempts_total",
                "Webhook delivery attempts by outcome",
                &["result"]
            )
            .expect("register webhook_attempts_total"),
            ws_connections_active: register_int_gauge!(
                "drust_ws_connections_active",
                "Currently-active WebSocket connections"
            )
            .expect("register ws_connections_active"),
            tenant_db_bytes: register_int_gauge_vec!(
                "drust_tenant_db_bytes",
                "Per-tenant data.sqlite byte size from last stats sample",
                &["tenant_id"]
            )
            .expect("register tenant_db_bytes"),
        };
        // Pre-initialize common label combinations so Prometheus emits the
        // metric lines even before the first observation — scrapers see a
        // stable set of series from the first scrape. Zero-valued is fine;
        // it distinguishes "counter exists but empty" from "never registered".
        m.bearer_denied_total
            .with_label_values(&["none", "HTTP_401"]);
        m.bearer_denied_total
            .with_label_values(&["unknown", "HTTP_401"]);
        m.webhook_attempts_total.with_label_values(&["success"]);
        m.webhook_attempts_total.with_label_values(&["4xx"]);
        m.webhook_attempts_total.with_label_values(&["5xx"]);
        m.webhook_attempts_total.with_label_values(&["timeout"]);
        m.webhook_attempts_total.with_label_values(&["network"]);
        m
    })
}

/// Handler for `GET /admin/_metrics`. Already admin-session-gated by router.
///
/// Refreshes the `drust_tenant_db_bytes` gauge from `meta.sqlite` at
/// scrape time (pull model — the stats sampler keeps `db_bytes` fresh at
/// `DRUST_STATS_SAMPLE_INTERVAL_SECS`, default 300 s).
pub async fn handler(State(state): State<MgmtState>) -> impl IntoResponse {
    let m = metrics();

    // Refresh tenant_db_bytes at scrape time.
    {
        let conn = state.meta.lock().await;
        if let Ok(mut stmt) =
            conn.prepare("SELECT id, COALESCE(db_bytes, 0) FROM tenants WHERE deleted_at IS NULL")
            && let Ok(rows) =
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        {
            for row in rows.flatten() {
                m.tenant_db_bytes.with_label_values(&[&row.0]).set(row.1);
            }
        }
    }

    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    if encoder.encode(&metric_families, &mut buffer).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode failed").into_response();
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        buffer,
    )
        .into_response()
}

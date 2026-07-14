//! v1.49 — transport-agnostic egress-allowlist config core (spec §Config).
//!
//! Service-only whole-list REPLACE shared by all three faces: MCP
//! `set_egress_allowlist` / `get_egress_allowlist` (`src/mcp/handler.rs`), REST
//! `PUT/GET /t/{tenant}/egress-allowlist` (handlers below), and the admin
//! `⚙ _settings` block (`src/mgmt/tenant_settings.rs`). Every mutation runs the
//! SAME config-time validation (origin shape + known system + count cap),
//! writes normalized JSON to `tenants.egress_allowlist_json`, and emits an
//! audit row (op `tenant.egress.set`) — so the three surfaces "同拒同納".
//!
//! The store is the single per-tenant column read by the webhook third gate
//! and the `http-fetch` host import via `egress::read_egress_allowlist`; this
//! module owns the WRITE side only. Reads here (`get_allowlist`) are pure.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

use crate::error::json_error;
use crate::safety::audit::AuditEntry;
use crate::tenant::egress::{EgressEntry, EgressSystem, normalize_origin};
use crate::tenant::router::TenantAuthState;

/// Default per-tenant entry cap; override with `DRUST_EGRESS_MAX_ENTRIES`.
pub const DEFAULT_MAX_ENTRIES: usize = 50;

/// Resolve the per-tenant entry cap from the environment (default 50). A
/// non-positive / unparsable value falls back to the default.
pub fn max_entries() -> usize {
    std::env::var("DRUST_EGRESS_MAX_ENTRIES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_ENTRIES)
}

/// Raw wire entry BEFORE validation — `system` arrives as a free string so a
/// bogus tag surfaces as a typed `EGRESS_BAD_SYSTEM` (400 / invalid_params)
/// instead of a serde rejection buried in the extractor. Shared by the REST
/// body and the MCP args struct.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct RawEgressEntry {
    /// `"webhook"` or `"function"`.
    pub system: String,
    /// Allowed origin, e.g. `"https://api.github.com"` (scheme://host[:port]).
    pub uri: String,
}

/// Config-time validation failures. Each maps to a 400 on REST / invalid_params
/// on MCP. Infra/DB failures travel a separate `anyhow` channel (→ 500), never
/// through this enum.
#[derive(Debug)]
pub enum EgressConfigError {
    /// `uri` is not a well-formed http(s) origin.
    BadOrigin(String),
    /// `system` is neither `"webhook"` nor `"function"`.
    BadSystem(String),
    /// Entry count exceeds `DRUST_EGRESS_MAX_ENTRIES`.
    TooMany(usize),
}

impl EgressConfigError {
    /// Stable machine code for REST `error_code` / MCP data.
    pub fn code(&self) -> &'static str {
        match self {
            EgressConfigError::BadOrigin(_) => "EGRESS_BAD_ORIGIN",
            EgressConfigError::BadSystem(_) => "EGRESS_BAD_SYSTEM",
            EgressConfigError::TooMany(_) => "EGRESS_TOO_MANY",
        }
    }
    /// Human-facing message.
    pub fn message(&self) -> String {
        match self {
            EgressConfigError::BadOrigin(u) => {
                format!("not a valid origin (want scheme://host[:port]): {u:?}")
            }
            EgressConfigError::BadSystem(s) => {
                format!("unknown system {s:?} (want \"webhook\" or \"function\")")
            }
            EgressConfigError::TooMany(n) => {
                format!("{n} entries exceeds the limit of {}", max_entries())
            }
        }
    }
}

impl std::fmt::Display for EgressConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // "<CODE>: <message>" — mirrors the REST json_error shape so the MCP
        // `bail_mcp`-style code extraction (split on ':') recovers the code.
        write!(f, "{}: {}", self.code(), self.message())
    }
}

/// Validate a raw entry list into normalized `EgressEntry`s (pure — no I/O).
/// Enforces the count cap first (cheap), then per-entry known-system + origin
/// shape. The normalized origin is what gets stored, so `https://A.com/` and
/// `https://a.com` collapse to one canonical form.
pub fn validate_entries(entries: &[RawEgressEntry]) -> Result<Vec<EgressEntry>, EgressConfigError> {
    if entries.len() > max_entries() {
        return Err(EgressConfigError::TooMany(entries.len()));
    }
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let system = EgressSystem::parse(&e.system)
            .ok_or_else(|| EgressConfigError::BadSystem(e.system.clone()))?;
        let origin =
            normalize_origin(&e.uri).map_err(|_| EgressConfigError::BadOrigin(e.uri.clone()))?;
        out.push(EgressEntry {
            system,
            uri: origin,
        });
    }
    Ok(out)
}

/// Whole-list REPLACE: validate → write normalized JSON → audit. The outer
/// `anyhow::Result` carries infra/DB failure (→ 500); the inner `Result`
/// carries config-time validation failure (→ 400 / invalid_params). Returns
/// the stored JSON on success. `actor_hint` is the audit `token_hint`
/// ("service" / "admin-ui").
pub async fn set_allowlist(
    meta: &Arc<Mutex<Connection>>,
    tenant: &str,
    entries: Vec<RawEgressEntry>,
    actor_hint: &str,
) -> anyhow::Result<Result<String, EgressConfigError>> {
    let normalized = match validate_entries(&entries) {
        Ok(n) => n,
        Err(e) => return Ok(Err(e)),
    };
    let stored = serde_json::to_string(&normalized).unwrap_or_else(|_| "[]".to_string());
    {
        let conn = meta.lock().await;
        conn.execute(
            "UPDATE tenants SET egress_allowlist_json = ?1 \
             WHERE id = ?2 AND deleted_at IS NULL",
            rusqlite::params![stored, tenant],
        )?;
    }
    // Fire-and-forget audit (global writer). op `tenant.egress.set` — every
    // allowlist change is auditable (the spec's "外洩後改動可稽核" mitigation).
    crate::safety::audit_db::try_send(
        &AuditEntry::success(tenant, actor_hint, "tenant.egress.set", 0)
            .with_extra(json!({ "entry_count": normalized.len() })),
    );
    Ok(Ok(stored))
}

/// Read the stored allowlist JSON (`'[]'` when absent — fail-safe, mirrors
/// `egress::read_egress_allowlist`).
pub async fn get_allowlist(meta: &Arc<Mutex<Connection>>, tenant: &str) -> String {
    let conn = meta.lock().await;
    crate::tenant::egress::read_egress_allowlist(&conn, tenant).unwrap_or_else(|_| "[]".to_string())
}

/// Build the `{ "entries": [...] }` JSON response body from stored JSON.
fn allowlist_body(stored: &str) -> serde_json::Value {
    let entries: serde_json::Value = serde_json::from_str(stored).unwrap_or_else(|_| json!([]));
    json!({ "entries": entries })
}

// ─── REST handlers (service-only; gated by require_service_layer) ────────────

/// Body for `PUT /t/{tenant}/egress-allowlist`.
#[derive(Debug, Deserialize)]
pub struct SetEgressBody {
    #[serde(default)]
    pub entries: Vec<RawEgressEntry>,
}

/// `PUT /t/{tenant}/egress-allowlist` — service-only whole-list replace.
pub async fn put_egress_allowlist(
    State(state): State<TenantAuthState>,
    Path(tenant): Path<String>,
    Json(body): Json<SetEgressBody>,
) -> Response {
    match set_allowlist(&state.meta, &tenant, body.entries, "service").await {
        Ok(Ok(stored)) => Json(allowlist_body(&stored)).into_response(),
        Ok(Err(e)) => json_error(StatusCode::BAD_REQUEST, e.code(), &e.message()),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            &e.to_string(),
        ),
    }
}

/// `GET /t/{tenant}/egress-allowlist` — service-only read.
pub async fn get_egress_allowlist(
    State(state): State<TenantAuthState>,
    Path(tenant): Path<String>,
) -> Response {
    let stored = get_allowlist(&state.meta, &tenant).await;
    Json(allowlist_body(&stored)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(system: &str, uri: &str) -> RawEgressEntry {
        RawEgressEntry {
            system: system.to_string(),
            uri: uri.to_string(),
        }
    }

    #[test]
    fn validate_normalizes_and_dispatches_system() {
        let out = validate_entries(&[
            raw("webhook", "https://GitLab.com/hook?q=1"),
            raw("function", "https://api.github.com:443"),
        ])
        .unwrap();
        assert_eq!(out[0].uri, "https://gitlab.com");
        assert_eq!(out[0].system, EgressSystem::Webhook);
        assert_eq!(out[1].uri, "https://api.github.com");
        assert_eq!(out[1].system, EgressSystem::Function);
    }

    #[test]
    fn validate_rejects_bad_origin_and_system() {
        assert_eq!(
            validate_entries(&[raw("webhook", "a.com")])
                .unwrap_err()
                .code(),
            "EGRESS_BAD_ORIGIN"
        );
        assert_eq!(
            validate_entries(&[raw("bogus", "https://a.com")])
                .unwrap_err()
                .code(),
            "EGRESS_BAD_SYSTEM"
        );
    }

    #[test]
    fn validate_enforces_count_cap() {
        let many: Vec<RawEgressEntry> = (0..(max_entries() + 1))
            .map(|i| raw("function", &format!("https://h{i}.example.com")))
            .collect();
        match validate_entries(&many).unwrap_err() {
            EgressConfigError::TooMany(n) => assert_eq!(n, max_entries() + 1),
            other => panic!("expected TooMany, got {other:?}"),
        }
    }
}

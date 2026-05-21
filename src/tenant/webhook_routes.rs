//! Service-only admin endpoints for managing this tenant's outbound webhook
//! subscriptions (the `_system_webhooks` table).
//!
//! Routes (all service-key-only):
//!   POST   /t/{tenant}/admin/webhooks         — create (returns secret once)
//!   GET    /t/{tenant}/admin/webhooks         — list (secrets redacted)
//!   GET    /t/{tenant}/admin/webhooks/{id}    — one (secret redacted)
//!   PATCH  /t/{tenant}/admin/webhooks/{id}    — update active/events/url
//!   DELETE /t/{tenant}/admin/webhooks/{id}    — remove
//!
//! Auth: service-only. `bearer_auth_layer` attaches `AuthCtx` as a request
//! extension; we gate on `AuthCtx::Service` here (mirrors `admin_user_routes`
//! and `oauth_admin_routes`). Secrets are returned **once** in the 201
//! response body of POST; every subsequent read redacts them to `●●●●`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

use crate::auth::middleware::ServiceTid;
use crate::error::json_error;
use crate::tenant::router::TenantAuthState;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn get_id(params: &HashMap<String, String>) -> Result<i64, Response> {
    let raw = params
        .get("id")
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "missing id"))?;
    raw.parse::<i64>()
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "id must be integer"))
}

/// True if `ip` is in any range we forbid for outbound webhook targets:
/// RFC1918 private (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1),
/// link-local (169.254/16, fe80::/10), wildcard (0.0.0.0/8), or IPv6 ULA
/// (fc00::/7). Returned for any IP that should never receive a webhook
/// from an internet-facing drust instance.
///
/// `localhost`/`127.0.0.1`/`::1` are deliberately included — the existing
/// `check_url` carve-out for `http://localhost` already runs BEFORE this
/// check (see `check_url`), so dev-mode webhooks pointing at the same
/// host still work.
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10/8
            if octets[0] == 10 { return true; }
            // 172.16/12
            if octets[0] == 172 && (octets[1] & 0xf0) == 16 { return true; }
            // 192.168/16
            if octets[0] == 192 && octets[1] == 168 { return true; }
            // 127/8 loopback
            if octets[0] == 127 { return true; }
            // 169.254/16 link-local
            if octets[0] == 169 && octets[1] == 254 { return true; }
            // 0/8 wildcard
            if octets[0] == 0 { return true; }
            false
        }
        IpAddr::V6(v6) => {
            // ::1 loopback
            if v6.is_loopback() { return true; }
            let segs = v6.segments();
            // fc00::/7 ULA  — first 7 bits = 1111110
            if (segs[0] & 0xfe00) == 0xfc00 { return true; }
            // fe80::/10 link-local — first 10 bits = 1111111010
            if (segs[0] & 0xffc0) == 0xfe80 { return true; }
            // ::ffff:a.b.c.d — IPv4-mapped IPv6; re-check the V4 part.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }
            false
        }
    }
}

#[cfg(test)]
mod private_ip_tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn rejects_rfc1918() {
        assert!(is_private_ip(ip("10.0.0.1")));
        assert!(is_private_ip(ip("172.16.5.10")));
        assert!(is_private_ip(ip("172.31.255.255")));
        assert!(is_private_ip(ip("192.168.1.1")));
    }

    #[test]
    fn rejects_loopback_and_link_local() {
        assert!(is_private_ip(ip("127.0.0.1")));
        assert!(is_private_ip(ip("169.254.169.254")));
        assert!(is_private_ip(ip("0.0.0.0")));
        assert!(is_private_ip(ip("::1")));
        assert!(is_private_ip(ip("fe80::1")));
        assert!(is_private_ip(ip("fc00::1")));
    }

    #[test]
    fn accepts_public_ips() {
        assert!(!is_private_ip(ip("8.8.8.8")));
        assert!(!is_private_ip(ip("203.0.113.5")));
        assert!(!is_private_ip(ip("2001:4860:4860::8888")));
    }

    #[test]
    fn ipv4_mapped_ipv6_rechecks() {
        // ::ffff:127.0.0.1 → loopback when unmapped
        assert!(is_private_ip(ip("::ffff:127.0.0.1")));
        // ::ffff:8.8.8.8 → public when unmapped
        assert!(!is_private_ip(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn check_url_http_bracket_ipv6_loopback_allowed() {
        // reqwest::Url::host_str() returns "[::1]" (with brackets) for IPv6
        // literals — the matches! guard in check_url accepts both forms.
        assert!(super::check_url("http://[::1]:8080/hook").is_ok());
    }
}

/// Pure validation for the subscriber URL — returns either `Ok(())` or a
/// `(error_code, message)` pair so callers (REST + MCP) can map to their
/// preferred error shape. Allow:
///   - any `https://…` whose host does NOT resolve to a private/loopback/
///     link-local IP (registration-time DNS check; see residual note below)
///   - `http://` ONLY when host is loopback (`127.0.0.1`, `localhost`, `::1`).
pub fn check_url(raw: &str) -> Result<(), (&'static str, &'static str)> {
    let parsed = match reqwest::Url::parse(raw) {
        Ok(u) => u,
        Err(_) => return Err(("INVALID_URL", "url failed to parse")),
    };
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");
    // v1.19.2 — explicit dev-mode carve-out preserved (loopback hostnames
    // over http://). Must run BEFORE the private-IP resolution check
    // below (which would reject 127.0.0.1).
    // Note: reqwest::Url::host_str() returns "[::1]" (with brackets) for
    // IPv6 literals, so we accept both forms.
    if scheme == "http" && matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]") {
        return Ok(());
    }
    if scheme != "https" {
        return Err((
            "INVALID_URL",
            "url must be https://, or http:// with loopback host",
        ));
    }
    // v1.19.2 SSRF defense: resolve the host to all IPs and reject if any
    // sits in a private / loopback / link-local range. Uses std::net DNS
    // resolution (sync — registration is rare and not on the hot path).
    // Residual: DNS rebinding (resolve to public at register time, change
    // DNS to private later) is NOT mitigated here — request-time resolve
    // + per-attempt re-validation is queued for v1.21.
    use std::net::ToSocketAddrs;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let lookup = format!("{host}:{port}");
    let resolved = match lookup.to_socket_addrs() {
        Ok(iter) => iter.collect::<Vec<_>>(),
        Err(_) => return Err(("INVALID_URL", "host could not be resolved to an IP")),
    };
    if resolved.is_empty() {
        return Err(("INVALID_URL", "host resolved to no IPs"));
    }
    if resolved.iter().any(|sa| is_private_ip(sa.ip())) {
        return Err((
            "INVALID_URL",
            "url host resolves to a private/loopback/link-local IP",
        ));
    }
    Ok(())
}

/// Pure validation for the event-name array.
pub(crate) fn check_events(events: &[String]) -> Result<(), (&'static str, &'static str)> {
    if events.is_empty() {
        return Err(("INVALID_EVENTS", "events array must be non-empty"));
    }
    for ev in events {
        if !matches!(ev.as_str(), "created" | "updated" | "deleted") {
            return Err((
                "INVALID_EVENTS",
                "events must be subset of {created,updated,deleted}",
            ));
        }
    }
    Ok(())
}

/// REST adapter: pure check → 422 Response.
fn validate_url(raw: &str) -> Result<(), Response> {
    check_url(raw).map_err(|(code, msg)| json_error(StatusCode::UNPROCESSABLE_ENTITY, code, msg))
}

/// REST adapter: pure check → 422 Response.
fn validate_events(events: &[String]) -> Result<(), Response> {
    check_events(events).map_err(|(code, msg)| json_error(StatusCode::UNPROCESSABLE_ENTITY, code, msg))
}

/// Generate a 64-char hex-encoded random secret (32 bytes from `OsRng` via
/// `rand::thread_rng`, matching the bearer-token pattern in `auth/bearer.rs`).
pub(crate) fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8] = b"0123456789abcdef";
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ─── request / response shapes ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateBody {
    pub collection: String,
    pub events: Vec<String>,
    pub url: String,
}

/// PATCH body — `secret` is explicitly listed so the handler can reject it
/// with 422 INVALID_PATCH (secrets cannot be rotated through the REST
/// surface; delete + recreate instead). Unknown fields are accepted and
/// ignored, matching the rest of drust REST (no `deny_unknown_fields`).
/// All present known fields are applied; absent ones are untouched.
#[derive(Deserialize)]
pub struct PatchBody {
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub events: Option<Vec<String>>,
    #[serde(default)]
    pub url: Option<String>,
    /// Forbidden — explicit error to discourage clients from trying.
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct WebhookOut {
    pub id: i64,
    pub collection: String,
    pub events: Vec<String>,
    pub url: String,
    /// Always `"●●●●"` on read paths; only the POST 201 response returns the
    /// raw secret (in a separate `CreateOut` shape — see `create_handler`).
    pub secret: &'static str,
    pub active: bool,
    pub last_failure_at: Option<String>,
    pub last_failure_reason: Option<String>,
    pub created_at: String,
}

// ─── handlers ────────────────────────────────────────────────────────────────

pub async fn create_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Json(body): Json<CreateBody>,
) -> Response {
    if let Err(r) = validate_url(&body.url) {
        return r;
    }
    if let Err(r) = validate_events(&body.events) {
        return r;
    }
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let collection = body.collection.clone();
    let events_json = match serde_json::to_string(&body.events) {
        Ok(s) => s,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "ENCODE_FAILED", ""),
    };
    let url = body.url.clone();
    let secret = generate_secret();
    let secret_for_db = secret.clone();
    let now = chrono::Utc::now().to_rfc3339();
    let now2 = now.clone();
    let res: rusqlite::Result<i64> = pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_webhooks \
                 (collection, events, url, secret, active, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                rusqlite::params![collection, events_json, url, secret_for_db, now2],
            )?;
            Ok(c.last_insert_rowid())
        })
        .await;
    match res {
        Ok(id) => (
            StatusCode::CREATED,
            Json(json!({
                "id": id,
                "collection": body.collection,
                "events": body.events,
                "url": body.url,
                "secret": secret,
                "active": true,
                "created_at": now,
            })),
        )
            .into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    }
}

pub async fn list_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
) -> Response {
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let rows: Vec<WebhookOut> = pool
        .with_reader(|c| {
            let mut stmt = c.prepare(
                "SELECT id, collection, events, url, active, \
                        last_failure_at, last_failure_reason, created_at \
                 FROM _system_webhooks \
                 ORDER BY id DESC",
            )?;
            let rows: Vec<WebhookOut> = stmt
                .query_map([], |r| {
                    let events_raw: String = r.get(2)?;
                    let events: Vec<String> =
                        serde_json::from_str(&events_raw).unwrap_or_default();
                    Ok(WebhookOut {
                        id: r.get(0)?,
                        collection: r.get(1)?,
                        events,
                        url: r.get(3)?,
                        secret: "●●●●",
                        active: r.get::<_, i64>(4)? != 0,
                        last_failure_at: r.get::<_, Option<String>>(5)?,
                        last_failure_reason: r.get::<_, Option<String>>(6)?,
                        created_at: r.get(7)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            Ok::<_, rusqlite::Error>(rows)
        })
        .await
        .unwrap_or_default();
    (StatusCode::OK, Json(json!({"webhooks": rows}))).into_response()
}

pub async fn get_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let id = match get_id(&params) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    fetch_webhook_row(pool, id).await
}

async fn fetch_webhook_row(pool: crate::storage::pool::SharedTenantPool, id: i64) -> Response {
    let row = pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT id, collection, events, url, active, \
                        last_failure_at, last_failure_reason, created_at \
                 FROM _system_webhooks WHERE id = ?1",
                rusqlite::params![id],
                |r| {
                    let events_raw: String = r.get(2)?;
                    let events: Vec<String> =
                        serde_json::from_str(&events_raw).unwrap_or_default();
                    Ok(WebhookOut {
                        id: r.get(0)?,
                        collection: r.get(1)?,
                        events,
                        url: r.get(3)?,
                        secret: "●●●●",
                        active: r.get::<_, i64>(4)? != 0,
                        last_failure_at: r.get::<_, Option<String>>(5)?,
                        last_failure_reason: r.get::<_, Option<String>>(6)?,
                        created_at: r.get(7)?,
                    })
                },
            )
        })
        .await;
    match row {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => json_error(StatusCode::NOT_FOUND, "NOT_FOUND", "webhook not found"),
    }
}

pub async fn patch_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Path(params): Path<HashMap<String, String>>,
    Json(body): Json<PatchBody>,
) -> Response {
    // Reject attempts to rotate the secret via PATCH — delete + recreate.
    if body.secret.is_some() {
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_PATCH",
            "secret cannot be updated via PATCH; rotate = delete+create",
        );
    }
    let id = match get_id(&params) {
        Ok(i) => i,
        Err(r) => return r,
    };
    if let Some(ref u) = body.url {
        if let Err(r) = validate_url(u) {
            return r;
        }
    }
    if let Some(ref evs) = body.events {
        if let Err(r) = validate_events(evs) {
            return r;
        }
    }
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let new_active = body.active.map(|b| if b { 1i64 } else { 0i64 });
    let new_events_json = match body.events.as_ref().map(serde_json::to_string).transpose() {
        Ok(v) => v,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "ENCODE_FAILED", ""),
    };
    let new_url = body.url.clone();
    let res = pool
        .with_writer(move |c| -> rusqlite::Result<usize> {
            let tx = c.transaction()?;
            if let Some(v) = new_active {
                tx.execute(
                    "UPDATE _system_webhooks SET active = ?1 WHERE id = ?2",
                    rusqlite::params![v, id],
                )?;
            }
            if let Some(ref e) = new_events_json {
                tx.execute(
                    "UPDATE _system_webhooks SET events = ?1 WHERE id = ?2",
                    rusqlite::params![e, id],
                )?;
            }
            if let Some(ref u) = new_url {
                tx.execute(
                    "UPDATE _system_webhooks SET url = ?1 WHERE id = ?2",
                    rusqlite::params![u, id],
                )?;
            }
            // Check the row exists — partial UPDATEs above silently no-op on
            // a missing id, so consult the row count explicitly.
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM _system_webhooks WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )?;
            tx.commit()?;
            Ok(count as usize)
        })
        .await;
    match res {
        Ok(0) => json_error(StatusCode::NOT_FOUND, "NOT_FOUND", "webhook not found"),
        Ok(_) => fetch_webhook_row(pool, id).await,
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    }
}

pub async fn delete_handler(
    State(state): State<TenantAuthState>,
    ServiceTid(tid): ServiceTid,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let id = match get_id(&params) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", ""),
    };
    let res = pool
        .with_writer(move |c| {
            c.execute(
                "DELETE FROM _system_webhooks WHERE id = ?1",
                rusqlite::params![id],
            )
        })
        .await;
    match res {
        Ok(0) => json_error(StatusCode::NOT_FOUND, "NOT_FOUND", "webhook not found"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", ""),
    }
}

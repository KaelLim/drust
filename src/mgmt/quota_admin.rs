//! v1.50 (Spec B, Task 6) — quota upgrade request / review admin plane.
//!
//! Three faces, all admin-plane only (there is deliberately NO per-tenant MCP
//! tool — a tenant's service key must never raise its own quota, spec §7):
//!
//! - member (owns the tenant): `POST /admin/tenants/{id}/quota/requests`
//!   files a `quota_requests` row. The route sits on `tenants_router`, so the
//!   Spec A `tenant_ownership_layer` already 404s a foreign tenant before the
//!   handler runs. `requested_tier <= current` → `400 QUOTA_TIER_NOT_INCREASE`;
//!   an existing pending row for the tenant → `409 QUOTA_REQUEST_PENDING`.
//! - owner: `GET /admin/quota-requests` (host-wide review page, owner-only via
//!   `require_owner_layer`), `POST /admin/quota-requests/{id}/decide`
//!   (approve = one transaction: raise `tenants.quota_tier` + close the
//!   request), and `PATCH /admin/tenants/{id}/quota` (direct set — in-handler
//!   owner check, since the tenants_router guard only enforces member
//!   visibility, not the owner role).
//!
//! A tier change (approve or direct PATCH) evicts the tenant's auth-cache
//! entries (`clear_tenant`) so the raised tier — which rides the bearer CTE
//! (Task 5) — takes effect on the very next data-plane request rather than
//! after the ≤10 s safety TTL. Every mutating face emits an audit row
//! (`tenant.quota.request` on file, `tenant.quota.set` on decide/direct-set).

use askama::Template;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use rusqlite::OptionalExtension;
use serde_json::json;

use crate::error::json_error;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::tenants::TenantsState;
use crate::mgmt::theme::{ResolvedPalette, ThemeHint, ThemeRenderCtx};

/// Upper bound on a requestable/settable tier (defensive — a 10 GiB × tier cap
/// stays sane; the UI never offers more than a handful).
const MAX_TIER: i64 = 1000;

// ─── request retention + submit rate limit (2026-08-02 review) ───────────────
//
// The parallel of `tenant_cap`'s pair, and the reason that pair exists at all:
// `create_cap_request` was written from this handler. The cap queue got both
// bounds first; this queue is strictly MORE exposed and had neither, because
// its pending gate is keyed on the TENANT — a member at the default cap of 3
// holds 3 concurrent pending rows, so one reject/refile cycle appends 3.

/// Days a DECIDED quota request is kept before the daily janitor prunes it.
/// `0` = keep forever. Pending requests are never auto-pruned.
pub const DEFAULT_REQUEST_RETENTION_DAYS: i64 = 90;

/// Quota requests one TENANT may accumulate per UTC day. `0` = unlimited.
///
/// Keyed on the tenant, not the admin, to match the one-pending-per-tenant gate
/// exactly: the row is about a tenant, the 409 is about a tenant, so the budget
/// is about a tenant. A per-admin key would instead punish an `owner`/`admin`,
/// who sees every tenant and may legitimately file for many in one day.
pub const DEFAULT_DAILY_SUBMIT_LIMIT: i64 = 5;

/// Retention for decided rows, from `DRUST_QUOTA_REQUEST_RETENTION_DAYS`. Same
/// `env_or` posture as the cap queue: unparseable or out-of-range → default,
/// never clamped, so a typo cannot silently mean "prune everything".
pub fn request_retention_days() -> i64 {
    std::env::var("DRUST_QUOTA_REQUEST_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|v| (0..=36_500).contains(v))
        .unwrap_or(DEFAULT_REQUEST_RETENTION_DAYS)
}

/// Per-tenant daily submit budget, from `DRUST_QUOTA_DAILY_SUBMIT_LIMIT`.
pub fn daily_submit_limit() -> i64 {
    std::env::var("DRUST_QUOTA_DAILY_SUBMIT_LIMIT")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|v| (0..=1_000).contains(v))
        .unwrap_or(DEFAULT_DAILY_SUBMIT_LIMIT)
}

/// Prune decided (`approved`/`rejected`) requests older than `days`, measured
/// from the DECISION. Returns the number of rows removed.
///
/// Verbatim the cap queue's contract, including both of its edge readings:
/// `days <= 0` keeps everything (`0` is "keep forever"; a negative is a caller
/// bug, and deleting the table is the worst possible reading of one), and
/// `pending` rows are never touched because a pending request is open work.
///
/// Anchored on `COALESCE(decided_at, created_at)`, never `created_at` alone: a
/// request that sat pending past the window would otherwise be destroyed by the
/// first pass after it was decided.
pub fn prune_decided_requests(conn: &rusqlite::Connection, days: i64) -> rusqlite::Result<usize> {
    if days <= 0 {
        return Ok(0);
    }
    conn.execute(
        "DELETE FROM quota_requests \
         WHERE status IN ('approved','rejected') \
           AND COALESCE(decided_at, created_at) < datetime('now', ?1)",
        rusqlite::params![format!("-{days} days")],
    )
}

/// Requests filed against this tenant today (UTC), whatever their status.
///
/// Decided rows count: the loop this bounds is request → rejected → request, so
/// counting only the pending one would make the limit unreachable.
pub fn submits_today(conn: &rusqlite::Connection, tenant_id: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM quota_requests \
         WHERE tenant_id = ?1 AND date(created_at) = date('now')",
        rusqlite::params![tenant_id],
        |r| r.get(0),
    )
}

/// Drop every request filed against `tenant_id`, in the caller's transaction.
///
/// Called from the id-recycle hard purge in `mgmt::tenants::crud`. That branch
/// deletes the soft-deleted tenant's row and tokens and hands the id to a NEW
/// tenant — and `decide_quota_request` resolves a request by its stored
/// `tenant_id` string, so a surviving pending row would apply the old tenant's
/// requested tier to the new one. The ids are caller-supplied and reusable by
/// design, which is exactly why nothing may outlive them.
pub fn delete_requests_for_tenant(
    conn: &rusqlite::Connection,
    tenant_id: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM quota_requests WHERE tenant_id = ?1",
        rusqlite::params![tenant_id],
    )
}

// ─── member: file an upgrade request ─────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct QuotaRequestBody {
    pub requested_tier: i64,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /admin/tenants/{id}/quota/requests`
///
/// Files a pending `quota_requests` row for a tenant the caller owns (the
/// route-layer ownership guard already enforced ownership + existence, so a
/// foreign/missing tenant never reaches here — it 404s at the layer). Returns
/// `201` with the new request. Emits audit `tenant.quota.request`.
pub async fn create_quota_request(
    State(state): State<TenantsState>,
    Path(tid): Path<String>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    axum::Json(body): axum::Json<QuotaRequestBody>,
) -> Response {
    if body.requested_tier < 1 || body.requested_tier > MAX_TIER {
        return json_error(
            StatusCode::BAD_REQUEST,
            "QUOTA_TIER_INVALID",
            "requested_tier must be between 1 and 1000",
        );
    }
    // Normalize the reason: trim, cap length, reject control chars (mirrors the
    // display-name validator's posture).
    let reason: Option<String> = match body.reason.as_deref().map(str::trim) {
        Some("") => None,
        Some(r) if r.len() > 500 => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "QUOTA_REASON_TOO_LONG",
                "reason must be at most 500 bytes",
            );
        }
        Some(r) if r.chars().any(|c| c.is_control() && c != '\n' && c != '\t') => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "QUOTA_REASON_INVALID",
                "reason must not contain control characters",
            );
        }
        Some(r) => Some(r.to_string()),
        None => None,
    };

    // All DB work in one sync block; the meta guard drops before any .await.
    let insert_result: Result<i64, Response> = {
        let conn = state.session.meta.lock().await;

        // Current tier doubles as the tenant existence check.
        let current_tier: i64 = match conn
            .query_row(
                "SELECT COALESCE(quota_tier, 1) FROM tenants \
                 WHERE id = ?1 AND deleted_at IS NULL",
                rusqlite::params![tid],
                |r| r.get(0),
            )
            .optional()
        {
            Ok(Some(v)) => v,
            Ok(None) => {
                return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", "no such tenant");
            }
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                );
            }
        };

        if body.requested_tier <= current_tier {
            return json_error(
                StatusCode::BAD_REQUEST,
                "QUOTA_TIER_NOT_INCREASE",
                "requested_tier must be greater than the current tier",
            );
        }

        // One pending request per tenant.
        let has_pending: bool = conn
            .prepare(
                "SELECT 1 FROM quota_requests \
                 WHERE tenant_id = ?1 AND status = 'pending' LIMIT 1",
            )
            .and_then(|mut s| s.exists(rusqlite::params![tid]))
            .unwrap_or(false);
        if has_pending {
            return json_error(
                StatusCode::CONFLICT,
                "QUOTA_REQUEST_PENDING",
                "a pending upgrade request already exists for this tenant",
            );
        }

        // 2026-08-02 review — the 409 above only stops two OPEN requests on one
        // tenant; it does nothing about request → rejected → request, which
        // appends a row per iteration. Count today's rows for this tenant
        // instead, so a rejection still costs budget. A read failure fails
        // CLOSED: an unreadable count is not evidence that there is room left.
        let limit = daily_submit_limit();
        if limit > 0 {
            match submits_today(&conn, &tid) {
                Ok(n) if n >= limit => {
                    return json_error(
                        StatusCode::TOO_MANY_REQUESTS,
                        "QUOTA_REQUEST_RATE_LIMITED",
                        &format!("at most {limit} quota requests per day for one tenant"),
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "DB_ERROR",
                        &e.to_string(),
                    );
                }
            }
        }

        if let Err(e) = conn.execute(
            "INSERT INTO quota_requests \
             (tenant_id, requester_admin_id, requested_tier, reason) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![tid, caller_id, body.requested_tier, reason],
        ) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
        Ok(conn.last_insert_rowid())
        // conn guard drops here — before any .await
    };
    let req_id = match insert_result {
        Ok(v) => v,
        Err(r) => return r,
    };

    let mut entry = crate::safety::audit::AuditEntry::success(&tid, "-", "tenant.quota.request", 0);
    entry.actor_admin_id = Some(caller_id);
    entry = entry.with_extra(json!({
        "request_id": req_id,
        "requested_tier": body.requested_tier,
    }));
    crate::safety::audit::write_entry(&state.log_dir, &entry).await;

    (
        StatusCode::CREATED,
        Json(json!({
            "id": req_id,
            "tenant_id": tid,
            "requested_tier": body.requested_tier,
            "status": "pending",
        })),
    )
        .into_response()
}

// ─── owner: direct tier set ──────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct QuotaTierBody {
    pub tier: i64,
}

/// `PATCH /admin/tenants/{id}/quota` body `{"tier": N}`
///
/// Owner-only direct tier set (no request needed). The tenants_router
/// ownership guard already ran; this handler adds the owner-role check that
/// the guard does not (a member owning the tenant still cannot self-raise).
/// Evicts the tenant's auth-cache entries so the new tier is live immediately.
/// Emits audit `tenant.quota.set`.
pub async fn patch_tenant_quota(
    State(state): State<TenantsState>,
    Path(tid): Path<String>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    axum::Extension(profile): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    axum::Json(body): axum::Json<QuotaTierBody>,
) -> Response {
    if !profile.is_owner {
        return json_error(StatusCode::FORBIDDEN, "NOT_OWNER", "owner role required");
    }
    if body.tier < 1 || body.tier > MAX_TIER {
        return json_error(
            StatusCode::BAD_REQUEST,
            "QUOTA_TIER_INVALID",
            "tier must be between 1 and 1000",
        );
    }
    {
        let conn = state.session.meta.lock().await;
        match conn.execute(
            "UPDATE tenants SET quota_tier = ?1 WHERE id = ?2 AND deleted_at IS NULL",
            rusqlite::params![body.tier, tid],
        ) {
            Ok(0) => {
                return json_error(StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", "no such tenant");
            }
            Ok(_) => {}
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                );
            }
        }
    }
    // Tier rides the bearer CTE (Task 5) — evict so the change is immediate.
    state.auth_cache.clear_tenant(&tid);

    let mut entry = crate::safety::audit::AuditEntry::success(&tid, "-", "tenant.quota.set", 0);
    entry.actor_admin_id = Some(caller_id);
    entry = entry.with_extra(json!({ "quota_tier": body.tier, "via": "direct" }));
    crate::safety::audit::write_entry(&state.log_dir, &entry).await;

    Json(json!({ "id": tid, "quota_tier": body.tier })).into_response()
}

// ─── owner: decide a pending request ─────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct DecideBody {
    pub action: String,
}

/// `POST /admin/quota-requests/{id}/decide` body `{"action":"approve"|"reject"}`
///
/// Owner-only (mounted behind `require_owner_layer`). Approve raises
/// `tenants.quota_tier` to the request's `requested_tier` AND closes the
/// request in ONE transaction (spec §6), then evicts the tenant's auth cache.
/// Reject only closes the request. Both emit audit `tenant.quota.set`.
pub async fn decide_quota_request(
    State(state): State<TenantsState>,
    Path(req_id): Path<i64>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    axum::Json(body): axum::Json<DecideBody>,
) -> Response {
    let approve = match body.action.as_str() {
        "approve" => true,
        "reject" => false,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "QUOTA_DECISION_INVALID",
                "action must be 'approve' or 'reject'",
            );
        }
    };

    // One sync block: read the pending row, apply the decision atomically.
    let decided: Result<(String, i64), Response> = {
        let mut conn = state.session.meta.lock().await;

        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT tenant_id, requested_tier FROM quota_requests \
                 WHERE id = ?1 AND status = 'pending'",
                rusqlite::params![req_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .unwrap_or(None);
        let (tenant_id, requested_tier) = match row {
            Some(v) => v,
            None => {
                return json_error(
                    StatusCode::NOT_FOUND,
                    "QUOTA_REQUEST_NOT_FOUND",
                    "no pending request with that id",
                );
            }
        };

        // v1.50 (Spec B, adversarial F4): re-validate requested_tier > current
        // AT APPROVE TIME. A request created when the tenant was at tier N can
        // sit pending while the owner raises the tier via a later request or a
        // direct PATCH; approving the stale row would silently DOWNGRADE the
        // quota. Re-read the live tier and refuse a non-increase (the request
        // stays pending so it can be rejected explicitly).
        if approve {
            use rusqlite::OptionalExtension;
            // v1.52 — a soft-deleted (or vanished) tenant returns no row here;
            // the old `.unwrap_or(1)` treated that as "current tier 1" and would
            // report an approval whose tier UPDATE (also scoped `deleted_at IS
            // NULL`) actually touched zero rows. Refuse explicitly instead.
            let current_tier: i64 = match conn
                .query_row(
                    "SELECT quota_tier FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
                    rusqlite::params![tenant_id],
                    |r| r.get(0),
                )
                .optional()
                .unwrap_or(None)
            {
                Some(t) => t,
                None => {
                    return json_error(
                        StatusCode::NOT_FOUND,
                        "TENANT_NOT_FOUND",
                        "the tenant no longer exists",
                    );
                }
            };
            if requested_tier <= current_tier {
                return json_error(
                    StatusCode::CONFLICT,
                    "QUOTA_TIER_NOT_INCREASE",
                    "the tenant is already at or above the requested tier",
                );
            }
        }

        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                );
            }
        };
        let tx_result: Result<(), rusqlite::Error> = (|| {
            if approve {
                tx.execute(
                    "UPDATE tenants SET quota_tier = ?1 \
                     WHERE id = ?2 AND deleted_at IS NULL",
                    rusqlite::params![requested_tier, tenant_id],
                )?;
            }
            tx.execute(
                "UPDATE quota_requests \
                 SET status = ?1, decided_by_admin_id = ?2, decided_at = datetime('now') \
                 WHERE id = ?3 AND status = 'pending'",
                rusqlite::params![
                    if approve { "approved" } else { "rejected" },
                    caller_id,
                    req_id
                ],
            )?;
            Ok(())
        })();
        match tx_result.and_then(|_| tx.commit()) {
            Ok(()) => Ok((tenant_id, requested_tier)),
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                );
            }
        }
        // conn guard drops here — before any .await
    };
    let (tenant_id, requested_tier) = match decided {
        Ok(v) => v,
        Err(r) => return r,
    };

    if approve {
        // Tier rides the bearer CTE (Task 5) — evict so it is immediate.
        state.auth_cache.clear_tenant(&tenant_id);
    }

    let mut entry =
        crate::safety::audit::AuditEntry::success(&tenant_id, "-", "tenant.quota.set", 0);
    entry.actor_admin_id = Some(caller_id);
    entry = entry.with_extra(json!({
        "request_id": req_id,
        "action": if approve { "approve" } else { "reject" },
        "quota_tier": if approve { Some(requested_tier) } else { None },
        "via": "request",
    }));
    crate::safety::audit::write_entry(&state.log_dir, &entry).await;

    Json(json!({
        "id": req_id,
        "tenant_id": tenant_id,
        "status": if approve { "approved" } else { "rejected" },
        "quota_tier": if approve { Some(requested_tier) } else { None },
    }))
    .into_response()
}

// ─── owner: review page ──────────────────────────────────────────────────────

/// One pending-request row for the review table (askama-friendly plain
/// strings — no enum method calls in the template).
pub struct QuotaRequestRow {
    pub id: i64,
    pub tenant_id: String,
    pub tenant_name: String,
    /// Requester email when set, else username (same rule as the list column).
    pub requester: String,
    pub current_tier: i64,
    pub requested_tier: i64,
    pub reason: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "quota_review.html")]
struct QuotaReviewPage {
    version: &'static str,
    requests: Vec<QuotaRequestRow>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

/// `GET /admin/quota-requests` — owner-only pending-request queue (the
/// `require_owner_layer` on the sub-router already denied members). Joins
/// `quota_requests` (pending) with `tenants` (name + current tier) and
/// `admins` (requester display).
pub async fn quota_requests_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
) -> Response {
    let requests: Vec<QuotaRequestRow> = {
        let conn = state.session.meta.lock().await;
        conn.prepare(
            "SELECT q.id, q.tenant_id, \
                    COALESCE(t.name, q.tenant_id), \
                    COALESCE(a.email, a.username, '#' || q.requester_admin_id), \
                    COALESCE(t.quota_tier, 1), q.requested_tier, \
                    COALESCE(q.reason, ''), q.created_at \
             FROM quota_requests q \
             LEFT JOIN tenants t ON t.id = q.tenant_id \
             LEFT JOIN admins  a ON a.id = q.requester_admin_id \
             WHERE q.status = 'pending' \
             ORDER BY q.created_at ASC, q.id ASC",
        )
        .and_then(|mut s| {
            s.query_map([], |r| {
                Ok(QuotaRequestRow {
                    id: r.get(0)?,
                    tenant_id: r.get(1)?,
                    tenant_name: r.get(2)?,
                    requester: r.get(3)?,
                    current_tier: r.get(4)?,
                    requested_tier: r.get(5)?,
                    reason: r.get(6)?,
                    created_at: r.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_default()
    };

    let trc = ThemeRenderCtx::build(theme);
    let page = QuotaReviewPage {
        version: env!("CARGO_PKG_VERSION"),
        requests,
        t: Translator::new(locale),
        admin,
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

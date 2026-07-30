//! v1.57 — per-member tenant creation cap.
//!
//! A `member` may own at most `effective_cap` live tenants at once. The
//! per-admin adjustment stored in `admins.tenant_cap_bonus` is a DELTA against
//! the global default, never an absolute ceiling: storing an absolute would mean
//! that raising `DRUST_MEMBER_TENANT_CAP` left previously-adjusted admins
//! behind. See docs/superpowers/specs/2026-07-30-member-tenant-cap-design.md.

use askama::Template;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use crate::error::json_error;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::theme::{ResolvedPalette, ThemeHint, ThemeRenderCtx};

/// Global fallback when `DRUST_MEMBER_TENANT_CAP` is unset or unparseable.
pub const DEFAULT_MEMBER_TENANT_CAP: i64 = 3;

/// Defensive upper bound on a requestable/settable cap.
pub const MAX_CAP: i64 = 100;

/// Global default cap, from `DRUST_MEMBER_TENANT_CAP`. Same `env_or` posture as
/// `DRUST_CRON_MAX_JOBS_PER_TENANT` (`src/cron/mod.rs`): unparseable → default.
pub fn configured_default() -> i64 {
    std::env::var("DRUST_MEMBER_TENANT_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMBER_TENANT_CAP)
}

/// Effective cap for an admin: the global default shifted by their stored delta,
/// clamped at zero.
pub fn effective_cap(default: i64, bonus: i64) -> i64 {
    (default + bonus).max(0)
}

/// The delta to STORE so that this admin's effective cap becomes `target_cap`
/// under the current `default`. The API speaks absolute numbers (that is what a
/// person means); storage holds the delta.
pub fn bonus_for_target(default: i64, target_cap: i64) -> i64 {
    target_cap - default
}

/// May this admin create one more tenant?
///
/// Only `member` is capped — `owner`/`admin` already see every tenant, so
/// creating one is a management act for them. Any OTHER role string fails
/// closed (capped), so a future role cannot silently gain unlimited creation by
/// not being listed here.
pub fn may_create_tenant(role: &str, owned: i64, effective_cap: i64) -> bool {
    if matches!(role, "owner" | "admin") {
        return true;
    }
    owned < effective_cap
}

/// Live tenants currently owned by `admin_id`. Soft-deleted rows do NOT count,
/// so deleting a tenant — or transferring its ownership away — frees a slot.
/// Same "current usage" semantics as the storage quota.
pub fn owned_tenant_count(conn: &rusqlite::Connection, admin_id: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM tenants WHERE owner_admin_id = ?1 AND deleted_at IS NULL",
        rusqlite::params![admin_id],
        |r| r.get(0),
    )
}

/// `(role, effective_cap)` for one admin. A missing admin row yields
/// `("member", …)` so an unknown caller is treated as the most restricted role
/// rather than silently uncapped.
pub fn effective_cap_for_admin(
    conn: &rusqlite::Connection,
    admin_id: i64,
) -> rusqlite::Result<(String, i64)> {
    let (role, bonus): (String, i64) = conn
        .query_row(
            "SELECT role, tenant_cap_bonus FROM admins WHERE id = ?1",
            rusqlite::params![admin_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or_else(|_| ("member".to_string(), 0));
    Ok((role, effective_cap(configured_default(), bonus)))
}

// ─── member: file a cap-increase request ──────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct CapRequestBody {
    pub requested_cap: i64,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /admin/tenant-cap/requests`
///
/// SELF-SCOPED: the subject is always the authenticated caller — there is no
/// "on behalf of another admin" parameter, so there is no cross-admin surface to
/// authorise. Emits audit `admin.tenant_cap.request`.
pub async fn create_cap_request(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    axum::Json(body): axum::Json<CapRequestBody>,
) -> Response {
    if body.requested_cap < 1 || body.requested_cap > MAX_CAP {
        return json_error(
            StatusCode::BAD_REQUEST,
            "TENANT_CAP_INVALID",
            &format!("requested_cap must be between 1 and {MAX_CAP}"),
        );
    }
    // Same normalisation as quota_admin::create_quota_request.
    let reason: Option<String> = match body.reason.as_deref().map(str::trim) {
        Some("") => None,
        Some(r) if r.len() > 500 => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TENANT_CAP_REASON_TOO_LONG",
                "reason must be at most 500 bytes",
            );
        }
        Some(r) if r.chars().any(|c| c.is_control() && c != '\n' && c != '\t') => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TENANT_CAP_REASON_INVALID",
                "reason must not contain control characters",
            );
        }
        Some(r) => Some(r.to_string()),
        None => None,
    };

    let insert_result: Result<i64, Response> = {
        let conn = state.session.meta.lock().await;

        let (_, cap) = match effective_cap_for_admin(&conn, caller_id) {
            Ok(v) => v,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                );
            }
        };
        if body.requested_cap <= cap {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TENANT_CAP_NOT_INCREASE",
                "requested_cap must be greater than your current cap",
            );
        }

        let has_pending: bool = conn
            .prepare(
                "SELECT 1 FROM tenant_cap_requests \
                 WHERE requester_admin_id = ?1 AND status = 'pending'",
            )
            .and_then(|mut s| s.exists(rusqlite::params![caller_id]))
            .unwrap_or(false);
        if has_pending {
            return json_error(
                StatusCode::CONFLICT,
                "TENANT_CAP_REQUEST_PENDING",
                "you already have a pending request",
            );
        }

        if let Err(e) = conn.execute(
            "INSERT INTO tenant_cap_requests (requester_admin_id, requested_cap, reason) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![caller_id, body.requested_cap, reason],
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

    let mut entry =
        crate::safety::audit::AuditEntry::success("-", "-", "admin.tenant_cap.request", 0);
    entry.actor_admin_id = Some(caller_id);
    entry = entry.with_extra(serde_json::json!({
        "request_id": req_id,
        "requested_cap": body.requested_cap,
    }));
    crate::safety::audit::write_entry(&state.log_dir, &entry).await;

    (
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "id": req_id,
            "requested_cap": body.requested_cap,
            "status": "pending",
        })),
    )
        .into_response()
}

// ─── owner: decide a pending request ─────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct CapDecideBody {
    pub action: String,
}

/// `POST /admin/tenant-cap-requests/{id}/decide` body `{"action":"approve"|"reject"}`
///
/// Owner-only (mounted behind `require_owner_layer`). Approve converts the
/// absolute `requested_cap` to a delta and writes `admins.tenant_cap_bonus`,
/// closing the row in ONE transaction. Reject only closes it.
pub async fn decide_cap_request(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    axum::extract::Path(req_id): axum::extract::Path<i64>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    axum::Json(body): axum::Json<CapDecideBody>,
) -> Response {
    let approve = match body.action.as_str() {
        "approve" => true,
        "reject" => false,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TENANT_CAP_DECISION_INVALID",
                "action must be 'approve' or 'reject'",
            );
        }
    };

    let decided: Result<(i64, i64), Response> = {
        use rusqlite::OptionalExtension;
        let mut conn = state.session.meta.lock().await;

        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT requester_admin_id, requested_cap FROM tenant_cap_requests \
                 WHERE id = ?1 AND status = 'pending'",
                rusqlite::params![req_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap_or(None);
        let (subject_id, requested_cap) = match row {
            Some(v) => v,
            None => {
                // Either no such id, or already decided. Distinguish so a
                // double-submitted approval reads as a conflict, not a 404.
                let exists: bool = conn
                    .prepare("SELECT 1 FROM tenant_cap_requests WHERE id = ?1")
                    .and_then(|mut s| s.exists(rusqlite::params![req_id]))
                    .unwrap_or(false);
                return if exists {
                    json_error(
                        StatusCode::CONFLICT,
                        "TENANT_CAP_REQUEST_DECIDED",
                        "that request has already been decided",
                    )
                } else {
                    json_error(
                        StatusCode::NOT_FOUND,
                        "TENANT_CAP_REQUEST_NOT_FOUND",
                        "no pending request with that id",
                    )
                };
            }
        };

        // v1.57 — the F4 analogue (see quota_admin::decide_quota_request): a
        // request filed when the admin was at cap N can sit pending while an
        // owner raises them via a direct set. Approving the stale row would
        // silently LOWER their cap. Re-read the live cap and refuse a
        // non-increase; the row stays pending so it can be rejected explicitly.
        if approve {
            let (_, current_cap) = match effective_cap_for_admin(&conn, subject_id) {
                Ok(v) => v,
                Err(e) => {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "DB_ERROR",
                        &e.to_string(),
                    );
                }
            };
            if requested_cap <= current_cap {
                return json_error(
                    StatusCode::CONFLICT,
                    "TENANT_CAP_NOT_INCREASE",
                    "that admin is already at or above the requested cap",
                );
            }
        }

        let new_bonus = bonus_for_target(configured_default(), requested_cap);
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
                    "UPDATE admins SET tenant_cap_bonus = ?1 WHERE id = ?2",
                    rusqlite::params![new_bonus, subject_id],
                )?;
            }
            tx.execute(
                "UPDATE tenant_cap_requests \
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
            Ok(()) => Ok((subject_id, requested_cap)),
            Err(e) => Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            )),
        }
        // conn guard drops here — before any .await
    };
    let (subject_id, requested_cap) = match decided {
        Ok(v) => v,
        Err(r) => return r,
    };

    let op = if approve {
        "admin.tenant_cap.set"
    } else {
        "admin.tenant_cap.reject"
    };
    let mut entry = crate::safety::audit::AuditEntry::success("-", "-", op, 0);
    entry.actor_admin_id = Some(caller_id);
    entry = entry.with_extra(serde_json::json!({
        "request_id": req_id,
        "subject_admin_id": subject_id,
        "requested_cap": requested_cap,
    }));
    crate::safety::audit::write_entry(&state.log_dir, &entry).await;

    axum::Json(serde_json::json!({ "ok": true })).into_response()
}

// ─── owner: direct cap set ───────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct CapSetBody {
    /// Absolute target cap, or `null` to clear the adjustment back to the
    /// global default.
    pub cap: Option<i64>,
}

/// `PATCH /admin/team/{admin_id}/tenant-cap` body `{"cap": N}` or `{"cap": null}`
///
/// Owner-only via an in-handler check — `team_router` admits `admin` too (its
/// route-layer guard only gates the team READ), and an `admin` must not set host
/// allowances. Emits audit `admin.tenant_cap.set`.
pub async fn patch_admin_tenant_cap(
    State(state): State<crate::mgmt::routes::MgmtState>,
    axum::extract::Path(subject_id): axum::extract::Path<i64>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    axum::Extension(profile): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    axum::Json(body): axum::Json<CapSetBody>,
) -> Response {
    if !profile.is_owner {
        return json_error(
            StatusCode::FORBIDDEN,
            "NOT_OWNER",
            "owner role required to set a tenant cap",
        );
    }
    if let Some(cap) = body.cap
        && (cap < 1 || cap > MAX_CAP)
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "TENANT_CAP_INVALID",
            &format!("cap must be between 1 and {MAX_CAP}"),
        );
    }
    let new_bonus = match body.cap {
        Some(cap) => bonus_for_target(configured_default(), cap),
        None => 0,
    };

    {
        let conn = state.meta.lock().await;
        let affected = match conn.execute(
            "UPDATE admins SET tenant_cap_bonus = ?1 WHERE id = ?2",
            rusqlite::params![new_bonus, subject_id],
        ) {
            Ok(n) => n,
            Err(e) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB_ERROR",
                    &e.to_string(),
                );
            }
        };
        if affected == 0 {
            return json_error(StatusCode::NOT_FOUND, "ADMIN_NOT_FOUND", "no such admin");
        }
    }

    let mut entry = crate::safety::audit::AuditEntry::success("-", "-", "admin.tenant_cap.set", 0);
    entry.actor_admin_id = Some(caller_id);
    entry = entry.with_extra(serde_json::json!({
        "subject_admin_id": subject_id,
        "cap": body.cap,
        "bonus": new_bonus,
    }));
    crate::safety::audit::write_entry(&state.log_dir, &entry).await;

    axum::Json(serde_json::json!({ "ok": true })).into_response()
}

// ─── owner: review page ──────────────────────────────────────────────────────

/// One pending cap-request row for the review table. Every figure is computed
/// in Rust — the template does no arithmetic.
pub struct CapRequestRow {
    pub id: i64,
    /// Requester email when set, else username, else `#<id>`.
    pub requester: String,
    pub requested_cap: i64,
    /// The requester's LIVE effective cap, so an owner decides with real
    /// numbers rather than only the requested figure.
    pub current_cap: i64,
    /// Live tenants they own right now.
    pub owned: i64,
    pub reason: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "tenant_cap_review.html")]
struct TenantCapReviewPage {
    version: &'static str,
    requests: Vec<CapRequestRow>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

/// `GET /admin/tenant-cap-requests` — owner-only pending-request queue (the
/// `require_owner_layer` on the sub-router already denied member + admin).
/// Joins the subject's live owned-tenant count and stored delta so the page
/// shows the current cap next to the requested one.
pub async fn cap_requests_page(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
) -> Response {
    let default = configured_default();
    let requests: Vec<CapRequestRow> = {
        let conn = state.session.meta.lock().await;
        conn.prepare(
            "SELECT r.id, \
                    COALESCE(a.email, a.username, '#' || r.requester_admin_id), \
                    r.requested_cap, COALESCE(a.tenant_cap_bonus, 0), \
                    COALESCE(r.reason, ''), r.created_at, \
                    (SELECT COUNT(*) FROM tenants t \
                      WHERE t.owner_admin_id = r.requester_admin_id \
                        AND t.deleted_at IS NULL) \
             FROM tenant_cap_requests r \
             LEFT JOIN admins a ON a.id = r.requester_admin_id \
             WHERE r.status = 'pending' \
             ORDER BY r.created_at ASC, r.id ASC",
        )
        .and_then(|mut s| {
            s.query_map([], |r| {
                let bonus: i64 = r.get(3)?;
                Ok(CapRequestRow {
                    id: r.get(0)?,
                    requester: r.get(1)?,
                    requested_cap: r.get(2)?,
                    current_cap: effective_cap(default, bonus),
                    reason: r.get(4)?,
                    created_at: r.get(5)?,
                    owned: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
        })
        .unwrap_or_default()
    };

    let trc = ThemeRenderCtx::build(theme);
    let page = TenantCapReviewPage {
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

#[cfg(test)]
mod cap_arithmetic_tests {
    use super::*;

    #[test]
    fn effective_cap_applies_bonus_as_a_delta() {
        assert_eq!(effective_cap(3, 0), 3, "no adjustment → the default");
        assert_eq!(effective_cap(3, 2), 5, "positive bonus raises");
        assert_eq!(effective_cap(3, -1), 2, "negative bonus restricts");
    }

    /// The whole point of the delta model: a global-default change lifts
    /// everyone, including admins who already carry an adjustment. An
    /// absolute-storage implementation fails this test.
    #[test]
    fn raising_the_default_lifts_an_adjusted_admin() {
        let bonus = bonus_for_target(3, 4); // approved to 4 while default was 3
        assert_eq!(bonus, 1);
        assert_eq!(effective_cap(3, bonus), 4, "still 4 under the old default");
        assert_eq!(
            effective_cap(10, bonus),
            11,
            "default 3→10 lifts them to 11"
        );
    }

    #[test]
    fn effective_cap_never_goes_negative() {
        assert_eq!(effective_cap(3, -5), 0, "clamped at zero, never negative");
        assert_eq!(effective_cap(0, -1), 0);
    }

    #[test]
    fn bonus_for_target_round_trips() {
        for (default, target) in [(3, 4), (3, 10), (10, 11), (5, 2)] {
            let bonus = bonus_for_target(default, target);
            assert_eq!(
                effective_cap(default, bonus),
                target,
                "default {default} target {target}"
            );
        }
    }

    #[test]
    fn only_member_is_capped() {
        // At the cap.
        assert!(!may_create_tenant("member", 3, 3), "member at cap refused");
        assert!(may_create_tenant("owner", 999, 3), "owner never capped");
        assert!(may_create_tenant("admin", 999, 3), "admin never capped");
    }

    #[test]
    fn member_below_cap_may_create() {
        assert!(may_create_tenant("member", 0, 3));
        assert!(may_create_tenant("member", 2, 3));
    }

    /// Over-cap is reachable by lowering someone's cap or demoting an owner who
    /// owns many tenants. Creation must still refuse — and nothing is deleted.
    #[test]
    fn member_over_cap_still_refused() {
        assert!(!may_create_tenant("member", 18, 3));
    }

    /// A zero effective cap (bonus dragged it to 0) means no creation at all.
    #[test]
    fn zero_cap_refuses_everything() {
        assert!(!may_create_tenant("member", 0, 0));
    }

    /// An unknown role string must fail CLOSED (treated as capped), so a future
    /// role added without updating this function cannot silently gain unlimited
    /// tenant creation.
    #[test]
    fn unknown_role_fails_closed() {
        assert!(!may_create_tenant("editor", 3, 3));
        assert!(
            may_create_tenant("editor", 0, 3),
            "still bounded by the cap"
        );
    }
}

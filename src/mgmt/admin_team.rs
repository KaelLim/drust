//! Admin team management — list/invite/role-change/remove.
//!
//! Owner guard: only admins with `role = 'owner'` may invite, promote/demote,
//! or remove team members. PATCH and DELETE enforce the ≥1 Owner invariant
//! TOCTOU-safely inside a write transaction on `meta.sqlite`.
//!
//! Audit ops: `admin.team.invite`, `admin.team.role_change`, `admin.team.remove`.
//!
//! v1.29.0.

use askama::Template;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AdminId;
use crate::error::json_error;
use crate::mgmt::admin_profile::AdminProfileExt;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::routes::MgmtState;
use crate::safety::audit::AuditEntry;

// ─── wire shapes ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AdminRow {
    pub id: i64,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct InviteBody {
    pub email: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RoleBody {
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct BatchInviteBody {
    pub emails: Vec<String>,
    #[serde(default)]
    pub role: Option<String>,
}

// ─── HTML page structs ───────────────────────────────────────────────────────

/// One row displayed in the /admin/team table.
struct AdminTeamRow {
    pub id: i64,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub role: String,
}

#[derive(Template)]
#[template(path = "admin_team.html")]
struct AdminTeamPage {
    version: &'static str,
    t: Translator,
    admin: AdminProfileExt,
    admins: Vec<AdminTeamRow>,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Synthetic password hash for invited admins who have no password yet.
/// Identical sentinel used by per-tenant OAuth-only users.
const OAUTH_ONLY_SENTINEL: &str = "$oauth-only$";

/// Valid role strings.
fn is_valid_role(r: &str) -> bool {
    matches!(r, "owner" | "admin" | "member")
}

/// Return 403 NOT_OWNER when the caller does not have the owner role.
fn owner_guard(profile: &AdminProfileExt) -> Result<(), Response> {
    if !profile.is_owner {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "NOT_OWNER",
            "owner role required",
        ));
    }
    Ok(())
}

/// v1.57 — team-manager gate: owner OR admin may manage MEMBER-role admins.
/// A `member` caller manages nothing → `403 NOT_A_MANAGER`. This is the
/// entry gate for member-scoped team ops; touching an owner/admin row (or
/// creating one) additionally requires `can_manage_privileged` (owner) at the
/// call site.
fn require_manage_members(profile: &AdminProfileExt) -> Result<(), Response> {
    if !crate::mgmt::tenant_authz::can_manage_members(&profile.role) {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "NOT_A_MANAGER",
            "owner or admin role required",
        ));
    }
    Ok(())
}

/// Email basic sanity check — must contain exactly one '@' and something on
/// both sides.  No RFC-5321 deep validation; the invite flow is Owner-only
/// so this is good-faith input.
fn validate_email(email: &str) -> bool {
    // Good-faith check (owner-only invite). Reject the shapes a bulk address-book
    // paste tends to produce — display names, angle brackets, quotes, and
    // multi-`@` strings — so `Alice <a@b.com>` or `a@b@c.com` don't slip through
    // as junk admin rows.
    if email.is_empty() || email.len() > 254 {
        return false;
    }
    if email
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';' | '"'))
    {
        return false;
    }
    // Exactly one '@'.
    let mut parts = email.split('@');
    let (local, domain) = match (parts.next(), parts.next(), parts.next()) {
        (Some(l), Some(d), None) => (l, d),
        _ => return false,
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    // Domain must be dotted with non-empty labels either side of the last dot.
    match domain.rsplit_once('.') {
        Some((head, tld)) => !head.is_empty() && !tld.is_empty(),
        None => false,
    }
}

// ─── shared per-email invite core ────────────────────────────────────────────

/// Why one email in an invite produced no new admin.
#[derive(Debug, Clone, Copy)]
enum SkipReason {
    /// Email failed `validate_email`.
    Invalid,
    /// An admin with this email already exists.
    Exists,
}

impl SkipReason {
    fn as_str(self) -> &'static str {
        match self {
            SkipReason::Invalid => "invalid",
            SkipReason::Exists => "exists",
        }
    }
}

/// Outcome of inviting one email.
enum InviteOutcome {
    Created { id: i64 },
    Skipped { reason: SkipReason },
}

/// Insert one admin (+ its PAT) inside `tx`. `email` must already be trimmed and
/// lowercased; `role` must already be validated (`owner|member`). Returns
/// `Created{id}` on success or `Skipped` when the email is malformed or already
/// taken. A hard rusqlite error propagates so the caller can roll back the whole
/// batch. Shared by single `invite_admin` and `batch_invite_admin` so both agree
/// on what "invite one admin" means (DRY).
fn insert_one_admin(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    role: &str,
) -> rusqlite::Result<InviteOutcome> {
    use rusqlite::OptionalExtension;

    if !validate_email(email) {
        return Ok(InviteOutcome::Skipped {
            reason: SkipReason::Invalid,
        });
    }

    // Uniqueness — case-insensitive, matching the single-invite check.
    let existing = tx
        .query_row(
            "SELECT 1 FROM admins WHERE email = ?1 COLLATE NOCASE",
            params![email],
            |_| Ok(()),
        )
        .optional()?;
    if existing.is_some() {
        return Ok(InviteOutcome::Skipped {
            reason: SkipReason::Exists,
        });
    }

    // Derive a unique username from the email local-part.
    let username_base = email
        .split('@')
        .next()
        .unwrap_or("admin")
        .replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    let username = {
        let mut candidate = username_base.clone();
        let mut suffix = 2u32;
        loop {
            let taken = tx
                .query_row(
                    "SELECT 1 FROM admins WHERE username = ?1",
                    params![candidate],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !taken {
                break candidate;
            }
            candidate = format!("{username_base}{suffix}");
            suffix += 1;
        }
    };

    // Insert the admin row. A UNIQUE collision (racing case) degrades to a
    // soft "exists" skip rather than aborting the batch.
    match tx.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, ?2, ?3, ?4)",
        params![username, OAUTH_ONLY_SENTINEL, email, role],
    ) {
        Ok(_) => {}
        Err(e) if e.to_string().contains("UNIQUE") => {
            return Ok(InviteOutcome::Skipped {
                reason: SkipReason::Exists,
            });
        }
        Err(e) => return Err(e),
    }

    let new_id = tx.last_insert_rowid();

    // Mint the admin's PAT (same shape as single invite).
    let pat_plaintext = crate::auth::admin_token::generate_token();
    let pat_hash = crate::auth::admin_token::hash_token(&pat_plaintext);
    tx.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (?1, ?2, ?3)",
        params![new_id, pat_hash, pat_plaintext],
    )?;

    Ok(InviteOutcome::Created { id: new_id })
}

// ─── handlers ────────────────────────────────────────────────────────────────

/// `GET /admin/team` — dispatches to HTML or JSON based on `Accept` header.
///
/// Browsers (no `Accept: application/json`) get the Askama page.
/// API clients (`Accept: application/json`) get the JSON list.
/// The existing JSON CRUD tests do not set an Accept header, so they still hit
/// this handler and get JSON via `list_admins_json` below.
pub async fn team_page_or_json(
    state: State<MgmtState>,
    locale_hint: LocaleHint,
    theme_hint: crate::mgmt::theme::ThemeHint,
    admin_ext: axum::Extension<AdminProfileExt>,
    headers: axum::http::HeaderMap,
) -> Response {
    // v1.57 — the team page is owner|admin only; a `member` is locked out (403).
    // This handler check covers BOTH the JSON and HTML dispatch branches (and any
    // future direct mount); the route-layer `require_sees_team_layer` gates the
    // GET independently for DiD ≥ 2.
    if !admin_ext.sees_team {
        return json_error(
            StatusCode::FORBIDDEN,
            "TEAM_REQUIRES_MANAGEMENT",
            "the team page requires the owner or admin role",
        );
    }
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Browsers send "text/html" in Accept; API clients either omit it or
    // send "application/json".  Default to JSON when unclear so the
    // existing tests (which set no Accept header) keep working.
    if accept.contains("text/html") && !accept.contains("application/json") {
        team_page(state, locale_hint, theme_hint, admin_ext).await
    } else {
        list_admins(state).await
    }
}

/// Render the HTML team page.
async fn team_page(
    State(s): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<AdminProfileExt>,
) -> Response {
    // v1.57 — owner|admin only (DiD with `team_page_or_json` + the route layer).
    if !admin.sees_team {
        return json_error(
            StatusCode::FORBIDDEN,
            "TEAM_REQUIRES_MANAGEMENT",
            "the team page requires the owner or admin role",
        );
    }
    let rows: Vec<AdminTeamRow> = {
        let conn = s.meta.lock().await;
        let mut stmt =
            match conn.prepare("SELECT id, display_name, email, role FROM admins ORDER BY id") {
                Ok(s) => s,
                Err(e) => {
                    return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
                }
            };
        stmt.query_map([], |r| {
            let id: i64 = r.get(0)?;
            let display_name: Option<String> = r.get(1)?;
            let email: Option<String> = r.get(2)?;
            let role: String = r.get(3)?;
            Ok((id, display_name, email, role))
        })
        .and_then(|iter| iter.collect::<rusqlite::Result<Vec<_>>>())
        .unwrap_or_default()
        .into_iter()
        .map(|(id, display_name, email, role)| AdminTeamRow {
            id,
            display_name,
            email,
            role,
        })
        .collect()
    };
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        AdminTeamPage {
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            admin,
            admins: rows,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap_or_default(),
    )
    .into_response()
}

/// `GET /admin/team` — list all admins (any authenticated admin may read).
pub async fn list_admins(State(s): State<MgmtState>) -> Response {
    // All DB work must finish before any await point, so collect into a
    // result while holding the lock, then drop the lock.
    let result: Result<Vec<AdminRow>, String> = {
        let conn = s.meta.lock().await;
        let mut stmt = match conn
            .prepare("SELECT id, email, display_name, role, created_at FROM admins ORDER BY id")
        {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
            }
        };
        stmt.query_map([], |r| {
            Ok(AdminRow {
                id: r.get(0)?,
                email: r.get(1)?,
                display_name: r.get(2)?,
                role: r.get(3)?,
                created_at: r.get(4)?,
            })
        })
        .and_then(|iter| iter.collect())
        .map_err(|e| e.to_string())
    };

    match result {
        Ok(admins) => Json(serde_json::json!({ "admins": admins })).into_response(),
        Err(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error_code": "INTERNAL", "message": msg })),
        )
            .into_response(),
    }
}

/// `POST /admin/team` — invite a new admin (Owner-only).
///
/// The invited admin is created with the OAuth-only sentinel password so
/// they can only sign in via OAuth (or have their password set out-of-band).
/// A username is auto-derived from the email local-part.
pub async fn invite_admin(
    State(s): State<MgmtState>,
    axum::Extension(AdminId(caller_id)): axum::Extension<AdminId>,
    axum::Extension(profile): axum::Extension<AdminProfileExt>,
    Json(body): Json<InviteBody>,
) -> Response {
    // v1.57 authority: a team manager (owner|admin) may invite MEMBER rows;
    // minting an owner/admin is owner-only. A `member` caller manages nothing.
    if let Err(r) = require_manage_members(&profile) {
        return r;
    }

    let role = body.role.as_deref().unwrap_or("member");
    if !is_valid_role(role) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ROLE",
            "role must be 'owner', 'admin' or 'member'",
        );
    }

    if matches!(role, "owner" | "admin")
        && !crate::mgmt::tenant_authz::can_manage_privileged(&profile.role)
    {
        return json_error(
            StatusCode::FORBIDDEN,
            "PRIVILEGED_ROLE_REQUIRED",
            "only an owner may invite an owner or admin",
        );
    }

    let email = body.email.trim().to_ascii_lowercase();
    if !validate_email(&email) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_EMAIL",
            "email must be a valid address",
        );
    }

    // Single-invite: run the shared per-email insert inside a transaction.
    // `insert_one_admin` is the one source of truth (also used by the batch
    // handler); map its Skipped outcomes back to the single-invite error codes.
    let db_result: Result<(i64, Option<String>), Response> = {
        let conn = s.meta.lock().await;

        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
            }
        };

        let new_id = match insert_one_admin(&tx, &email, role) {
            Ok(InviteOutcome::Created { id }) => id,
            Ok(InviteOutcome::Skipped {
                reason: SkipReason::Invalid,
            }) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_EMAIL",
                    "email must be a valid address",
                );
            }
            Ok(InviteOutcome::Skipped {
                reason: SkipReason::Exists,
            }) => {
                return json_error(
                    StatusCode::CONFLICT,
                    "ADMIN_EMAIL_TAKEN",
                    "an admin with that email already exists",
                );
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
            }
        };

        if let Err(e) = tx.commit() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
            )
                .into_response();
        }

        // Fetch caller email for audit attribution.
        let caller_email: Option<String> = conn
            .query_row(
                "SELECT email FROM admins WHERE id = ?1",
                params![caller_id],
                |r| r.get(0),
            )
            .ok();

        Ok((new_id, caller_email))
        // conn guard drops here — before any .await
    };

    let (new_id, caller_email) = match db_result {
        Ok(v) => v,
        Err(r) => return r,
    };

    // Emit audit (async — safe; lock already released).
    let mut entry = AuditEntry::success("-", "-", "admin.team.invite", 0);
    entry.actor_admin_id = Some(caller_id);
    entry.actor_email_snapshot = caller_email;
    entry = entry.with_extra(serde_json::json!({
        "invited_admin_id": new_id,
        "invited_email": email,
        "role": role,
    }));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    let mut resp = Json(serde_json::json!({
        "id": new_id,
        "email": email,
        "role": role,
    }))
    .into_response();
    *resp.status_mut() = StatusCode::CREATED;
    resp
}

/// `PATCH /admin/team/{id}/role` — change an admin's role (Owner-only).
///
/// Invariant: demoting the last Owner is rejected with 409 LAST_OWNER.
/// Enforced TOCTOU-safely inside an `unchecked_transaction`.
pub async fn change_role(
    State(s): State<MgmtState>,
    Path(target_id): Path<i64>,
    axum::Extension(AdminId(caller_id)): axum::Extension<AdminId>,
    axum::Extension(profile): axum::Extension<AdminProfileExt>,
    Json(body): Json<RoleBody>,
) -> Response {
    // v1.57 authority: a `member` caller manages nothing. Touching an
    // owner/admin row (as the target's CURRENT role or the requested new role)
    // is owner-only (`can_manage_privileged`, checked below once the target's
    // role is known); an admin may only operate on member rows.
    if let Err(r) = require_manage_members(&profile) {
        return r;
    }

    let new_role = body.role.clone();
    if !is_valid_role(&new_role) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ROLE",
            "role must be 'owner' or 'member'",
        );
    }

    // All DB work inside a single sync block before any .await.
    let db_result: Result<(String, Option<String>), Response> = {
        let conn = s.meta.lock().await;

        // Check target exists.
        let current_role: Option<String> = conn
            .query_row(
                "SELECT role FROM admins WHERE id = ?1",
                params![target_id],
                |r| r.get(0),
            )
            .ok();
        let current_role = match current_role {
            Some(r) => r,
            None => return json_error(StatusCode::NOT_FOUND, "ADMIN_NOT_FOUND", "admin not found"),
        };

        // v1.57 privileged gate: creating/altering an owner|admin role — or
        // touching a row that currently HOLDS one — is owner-only. An admin
        // (team manager) may only operate on member rows staying member.
        // Placed before the no-op short-circuit so an admin cannot even
        // no-op-touch an owner/admin row.
        let touches_privileged = matches!(new_role.as_str(), "owner" | "admin")
            || matches!(current_role.as_str(), "owner" | "admin");
        if touches_privileged && !crate::mgmt::tenant_authz::can_manage_privileged(&profile.role) {
            return json_error(
                StatusCode::FORBIDDEN,
                "PRIVILEGED_ROLE_REQUIRED",
                "only an owner may set or change owner/admin roles",
            );
        }

        // If the role isn't actually changing, succeed immediately.
        if current_role == new_role {
            return Json(serde_json::json!({ "id": target_id, "role": new_role })).into_response();
        }

        // TOCTOU-safe invariant check.
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
            }
        };

        if new_role == "member" && current_role == "owner" {
            let other_owner: bool = tx
                .query_row(
                    "SELECT 1 FROM admins WHERE role = 'owner' AND id != ?1 LIMIT 1",
                    params![target_id],
                    |_| Ok(()),
                )
                .is_ok();
            if !other_owner {
                return json_error(
                    StatusCode::CONFLICT,
                    "LAST_OWNER",
                    "cannot demote the last owner",
                );
            }
        }

        if let Err(e) = tx.execute(
            "UPDATE admins SET role = ?1 WHERE id = ?2",
            params![new_role, target_id],
        ) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
            )
                .into_response();
        }

        if let Err(e) = tx.commit() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
            )
                .into_response();
        }

        // Fetch caller email for attribution.
        let caller_email: Option<String> = conn
            .query_row(
                "SELECT email FROM admins WHERE id = ?1",
                params![caller_id],
                |r| r.get(0),
            )
            .ok();

        Ok((current_role, caller_email))
        // conn guard drops here — before any .await
    };

    let (old_role, caller_email) = match db_result {
        Ok(v) => v,
        Err(r) => return r,
    };

    // hook 13 — role flip re-scopes every PAT of this admin: an owner→member
    // demotion narrows their PATs to owned tenants only (v1.50 CTE deny), but
    // a freshly-used PAT may still sit in the data-plane auth cache bound to a
    // foreign tenant and be served on a hit WITHOUT a meta lookup. Evict now
    // so the new scope applies immediately, not after the 10s safety TTL.
    // Mirrors remove_admin below.
    s.auth_cache.clear_admin_pat(target_id);

    // Emit audit (async — safe; lock already released).
    let mut entry = AuditEntry::success("-", "-", "admin.team.role_change", 0);
    entry.actor_admin_id = Some(caller_id);
    entry.actor_email_snapshot = caller_email;
    entry = entry.with_extra(serde_json::json!({
        "target_admin_id": target_id,
        "old_role": old_role,
        "new_role": new_role,
    }));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    Json(serde_json::json!({ "id": target_id, "role": new_role })).into_response()
}

/// `DELETE /admin/team/{id}` — remove an admin (Owner-only).
///
/// Invariant: removing the last Owner is rejected with 409 LAST_OWNER.
/// Enforced TOCTOU-safely inside an `unchecked_transaction`.
/// Admin sessions are deleted manually; `_admin_tokens` CASCADE on FK delete.
pub async fn remove_admin(
    State(s): State<MgmtState>,
    Path(target_id): Path<i64>,
    axum::Extension(AdminId(caller_id)): axum::Extension<AdminId>,
    axum::Extension(profile): axum::Extension<AdminProfileExt>,
) -> Response {
    // v1.57 authority: a `member` caller manages nothing; removing an
    // owner/admin row is owner-only (`can_manage_privileged`, checked below once
    // the target's role is known); an admin may only remove member rows.
    if let Err(r) = require_manage_members(&profile) {
        return r;
    }

    // All DB work inside a single sync block before any .await.
    let db_result: Result<(String, Option<String>, Option<String>), Response> = {
        let conn = s.meta.lock().await;

        // Snapshot target role + email BEFORE the DELETE so the audit row
        // can identify who was removed even after the admins row is gone.
        let target_snap: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT role, email FROM admins WHERE id = ?1",
                params![target_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .ok();
        let (target_role, target_email) = match target_snap {
            Some(s) => s,
            None => return json_error(StatusCode::NOT_FOUND, "ADMIN_NOT_FOUND", "admin not found"),
        };

        // v1.57 privileged gate: removing a row that HOLDS an owner|admin role is
        // owner-only. An admin (team manager) may only remove member rows. Placed
        // before the last-owner guard so an admin never learns owner-count state.
        if matches!(target_role.as_str(), "owner" | "admin")
            && !crate::mgmt::tenant_authz::can_manage_privileged(&profile.role)
        {
            return json_error(
                StatusCode::FORBIDDEN,
                "PRIVILEGED_ROLE_REQUIRED",
                "only an owner may remove owner/admin roles",
            );
        }

        // TOCTOU-safe invariant check inside a transaction.
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
            }
        };

        if target_role == "owner" {
            let other_owner: bool = tx
                .query_row(
                    "SELECT 1 FROM admins WHERE role = 'owner' AND id != ?1 LIMIT 1",
                    params![target_id],
                    |_| Ok(()),
                )
                .is_ok();
            if !other_owner {
                return json_error(
                    StatusCode::CONFLICT,
                    "LAST_OWNER",
                    "cannot remove the last owner",
                );
            }
        }

        // Delete sessions manually (_admin_tokens cascade via FK ON DELETE CASCADE).
        if let Err(e) = tx.execute(
            "DELETE FROM sessions WHERE admin_id = ?1",
            params![target_id],
        ) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
            )
                .into_response();
        }

        if let Err(e) = tx.execute("DELETE FROM admins WHERE id = ?1", params![target_id]) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
            )
                .into_response();
        }

        if let Err(e) = tx.commit() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
            )
                .into_response();
        }

        // Fetch caller email for attribution.
        let caller_email: Option<String> = conn
            .query_row(
                "SELECT email FROM admins WHERE id = ?1",
                params![caller_id],
                |r| r.get(0),
            )
            .ok();

        Ok((target_role, target_email, caller_email))
        // conn guard drops here — before any .await
    };

    let (removed_role, removed_email, caller_email) = match db_result {
        Ok(v) => v,
        Err(r) => return r,
    };

    // audit3 F4 — the cascade DELETE on `admins` revoked this admin's PATs at
    // the DB level (FK ON DELETE CASCADE), but a freshly-used PAT may still sit
    // in the data-plane auth cache, served on a cache hit WITHOUT a meta lookup.
    // Evict it now so a removed admin loses service-level data-plane access
    // immediately, not after the 10s safety TTL. Mirrors hook 2 (admin_pat.rs).
    s.auth_cache.clear_admin_pat(target_id);

    // Emit audit (async — safe; lock already released).
    let mut entry = AuditEntry::success("-", "-", "admin.team.remove", 0);
    entry.actor_admin_id = Some(caller_id);
    entry.actor_email_snapshot = caller_email;
    entry = entry.with_extra(serde_json::json!({
        "removed_admin_id": target_id,
        "removed_role": removed_role,
        "removed_email": removed_email,
    }));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    Json(serde_json::json!({ "removed": true })).into_response()
}

/// `POST /admin/team/batch` — invite many admins at once (Owner-only).
///
/// Body `{ emails: [..], role? }`. Each email is trimmed + lowercased and
/// deduped within the batch; malformed / already-existing / duplicate emails
/// are reported in `skipped` without aborting the others. Every created admin
/// is minted a PAT and gets one `admin.team.invite` audit row — identical to
/// the single-invite path (shared `insert_one_admin`). The whole batch runs in
/// one transaction: a hard DB error rolls everything back.
pub async fn batch_invite_admin(
    State(s): State<MgmtState>,
    axum::Extension(AdminId(caller_id)): axum::Extension<AdminId>,
    axum::Extension(profile): axum::Extension<AdminProfileExt>,
    Json(body): Json<BatchInviteBody>,
) -> Response {
    // v1.57 authority: same up-front matrix as the single-invite path — owner|
    // admin may bulk-invite MEMBER rows; minting owner/admin is owner-only; a
    // `member` caller manages nothing.
    if let Err(r) = require_manage_members(&profile) {
        return r;
    }

    let role = body.role.as_deref().unwrap_or("member");
    if !is_valid_role(role) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_ROLE",
            "role must be 'owner', 'admin' or 'member'",
        );
    }

    if matches!(role, "owner" | "admin")
        && !crate::mgmt::tenant_authz::can_manage_privileged(&profile.role)
    {
        return json_error(
            StatusCode::FORBIDDEN,
            "PRIVILEGED_ROLE_REQUIRED",
            "only an owner may invite an owner or admin",
        );
    }

    let max = std::env::var("DRUST_ADMIN_BATCH_MAX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(50);
    if body.emails.len() > max {
        return json_error(
            StatusCode::BAD_REQUEST,
            "TOO_MANY",
            "too many emails in one batch",
        );
    }

    // Normalize + dedupe (preserve order). Blank entries and repeated paste
    // lines are silently collapsed — a within-batch duplicate's outcome is
    // already carried by its first occurrence, so a separate skip entry would
    // just double-report the same address.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut normalized: Vec<String> = Vec::new();
    for raw in &body.emails {
        let e = raw.trim().to_ascii_lowercase();
        if e.is_empty() {
            continue;
        }
        if seen.insert(e.clone()) {
            normalized.push(e);
        }
    }

    // Whole batch in one transaction: hard errors roll back everything, soft
    // skips (invalid/exists) don't abort their siblings.
    type BatchOk = (
        Vec<(i64, String)>,
        Vec<(String, SkipReason)>,
        Option<String>,
    );
    let db_result: Result<BatchOk, Response> = {
        let conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
                )
                    .into_response();
            }
        };

        let mut created: Vec<(i64, String)> = Vec::new();
        let mut skipped_db: Vec<(String, SkipReason)> = Vec::new();
        for e in &normalized {
            match insert_one_admin(&tx, e, role) {
                Ok(InviteOutcome::Created { id }) => created.push((id, e.clone())),
                Ok(InviteOutcome::Skipped { reason }) => skipped_db.push((e.clone(), reason)),
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error_code": "INTERNAL",
                            "message": err.to_string(),
                        })),
                    )
                        .into_response();
                }
            }
        }

        if let Err(e) = tx.commit() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error_code": "INTERNAL", "message": e.to_string() })),
            )
                .into_response();
        }

        let caller_email: Option<String> = conn
            .query_row(
                "SELECT email FROM admins WHERE id = ?1",
                params![caller_id],
                |r| r.get(0),
            )
            .ok();

        Ok((created, skipped_db, caller_email))
        // conn guard drops here — before any .await
    };

    let (created, skipped_db, caller_email) = match db_result {
        Ok(v) => v,
        Err(r) => return r,
    };

    // One audit row per created admin (lock released — safe to await).
    for (id, email) in &created {
        let mut entry = AuditEntry::success("-", "-", "admin.team.invite", 0);
        entry.actor_admin_id = Some(caller_id);
        entry.actor_email_snapshot = caller_email.clone();
        entry = entry.with_extra(serde_json::json!({
            "invited_admin_id": id,
            "invited_email": email,
            "role": role,
        }));
        crate::safety::audit::write_entry(&s.log_dir, &entry).await;
    }

    let created_json: Vec<serde_json::Value> = created
        .iter()
        .map(|(id, email)| serde_json::json!({ "id": id, "email": email }))
        .collect();
    let skipped_json: Vec<serde_json::Value> = skipped_db
        .iter()
        .map(|(email, reason)| serde_json::json!({ "email": email, "reason": reason.as_str() }))
        .collect();

    let status = if created.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let mut resp = Json(serde_json::json!({
        "created": created_json,
        "skipped": skipped_json,
    }))
    .into_response();
    *resp.status_mut() = status;
    resp
}

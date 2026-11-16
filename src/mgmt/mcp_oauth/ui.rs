//! MA0-9 — the admin-plane faces of MCP OAuth grants: the settings card
//! (list + self-service revoke) and the team page's "revoke this member's MCP
//! connections". Every route here is merged only when
//! `McpOauthConfig::enabled()`; with MCP off none of this is reachable and
//! `settings_page` never reads `_mcp_oauth_grants`.
//!
//! Revocation narrows access, so — like `cli_token_revoke` on the same page —
//! there is no CSRF field and no rate limit (SameSite=Lax session cookie).
//! Nothing here touches the auth cache or the realtime buses: MCP grants are
//! not cached and an MCP token cannot open SSE or rooms (design §4.6).
//!
//! Turning DRUST_MCP off hides these routes but revokes nothing: the grants
//! stay live in meta and work again when it is turned back on.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Json};
use rusqlite::{Connection, OptionalExtension, params};

use super::store::{self, GrantOwner, RevokeReason, RevokedGrant};
use crate::auth::middleware::{AdminId, AuthMethod};
use crate::error::json_error;
use crate::mgmt::admin_profile::AdminProfileExt;
use crate::mgmt::routes::MgmtState;
use crate::mgmt::tenant_authz::{can_manage_members, can_manage_privileged};
use crate::safety::audit::AuditEntry;

/// One row of the settings card. Askama reads the public fields.
pub struct McpGrantRow {
    pub id: i64,
    pub client_display: String,
    pub redirect_host: String,
    pub kind: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expired: bool,
    /// Last time an already-superseded sibling refresh of this grant was
    /// presented (`_mcp_oauth_grants.sibling_rejected_at`). Shown with its
    /// time so the owner can compare it with `last_used_at`.
    pub sibling_rejected_at: Option<String>,
}

const LIST_SQL: &str = "\
SELECT g.id, g.client_id, g.redirect_host, g.kind, g.created_at, g.last_used_at, \
       MIN(g.idle_expires_at, g.absolute_expires_at) <= datetime('now') AS expired, \
       g.sibling_rejected_at \
FROM _mcp_oauth_grants g \
JOIN admins a ON a.id = g.admin_id AND a.created_at = g.admin_created_at \
WHERE g.admin_id = ?1 AND g.revoked_at IS NULL \
ORDER BY COALESCE(g.last_used_at, g.created_at) DESC, g.id DESC";

/// Only the caller's own, unrevoked grants whose `admin_created_at` still
/// matches the live `admins` row (a previous holder of a recycled id never
/// shows up — layer 3 of the remove_admin defence).
/// Expired-but-unrevoked grants ARE listed (flagged) until the sweep deletes
/// them 30 days later, so the owner can see what lapsed.
pub fn list_grants_for_settings(
    conn: &Connection,
    admin_id: i64,
) -> rusqlite::Result<Vec<McpGrantRow>> {
    // `prepare`, not `prepare_cached`: an explicit projection either way
    // (invariant 11); same as the `cli_tokens` listing on the settings page.
    let mut stmt = conn.prepare(LIST_SQL)?;
    let rows = stmt.query_map(params![admin_id], |r| {
        let client_id: String = r.get(1)?;
        Ok(McpGrantRow {
            id: r.get(0)?,
            client_display: client_display(&client_id),
            redirect_host: r.get(2)?,
            kind: r.get(3)?,
            created_at: r.get(4)?,
            last_used_at: r.get(5)?,
            expired: r.get::<_, i64>(6)? != 0,
            sibling_rejected_at: r.get(7)?,
        })
    })?;
    rows.collect()
}

/// Display name of a pinned client; the raw client_id when unknown.
fn client_display(client_id: &str) -> String {
    match super::clients::find_client(client_id) {
        Some(c) => c.display_name.to_string(),
        None => client_id.to_string(),
    }
}

/// Typed reminder that `team_authority` ran before `GrantOwner::managed`.
/// The field is private, so only this file can build one; `store` reads it
/// through `target_admin_id()`. This is an in-crate type hint against
/// FORGETTING the gate, not a security boundary: `AdminProfileExt` has all-pub
/// fields, so crate code could fabricate an owner profile and call the gate.
pub struct TeamAuthority {
    target_admin_id: i64,
}

impl TeamAuthority {
    pub(super) fn target_admin_id(&self) -> i64 {
        self.target_admin_id
    }
}

/// Same matrix as `admin_team::remove_admin`: a member manages nobody
/// (NOT_A_MANAGER); a missing target is 404 ADMIN_NOT_FOUND; acting on an
/// owner/admin row is owner-only (PRIVILEGED_ROLE_REQUIRED). Written as an
/// allow-list on the target role — identical to remove_admin for the three
/// valid roles, fail-closed for anything else. The TARGET's role is read on
/// `conn`, which must be the same meta guard the revoke then runs under; the
/// CALLER's role comes from `admin_profile_layer`, read under an earlier,
/// separate lock — the same shape as `remove_admin`.
pub fn team_authority(
    conn: &Connection,
    profile: &AdminProfileExt,
    target_admin_id: i64,
) -> Result<TeamAuthority, Response> {
    if !can_manage_members(&profile.role) {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "NOT_A_MANAGER",
            "owner or admin role required",
        ));
    }
    let role: Option<String> = conn
        .query_row(
            "SELECT role FROM admins WHERE id = ?1",
            params![target_admin_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(internal)?;
    let Some(role) = role else {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "ADMIN_NOT_FOUND",
            "admin not found",
        ));
    };
    if role != "member" && !can_manage_privileged(&profile.role) {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "PRIVILEGED_ROLE_REQUIRED",
            "only an owner may revoke an owner or admin's MCP connections",
        ));
    }
    Ok(TeamAuthority { target_admin_id })
}

fn internal(e: rusqlite::Error) -> Response {
    tracing::warn!(
        error = %crate::error::sqlite_error_without_sql(&e),
        "mcp_oauth ui: meta query failed"
    );
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL",
        "internal error",
    )
}

/// `POST /admin/settings/mcp-grants/{id}/revoke`. Owner-bound in SQL via
/// `GrantOwner::caller` — someone else's id, an unknown id and an
/// already-revoked id are the SAME 404 (no existence oracle), whatever the
/// caller's role. `caller` MUST come from the `Extension<AdminId>` extractor,
/// never from the path (rules: auth-tenancy "MCP grant revoke UI").
pub async fn settings_revoke(
    State(s): State<MgmtState>,
    Extension(caller): Extension<AdminId>,
    Path(grant_id): Path<i64>,
    method: Option<Extension<AuthMethod>>,
) -> Response {
    let email = {
        let conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => return internal(e),
        };
        let outcome = match store::revoke_mcp_grant(
            &tx,
            &GrantOwner::caller(&caller),
            grant_id,
            RevokeReason::User,
        ) {
            Ok(r) => r,
            Err(e) => return internal(e),
        };
        if outcome == RevokedGrant::NotFound {
            // Nothing was written; dropping `tx` rolls back.
            return json_error(
                StatusCode::NOT_FOUND,
                "MCP_GRANT_NOT_FOUND",
                "no active MCP connection with that id for this admin",
            );
        }
        if let Err(e) = tx.commit() {
            return internal(e);
        }
        email_of(&conn, caller.0)
    }; // meta guard dropped before the audit await
    let entry = audit_entry(
        "mcp_oauth.grant.revoke",
        caller.0,
        email,
        method.as_ref(),
        serde_json::json!({ "grant_id": grant_id, "reason": "user" }),
    );
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
    Redirect::to(&crate::base_path::base("/admin/settings")).into_response()
}

/// `POST /admin/settings/mcp-grants/revoke-all` — the caller's own grants only.
/// Zero grants is not an error (idempotent 303). The count is whatever
/// `revoke_all_mcp_grants` found live for this admin id, which can exceed the
/// rows the card showed (the card also filters on `admin_created_at`).
pub async fn settings_revoke_all(
    State(s): State<MgmtState>,
    Extension(caller): Extension<AdminId>,
    method: Option<Extension<AuthMethod>>,
) -> Response {
    let (n, email) = {
        let conn = s.meta.lock().await;
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => return internal(e),
        };
        let n = match store::revoke_all_mcp_grants(
            &tx,
            &GrantOwner::caller(&caller),
            RevokeReason::UserAll,
        ) {
            Ok(n) => n,
            Err(e) => return internal(e),
        };
        if let Err(e) = tx.commit() {
            return internal(e);
        }
        let email = if n > 0 {
            email_of(&conn, caller.0)
        } else {
            None
        };
        (n, email)
    };
    if n > 0 {
        let entry = audit_entry(
            "mcp_oauth.grant.revoke",
            caller.0,
            email,
            method.as_ref(),
            serde_json::json!({ "reason": "user_all", "revoked": n }),
        );
        crate::safety::audit::write_entry(&s.log_dir, &entry).await;
    }
    Redirect::to(&crate::base_path::base("/admin/settings")).into_response()
}

/// `DELETE /admin/team/{id}/mcp-grants` — revoke every MCP grant of `{id}`
/// (an ADMIN id, not a tenant id: this route is on `team_router`, never under
/// `tenant_ownership_layer`). Authority decided in-handler: the route layer on
/// `team_router` gates only GET.
pub async fn team_revoke_mcp(
    State(s): State<MgmtState>,
    Path(target_id): Path<i64>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
    Extension(profile): Extension<AdminProfileExt>,
    method: Option<Extension<AuthMethod>>,
) -> Response {
    let (n, caller_email) = {
        let conn = s.meta.lock().await;
        let authority = match team_authority(&conn, &profile, target_id) {
            Ok(a) => a,
            Err(r) => return r,
        };
        let tx = match conn.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => return internal(e),
        };
        let n = match store::revoke_all_mcp_grants(
            &tx,
            &GrantOwner::managed(&authority),
            RevokeReason::TeamAdmin,
        ) {
            Ok(n) => n,
            Err(e) => return internal(e),
        };
        if let Err(e) = tx.commit() {
            return internal(e);
        }
        (n, email_of(&conn, caller_id))
    };
    let entry = audit_entry(
        "admin.mcp_grant.revoke",
        caller_id,
        caller_email,
        method.as_ref(),
        serde_json::json!({ "target_admin_id": target_id, "revoked": n }),
    );
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
    Json(serde_json::json!({ "revoked": n })).into_response()
}

/// Read under the guard the handler already holds (no second lock).
fn email_of(conn: &Connection, admin_id: i64) -> Option<String> {
    conn.query_row(
        "SELECT email FROM admins WHERE id = ?1",
        params![admin_id],
        |r| r.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

/// Host-level sentinel tenant "-" like `login_submit`; `actor_admin_id` and
/// `actor_email_snapshot` always paired (audit.rs doc). `auth_method` names
/// which arm of `admin_session_layer` admitted the caller.
fn audit_entry(
    op: &str,
    admin_id: i64,
    email: Option<String>,
    method: Option<&Extension<AuthMethod>>,
    extra: serde_json::Value,
) -> AuditEntry {
    let mut entry = AuditEntry::success("-", "-", op, 0);
    entry.actor_admin_id = Some(admin_id);
    entry.actor_email_snapshot = email;
    entry.auth_method = audit_auth_method(method.map(|Extension(m)| *m));
    entry.with_extra(extra)
}

/// Exhaustive on purpose: a third `AuthMethod` variant must pick its string here.
fn audit_auth_method(method: Option<AuthMethod>) -> Option<String> {
    match method {
        Some(AuthMethod::Cookie) => Some("admin_cookie".to_string()),
        Some(AuthMethod::Pat) => Some("admin_pat".to_string()),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real meta.sqlite (open_meta + run_migrations) with an owner, an
    /// admin and a member; returns the connection and the three ids.
    fn meta(dir: &std::path::Path) -> (Connection, [i64; 3]) {
        let conn = crate::storage::meta::open_meta(&dir.join("meta.sqlite")).unwrap();
        crate::db::migrations::run_migrations(&conn, dir).unwrap();
        let mut ids = [0; 3];
        for (i, role) in ["owner", "admin", "member"].iter().enumerate() {
            conn.execute(
                "INSERT INTO admins (username, password_hash, role) \
                 VALUES (?1, '$oauth-only$', ?2)",
                params![format!("u_{role}"), role],
            )
            .unwrap();
            ids[i] = conn.last_insert_rowid();
        }
        (conn, ids)
    }

    fn profile(role: &str) -> AdminProfileExt {
        AdminProfileExt {
            role: role.to_string(),
            ..AdminProfileExt::placeholder()
        }
    }

    async fn err_code(r: Response) -> (StatusCode, String) {
        let status = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        (status, v["error_code"].as_str().unwrap_or("").to_string())
    }

    #[tokio::test]
    async fn team_authority_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, ids) = meta(dir.path());
        let roles = ["owner", "admin", "member"];
        for caller in roles {
            for (ti, target) in roles.iter().enumerate() {
                let ctx = format!("{caller} -> {target}");
                let res = team_authority(&conn, &profile(caller), ids[ti]);
                let ok = match caller {
                    "owner" => true,
                    "admin" => *target == "member",
                    _ => false,
                };
                match res {
                    Ok(a) => {
                        assert!(ok, "{ctx}: expected a refusal");
                        assert_eq!(a.target_admin_id(), ids[ti], "{ctx}");
                    }
                    Err(r) => {
                        assert!(!ok, "{ctx}: expected Ok");
                        let want = if caller == "member" {
                            "NOT_A_MANAGER"
                        } else {
                            "PRIVILEGED_ROLE_REQUIRED"
                        };
                        assert_eq!(
                            err_code(r).await,
                            (StatusCode::FORBIDDEN, want.to_string()),
                            "{ctx}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn team_authority_missing_target_is_404_after_manager_gate() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, _) = meta(dir.path());
        let r = team_authority(&conn, &profile("owner"), 999_999)
            .err()
            .expect("missing target");
        assert_eq!(
            err_code(r).await,
            (StatusCode::NOT_FOUND, "ADMIN_NOT_FOUND".to_string())
        );
        // The manager gate runs before the lookup: a member cannot probe ids.
        let r = team_authority(&conn, &profile("member"), 999_999)
            .err()
            .expect("member");
        assert_eq!(
            err_code(r).await,
            (StatusCode::FORBIDDEN, "NOT_A_MANAGER".to_string())
        );
    }

    #[tokio::test]
    async fn team_authority_unknown_target_role_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, ids) = meta(dir.path());
        // admins.role has no CHECK, so an unknown value can be stored.
        conn.execute(
            "UPDATE admins SET role = 'bogus' WHERE id = ?1",
            params![ids[2]],
        )
        .unwrap();
        let r = team_authority(&conn, &profile("admin"), ids[2])
            .err()
            .expect("admin on an unknown role");
        assert_eq!(
            err_code(r).await,
            (
                StatusCode::FORBIDDEN,
                "PRIVILEGED_ROLE_REQUIRED".to_string()
            )
        );
        let a = team_authority(&conn, &profile("owner"), ids[2]).expect("owner on an unknown role");
        assert_eq!(a.target_admin_id(), ids[2]);
    }

    /// A grant of `admin_id` with the given idle modifier; returns its id.
    fn seed(conn: &Connection, admin_id: i64, idle: &str) -> i64 {
        conn.execute(
            "INSERT INTO _mcp_oauth_grants \
               (admin_id, admin_created_at, client_id, redirect_host, \
                idle_expires_at, absolute_expires_at) \
             SELECT id, created_at, \
                    'https://claude.ai/oauth/claude-code-client-metadata', 'localhost', \
                    datetime('now', ?2), datetime('now', '+90 days') \
               FROM admins WHERE id = ?1",
            params![admin_id, idle],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn list_filters_and_flags() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, ids) = meta(dir.path());
        let (me, other) = (ids[0], ids[1]);
        let live = seed(&conn, me, "+30 days");
        conn.execute(
            "UPDATE _mcp_oauth_grants SET last_used_at = datetime('now', '+1 hour') \
             WHERE id = ?1",
            params![live],
        )
        .unwrap();
        let revoked = seed(&conn, me, "+30 days");
        conn.execute(
            "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now'), revoke_reason = 'user' \
             WHERE id = ?1",
            params![revoked],
        )
        .unwrap();
        let expired = seed(&conn, me, "-1 hour");
        let sibling = seed(&conn, me, "+30 days");
        conn.execute(
            "UPDATE _mcp_oauth_grants SET sibling_rejected_at = '2026-01-02 03:04:05' \
             WHERE id = ?1",
            params![sibling],
        )
        .unwrap();
        let foreign = seed(&conn, other, "+30 days");
        let recycled = seed(&conn, me, "+30 days");
        conn.execute(
            "UPDATE _mcp_oauth_grants SET admin_created_at = '2000-01-01 00:00:00' \
             WHERE id = ?1",
            params![recycled],
        )
        .unwrap();

        let rows = list_grants_for_settings(&conn, me).unwrap();
        let got: Vec<i64> = rows.iter().map(|r| r.id).collect();
        // live first (latest last_used_at), then the two never-used ones by id DESC.
        assert_eq!(got, vec![live, sibling, expired]);
        for absent in [revoked, foreign, recycled] {
            assert!(!got.contains(&absent), "{absent} must not be listed");
        }
        let by_id = |id: i64| rows.iter().find(|r| r.id == id).unwrap();
        assert!(!by_id(live).expired);
        assert!(by_id(expired).expired);
        assert!(!by_id(sibling).expired);
        assert_eq!(
            by_id(sibling).sibling_rejected_at.as_deref(),
            Some("2026-01-02 03:04:05")
        );
        assert_eq!(by_id(live).sibling_rejected_at, None);
        assert_eq!(by_id(expired).sibling_rejected_at, None);
        for r in &rows {
            assert_eq!(r.client_display, "Claude Code");
            assert_eq!(r.redirect_host, "localhost");
            assert_eq!(r.kind, "authorization_code");
        }
        assert!(by_id(live).last_used_at.is_some());
        assert!(by_id(expired).last_used_at.is_none());
    }

    /// Integration tests cannot read audit rows (first-write-wins global
    /// writer), so the row shape is pinned here: actor and email paired,
    /// the session arm named, the host-level sentinel tenant.
    #[test]
    fn audit_entry_carries_the_actor_and_the_session_arm() {
        let extra = serde_json::json!({ "grant_id": 7, "reason": "user" });
        let cookie = audit_entry(
            "mcp_oauth.grant.revoke",
            3,
            Some("a@example.test".to_string()),
            Some(&Extension(AuthMethod::Cookie)),
            extra.clone(),
        );
        assert_eq!(cookie.tenant, "-");
        assert_eq!(cookie.op, "mcp_oauth.grant.revoke");
        assert_eq!(cookie.actor_admin_id, Some(3));
        assert_eq!(
            cookie.actor_email_snapshot.as_deref(),
            Some("a@example.test")
        );
        assert_eq!(cookie.auth_method.as_deref(), Some("admin_cookie"));
        assert_eq!(serde_json::Value::Object(cookie.extra), extra);
        let pat = audit_entry(
            "admin.mcp_grant.revoke",
            3,
            None,
            Some(&Extension(AuthMethod::Pat)),
            serde_json::json!({}),
        );
        assert_eq!(pat.auth_method.as_deref(), Some("admin_pat"));
        assert_eq!(audit_auth_method(None), None);
    }

    #[test]
    fn client_display_falls_back_to_the_raw_id() {
        assert_eq!(
            client_display("https://claude.ai/oauth/claude-code-client-metadata"),
            "Claude Code"
        );
        assert_eq!(
            client_display("https://unknown.example/x"),
            "https://unknown.example/x"
        );
    }

    const PARTIALS: &[(&str, &str)] = &[
        (
            "_settings_mcp_grants.html",
            include_str!("../templates/_settings_mcp_grants.html"),
        ),
        (
            "_settings_mcp_grants_js.html",
            include_str!("../templates/_settings_mcp_grants_js.html"),
        ),
        (
            "_team_mcp_revoke_btn.html",
            include_str!("../templates/_team_mcp_revoke_btn.html"),
        ),
        (
            "_team_mcp_revoke_js.html",
            include_str!("../templates/_team_mcp_revoke_js.html"),
        ),
    ];

    /// Invariant 15: default mode is byte-identical, so a hardcoded `/drust`
    /// would pass every page test. Every outbound URL in the four partials
    /// starts with the base-path helper.
    #[test]
    fn templates_route_through_base_path() {
        const BASE: &str = "{{ crate::base_path::base_path() }}";
        let mut urls = 0;
        for (name, src) in PARTIALS {
            assert!(!src.contains("/drust"), "{name} hardcodes /drust");
            // Leading space: `data-action="…"` is a JS hook, not a form action.
            for needle in [" action=\"", "fetch('"] {
                for (at, _) in src.match_indices(needle) {
                    let rest = &src[at + needle.len()..];
                    assert!(
                        rest.starts_with(BASE),
                        "{name}: `{needle}` not followed by the base path"
                    );
                    urls += 1;
                }
            }
        }
        // Two form actions on the card, one fetch on the team page.
        assert_eq!(urls, 3);
    }

    /// MA0-PLAN §3.11 rule 4: the two existing pages change only by a
    /// flag-gated include appended to the END of an existing line, so with
    /// `mcp_enabled = false` they render byte-identically.
    #[test]
    fn templates_are_flag_gated_line_suffixes() {
        let pages = [
            (
                "settings.html",
                include_str!("../templates/settings.html"),
                &["_settings_mcp_grants.html", "_settings_mcp_grants_js.html"][..],
                2,
            ),
            (
                "admin_team.html",
                include_str!("../templates/admin_team.html"),
                &["_team_mcp_revoke_btn.html", "_team_mcp_revoke_js.html"][..],
                3,
            ),
        ];
        for (page, src, names, want) in pages {
            let mut found = 0;
            for name in names {
                let include = format!("{{% include \"{name}\" %}}");
                let suffix = format!("{{% if mcp_enabled %}}{include}{{% endif %}}");
                for line in src.lines().filter(|l| l.contains(&include)) {
                    assert!(
                        line.ends_with(&suffix),
                        "{page}: `{name}` is not a flag-gated line suffix: {line:?}"
                    );
                    assert!(
                        line.len() > suffix.len(),
                        "{page}: `{name}` sits on a line of its own"
                    );
                    found += 1;
                }
            }
            assert_eq!(found, want, "{page}: flag-gated includes");
        }
    }
}

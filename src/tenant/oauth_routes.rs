//! Per-tenant OAuth start + callback handlers. End users of a tenant's
//! application sign in via Google/GitHub and receive a `drust_user_*`
//! bearer token (the v1.9 user-session shape). Token delivery is via
//! URL fragment to the frontend's redirect_uri (Supabase/Auth0 pattern).

use crate::oauth::{
    github::GitHubAdapter, google::GoogleAdapter, provider::OauthProvider, state as oauth_state,
};
use crate::tenant::oauth_config;
use crate::tenant::router::TenantAuthState;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(serde::Deserialize)]
pub(crate) struct CallbackQuery {
    pub(crate) code: String,
    pub(crate) state: String,
}

/// Redirect back to the validated frontend with `#error=<code>`. Caller
/// MUST have validated `frontend_redirect_uri` against the allowlist
/// before invoking — private helper.
/// Build a 302 to `loc` that also clears the two OAuth cookies. Falls back to
/// a 500 (instead of panicking) if `loc` can't form a valid `Location` header
/// — e.g. a pre-patch allowlisted `frontend` carrying a control byte that the
/// hardened `validate_redirect_uri` now rejects at write time.
fn build_fragment_redirect(loc: &str, tid: &str) -> Response {
    match Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, loc)
        .header(header::SET_COOKIE, clear_cookie(STATE_COOKIE, tid))
        .header(header::SET_COOKIE, clear_cookie(PKCE_COOKIE, tid))
        .body(axum::body::Body::empty())
    {
        Ok(resp) => resp,
        Err(_) => plain_text_clear_cookies(
            StatusCode::INTERNAL_SERVER_ERROR,
            "oauth_redirect_error",
            tid,
        ),
    }
}

fn redirect_with_fragment_error(frontend: &str, code: &str, tid: &str) -> Response {
    build_fragment_redirect(&format!("{frontend}#error={code}"), tid)
}

fn parse_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for kv in raw.split(';') {
        let kv = kv.trim();
        if let Some((k, v)) = kv.split_once('=')
            && k == name
        {
            return Some(v.to_string());
        }
    }
    None
}

pub(crate) const STATE_COOKIE: &str = "drust_t_oauth_state";
pub(crate) const PKCE_COOKIE: &str = "drust_t_oauth_pkce";
pub(crate) const COOKIE_TTL_SECS: i64 = 300;

// v1.32.1 (D7): the former `drust_t_oauth_redirect_uri` cookie was retired.
// `redirect_uri` now travels inside the `state` query param via an
// HMAC-bound envelope so two parallel /start calls in different tabs no
// longer clobber each other's redirect. See
// `crate::oauth::state::TenantOauthStateToken`.

/// Build the cookie attribute suffix (no `key=value` prefix). Path =
/// `/drust/t/<tid>/oauth/` is REQUIRED because Caddy strips `/drust`
/// before forwarding to axum — browsers must see the full prefix to
/// send the cookie back on the callback. See memory
/// `project_drust_caddy_prefix_paths`.
pub(crate) fn cookie_attrs(tid: &str, secure: bool) -> String {
    let scheme_attrs = if secure { "Secure; " } else { "" };
    format!(
        "Path=/drust/t/{tid}/oauth/; HttpOnly; {scheme_attrs}SameSite=Lax; Max-Age={ttl}",
        tid = tid,
        scheme_attrs = scheme_attrs,
        ttl = COOKIE_TTL_SECS,
    )
}

pub(crate) fn set_cookie(name: &str, value: &str, tid: &str, secure: bool) -> String {
    format!("{name}={value}; {attrs}", attrs = cookie_attrs(tid, secure))
}

pub(crate) fn clear_cookie(name: &str, tid: &str) -> String {
    format!("{name}=; Path=/drust/t/{tid}/oauth/; Max-Age=0; HttpOnly; SameSite=Lax")
}

pub(crate) fn secure_from_headers(h: &axum::http::HeaderMap) -> bool {
    h.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) == Some("https")
}

/// Build an adapter from a stored config row. Returns `None` on an
/// unrecognised provider name. The upsert path validates the provider
/// name, but a stale row from a future drust release (or hand-edited
/// SQL) could carry an unknown value — returning None instead of
/// panicking keeps the request handler honest.
///
/// Tests inject fake adapters via `state.oauth_adapter_override`; in
/// production that map is empty and we fall through to
/// `GoogleAdapter::production` / `GitHubAdapter::production`.
pub(crate) fn build_adapter(
    state: &TenantAuthState,
    cfg: &oauth_config::OauthProviderConfig,
) -> Option<std::sync::Arc<dyn OauthProvider>> {
    if let Some(over) = state.oauth_adapter_override.get(&cfg.provider) {
        return Some(over.clone());
    }
    match cfg.provider.as_str() {
        "google" => Some(std::sync::Arc::new(GoogleAdapter::production(
            cfg.client_id.clone(),
            cfg.client_secret.clone(),
        ))),
        "github" => Some(std::sync::Arc::new(GitHubAdapter::production(
            cfg.client_id.clone(),
            cfg.client_secret.clone(),
        ))),
        _ => None,
    }
}

pub(crate) fn plain_text(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// Same as `plain_text` but also clears the two OAuth cookies. Used by
/// `/callback` steps 1-4 (pre-validation failures) so a stale cookie
/// pair isn't carried across browser retries.
fn plain_text_clear_cookies(status: StatusCode, body: &str, tid: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::SET_COOKIE, clear_cookie(STATE_COOKIE, tid))
        .header(header::SET_COOKIE, clear_cookie(PKCE_COOKIE, tid))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

#[derive(serde::Deserialize)]
pub(crate) struct StartQuery {
    pub(crate) redirect_uri: String,
}

pub(crate) async fn oauth_start(
    Path(params): Path<HashMap<String, String>>,
    State(state): State<TenantAuthState>,
    Query(q): Query<StartQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let tid = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return plain_text(StatusCode::BAD_REQUEST, "missing tenant"),
    };
    let provider_name = match params.get("provider") {
        Some(p) => p.clone(),
        None => return plain_text(StatusCode::BAD_REQUEST, "missing provider"),
    };

    // Rate-limit before any DB hit (shares the OAuth-flow budget with
    // /callback, 5/60s/IP). Defense-in-depth on top of the existence gate.
    let fallback_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);
    if !state.oauth_callback_rl.check(ip) {
        return plain_text(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }

    // Validate tenant exists in meta BEFORE get_or_open — prevents disk-fill
    // from arbitrary tenant IDs creating junk tenant DBs (mirrors login_handler).
    let tenant_exists = {
        let conn = state.meta.lock().await;
        conn.query_row(
            "SELECT 1 FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tid],
            |_| Ok(()),
        )
        .is_ok()
    };
    if !tenant_exists {
        return plain_text(StatusCode::NOT_FOUND, "tenant not found");
    }

    // Look up provider config from the tenant DB.
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => return plain_text(StatusCode::NOT_FOUND, "tenant not found"),
    };

    let provider_name_for_lookup = provider_name.clone();
    let cfg_opt = pool
        .with_reader(move |c| oauth_config::get(c, &provider_name_for_lookup))
        .await;
    let cfg = match cfg_opt {
        Ok(Some(c)) => c,
        Ok(None) => return plain_text(StatusCode::BAD_REQUEST, "oauth_misconfigured"),
        Err(_) => return plain_text(StatusCode::INTERNAL_SERVER_ERROR, "db error"),
    };

    // Validate redirect_uri against allowlist (exact match).
    if !cfg
        .allowed_redirect_uris
        .iter()
        .any(|u| u == &q.redirect_uri)
    {
        return plain_text(StatusCode::BAD_REQUEST, "oauth_invalid_redirect");
    }

    // v1.32.1 (D7): bind redirect_uri INTO the `state` value via HMAC
    // instead of via a separate cookie. The cookie still pins the nonce
    // half (the encoded token contains nonce + redirect_uri + HMAC), so
    // a CSRF that forges `state` query param still has to match the
    // cookie — but we now also recover redirect_uri from the state itself
    // and re-check the allowlist at callback (TOCTOU-safe).
    let state_token = oauth_state::TenantOauthStateToken::new(q.redirect_uri.clone());
    let csrf_state = state_token.encode(state.tenant_oauth_state_secret.as_ref());
    let (pkce_verifier, pkce_challenge) = oauth_state::issue_pkce();

    if state.public_url.is_empty() {
        return plain_text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DRUST_PUBLIC_URL not set",
        );
    }
    let drust_callback = format!(
        "{pu}/drust/t/{tid}/oauth/{provider_name}/callback",
        pu = state.public_url
    );

    let adapter = match build_adapter(&state, &cfg) {
        Some(a) => a,
        None => return plain_text(StatusCode::BAD_REQUEST, "oauth_misconfigured"),
    };
    let auth_url = adapter.authorize_url(&csrf_state, &pkce_challenge, &drust_callback);

    let secure = secure_from_headers(&headers);
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, auth_url)
        .header(
            header::SET_COOKIE,
            set_cookie(STATE_COOKIE, &csrf_state, &tid, secure),
        )
        .header(
            header::SET_COOKIE,
            set_cookie(PKCE_COOKIE, &pkce_verifier, &tid, secure),
        )
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn audit_oauth_success(
    _state: &TenantAuthState,
    tid: &str,
    provider: &str,
    user_id: &str,
    email: &str,
) {
    let op = format!("GET /t/{tid}/oauth/{provider}/callback");
    let mut entry = crate::safety::audit::AuditEntry::success(tid, "-", &op, 0)
        .with_extra(serde_json::json!({ "auth_user_id": user_id, "auth_kind": "user" }));
    entry.auth_method = Some(format!("oauth_{provider}"));
    entry.oauth_email = Some(sanitize_email(email));
    crate::safety::audit_db::try_send(&entry);
}

async fn audit_oauth_failure(
    _state: &TenantAuthState,
    tid: &str,
    provider: &str,
    email: Option<&str>,
    error_code: &str,
) {
    let op = format!("GET /t/{tid}/oauth/{provider}/callback");
    let mut entry = crate::safety::audit::AuditEntry::failure(tid, "-", &op, 0, "HTTP_400", "")
        .with_extra(serde_json::json!({ "auth_kind": "user" }));
    entry.auth_method = Some(format!("oauth_{provider}"));
    entry.oauth_email = email.map(sanitize_email);
    entry.oauth_error_code = Some(error_code.to_string());
    crate::safety::audit_db::try_send(&entry);
}

pub(crate) fn sanitize_email(s: &str) -> String {
    // Duplicated from src/mgmt/oauth_login.rs intentionally — moving to a
    // shared module is the v1.13 refactor (yagni for now).
    if crate::bin_helpers::validate_email(s) {
        s.to_lowercase()
    } else {
        "<invalid>".into()
    }
}

fn redirect_with_fragment_success(
    frontend: &str,
    token: &str,
    expires_in_secs: u64,
    tid: &str,
) -> Response {
    let loc =
        format!("{frontend}#access_token={token}&token_type=Bearer&expires_in={expires_in_secs}");
    build_fragment_redirect(&loc, tid)
}

/// Result of resolving an OAuth identity to a `_system_users` row.
pub(crate) struct ResolvedUser {
    pub id: String,
    /// True when an existing UNVERIFIED PASSWORD account was claimed by this
    /// OAuth login (password wiped, verified set, sessions revoked) — the
    /// caller must invalidate the auth cache for `id`.
    pub claimed: bool,
}

/// Look up `_system_users.id` by case-insensitive email, claiming an unverified
/// password account (OAuth-authoritative, spec A1), or auto-creating a row when
/// `allow_self_register` is true. Returns `Ok(None)` to signal the caller should
/// render `oauth_not_allowed`. OAuth-only users carry the sentinel password hash
/// so the password login path short-circuits before reaching argon2. `name` and
/// `picture` land in the `profile` JSON column (spec §3.3).
fn find_or_create_user(
    conn: &rusqlite::Connection,
    email: &str,
    name: Option<&str>,
    picture: Option<&str>,
    allow_self_register: bool,
) -> rusqlite::Result<Option<ResolvedUser>> {
    use rusqlite::OptionalExtension;
    let existing: Option<(String, String, i64)> = conn
        .query_row(
            "SELECT id, password_hash, verified FROM _system_users \
             WHERE email = ?1 COLLATE NOCASE",
            [email],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((id, password_hash, verified)) = existing {
        // OAuth has proven email ownership (step-6 email_verified gate). If the
        // matched row is an UNVERIFIED PASSWORD account, the proven owner claims
        // it: wipe the password (evict a pre-seeded squatter), mark verified,
        // and revoke all sessions (evict live attacker sessions). Sentinel rows
        // and admin-verified rows link unchanged.
        let is_password = !crate::auth::oauth_sentinel::is_oauth_only(&password_hash);
        if is_password && verified == 0 {
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "UPDATE _system_users SET password_hash = ?1, verified = 1, updated_at = ?2 \
                 WHERE id = ?3",
                rusqlite::params![crate::auth::oauth_sentinel::OAUTH_ONLY_SENTINEL, now, id],
            )?;
            crate::auth::user_session::revoke_all_sessions(conn, &id)?;
            return Ok(Some(ResolvedUser { id, claimed: true }));
        }
        return Ok(Some(ResolvedUser { id, claimed: false }));
    }
    if !allow_self_register {
        return Ok(None);
    }
    let new_id = format!("u-{}", uuid::Uuid::new_v4());
    // Spec §3.3: profile carries `name` + `picture` (the latter as null
    // when the provider didn't supply one).
    let profile = serde_json::json!({
        "name": name.unwrap_or(""),
        "picture": picture,
    })
    .to_string();
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO _system_users \
           (id, email, password_hash, verified, profile, created_at, updated_at) \
         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?5)",
        rusqlite::params![
            new_id,
            email,
            crate::auth::oauth_sentinel::OAUTH_ONLY_SENTINEL,
            profile,
            now,
        ],
    )?;
    Ok(Some(ResolvedUser {
        id: new_id,
        claimed: false,
    }))
}

async fn allow_self_register_for_tenant(
    state: &TenantAuthState,
    tid: &str,
) -> Result<bool, rusqlite::Error> {
    let meta = state.meta.lock().await;
    let v: i64 = meta.query_row(
        "SELECT allow_self_register FROM tenants WHERE id = ?1",
        [tid],
        |r| r.get(0),
    )?;
    Ok(v != 0)
}

pub(crate) async fn oauth_callback(
    Path(params): Path<HashMap<String, String>>,
    State(state): State<TenantAuthState>,
    Query(q): Query<CallbackQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let tid = match params.get("tenant") {
        Some(t) => t.clone(),
        None => return plain_text(StatusCode::BAD_REQUEST, "missing tenant"),
    };
    let provider_name = match params.get("provider") {
        Some(p) => p.clone(),
        None => return plain_text(StatusCode::BAD_REQUEST, "missing provider"),
    };

    // Rate-limit before any DB hit (5 / 60 s / IP). Defends the
    // provider-exchange path from brute-force replay. Plain `plain_text`
    // (no cookie clear) so retry from the same browser still has cookies.
    let fallback_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);
    if !state.oauth_callback_rl.check(ip) {
        return plain_text(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let ip_str = ip.to_string();

    // Validate tenant exists in meta BEFORE get_or_open — prevents disk-fill
    // from arbitrary tenant IDs creating junk tenant DBs (mirrors login_handler
    // and oauth_start). The rate-limit above is defense-in-depth; this gate is
    // what structurally closes the disk-fill vector.
    let tenant_exists = {
        let conn = state.meta.lock().await;
        conn.query_row(
            "SELECT 1 FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tid],
            |_| Ok(()),
        )
        .is_ok()
    };
    if !tenant_exists {
        return plain_text_clear_cookies(StatusCode::NOT_FOUND, "tenant not found", &tid);
    }

    // Step 1: provider exists.
    let pool = match state.registry.get_or_open(&tid) {
        Ok(p) => p,
        Err(_) => {
            return plain_text_clear_cookies(StatusCode::NOT_FOUND, "tenant not found", &tid);
        }
    };
    let provider_name_for_lookup = provider_name.clone();
    let cfg_opt = pool
        .with_reader(move |c| oauth_config::get(c, &provider_name_for_lookup))
        .await;
    let cfg = match cfg_opt {
        Ok(Some(c)) => c,
        Ok(None) => {
            return plain_text_clear_cookies(StatusCode::BAD_REQUEST, "oauth_misconfigured", &tid);
        }
        Err(_) => {
            return plain_text_clear_cookies(StatusCode::INTERNAL_SERVER_ERROR, "db error", &tid);
        }
    };

    // Step 2: state cookie matches query state (constant-time). The state
    // value is now an HMAC-bound envelope (see TenantOauthStateToken) but
    // the cookie-vs-query equality check is still the first CSRF gate.
    let cookie_state = parse_cookie(&headers, STATE_COOKIE).unwrap_or_default();
    if !crate::oauth::state::verify_state(&cookie_state, &q.state) {
        return plain_text_clear_cookies(StatusCode::BAD_REQUEST, "oauth_state_mismatch", &tid);
    }

    // Step 3: PKCE verifier present.
    let pkce_verifier = parse_cookie(&headers, PKCE_COOKIE).unwrap_or_default();
    if pkce_verifier.is_empty() {
        return plain_text_clear_cookies(StatusCode::BAD_REQUEST, "oauth_state_mismatch", &tid);
    }

    // Step 4: decode the state envelope to recover the redirect_uri the
    // /start handler signed. Two checks in defense-in-depth order:
    //   (1) HMAC verifies → state was minted by THIS process for THIS
    //       redirect_uri (an attacker can't forge a new envelope).
    //   (2) recovered redirect_uri is STILL on the per-tenant allowlist —
    //       TOCTOU guard: admin may have shrunk the allowlist between
    //       /start and /callback, and we re-read it from the DB fresh
    //       above (Step 1). Even if (1) somehow passes for an off-list
    //       URI, this check still blocks.
    let envelope = match crate::oauth::state::TenantOauthStateToken::decode(
        &q.state,
        state.tenant_oauth_state_secret.as_ref(),
    ) {
        Ok(t) => t,
        Err(_) => {
            return plain_text_clear_cookies(StatusCode::BAD_REQUEST, "oauth_state_mismatch", &tid);
        }
    };
    let frontend_uri = envelope.redirect_uri;
    if !cfg.allowed_redirect_uris.iter().any(|u| u == &frontend_uri) {
        return plain_text_clear_cookies(StatusCode::BAD_REQUEST, "oauth_invalid_redirect", &tid);
    }

    // Step 5: exchange code+verifier with the provider.
    // Mirror /start: refuse early when public URL isn't configured rather
    // than letting the provider return an opaque oauth_provider_error.
    if state.public_url.is_empty() {
        return plain_text_clear_cookies(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DRUST_PUBLIC_URL not set",
            &tid,
        );
    }
    let drust_callback = format!(
        "{pu}/drust/t/{tid}/oauth/{provider_name}/callback",
        pu = state.public_url
    );
    let adapter = match build_adapter(&state, &cfg) {
        Some(a) => a,
        None => {
            return plain_text_clear_cookies(StatusCode::BAD_REQUEST, "oauth_misconfigured", &tid);
        }
    };
    let user = match adapter
        .exchange(&q.code, &pkce_verifier, &drust_callback)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                tenant = %tid,
                provider = %provider_name,
                error = %e,
                "oauth exchange failed"
            );
            // Email not yet known — pass None.
            audit_oauth_failure(&state, &tid, &provider_name, None, "oauth_provider_error").await;
            return redirect_with_fragment_error(&frontend_uri, "oauth_provider_error", &tid);
        }
    };

    // Step 6: email_verified.
    if !user.email_verified {
        audit_oauth_failure(
            &state,
            &tid,
            &provider_name,
            Some(&user.email),
            "oauth_email_unverified",
        )
        .await;
        return redirect_with_fragment_error(&frontend_uri, "oauth_email_unverified", &tid);
    }

    // Step 7: find or auto-create _system_users.
    let allow_self_register = match allow_self_register_for_tenant(&state, &tid).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                tenant = %tid,
                error = %e,
                "allow_self_register read failed"
            );
            audit_oauth_failure(
                &state,
                &tid,
                &provider_name,
                Some(&user.email),
                "oauth_session_error",
            )
            .await;
            return redirect_with_fragment_error(&frontend_uri, "oauth_session_error", &tid);
        }
    };
    // Steps 7 + 8 in one writer pass: find/create the user row, then
    // mint the session token. Single mutex acquisition prevents the race
    // where two concurrent callbacks for the same email both observe
    // "no row" → both INSERT → second hits UNIQUE.
    let email_for_lookup = user.email.clone();
    let name_for_lookup = user.name.clone();
    let picture_for_lookup = user.picture.clone();
    let ip_for_session = ip_str.clone();
    // with_writer_tx (not with_writer): the claim path is now a 3-statement
    // sequence (password-wipe UPDATE + session-revoke DELETE + new-session
    // INSERT). Wrap it in one transaction so a failure on the final INSERT
    // rolls back the wipe+revoke instead of leaving a password-less, session-
    // less half-state. clear_user stays AFTER the await (post-commit).
    let res: rusqlite::Result<Option<(String, String, bool)>> = pool
        .with_writer_tx(move |c| {
            match find_or_create_user(
                c,
                &email_for_lookup,
                name_for_lookup.as_deref(),
                picture_for_lookup.as_deref(),
                allow_self_register,
            )? {
                None => Ok(None),
                Some(resolved) => {
                    let token = crate::auth::user_session::create_session(
                        c,
                        &resolved.id,
                        Some(ip_for_session.as_str()),
                        30,
                    )?;
                    Ok(Some((resolved.id, token, resolved.claimed)))
                }
            }
        })
        .await;
    let (user_id, token) = match res {
        Ok(Some((uid, token, claimed))) => {
            // A1: a claim revoked prior sessions for this user — invalidate the
            // process-local auth cache so a cached attacker session self-rejects
            // immediately (mirrors the delete_user cascade hook, v1.35).
            if claimed {
                state.auth_cache.clear_user(&uid);
            }
            (uid, token)
        }
        Ok(None) => {
            audit_oauth_failure(
                &state,
                &tid,
                &provider_name,
                Some(&user.email),
                "oauth_not_allowed",
            )
            .await;
            return redirect_with_fragment_error(&frontend_uri, "oauth_not_allowed", &tid);
        }
        Err(e) => {
            tracing::error!(
                tenant = %tid,
                error = %e,
                "user create / session insert failed"
            );
            audit_oauth_failure(
                &state,
                &tid,
                &provider_name,
                Some(&user.email),
                "oauth_session_error",
            )
            .await;
            return redirect_with_fragment_error(&frontend_uri, "oauth_session_error", &tid);
        }
    };

    // Step 9: audit success row.
    audit_oauth_success(&state, &tid, &provider_name, &user_id, &user.email).await;

    // Step 10: 302 to frontend with success fragment.
    const THIRTY_DAYS_SECS: u64 = 30 * 86400;
    redirect_with_fragment_success(&frontend_uri, &token, THIRTY_DAYS_SECS, &tid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_attrs_includes_drust_t_prefix() {
        let s = cookie_attrs("tid-1", true);
        assert!(s.contains("Path=/drust/t/tid-1/oauth/"), "{s}");
        assert!(s.contains("Secure"), "{s}");
        assert!(s.contains("HttpOnly"), "{s}");
        assert!(s.contains("SameSite=Lax"), "{s}");
        assert!(s.contains("Max-Age=300"), "{s}");
    }

    #[test]
    fn cookie_attrs_skips_secure_in_dev() {
        let s = cookie_attrs("tid-1", false);
        assert!(!s.contains("Secure"), "{s}");
        // But path/HttpOnly/SameSite still present
        assert!(s.contains("Path=/drust/t/tid-1/oauth/"), "{s}");
        assert!(s.contains("HttpOnly"), "{s}");
    }

    #[test]
    fn secure_from_headers_https() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(secure_from_headers(&h));
    }

    #[test]
    fn secure_from_headers_http_no() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!secure_from_headers(&h));
    }

    #[test]
    fn secure_from_headers_missing_defaults_false() {
        let h = axum::http::HeaderMap::new();
        assert!(!secure_from_headers(&h));
    }

    fn users_db() -> rusqlite::Connection {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE _system_users (id TEXT PRIMARY KEY, email TEXT, password_hash TEXT, \
             verified INTEGER, profile TEXT, created_at TEXT, updated_at TEXT);",
        )
        .unwrap();
        c.execute_batch(crate::db::migrations::SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS)
            .unwrap();
        c
    }

    #[test]
    fn oauth_claims_unverified_password_account() {
        let c = users_db();
        // Attacker pre-seeded a password account for the victim email (verified=0).
        c.execute(
            "INSERT INTO _system_users (id,email,password_hash,verified,created_at,updated_at) \
             VALUES ('u-att','victim@x.com','$argon2-attacker$',0,'2026','2026')",
            [],
        )
        .unwrap();
        crate::auth::user_session::create_session(&c, "u-att", None, 30).unwrap();

        let r = find_or_create_user(&c, "victim@x.com", Some("V"), None, false)
            .unwrap()
            .expect("match");
        assert_eq!(r.id, "u-att");
        assert!(r.claimed, "unverified password account must be claimed");

        let (ph, verified): (String, i64) = c
            .query_row(
                "SELECT password_hash, verified FROM _system_users WHERE id='u-att'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            crate::auth::oauth_sentinel::is_oauth_only(&ph),
            "password wiped to oauth-only sentinel"
        );
        assert_eq!(verified, 1);
        let n: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM _system_sessions WHERE user_id='u-att'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "prior sessions revoked on claim");
    }

    #[test]
    fn oauth_links_sentinel_account_without_claim() {
        let c = users_db();
        c.execute(
            "INSERT INTO _system_users (id,email,password_hash,verified,created_at,updated_at) \
             VALUES ('u-o','u@x.com',?1,1,'2026','2026')",
            [crate::auth::oauth_sentinel::OAUTH_ONLY_SENTINEL],
        )
        .unwrap();
        let r = find_or_create_user(&c, "u@x.com", None, None, false)
            .unwrap()
            .expect("match");
        assert_eq!(r.id, "u-o");
        assert!(!r.claimed, "oauth-only row links as-is, no claim");
    }

    #[test]
    fn oauth_no_match_no_self_register_returns_none() {
        let c = users_db();
        assert!(
            find_or_create_user(&c, "nobody@x.com", None, None, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fragment_redirect_with_control_char_frontend_yields_500_not_panic() {
        // A pre-patch allowlisted frontend carrying a control byte can't form a
        // valid Location header — must degrade to a graceful 500, not panic.
        let resp =
            redirect_with_fragment_error("https://app/cb\u{0001}", "oauth_provider_error", "t1");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

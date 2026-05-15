//! Per-tenant OAuth start + callback handlers. End users of a tenant's
//! application sign in via Google/GitHub and receive a `drust_user_*`
//! bearer token (the v1.9 user-session shape). Token delivery is via
//! URL fragment to the frontend's redirect_uri (Supabase/Auth0 pattern).

use crate::oauth::{
    github::GitHubAdapter,
    google::GoogleAdapter,
    provider::OauthProvider,
    state as oauth_state,
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
fn redirect_with_fragment_error(frontend: &str, code: &str, tid: &str) -> Response {
    let loc = format!("{frontend}#error={code}");
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, loc)
        .header(header::SET_COOKIE, clear_cookie(STATE_COOKIE, tid))
        .header(header::SET_COOKIE, clear_cookie(PKCE_COOKIE, tid))
        .header(header::SET_COOKIE, clear_cookie(REDIRECT_URI_COOKIE, tid))
        .body(axum::body::Body::empty())
        .unwrap()
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
pub(crate) const REDIRECT_URI_COOKIE: &str = "drust_t_oauth_redirect_uri";
pub(crate) const COOKIE_TTL_SECS: i64 = 300;

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
    h.get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
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

/// Same as `plain_text` but also clears the three OAuth cookies. Used by
/// `/callback` steps 1-4 (pre-validation failures) so a stale cookie
/// triple isn't carried across browser retries.
fn plain_text_clear_cookies(status: StatusCode, body: &str, tid: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::SET_COOKIE, clear_cookie(STATE_COOKIE, tid))
        .header(header::SET_COOKIE, clear_cookie(PKCE_COOKIE, tid))
        .header(header::SET_COOKIE, clear_cookie(REDIRECT_URI_COOKIE, tid))
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
    if !cfg.allowed_redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return plain_text(StatusCode::BAD_REQUEST, "oauth_invalid_redirect");
    }

    let csrf_state = oauth_state::issue_state();
    let (pkce_verifier, pkce_challenge) = oauth_state::issue_pkce();

    if state.public_url.is_empty() {
        return plain_text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DRUST_PUBLIC_URL not set",
        );
    }
    let drust_callback =
        format!("{pu}/drust/t/{tid}/oauth/{provider_name}/callback", pu = state.public_url);

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
        .header(
            header::SET_COOKIE,
            set_cookie(REDIRECT_URI_COOKIE, &q.redirect_uri, &tid, secure),
        )
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn audit_oauth_success(
    state: &TenantAuthState,
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
    crate::safety::audit::write_entry(state.audit.log_dir(), &entry).await;
}

async fn audit_oauth_failure(
    state: &TenantAuthState,
    tid: &str,
    provider: &str,
    email: Option<&str>,
    error_code: &str,
) {
    let op = format!("GET /t/{tid}/oauth/{provider}/callback");
    let mut entry =
        crate::safety::audit::AuditEntry::failure(tid, "-", &op, 0, "HTTP_400", "")
            .with_extra(serde_json::json!({ "auth_kind": "user" }));
    entry.auth_method = Some(format!("oauth_{provider}"));
    entry.oauth_email = email.map(sanitize_email);
    entry.oauth_error_code = Some(error_code.to_string());
    crate::safety::audit::write_entry(state.audit.log_dir(), &entry).await;
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
    let loc = format!(
        "{frontend}#access_token={token}&token_type=Bearer&expires_in={expires_in_secs}"
    );
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, loc)
        .header(header::SET_COOKIE, clear_cookie(STATE_COOKIE, tid))
        .header(header::SET_COOKIE, clear_cookie(PKCE_COOKIE, tid))
        .header(header::SET_COOKIE, clear_cookie(REDIRECT_URI_COOKIE, tid))
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Look up `_system_users.id` by case-insensitive email match, or auto-create
/// a row when `allow_self_register` is true. Returns `Ok(None)` to signal the
/// caller should render `oauth_not_allowed` (existing row absent, self-register
/// disabled). OAuth-only users carry the sentinel password hash so the password
/// login path short-circuits before reaching argon2. `name` and `picture` land
/// in the `profile` JSON column under `"name"` / `"picture"` keys (spec §3.3).
fn find_or_create_user(
    conn: &rusqlite::Connection,
    email: &str,
    name: Option<&str>,
    picture: Option<&str>,
    allow_self_register: bool,
) -> rusqlite::Result<Option<String>> {
    use rusqlite::OptionalExtension;
    let existing: Option<String> = conn
        .query_row(
            "SELECT id FROM _system_users WHERE email = ?1 COLLATE NOCASE",
            [email],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(id) = existing {
        return Ok(Some(id));
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
    Ok(Some(new_id))
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
            return plain_text_clear_cookies(
                StatusCode::BAD_REQUEST,
                "oauth_misconfigured",
                &tid,
            );
        }
        Err(_) => {
            return plain_text_clear_cookies(
                StatusCode::INTERNAL_SERVER_ERROR,
                "db error",
                &tid,
            );
        }
    };

    // Step 2: state cookie matches query state (constant-time).
    let cookie_state = parse_cookie(&headers, STATE_COOKIE).unwrap_or_default();
    if !crate::oauth::state::verify_state(&cookie_state, &q.state) {
        return plain_text_clear_cookies(
            StatusCode::BAD_REQUEST,
            "oauth_state_mismatch",
            &tid,
        );
    }

    // Step 3: PKCE verifier present.
    let pkce_verifier = parse_cookie(&headers, PKCE_COOKIE).unwrap_or_default();
    if pkce_verifier.is_empty() {
        return plain_text_clear_cookies(
            StatusCode::BAD_REQUEST,
            "oauth_state_mismatch",
            &tid,
        );
    }

    // Step 4: frontend redirect_uri cookie present AND still in allowlist
    // (TOCTOU guard: admin may have shrunk allowlist between /start and /callback).
    let frontend_uri = parse_cookie(&headers, REDIRECT_URI_COOKIE).unwrap_or_default();
    if frontend_uri.is_empty()
        || !cfg
            .allowed_redirect_uris
            .iter()
            .any(|u| u == &frontend_uri)
    {
        return plain_text_clear_cookies(
            StatusCode::BAD_REQUEST,
            "oauth_invalid_redirect",
            &tid,
        );
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
    let drust_callback =
        format!("{pu}/drust/t/{tid}/oauth/{provider_name}/callback", pu = state.public_url);
    let adapter = match build_adapter(&state, &cfg) {
        Some(a) => a,
        None => {
            return plain_text_clear_cookies(
                StatusCode::BAD_REQUEST,
                "oauth_misconfigured",
                &tid,
            );
        }
    };
    let user = match adapter.exchange(&q.code, &pkce_verifier, &drust_callback).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                tenant = %tid,
                provider = %provider_name,
                error = %e,
                "oauth exchange failed"
            );
            // Email not yet known — pass None.
            audit_oauth_failure(&state, &tid, &provider_name, None, "oauth_provider_error")
                .await;
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
    let res: rusqlite::Result<Option<(String, String)>> = pool
        .with_writer(move |c| {
            match find_or_create_user(
                c,
                &email_for_lookup,
                name_for_lookup.as_deref(),
                picture_for_lookup.as_deref(),
                allow_self_register,
            )? {
                None => Ok(None),
                Some(uid) => {
                    let token = crate::auth::user_session::create_session(
                        c,
                        &uid,
                        Some(ip_for_session.as_str()),
                        30,
                    )?;
                    Ok(Some((uid, token)))
                }
            }
        })
        .await;
    let (user_id, token) = match res {
        Ok(Some(pair)) => pair,
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
}

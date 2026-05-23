//! Admin-specific OAuth glue. Calls into src/oauth/ (provider-agnostic
//! library) and turns a VerifiedUser into an admin session.

use crate::auth::middleware::build_session_cookie;
use crate::auth::session::create_session;
use crate::mgmt::routes::MgmtState;
use crate::oauth::state as oauth_state;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum_extra::extract::CookieJar;
use serde::Deserialize;

pub(crate) fn secure_from_headers(h: &HeaderMap) -> bool {
    h.get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
}

fn redirect_login_error(err: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, format!("/drust/login?oauth_error={err}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

pub async fn oauth_start(
    Path(provider): Path<String>,
    State(s): State<MgmtState>,
    headers: HeaderMap,
) -> Response {
    let Some(p) = s.oauth_registry.get(&provider) else {
        return redirect_login_error("oauth_misconfigured");
    };
    if s.public_url.is_empty() {
        return redirect_login_error("oauth_misconfigured");
    }

    let state = oauth_state::issue_state();
    let (verifier, challenge) = oauth_state::issue_pkce();
    let redirect_uri = format!("{}/drust/admin/oauth/{}/callback", s.public_url, provider);
    let auth_url = p.authorize_url(&state, &challenge, &redirect_uri);

    let secure = secure_from_headers(&headers);
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, auth_url)
        .header(
            header::SET_COOKIE,
            oauth_state::state_cookie(&state, secure).to_string(),
        )
        .header(
            header::SET_COOKIE,
            oauth_state::pkce_cookie(&verifier, secure).to_string(),
        )
        .body(axum::body::Body::empty())
        .unwrap()
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn oauth_callback(
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
    cookies: CookieJar,
    headers: HeaderMap,
    State(s): State<MgmtState>,
) -> Response {
    // v1.19.2 — per-IP rate limit. Same shape as tenant oauth_callback.
    let fallback_addr: std::net::SocketAddr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);
    if !s.admin_oauth_callback_rl.check(ip) {
        audit_oauth_failure(&s, &provider, None, "rate_limited").await;
        return redirect_login_error("rate_limited");
    }
    // 1. provider exists
    let Some(p) = s.oauth_registry.get(&provider) else {
        return redirect_login_error("oauth_misconfigured");
    };
    // 2. state match
    let cookie_state = cookies
        .get(oauth_state::STATE_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if !oauth_state::verify_state(&cookie_state, &q.state) {
        return redirect_login_error("oauth_state_mismatch");
    }
    // 3. PKCE verifier from cookie
    let verifier = cookies
        .get(oauth_state::PKCE_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if verifier.is_empty() {
        return redirect_login_error("oauth_state_mismatch");
    }
    // 4. exchange
    let redirect_uri = format!("{}/drust/admin/oauth/{}/callback", s.public_url, provider);
    let user = match p.exchange(&q.code, &verifier, &redirect_uri).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(provider, "oauth exchange failed: {e}");
            return redirect_login_error("oauth_provider_error");
        }
    };
    // 5. verified
    if !user.email_verified {
        audit_oauth_failure(&s, &provider, Some(&user.email), "oauth_email_unverified").await;
        return redirect_login_error("oauth_email_unverified");
    }
    // 6. allowlist
    if !s.oauth_allowlist.contains(&user.email) {
        audit_oauth_failure(&s, &provider, Some(&user.email), "oauth_not_allowed").await;
        return redirect_login_error("oauth_not_allowed");
    }
    // 7. admin row + 8. session — both touch the meta connection, so hold
    // the mutex for both. Matches the locking shape of `login_submit` in
    // src/mgmt/routes.rs.
    let mut conn = s.meta.lock().await;
    let admin_id = match crate::storage::meta::find_admin_id_by_email(&conn, &user.email) {
        Ok(Some(id)) => id,
        Ok(None) => {
            drop(conn);
            audit_oauth_failure(&s, &provider, Some(&user.email), "oauth_admin_email_missing")
                .await;
            return redirect_login_error("oauth_admin_email_missing");
        }
        Err(e) => {
            drop(conn);
            tracing::error!("admin lookup failed: {e}");
            return redirect_login_error("oauth_provider_error");
        }
    };
    let ttl_secs = (s.session_ttl_days * 86_400) as i64;
    let token = match create_session(&mut conn, admin_id, ttl_secs) {
        Ok(t) => t,
        Err(e) => {
            drop(conn);
            tracing::error!("session create failed: {e}");
            return redirect_login_error("oauth_provider_error");
        }
    };
    // v1.22 — read persisted locale before dropping the conn so the SET_COOKIE
    // below can mirror DB → cookie for the new device. Missing column / NULL
    // / unknown value all skip the cookie write (Accept-Language fallback).
    // v1.23 — same pattern for `theme`; merged into one query.
    let (admin_locale, admin_theme): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT locale, theme FROM admins WHERE id = ?1",
            rusqlite::params![admin_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or((None, None));
    drop(conn);
    let session_cookie = build_session_cookie(&token, s.session_ttl_days * 86_400);
    audit_oauth_success(&s, &provider, &user.email, admin_id).await;

    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, "/drust/admin/tenants")
        .header(header::SET_COOKIE, session_cookie)
        .header(
            header::SET_COOKIE,
            oauth_state::clear_state_cookie().to_string(),
        )
        .header(
            header::SET_COOKIE,
            oauth_state::clear_pkce_cookie().to_string(),
        );
    if let Some(loc) = admin_locale.as_deref()
        && matches!(loc, "en" | "zh-TW")
    {
        builder = builder.header(
            header::SET_COOKIE,
            format!("drust_locale={loc}; Path=/; Max-Age=31536000; SameSite=Lax"),
        );
    }
    if let Some(th) = admin_theme.as_deref()
        && crate::mgmt::theme::Theme::from_tag(th).is_some()
    {
        builder = builder.header(
            header::SET_COOKIE,
            format!("drust_theme={th}; Path=/; Max-Age=31536000; SameSite=Lax"),
        );
    }
    builder.body(axum::body::Body::empty()).unwrap()
}

async fn audit_oauth_success(s: &MgmtState, provider: &str, email: &str, admin_id: i64) {
    let op = format!("GET /admin/oauth/{provider}/callback");
    let mut entry = crate::safety::audit::AuditEntry::success("-", "-", &op, 0)
        .with_extra(serde_json::json!({ "admin_id": admin_id, "auth_kind": "admin" }));
    entry.auth_method = Some(format!("oauth_{provider}"));
    entry.oauth_email = Some(sanitize_email(email));
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
}

async fn audit_oauth_failure(s: &MgmtState, provider: &str, email: Option<&str>, code: &str) {
    let op = format!("GET /admin/oauth/{provider}/callback");
    let mut entry = crate::safety::audit::AuditEntry::failure("-", "-", &op, 0, "HTTP_403", "")
        .with_extra(serde_json::json!({ "auth_kind": "admin" }));
    entry.auth_method = Some(format!("oauth_{provider}"));
    entry.oauth_email = email.map(sanitize_email);
    entry.oauth_error_code = Some(code.to_string());
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;
}

fn sanitize_email(s: &str) -> String {
    if crate::bin_helpers::validate_email(s) {
        s.to_lowercase()
    } else {
        "<invalid>".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn secure_from_xff_https_yes() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(secure_from_headers(&h));
    }

    #[test]
    fn secure_from_xff_http_no() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!secure_from_headers(&h));
    }

    #[test]
    fn secure_no_xff_defaults_false() {
        let h = HeaderMap::new();
        assert!(!secure_from_headers(&h));
    }
}

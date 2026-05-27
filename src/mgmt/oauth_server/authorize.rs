//! OAuth 2.1 /authorize endpoint — GET (consent screen) + POST (code issuance).
//!
//! Both GET and POST live in the `public` router scope (no automatic
//! admin_session_layer 302). The GET handler checks for an admin session
//! manually: if absent it sets the `drust_oauth_intent` cookie and
//! bounces to /drust/login; if present it renders the consent page.
//! The POST handler also checks manually and returns 401 if no session
//! (a member of the public cannot approve consent on someone else's behalf).

use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use rusqlite::params;
use serde::Deserialize;

use crate::auth::session::validate_session;
use crate::error::json_error;
use crate::mgmt::admin_profile::{load_admin_profile, AdminProfileExt};
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::oauth_server::{return_url, storage};
use crate::mgmt::routes::MgmtState;
use crate::mgmt::theme::ThemeHint;
use crate::safety::audit::AuditEntry;

// ─── request / form types ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: Option<String>,
    pub resource: String,
    pub scope: Option<String>,
}

#[derive(Deserialize)]
pub struct ConsentForm {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: Option<String>,
    pub resource: String,
    pub scope: Option<String>,
    pub decision: String,
}

// ─── template ────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "oauth_consent.html")]
struct ConsentPage {
    version: &'static str,
    t: Translator,
    admin: AdminProfileExt,
    client_name: String,
    resource_uri: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: String,
    scope: String,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn validate_resource_uri(uri: &str) -> bool {
    // Must look like http(s)://host/drust/t/<id>/mcp or /drust/t/<id>/mcp/...
    let re =
        regex_lite::Regex::new(r"^https?://[^/]+/drust/t/[^/]+/mcp(/|$)").unwrap();
    re.is_match(uri)
}

fn error_redirect(redirect_uri: &str, error_code: &str, state: Option<&str>) -> Response {
    let location = format!(
        "{redirect_uri}?error={}&state={}",
        urlencoding::encode(error_code),
        urlencoding::encode(state.unwrap_or("")),
    );
    Redirect::to(&location).into_response()
}

/// Extract and validate the admin session cookie, returning the admin_id if
/// the session is valid. Used instead of `admin_session_layer` so the /oauth/
/// authorize routes can live in the `public` scope and do their own
/// session-absent handling (intent cookie + redirect to /login rather than
/// the unconditional 302 from admin_session_layer).
async fn resolve_admin(
    s: &MgmtState,
    headers: &axum::http::HeaderMap,
) -> Option<(i64, AdminProfileExt)> {
    use crate::auth::middleware::SESSION_COOKIE;
    let raw_cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let token = raw_cookie.split(';').find_map(|part| {
        let p = part.trim();
        p.strip_prefix(&format!("{SESSION_COOKIE}="))
            .map(|v| v.to_string())
    })?;
    let conn = s.meta.lock().await;
    let admin_id = validate_session(&conn, &token).ok().flatten()?;
    let profile = load_admin_profile(&conn, admin_id)
        .ok()
        .flatten()
        .unwrap_or_else(AdminProfileExt::placeholder);
    Some((admin_id, profile))
}

// ─── GET /oauth/authorize ────────────────────────────────────────────────────

pub async fn authorize_get(
    State(s): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    headers: axum::http::HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    // 1. response_type must be "code"
    if q.response_type != "code" {
        return error_redirect(
            &q.redirect_uri,
            "unsupported_response_type",
            q.state.as_deref(),
        );
    }
    // 2. PKCE method must be S256
    if q.code_challenge_method != "S256" {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PKCE",
            "code_challenge_method must be S256",
        );
    }
    // 3. resource must look like /drust/t/<id>/mcp
    if !validate_resource_uri(&q.resource) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_RESOURCE",
            "resource must point to a drust MCP endpoint",
        );
    }
    // 4. client exists + redirect_uri is registered
    let row: Option<(String, String)> = {
        let conn = s.meta.lock().await;
        conn.query_row(
            "SELECT client_name, redirect_uris_json FROM _oauth_clients WHERE id = ?1 AND revoked_at IS NULL",
            params![&q.client_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()
    };
    let (client_name, allowed_uris_json) = match row {
        Some(r) => r,
        None => return json_error(StatusCode::BAD_REQUEST, "INVALID_CLIENT", "no such client"),
    };
    let allowed: Vec<String> = serde_json::from_str(&allowed_uris_json).unwrap_or_default();
    if !allowed.iter().any(|u| u == &q.redirect_uri) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REDIRECT_URI",
            "redirect_uri not registered for this client",
        );
    }

    // 5. Check admin session — if absent, bounce through /login with intent cookie
    let maybe_admin = resolve_admin(&s, &headers).await;
    if maybe_admin.is_none() {
        let intent_path = format!(
            "/oauth/authorize?response_type=code&client_id={cid}&redirect_uri={ru}&code_challenge={cc}&code_challenge_method=S256&state={st}&resource={rs}&scope={sc}",
            cid = urlencoding::encode(&q.client_id),
            ru  = urlencoding::encode(&q.redirect_uri),
            cc  = urlencoding::encode(&q.code_challenge),
            st  = urlencoding::encode(q.state.as_deref().unwrap_or("")),
            rs  = urlencoding::encode(&q.resource),
            sc  = urlencoding::encode(q.scope.as_deref().unwrap_or("drust")),
        );
        let secure = std::env::var("DRUST_DEV_NO_SECURE_COOKIES").is_err();
        let mut resp = Redirect::to("/drust/login").into_response();
        resp.headers_mut().append(
            axum::http::header::SET_COOKIE,
            return_url::build_set(&intent_path, secure).parse().unwrap(),
        );
        return resp;
    }

    let (_admin_id, admin) = maybe_admin.unwrap();

    // 6. Render consent page
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        ConsentPage {
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            admin,
            client_name,
            resource_uri: q.resource.clone(),
            client_id: q.client_id,
            redirect_uri: q.redirect_uri,
            code_challenge: q.code_challenge,
            code_challenge_method: q.code_challenge_method,
            state: q.state.unwrap_or_default(),
            scope: q.scope.unwrap_or_else(|| "drust".into()),
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

// ─── POST /oauth/authorize ────────────────────────────────────────────────────

pub async fn authorize_post(
    State(s): State<MgmtState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    // Require admin session — a member of the public must not be able to
    // approve consent on behalf of an admin.
    let maybe_admin = resolve_admin(&s, &headers).await;
    let (admin_id, _profile) = match maybe_admin {
        Some(pair) => pair,
        None => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHENTICATED",
                "admin session required to approve OAuth consent",
            );
        }
    };

    if form.decision != "approve" {
        return error_redirect(&form.redirect_uri, "access_denied", form.state.as_deref());
    }

    let code = storage::new_auth_code();
    let code_hash = storage::sha256_b64(&code);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    let expires_at_str = expires_at
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let db_result: Result<(), Response> = {
        let conn = s.meta.lock().await;
        // Re-validate client (TOCTOU guard)
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT client_name, redirect_uris_json FROM _oauth_clients WHERE id = ?1 AND revoked_at IS NULL",
                params![&form.client_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let Some((_, uris_json)) = row else {
            return json_error(
                StatusCode::BAD_REQUEST,
                "INVALID_CLIENT",
                "client gone or revoked",
            );
        };
        let allowed: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();
        if !allowed.iter().any(|u| u == &form.redirect_uri) {
            return json_error(
                StatusCode::BAD_REQUEST,
                "INVALID_REDIRECT_URI",
                "redirect_uri mismatch",
            );
        }
        if let Err(e) = conn.execute(
            "INSERT INTO _oauth_authorization_codes
                (code_hash, client_id, admin_id, redirect_uri, pkce_challenge, pkce_challenge_method,
                 resource_uri, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &code_hash,
                &form.client_id,
                admin_id,
                &form.redirect_uri,
                &form.code_challenge,
                &form.code_challenge_method,
                &form.resource,
                form.scope.as_deref(),
                &expires_at_str,
            ],
        ) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            );
        }
        Ok(())
    };
    if let Err(r) = db_result {
        return r;
    }

    let entry = AuditEntry::success("-", "-", "admin.oauth.consent", 0).with_extra(
        serde_json::json!({
            "client_id": &form.client_id,
            "actor_admin_id": admin_id,
            "resource_uri": &form.resource,
        }),
    );
    crate::safety::audit::write_entry(&s.log_dir, &entry).await;

    let state_param = form.state.as_deref().unwrap_or("");
    let location = format!(
        "{}?code={}&state={}",
        form.redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(state_param),
    );
    Redirect::to(&location).into_response()
}

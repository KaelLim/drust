//! OAuth-providers admin page (group E). Relocated from `tenants.rs` by Finding #4.

use super::TenantsState;
use super::common;
use crate::mgmt::i18n::{Locale, LocaleHint, Translator};
use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};

// ─── v1.12: per-tenant OAuth providers admin UI ──────────────────────────────

#[derive(Template)]
#[template(path = "tenant_oauth_providers.html")]
struct TenantOauthProvidersPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    providers: Vec<TenantOauthProviderRow>,
    /// Driver list for `_collection_sidebar.html`.
    collections: Vec<crate::storage::schema::Collection>,
    /// Always `"_oauth_providers"` here — sidebar `.on` matching.
    active_coll: String,
    /// Surfaced after a failed upsert (validation / DB error). `None`
    /// on the plain GET render.
    error: Option<String>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

struct TenantOauthProviderRow {
    provider: String,
    client_id: String,
    /// First 12 chars + ellipsis when long enough; otherwise full id.
    client_id_short: String,
    allowed_redirect_uris: Vec<String>,
    /// Newline-joined `allowed_redirect_uris`, for the inline edit textarea.
    allowed_redirect_uris_text: String,
    updated_at: String,
}

impl TenantOauthProviderRow {
    fn from_config(cfg: crate::tenant::oauth_config::OauthProviderConfig) -> Self {
        let client_id_short = if cfg.client_id.chars().count() > 16 {
            let truncated: String = cfg.client_id.chars().take(12).collect();
            format!("{truncated}…")
        } else {
            cfg.client_id.clone()
        };
        let allowed_redirect_uris_text = cfg.allowed_redirect_uris.join("\n");
        Self {
            provider: cfg.provider,
            client_id: cfg.client_id,
            client_id_short,
            allowed_redirect_uris: cfg.allowed_redirect_uris,
            allowed_redirect_uris_text,
            updated_at: cfg.updated_at,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct OauthProviderUpsertForm {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    /// Newline-separated list — the handler splits + trims + drops empties.
    pub allowed_redirect_uris: String,
}

/// Render the page. Internal helper so the upsert handler can surface an
/// error inline without an extra round-trip.
async fn render_oauth_providers_page(
    state: &TenantsState,
    tenant_id: String,
    error: Option<String>,
    locale: Locale,
    theme: crate::mgmt::theme::Theme,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
) -> Response {
    let (tenant_name, collections) = match common::load_tenant_shell(state, &tenant_id).await {
        Ok(t) => t,
        Err(r) => return r,
    };

    // Read the providers via the shared pool's reader (consistent with the
    // REST admin endpoints, and uses the same connection cache).
    let providers: Vec<TenantOauthProviderRow> = match state.tenants.get_or_open(&tenant_id) {
        Ok(pool) => match pool.with_reader(crate::tenant::oauth_config::list).await {
            Ok(rows) => rows
                .into_iter()
                .map(TenantOauthProviderRow::from_config)
                .collect(),
            Err(_) => vec![],
        },
        Err(_) => vec![],
    };

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantOauthProvidersPage {
            version: env!("CARGO_PKG_VERSION"),
            tenant_id,
            tenant_name,
            providers,
            collections,
            active_coll: "_oauth_providers".to_string(),
            error,
            t: Translator::new(locale),
            admin,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// `GET /admin/tenants/{id}/_oauth_providers`
pub async fn tenant_oauth_providers_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
) -> Response {
    render_oauth_providers_page(&state, tenant_id, None, locale, theme, admin).await
}

/// `POST /admin/tenants/{id}/_oauth_providers` — upsert. Splits the
/// textarea on newline, trims, drops empties, then calls the same
/// `oauth_config::upsert` helper the REST admin endpoint uses. On error
/// re-renders the page with the validation message in the inline banner;
/// on success 303s back to the GET so a refresh doesn't resubmit.
pub async fn tenant_oauth_provider_upsert(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
    Form(form): Form<OauthProviderUpsertForm>,
) -> Response {
    // Guard FIRST: a missing/soft-deleted tenant must not be re-materialised
    // by the writer-mutex below via get_or_open → open_write → create_dir_all.
    // GET path runs the same check via load_tenant_shell; DELETE and the
    // upsert error-leg need it too.
    if let Some(r) = common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }

    let uris: Vec<String> = form
        .allowed_redirect_uris
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Pre-validate so we can show the message inline without ever opening
    // the writer mutex.
    if let Err(e) = crate::tenant::oauth_config::validate_upsert(
        &form.provider,
        &form.client_id,
        &form.client_secret,
        &uris,
    ) {
        return render_oauth_providers_page(
            &state,
            tenant_id,
            Some(e.to_string()),
            locale,
            theme,
            admin.clone(),
        )
        .await;
    }

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };
    let provider = form.provider.clone();
    let client_id = form.client_id.clone();
    let client_secret = form.client_secret.clone();
    let uris_owned = uris.clone();
    let res: Result<(), String> = pool
        .with_writer(move |c| {
            crate::tenant::oauth_config::upsert(
                c,
                &provider,
                &client_id,
                &client_secret,
                &uris_owned,
            )
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
        })
        .await
        .map_err(|e| e.to_string());

    match res {
        Ok(()) => Redirect::to(&crate::base_path::base(&format!(
            "/admin/tenants/{tenant_id}/_oauth_providers"
        )))
        .into_response(),
        Err(msg) => {
            render_oauth_providers_page(&state, tenant_id, Some(msg), locale, theme, admin).await
        }
    }
}

/// `POST /admin/tenants/{id}/_oauth_providers/{provider}/delete` —
/// idempotent delete. Always redirects back to the list (no error banner
/// needed; the row simply disappears).
pub async fn tenant_oauth_provider_delete(
    State(state): State<TenantsState>,
    Path((tenant_id, provider)): Path<(String, String)>,
) -> Response {
    // Guard FIRST: a missing/soft-deleted tenant must not be re-materialised
    // by get_or_open → open_write → create_dir_all. GET path runs the same
    // check via load_tenant_shell.
    if let Some(r) = common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    if let Ok(pool) = state.tenants.get_or_open(&tenant_id) {
        let provider2 = provider.clone();
        let _ = pool
            .with_writer(move |c| crate::tenant::oauth_config::delete(c, &provider2))
            .await;
    }
    Redirect::to(&crate::base_path::base(&format!(
        "/admin/tenants/{tenant_id}/_oauth_providers"
    )))
    .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub struct OauthRedirectUrisForm {
    /// Newline-separated — split + trim + drop empties (same as the upsert form).
    pub allowed_redirect_uris: String,
}

/// `POST /admin/tenants/{id}/_oauth_providers/{provider}/redirect-uris` —
/// update ONLY the redirect URIs for an existing provider (no secret).
/// Mirrors `tenant_oauth_provider_upsert`: inline error banner on failure,
/// 303 back to the page on success.
pub async fn tenant_oauth_redirect_uris_update(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path((tenant_id, provider)): Path<(String, String)>,
    Form(form): Form<OauthRedirectUrisForm>,
) -> Response {
    if let Some(r) = common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    let uris: Vec<String> = form
        .allowed_redirect_uris
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if uris.is_empty() {
        return render_oauth_providers_page(
            &state,
            tenant_id,
            Some(crate::tenant::oauth_config::OauthConfigError::EmptyRedirectUris.to_string()),
            locale,
            theme,
            admin,
        )
        .await;
    }
    for u in &uris {
        if let Err(e) = crate::tenant::oauth_config::validate_redirect_uri(u) {
            return render_oauth_providers_page(
                &state,
                tenant_id,
                Some(e.to_string()),
                locale,
                theme,
                admin,
            )
            .await;
        }
    }

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };
    let provider2 = provider.clone();
    let uris_owned = uris.clone();
    let res: Result<bool, String> = pool
        .with_writer(move |c| {
            crate::tenant::oauth_config::update_redirect_uris(c, &provider2, &uris_owned)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
        })
        .await
        .map_err(|e| e.to_string());

    match res {
        Ok(true) => Redirect::to(&crate::base_path::base(&format!(
            "/admin/tenants/{tenant_id}/_oauth_providers"
        )))
        .into_response(),
        Ok(false) => {
            render_oauth_providers_page(
                &state,
                tenant_id,
                Some("provider not configured".to_string()),
                locale,
                theme,
                admin,
            )
            .await
        }
        Err(msg) => {
            render_oauth_providers_page(&state, tenant_id, Some(msg), locale, theme, admin).await
        }
    }
}

//! v1.31.5 — Admin Broadcast Inspector page.
//!
//! GET /drust/admin/tenants/{id}/_broadcast
//!
//! Renders a single page that opens a WebSocket to the existing v1.31
//! multiplex endpoint at /t/{id}/realtime, lets the operator subscribe
//! to rooms, watch the live tail, and publish JSON payloads — all over
//! the unchanged v1.31 wire. Zero new tenant-facing endpoints. The
//! page also exposes a per-room [Evict] button that POSTs to the
//! v1.31.3 admin endpoint `/admin/tenants/{id}/realtime/rooms/{room}/evict`.
//!
//! Auth bridge: admin-session-gated (existing `admin_session_layer`).
//! The tenant's service bearer plaintext is server-injected into a
//! hidden form field via `tokens::read_slot(..., "service")`. JS opens
//! WS with `?token=$bearer` (which the existing `ws_query_token_adapter`
//! rewrites to an Authorization header upstream of bearer_auth_layer).
//!
//! Tokens minted before v1.1c stored only a hash; for those tenants we
//! render the page with a "regenerate service key" banner and the
//! Connect button disabled. Same idea `_api_keys` already handles for
//! its "copy" button.

use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use rusqlite::params;

use crate::mgmt::admin_profile::AdminProfileExt;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::tenants::TenantsState;
use crate::mgmt::theme::{ResolvedPalette, ThemeHint, ThemeRenderCtx};
use crate::storage::tenant_db::validate_tenant_id;

#[derive(Template)]
#[template(path = "tenant_broadcast.html")]
struct BroadcastInspectorPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    /// Browser-facing WS path with the mandatory `/drust` prefix
    /// (Caddy strips it before drust sees it; integration tests
    /// bypass Caddy via `oneshot` so the missing prefix bug would
    /// only show up in production — unit test #2 below pins the
    /// literal string).
    ws_path: String,
    /// Service bearer plaintext. Empty string when
    /// `bearer_missing == true`.
    bearer: String,
    /// True when the tenant's service token row has no plaintext
    /// (minted before v1.1c). Template branches on this flag rather
    /// than truthy-checking the bearer string.
    bearer_missing: bool,
    /// Sidebar `.on` matching — always `"_broadcast"`.
    active_coll: String,
    /// Collections list for the sidebar — empty Vec is fine.
    collections: Vec<crate::storage::schema::Collection>,
    /// JSON object literal of every i18n string the inline JS needs,
    /// pre-serialized via `serde_json` (handles `"`, `\`, non-ASCII)
    /// then post-processed to replace `</` with `<\/` so a stray
    /// `</script>` in a translation cannot break out of the surrounding
    /// `<script>` element. Embed via `const I18N = {{ i18n_js|safe }};`
    /// — `|safe` is sound by construction after both steps.
    i18n_js: String,
    t: Translator,
    admin: AdminProfileExt,
    palette_resolved: ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

impl BroadcastInspectorPage {
    /// Build the WS path string. Single source of truth for the
    /// cross-tenant invariant — `tenant_id` is the only interpolated
    /// segment. The `/drust` prefix is load-bearing (see module doc).
    fn build_ws_path(tenant_id: &str) -> String {
        format!("/drust/t/{}/realtime", tenant_id)
    }
}

/// `GET /admin/tenants/{id}/_broadcast`
pub async fn broadcast_inspector_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    axum::Extension(admin): axum::Extension<AdminProfileExt>,
    Path(tenant_id): Path<String>,
) -> Response {
    if validate_tenant_id(&tenant_id).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid tenant id").into_response();
    }

    // Meta lookup: tenant existence + service bearer plaintext.
    let (tenant_name, bearer_opt) = {
        let conn = state.session.meta.lock().await;
        let name: Option<String> = conn
            .query_row(
                "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
                params![tenant_id],
                |r| r.get(0),
            )
            .ok();
        let name = match name {
            Some(n) => n,
            None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        };
        let bearer_opt = crate::mgmt::tokens::read_slot(&conn, &tenant_id, "service")
            .and_then(|s| s.plaintext);
        (name, bearer_opt)
    };

    // Collections list for the sidebar. Failure (fresh tenant without
    // data.sqlite yet) is non-fatal — the sidebar still renders the
    // virtual entries.
    let collections = crate::storage::tenant_db::open_read(&state.data_dir, &tenant_id)
        .ok()
        .and_then(|c| crate::storage::schema::list_collections(&c).ok())
        .unwrap_or_default();

    let ws_path = BroadcastInspectorPage::build_ws_path(&tenant_id);
    let bearer_missing = bearer_opt.is_none();
    let bearer = bearer_opt.unwrap_or_default();
    let trc = ThemeRenderCtx::build(theme);

    // Pre-serialize every i18n string the inline JS reads into one JSON
    // object literal. Keeps the template simple (no `|json|safe` filter,
    // which would require askama's serde-json feature) and keeps each
    // value safe to embed verbatim into the JS source.
    let t_for_js = Translator::new(locale);
    let mut i18n_map = serde_json::Map::new();
    for (js_key, t_key) in [
        ("state_disconnected",    "broadcast_inspector.conn.state_disconnected"),
        ("state_connecting",      "broadcast_inspector.conn.state_connecting"),
        ("state_connected",       "broadcast_inspector.conn.state_connected"),
        ("state_bearer_rejected", "broadcast_inspector.conn.state_bearer_rejected"),
        ("state_unreachable",     "broadcast_inspector.conn.state_unreachable"),
        ("state_server_closed",   "broadcast_inspector.conn.state_server_closed"),
        ("btn_connect",           "broadcast_inspector.conn.btn_connect"),
        ("btn_disconnect",        "broadcast_inspector.conn.btn_disconnect"),
        ("btn_unsub",             "broadcast_inspector.subs.btn_unsub"),
        ("btn_evict",             "broadcast_inspector.subs.btn_evict"),
        ("btn_pause",             "broadcast_inspector.tail.btn_pause"),
        ("btn_resume",            "broadcast_inspector.tail.btn_resume"),
        ("payload_invalid",       "broadcast_inspector.publish.payload_invalid"),
        ("confirm_evict_tpl",     "broadcast_inspector.subs.confirm_evict"),
        ("counter_tpl",           "broadcast_inspector.publish.counter"),
        ("lagged_tpl",            "broadcast_inspector.tail.lagged_row"),
        ("paused_drop_tpl",       "broadcast_inspector.tail.paused_drop"),
        ("new_pill_tpl",          "broadcast_inspector.tail.new_pill"),
        ("self_tag",              "broadcast_inspector.tail.self_tag"),
        ("connected_tpl",         "broadcast_inspector.conn.state_connected"),
    ] {
        i18n_map.insert(
            js_key.to_string(),
            serde_json::Value::String(t_for_js.s(t_key).into_owned()),
        );
    }
    // Post-process `</` → `<\/` so a future translation containing
    // `</script>` cannot break out of the surrounding <script> element
    // (HTML5 §8.2.4.6: the script-data state terminates on any literal
    // `</script` regardless of JS string-literal context). serde_json
    // escapes `"`, `\`, and control chars but NOT `</`. With this line
    // the "safe to embed verbatim" claim on `i18n_js` is true by
    // construction, not by content audit of the TOML bundle.
    let i18n_js = serde_json::Value::Object(i18n_map)
        .to_string()
        .replace("</", r"<\/");

    let page = BroadcastInspectorPage {
        version: env!("CARGO_PKG_VERSION"),
        tenant_id,
        tenant_name,
        ws_path,
        bearer,
        bearer_missing,
        active_coll: "_broadcast".to_string(),
        collections,
        i18n_js,
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
mod tests {
    use super::*;

    #[test]
    fn ws_path_has_drust_prefix_and_tenant_segment() {
        let p = BroadcastInspectorPage::build_ws_path("alpha-tenant");
        assert_eq!(p, "/drust/t/alpha-tenant/realtime");
        assert!(
            p.starts_with("/drust/"),
            "WS path missing /drust prefix — Caddy strips it on the browser hop; \
             leaving it off gives 404. Path was: {p}"
        );
    }

    #[test]
    fn ws_path_does_not_leak_other_tenant_ids() {
        let p = BroadcastInspectorPage::build_ws_path("alpha");
        for forbidden in &[
            "beta",
            "00000000-0000-0000-0000-000000000000",
            "gamma-tenant",
        ] {
            assert!(
                !p.contains(forbidden),
                "WS path leaks unrelated tenant id `{forbidden}`: {p}"
            );
        }
    }

    #[test]
    fn bearer_missing_flag_independent_of_bearer_string() {
        // When the helper returns None, bearer_missing must be true AND
        // bearer must be empty — template branches on the flag.
        let bearer_opt: Option<String> = None;
        let bearer_missing = bearer_opt.is_none();
        let bearer = bearer_opt.unwrap_or_default();
        assert!(bearer_missing);
        assert_eq!(bearer, "");

        // When the helper returns Some(s), the inverse holds.
        let bearer_opt: Option<String> = Some("drust_service_test123".to_string());
        let bearer_missing = bearer_opt.is_none();
        let bearer = bearer_opt.unwrap_or_default();
        assert!(!bearer_missing);
        assert_eq!(bearer, "drust_service_test123");
    }

    /// Spec Testing/unit #1: the template payload struct round-trips
    /// fixture values into rendered HTML directly via `.render()`,
    /// without touching the meta DB, the tenant pool, the
    /// `tokens::read_slot` helper, or any handler-side env var. The
    /// integration tests already exercise the full handler stack;
    /// this is the focused, in-process regression for the template
    /// layer itself — flipping a field on the struct here is the
    /// cheapest possible signal that the askama template still
    /// compiles and still binds the load-bearing fields.
    ///
    /// (`Translator::new` internally calls `init_bundles()`, which
    /// is a `OnceLock::get_or_init` — that's a transitive dep of
    /// the i18n layer and unavoidable. The point of this test is
    /// that nothing else in the rendering path reaches outside the
    /// struct literal: no DB, no env, no process-wide state owned
    /// by `tenant_broadcast` itself.)
    #[test]
    fn render_roundtrips_fixture_struct_to_html_without_handler_state() {
        let tenant_id = "fixture-tenant-zzz";
        let bearer = "drust_service_fixture_BEARER";
        let ws_path = BroadcastInspectorPage::build_ws_path(tenant_id);
        let trc = ThemeRenderCtx::build(crate::mgmt::theme::Theme::System);

        let page = BroadcastInspectorPage {
            version: "test-version",
            tenant_id: tenant_id.to_string(),
            tenant_name: "Fixture Tenant".to_string(),
            ws_path: ws_path.clone(),
            bearer: bearer.to_string(),
            bearer_missing: false,
            active_coll: "_broadcast".to_string(),
            collections: Vec::new(),
            i18n_js: "{}".to_string(),
            t: Translator::new(crate::mgmt::i18n::Locale::En),
            admin: AdminProfileExt::placeholder(),
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        };

        let html = page.render().expect("template renders from struct alone");

        // Fixture tenant id appears in the rendered HTML at least once
        // (template binds it into ws-url, tenant-id-field, sidebar links).
        assert!(
            html.contains(tenant_id),
            "rendered HTML should bind the fixture tenant id; not found"
        );

        // The full /drust-prefixed ws path appears verbatim as the
        // hidden ws-url input's value — proves `build_ws_path` output
        // flows through the template unchanged.
        assert!(
            html.contains(&format!(
                r#"id="ws-url" value="/drust/t/{}/realtime""#,
                tenant_id
            )),
            "rendered HTML should bind the load-bearing /drust-prefixed ws path"
        );

        // Bearer plaintext appears inside the hidden bearer field.
        assert!(
            html.contains(&format!(r#"id="bearer-field" value="{}""#, bearer)),
            "rendered HTML should bind the fixture bearer into id=\"bearer-field\""
        );
    }
}

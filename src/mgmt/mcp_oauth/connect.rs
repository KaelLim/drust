//! The admin pages that help people connect Claude Code to the account-level
//! MCP endpoint: "Connect Claude Code" (`GET /admin/mcp`) and the owner-only
//! connection diagnostics (`GET /admin/mcp/diagnostics`).
//!
//! Both pages are mounted only while `McpOauthConfig::enabled()`. Every URL and
//! command they show is derived on the server from `McpOauthConfig` (and so
//! from the process-global base path); the browser never assembles one from
//! `window.location`. The handlers read nothing from the database.
//!
//! Commands are POSIX shell examples only: the single-quoted JSON of `add-json`
//! does not survive the Windows shells' quoting rules, which is why the
//! per-tenant UI dropped `add-json`. No command is built from a URL that a
//! POSIX shell would interpret (see `shell_safe`); the connect page then has
//! nothing to show.

use std::collections::HashSet;

use askama::Template;
use axum::Extension;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use crate::mcp::account::AccountMcp;
use crate::mgmt::admin_profile::AdminProfileExt;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::mcp_oauth::config::{DisabledReason, McpOauthConfig};
use crate::mgmt::routes::MgmtState;
use crate::mgmt::theme::{ResolvedPalette, Theme, ThemeHint, ThemeRenderCtx};

/// The commands the connect page prints, all derived from `resource_url()`.
pub struct ConnectCommands {
    pub resource_url: String,
    pub add: String,
    pub add_json: String,
    pub login: &'static str,
    pub list: &'static str,
    pub remove_old: &'static str,
    pub old_rule: &'static str,
    pub new_rule: &'static str,
    pub logout: &'static str,
    pub remove: &'static str,
    /// The `authServerMetadataUrl` fallback; `None` under an empty base path,
    /// where both discovery documents already sit at the host root.
    pub metadata_fallback: Option<String>,
}

/// Every byte is ASCII alphanumeric or one of . : / _ ~ -, so the URL can sit
/// unquoted in a POSIX shell command and inside the single-quoted JSON of
/// add-json. A DNS host name always passes; an IPv6 literal does not.
fn shell_safe(url: &str) -> bool {
    url.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".:/_~-".contains(&b))
}

/// `None` while disabled, and `None` when `resource_url()` or (base path set)
/// the `authServerMetadataUrl` carries a byte outside `[A-Za-z0-9.:/_~-]`.
pub fn connect_commands(cfg: &McpOauthConfig) -> Option<ConnectCommands> {
    if !cfg.enabled() {
        return None;
    }
    let resource_url = cfg.resource_url();
    if !shell_safe(&resource_url) {
        return None;
    }
    let metadata_fallback = if crate::base_path::base_path().is_empty() {
        None
    } else {
        let as_url = cfg.endpoint_url("/.well-known/oauth-authorization-server");
        if !shell_safe(&as_url) {
            return None;
        }
        Some(format!(
            r#"claude mcp add-json drust '{{"type":"http","url":"{resource_url}","oauth":{{"authServerMetadataUrl":"{as_url}"}}}}' --scope user"#
        ))
    };
    Some(ConnectCommands {
        add: format!("claude mcp add --transport http --scope user drust {resource_url}"),
        add_json: format!(
            r#"claude mcp add-json drust '{{"type":"http","url":"{resource_url}"}}' --scope user"#
        ),
        resource_url,
        login: "claude mcp login drust",
        list: "claude mcp list",
        remove_old: "claude mcp remove drust-<tenant>",
        old_rule: "mcp__drust-<tenant>__*",
        new_rule: "mcp__drust__*",
        logout: "claude mcp logout drust",
        remove: "claude mcp remove drust",
        metadata_fallback,
    })
}

/// One address the diagnostics page requests from the browser. `expect` names
/// the check the page script runs on the answer: `challenge`, `prm`, `as` or
/// `token_error`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagCheck {
    pub id: &'static str,
    pub method: &'static str,
    pub url: String,
    pub expect: &'static str,
    pub label_key: &'static str,
    pub hint_key: &'static str,
}

/// The diagnostics check list, in table order, with every check whose URL
/// equals an earlier one's dropped (the earlier one is kept). Empty while
/// disabled. Under an empty base path that leaves `mcp`, `prm`, `as_root` and
/// `token`.
pub fn diag_checks(cfg: &McpOauthConfig) -> Vec<DiagCheck> {
    let Some(o) = cfg.public_origin() else {
        return Vec::new();
    };
    let check = |id, method, url, expect, label_key, hint_key| DiagCheck {
        id,
        method,
        url,
        expect,
        label_key,
        hint_key,
    };
    let mut checks = vec![
        check(
            "mcp",
            "POST",
            cfg.resource_url(),
            "challenge",
            "mcp_diag.check.mcp.label",
            "mcp_diag.check.mcp.hint",
        ),
        check(
            "prm",
            "GET",
            cfg.prm_url(),
            "prm",
            "mcp_diag.check.prm.label",
            "mcp_diag.check.prm.hint",
        ),
        check(
            "prm_root",
            "GET",
            format!(
                "{o}/.well-known/oauth-protected-resource{}",
                crate::base_path::base("/mcp")
            ),
            "prm",
            "mcp_diag.check.prm_root.label",
            "mcp_diag.check.prm_root.hint",
        ),
        check(
            "as_root",
            "GET",
            format!(
                "{o}/.well-known/oauth-authorization-server{}",
                crate::base_path::base_path()
            ),
            "as",
            "mcp_diag.check.as_root.label",
            "mcp_diag.check.as_root.hint",
        ),
        check(
            "as_base",
            "GET",
            cfg.endpoint_url("/.well-known/oauth-authorization-server"),
            "as",
            "mcp_diag.check.as_base.label",
            "mcp_diag.check.as_base.hint",
        ),
        check(
            "token",
            "POST",
            cfg.endpoint_url("/oauth/token"),
            "token_error",
            "mcp_diag.check.token.label",
            "mcp_diag.check.token.hint",
        ),
    ];
    let mut seen = HashSet::new();
    checks.retain(|c| seen.insert(c.url.clone()));
    checks
}

/// What the diagnostics page script reads: the public origin, the page's own
/// public URL, the expected `resource` and `issuer`, and each check's id,
/// method, URL and expectation. The locale keys stay on the server. `None`
/// while disabled.
pub fn diagnostics_json(cfg: &McpOauthConfig) -> Option<serde_json::Value> {
    let origin = cfg.public_origin()?;
    let checks: Vec<serde_json::Value> = diag_checks(cfg)
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "method": c.method,
                "url": c.url,
                "expect": c.expect,
            })
        })
        .collect();
    Some(serde_json::json!({
        "origin": origin,
        "page": cfg.endpoint_url("/admin/mcp/diagnostics"),
        "resource": cfg.resource_url(),
        "issuer": cfg.issuer(),
        "checks": checks,
    }))
}

/// The locale key of the one sentence the diagnostics page shows for a
/// disabled server.
pub fn disabled_reason_key(r: &DisabledReason) -> &'static str {
    match r {
        DisabledReason::ModeOff => "mcp_diag.reason.mode_off",
        DisabledReason::AutoBeforeMa1d => "mcp_diag.reason.auto",
        DisabledReason::InvalidMode(_) => "mcp_diag.reason.invalid_mode",
        DisabledReason::PublicUrlMissing => "mcp_diag.reason.public_url_missing",
        DisabledReason::PublicUrlInvalid(_) => "mcp_diag.reason.public_url_invalid",
        DisabledReason::InsecureHttp => "mcp_diag.reason.insecure_http",
        DisabledReason::BasePathInvalid => "mcp_diag.reason.base_path_invalid",
    }
}

/// The static detail shown next to the sentence: only `PublicUrlInvalid`'s
/// reason word. The raw `DRUST_MCP` value of `InvalidMode` is operator input
/// and is never shown.
pub fn disabled_reason_detail(r: &DisabledReason) -> Option<&'static str> {
    match r {
        DisabledReason::PublicUrlInvalid(why) => Some(*why),
        _ => None,
    }
}

#[derive(Template)]
#[template(path = "mcp_connect.html")]
struct McpConnectPage {
    version: &'static str,
    t: Translator,
    admin: AdminProfileExt,
    palette_resolved: ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
    cmds: ConnectCommands,
    tool_count: usize,
}

/// The connect page, or `None` when `connect_commands` has nothing to show
/// (disabled, or a public URL that is not shell-safe).
fn connect_page_html(
    cfg: &McpOauthConfig,
    t: Translator,
    admin: AdminProfileExt,
    theme: Theme,
) -> Option<String> {
    let cmds = connect_commands(cfg)?;
    let trc = ThemeRenderCtx::build(theme);
    Some(
        McpConnectPage {
            version: env!("CARGO_PKG_VERSION"),
            t,
            admin,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
            cmds,
            tool_count: AccountMcp::tool_count(),
        }
        .render()
        .unwrap_or_default(),
    )
}

/// `GET /admin/mcp` — "Connect Claude Code", a personal page for every role.
pub async fn connect_page(
    State(s): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    ThemeHint(theme): ThemeHint,
    Extension(admin): Extension<AdminProfileExt>,
) -> Response {
    match connect_page_html(&s.mcp_oauth, Translator::new(locale), admin, theme) {
        Some(html) => Html(html).into_response(),
        // Mounted only while enabled, so None means the public URL is not shell-safe: no command to show.
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::config::{DisabledReason, McpOauthConfig, McpOauthEnv};

    fn on() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }
    fn cfg(mode: Option<&str>, url: Option<&str>, base: &str) -> McpOauthConfig {
        McpOauthConfig::from_parts(
            &McpOauthEnv {
                mode,
                public_url: url,
                ..Default::default()
            },
            base,
            [1; 32],
            [2; 32],
        )
    }

    #[test]
    fn connect_commands_use_the_resource_url() {
        let c = connect_commands(&on()).expect("enabled");
        assert_eq!(c.resource_url, "https://drust.test/drust/mcp");
        assert_eq!(
            c.add,
            "claude mcp add --transport http --scope user drust https://drust.test/drust/mcp"
        );
        assert_eq!(
            c.add_json,
            r#"claude mcp add-json drust '{"type":"http","url":"https://drust.test/drust/mcp"}' --scope user"#
        );
        assert_eq!(
            c.metadata_fallback.as_deref(),
            Some(
                r#"claude mcp add-json drust '{"type":"http","url":"https://drust.test/drust/mcp","oauth":{"authServerMetadataUrl":"https://drust.test/drust/.well-known/oauth-authorization-server"}}' --scope user"#
            )
        );
        assert_eq!(
            (c.login, c.list, c.logout, c.remove),
            (
                "claude mcp login drust",
                "claude mcp list",
                "claude mcp logout drust",
                "claude mcp remove drust"
            )
        );
        assert_eq!(
            (c.remove_old, c.old_rule, c.new_rule),
            (
                "claude mcp remove drust-<tenant>",
                "mcp__drust-<tenant>__*",
                "mcp__drust__*"
            )
        );
        // The JSON inside the single quotes parses and carries type http.
        let inner = c.add_json.split('\'').nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(inner).unwrap();
        assert_eq!(v["type"], "http");
    }

    #[test]
    fn connect_commands_are_none_while_disabled() {
        assert!(connect_commands(&McpOauthConfig::disabled()).is_none());
        assert!(connect_commands(&cfg(Some("on"), None, "/drust")).is_none());
    }

    #[test]
    fn connect_commands_never_print_a_shell_metacharacter() {
        const META: &[char] = &[
            '\'', '"', '\\', ' ', '$', '`', ';', '&', '|', '(', ')', '<', '>', '*', '?', '[', ']',
            '{', '}', '!',
        ];
        let c = connect_commands(&on()).expect("enabled");
        // The add command is words separated by single spaces; no word may
        // carry a metacharacter, and neither may the URL.
        for s in c.add.split(' ').chain([c.resource_url.as_str()]) {
            assert!(!s.is_empty() && !s.contains(META), "{s:?}");
        }
        // Url::parse lets these into a host; whether or not one enables MCP, no
        // command may be built from it.
        for url in [
            "https://dr'ust.test",
            "https://dr$ust.test",
            "https://dr`ust.test",
            "https://a;b.test",
            "https://a&b.test",
            "https://a(b.test",
            "https://[::1]:8443",
        ] {
            assert!(
                connect_commands(&cfg(Some("on"), Some(url), "/drust")).is_none(),
                "{url}"
            );
        }
        // The base path reaches every URL; base_path_ok must keep refusing these.
        for base in [
            "/dr'ust", "/dr ust", "/dr$ust", "/dr`ust", "/dr\"ust", "/dr\\ust", "/dr;ust",
        ] {
            assert!(
                !cfg(Some("on"), Some("https://drust.test"), base).enabled(),
                "{base}"
            );
        }
    }

    #[test]
    fn diag_checks_follow_the_table_under_a_base_path() {
        let got: Vec<(&str, &str, String, &str)> = diag_checks(&on())
            .into_iter()
            .map(|c| (c.id, c.method, c.url, c.expect))
            .collect();
        let want = [
            ("mcp", "POST", "https://drust.test/drust/mcp", "challenge"),
            (
                "prm",
                "GET",
                "https://drust.test/drust/.well-known/oauth-protected-resource/mcp",
                "prm",
            ),
            (
                "prm_root",
                "GET",
                "https://drust.test/.well-known/oauth-protected-resource/drust/mcp",
                "prm",
            ),
            (
                "as_root",
                "GET",
                "https://drust.test/.well-known/oauth-authorization-server/drust",
                "as",
            ),
            (
                "as_base",
                "GET",
                "https://drust.test/drust/.well-known/oauth-authorization-server",
                "as",
            ),
            (
                "token",
                "POST",
                "https://drust.test/drust/oauth/token",
                "token_error",
            ),
        ];
        assert_eq!(got.len(), want.len());
        for (g, w) in got.iter().zip(want) {
            assert_eq!((g.0, g.1, g.2.as_str(), g.3), w);
        }
        for c in diag_checks(&on()) {
            assert_eq!(c.label_key, format!("mcp_diag.check.{}.label", c.id));
            assert_eq!(c.hint_key, format!("mcp_diag.check.{}.hint", c.id));
        }
    }

    #[test]
    fn diag_checks_and_json_are_empty_while_disabled() {
        assert!(diag_checks(&McpOauthConfig::disabled()).is_empty());
        assert!(diagnostics_json(&McpOauthConfig::disabled()).is_none());
    }

    #[test]
    fn diagnostics_json_mirrors_the_checks_and_carries_no_credential() {
        let v = diagnostics_json(&on()).unwrap();
        assert_eq!(v["origin"], "https://drust.test");
        assert_eq!(v["page"], "https://drust.test/drust/admin/mcp/diagnostics");
        assert_eq!(v["resource"], "https://drust.test/drust/mcp");
        assert_eq!(v["issuer"], "https://drust.test/drust");
        let checks = v["checks"].as_array().unwrap();
        let from_fn = diag_checks(&on());
        assert_eq!(checks.len(), from_fn.len());
        for (j, c) in checks.iter().zip(&from_fn) {
            assert_eq!(
                j.as_object().unwrap().len(),
                4,
                "only id, method, url, expect"
            );
            assert_eq!(
                (
                    j["id"].as_str(),
                    j["method"].as_str(),
                    j["url"].as_str(),
                    j["expect"].as_str()
                ),
                (
                    Some(c.id),
                    Some(c.method),
                    Some(c.url.as_str()),
                    Some(c.expect)
                )
            );
        }
        let keys: std::collections::BTreeSet<&str> =
            v.as_object().unwrap().keys().map(String::as_str).collect();
        let want =
            std::collections::BTreeSet::from(["checks", "issuer", "origin", "page", "resource"]);
        assert_eq!(keys, want, "top-level keys");
        // Case-sensitive header names: every URL in the JSON is lower case, so
        // "oauth-authorization-server" does not match "Authorization".
        let s = v.to_string();
        for bad in ["drust_", "Authorization", "Cookie", "Bearer"] {
            assert!(!s.contains(bad), "diag_json contains {bad}");
        }
    }

    #[test]
    fn every_disabled_reason_maps_to_a_real_locale_key() {
        let reasons = [
            (cfg(Some("off"), None, "/drust"), DisabledReason::ModeOff),
            (
                cfg(Some("auto"), Some("https://drust.test"), "/drust"),
                DisabledReason::AutoBeforeMa1d,
            ),
            (
                cfg(Some("sideways-x"), None, "/drust"),
                DisabledReason::InvalidMode("sideways-x".into()),
            ),
            (
                cfg(Some("on"), None, "/drust"),
                DisabledReason::PublicUrlMissing,
            ),
            (
                cfg(Some("on"), Some("https://ZQX@drust.test"), "/drust"),
                DisabledReason::PublicUrlInvalid("userinfo"),
            ),
            (
                cfg(Some("on"), Some("http://drust.test"), "/drust"),
                DisabledReason::InsecureHttp,
            ),
            (
                cfg(Some("on"), Some("https://drust.test"), "/dr ust"),
                DisabledReason::BasePathInvalid,
            ),
        ];
        // en only: Translator::s falls back to en, so a zh lookup can never
        // show the sentinel. zh-TW parity is proven by i18n_parity (PREFIXES)
        // and mcp_account_ui_locale_values_render_verbatim.
        let en = crate::mgmt::i18n::Translator::new(crate::mgmt::i18n::Locale::En);
        let mut keys = std::collections::BTreeSet::new();
        for (c, want) in &reasons {
            let r = c.disabled_reason().expect("disabled");
            assert_eq!(r, want);
            let k = disabled_reason_key(r);
            assert!(k.starts_with("mcp_diag.reason."), "{k}");
            assert!(!en.s(k).starts_with("!!"), "{k} missing in en");
            keys.insert(k);
        }
        assert_eq!(keys.len(), 7, "one key per variant");
        assert_eq!(
            disabled_reason_detail(&DisabledReason::PublicUrlInvalid("userinfo")),
            Some("userinfo")
        );
        assert_eq!(
            disabled_reason_detail(&DisabledReason::InvalidMode("sideways-x".into())),
            None
        );
        assert_eq!(disabled_reason_detail(&DisabledReason::ModeOff), None);
        for c in diag_checks(&on()) {
            for k in [c.label_key, c.hint_key] {
                assert!(!en.s(k).starts_with("!!"), "{k} missing in en");
            }
        }
    }

    #[test]
    fn connect_pages_read_nothing_from_the_database() {
        let src = include_str!("connect.rs");
        let code = crate::tenant::rooms::srcpin::code_only(src);
        let prod = crate::tenant::rooms::srcpin::production_half(&code);
        // MgmtState's database handles (meta, audit_meta_read, tenants) and the
        // ways in. `.meta.` / `.meta)` / `.meta,` rather than a bare `.meta`, which
        // would match the `metadata_fallback` field.
        for n in [
            concat!(".lo", "ck("),
            concat!("rusq", "lite"),
            concat!("get_or_", "create"),
            concat!("get_if_", "live"),
            concat!(".me", "ta."),
            concat!(".me", "ta)"),
            concat!(".me", "ta,"),
            concat!("audit_me", "ta_read"),
            concat!(".ten", "ants"),
        ] {
            assert!(!prod.contains(n), "connect.rs production code names {n}");
        }
    }

    #[test]
    fn connect_page_html_is_none_while_disabled() {
        let t = crate::mgmt::i18n::Translator::new(crate::mgmt::i18n::Locale::En);
        assert!(
            connect_page_html(
                &McpOauthConfig::disabled(),
                t,
                crate::mgmt::admin_profile::AdminProfileExt::placeholder(),
                crate::mgmt::theme::Theme::System
            )
            .is_none()
        );
    }
}

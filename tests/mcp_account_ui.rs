//! The account-level MCP pages of the admin plane: "Connect Claude Code"
//! (every role) and the owner-only connection diagnostics. Requests go
//! through the production router at ROOT paths; outbound strings carry
//! `/drust`. Neither page writes audit rows, so none are asserted.
//!
//! Every DB touch takes `fx.meta` in its own block and drops it before the
//! next HTTP request (the handlers lock the same mutex).

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use rusqlite::params;

use crate::common::mcp_oauth as mo;

// ─── file-private helpers ────────────────────────────────────────────────────

/// `"drust_session=<t>"` for `admin_id`, minted directly.
async fn session(fx: &mo::McpOauthFixture, admin_id: i64) -> String {
    let mut c = fx.meta.lock().await;
    let t = drust::auth::session::create_session(&mut c, admin_id, 3600).unwrap();
    format!("drust_session={t}")
}

/// `GET <uri>` with each `(name, value)` header, through the production router.
async fn get_with(app: &axum::Router, uri: &str, headers: &[(&str, &str)]) -> Response<Body> {
    let mut b = Request::builder().method("GET").uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    mo::send(app, b.body(Body::empty()).unwrap()).await
}

/// A browser page load: `Accept: text/html`, plus the cookie when given.
async fn get_page(app: &axum::Router, uri: &str, cookie: Option<&str>) -> Response<Body> {
    let mut h = vec![("accept", "text/html")];
    if let Some(c) = cookie {
        h.push(("cookie", c));
    }
    get_with(app, uri, &h).await
}

async fn body(resp: Response<Body>) -> String {
    let b = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

/// Revokes the admin's live unlabeled PAT and inserts one whose plaintext is
/// known and also stored in `plaintext` (as the settings page stores it).
/// Returns the PAT.
async fn known_pat(fx: &mo::McpOauthFixture, admin_id: i64) -> String {
    let c = fx.meta.lock().await;
    c.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') \
         WHERE admin_id = ?1 AND revoked_at IS NULL AND label IS NULL",
        params![admin_id],
    )
    .unwrap();
    let pat = drust::auth::admin_token::generate_token();
    c.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (?1, ?2, ?3)",
        params![admin_id, drust::auth::admin_token::hash_token(&pat), pat],
    )
    .unwrap();
    pat
}

/// Tenant `acme` (owned by the owner) with a live service and anon key;
/// returns both plaintexts.
async fn seed_tenant_keys(fx: &mo::McpOauthFixture) -> Vec<String> {
    let c = fx.meta.lock().await;
    c.execute(
        "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('acme', 'Acme', ?1)",
        params![fx.owner_id],
    )
    .unwrap();
    let mut keys = Vec::new();
    for role in ["service", "anon"] {
        let key = drust::auth::bearer::generate_token();
        c.execute(
            "INSERT INTO tokens (tenant_id, token_hash, plaintext, label, role) \
             VALUES ('acme', ?1, ?2, ?3, ?4)",
            params![
                drust::auth::bearer::hash_token(&key),
                key,
                format!("initial-{role}"),
                role
            ],
        )
        .unwrap();
        keys.push(key);
    }
    keys
}

/// Every credential plaintext the host holds for the owner: a known PAT, one
/// live grant's access and refresh, and the tenant keys. Call once per fixture.
async fn seed_secrets(fx: &mo::McpOauthFixture) -> Vec<String> {
    let mut out = vec![known_pat(fx, fx.owner_id).await];
    {
        let c = fx.meta.lock().await;
        let g = mo::seed_grant(
            &c,
            &mo::SeedGrant {
                admin_id: fx.owner_id,
                idle: "+30 days",
                absolute: "+90 days",
                revoked: false,
            },
        );
        let t = mo::seed_tokens(&c, g);
        out.push(t.access);
        out.push(t.refresh);
    }
    out.extend(seed_tenant_keys(fx).await);
    out
}

/// The pages this file adds; each rides `protected`.
const NEW_PAGES: &[&str] = &["/admin/mcp", "/admin/mcp/diagnostics"];

/// Every key of `locales/<file>`, flattened to dotted paths.
fn bundle(file: &str) -> std::collections::BTreeMap<String, String> {
    fn flatten(
        prefix: &str,
        v: &toml::Value,
        out: &mut std::collections::BTreeMap<String, String>,
    ) {
        match v {
            toml::Value::Table(t) => {
                for (k, child) in t {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    flatten(&key, child, out);
                }
            }
            toml::Value::String(s) => {
                out.insert(prefix.to_string(), s.clone());
            }
            other => {
                out.insert(prefix.to_string(), other.to_string());
            }
        }
    }
    let path = format!("{}/locales/{file}", env!("CARGO_MANIFEST_DIR"));
    let v: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut all = std::collections::BTreeMap::new();
    flatten("", &v, &mut all);
    all
}

/// askama's HTML escaper, as it renders text.
fn esc(s: &str) -> String {
    s.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

const ADD_CMD: &str =
    "claude mcp add --transport http --scope user drust https://drust.test/drust/mcp";

/// (section letter of the connect page contract, en key) — every key must
/// appear verbatim on the page.
const SECTION_KEYS: &[(&str, &str)] = &[
    ("a", "mcp_connect.add.step_add"),
    ("a", "mcp_connect.add.step_auth"),
    ("a", "mcp_connect.add.ssh"),
    ("a", "mcp_connect.add.json"),
    ("b", "mcp_connect.migrate.remove"),
    ("c", "mcp_connect.migrate.rules"),
    ("d", "mcp_connect.disconnect.body"),
    ("e", "mcp_connect.scope.clients"),
    ("f", "mcp_connect.scope.ci"),
    ("g", "mcp_connect.migrate.reroll"),
    ("h", "mcp_connect.url_change.body"),
    ("i", "mcp_connect.fallback.body"),
    ("j", "mcp_connect.disconnect.manage"),
    ("j", "mcp_connect.disconnect.manage_link"),
    ("-", "mcp_connect.scope.functions"),
    ("-", "mcp_connect.scope.uploads"),
    ("-", "mcp_connect.scope.rights"),
];

// ─── the connect page ────────────────────────────────────────────────────────

#[tokio::test]
async fn connect_page_is_open_to_every_role() {
    let fx = mo::fixture(true).await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    for id in [fx.owner_id, a, m] {
        let s = session(&fx, id).await;
        let r = get_page(&fx.app, "/admin/mcp", Some(&s)).await;
        assert_eq!(r.status(), StatusCode::OK, "admin {id}");
        let b = body(r).await;
        assert!(
            b.contains(ADD_CMD),
            "admin {id}: the add command names resource_url()"
        );
        assert!(ADD_CMD.ends_with(mo::RESOURCE));
    }
}

#[tokio::test]
async fn connect_page_carries_every_section() {
    let fx = mo::fixture(true).await;
    let s = session(&fx, fx.owner_id).await;
    let b = body(get_page(&fx.app, "/admin/mcp", Some(&s)).await).await;
    let en = bundle("en.toml");
    for (letter, key) in SECTION_KEYS {
        let v = en
            .get(*key)
            .unwrap_or_else(|| panic!("{key} missing in en.toml"));
        assert!(b.contains(v.as_str()), "({letter}) {key} not on the page");
    }
    assert!(!b.contains("!!"), "a missing locale key renders as !!key!!");
}

#[tokio::test]
async fn connect_page_shows_the_account_tool_count() {
    let fx = mo::fixture(true).await;
    let s = session(&fx, fx.owner_id).await;
    let b = body(get_page(&fx.app, "/admin/mcp", Some(&s)).await).await;
    let n = drust::mcp::account::AccountMcp::tool_count();
    assert!(
        b.contains(&format!("<span class=\"pill info\">{n} tools</span>")),
        "{n} tools"
    );
}

#[tokio::test]
async fn connect_page_renders_commands_as_escaped_text() {
    let fx = mo::fixture(true).await;
    let s = session(&fx, fx.owner_id).await;
    let b = body(get_page(&fx.app, "/admin/mcp", Some(&s)).await).await;
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests(mo::PUBLIC_URL);
    let c = drust::mgmt::mcp_oauth::connect::connect_commands(&cfg).unwrap();
    for (id, text) in [
        ("mcp-cmd-add", c.add.clone()),
        ("mcp-cmd-login", c.login.to_string()),
        ("mcp-cmd-json", c.add_json.clone()),
        ("mcp-cmd-fallback", c.metadata_fallback.clone().unwrap()),
    ] {
        assert!(
            b.contains(&format!(
                "<pre class=\"code\" id=\"{id}\">{}</pre>",
                esc(&text)
            )),
            "{id}"
        );
        assert!(
            b.contains(&format!("data-mcp-copy=\"{id}\"")),
            "{id}: copy button"
        );
    }
    assert!(b.contains(
        "&#39;{&#34;type&#34;:&#34;http&#34;,&#34;url&#34;:&#34;https://drust.test/drust/mcp&#34;}&#39;"
    ));
    assert!(b.contains("<code>mcp__drust-&#60;tenant&#62;__*</code> → <code>mcp__drust__*</code>"));
    assert!(b.contains("claude mcp remove drust-&#60;tenant&#62;"));
    assert!(b.contains("claude mcp logout drust\nclaude mcp remove drust</pre>"));
}

#[tokio::test]
async fn connect_page_embeds_no_credential() {
    let fx = mo::fixture(true).await;
    let secrets = seed_secrets(&fx).await;
    let s = session(&fx, fx.owner_id).await;
    let r = get_page(&fx.app, "/admin/mcp", Some(&s)).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "the page must render for the negatives to mean anything"
    );
    let b = body(r).await;
    assert!(b.contains(ADD_CMD));
    for (i, secret) in secrets.iter().enumerate() {
        assert!(!b.contains(secret.as_str()), "credential #{i} on the page");
    }
    for prefix in ["drust_pat_", "drust_mcpat_", "drust_mcprt_", "drust_upl_"] {
        assert!(!b.contains(prefix), "{prefix}");
    }
}

#[tokio::test]
async fn new_pages_require_an_admin_credential() {
    let fx = mo::fixture(true).await;
    let access = {
        let c = fx.meta.lock().await;
        let g = mo::seed_grant(
            &c,
            &mo::SeedGrant {
                admin_id: fx.owner_id,
                idle: "+30 days",
                absolute: "+90 days",
                revoked: false,
            },
        );
        mo::seed_tokens(&c, g).access
    };
    let key = seed_tenant_keys(&fx).await.remove(0);
    let (mcp_auth, key_auth) = (format!("Bearer {access}"), format!("Bearer {key}"));
    let cases: [(&str, Vec<(&str, &str)>); 4] = [
        ("no cookie, html", vec![("accept", "text/html")]),
        ("no cookie, json", vec![("accept", "application/json")]),
        (
            "MCP access token",
            vec![("authorization", mcp_auth.as_str())],
        ),
        ("tenant key", vec![("authorization", key_auth.as_str())]),
    ];
    for (what, h) in &cases {
        let reference = mo::response_snapshot(get_with(&fx.app, "/admin/settings", h).await).await;
        assert!(
            !reference.0.is_success() && !reference.0.is_server_error(),
            "{what}: {}",
            reference.0
        );
        for page in NEW_PAGES {
            let got = mo::response_snapshot(get_with(&fx.app, page, h).await).await;
            assert_eq!(
                got, reference,
                "{what}: {page} answers like /admin/settings"
            );
        }
    }
}

#[tokio::test]
async fn connect_page_links_to_the_settings_card() {
    let fx = mo::fixture(true).await;
    let s = session(&fx, fx.owner_id).await;
    let b = body(get_page(&fx.app, "/admin/mcp", Some(&s)).await).await;
    assert!(b.contains("href=\"/drust/admin/settings#mcp-grants\""));
    let settings = body(get_page(&fx.app, "/admin/settings", Some(&s)).await).await;
    let card = &settings[settings.find("id=\"mcp-grants\"").expect("card")..];
    let card = &card[..card.find("<script").expect("scripts follow the card")];
    assert!(card.contains("href=\"/drust/admin/mcp\">Connect Claude Code</a>"));
}

#[tokio::test]
async fn connect_page_zh_tw_has_every_key() {
    let fx = mo::fixture(true).await;
    let s = session(&fx, fx.owner_id).await;
    let cookie = format!("{s}; drust_locale=zh-TW");
    let b = body(get_page(&fx.app, "/admin/mcp", Some(&cookie)).await).await;
    let zh = bundle("zh-TW.toml");
    assert!(b.contains("串接 Claude Code"));
    // zh[*key] panics when zh-TW lacks the key; the contains() fails when the
    // page fell back to en. The "!!" check only catches a key missing in BOTH.
    for (_, key) in SECTION_KEYS {
        assert!(b.contains(zh[*key].as_str()), "zh-TW {key} not on the page");
    }
    assert!(!b.contains("!!"));
}

#[tokio::test]
async fn disabled_connect_page_is_not_mounted() {
    use drust::mgmt::mcp_oauth::config::{McpOauthConfig, McpOauthEnv};
    let on_without_url = McpOauthConfig::from_parts(
        &McpOauthEnv {
            mode: Some("on"),
            public_url: None,
            ..Default::default()
        },
        "/drust",
        [1; 32],
        [2; 32],
    );
    for cfg in [McpOauthConfig::disabled(), on_without_url] {
        let fx = mo::fixture_with(cfg).await;
        let s = session(&fx, fx.owner_id).await;
        for cookie in [Some(s.as_str()), None] {
            for accept in [None, Some("text/html"), Some("application/json")] {
                let req = |uri: &str| {
                    let mut b = Request::builder().method("GET").uri(uri);
                    if let Some(c) = cookie {
                        b = b.header(header::COOKIE, c);
                    }
                    if let Some(a) = accept {
                        b = b.header(header::ACCEPT, a);
                    }
                    b.body(Body::empty()).unwrap()
                };
                let never =
                    mo::response_snapshot(mo::send(&fx.app, req("/admin/nonexistent")).await).await;
                let got = mo::response_snapshot(mo::send(&fx.app, req("/admin/mcp")).await).await;
                assert_eq!(got, never, "cookie {} accept {accept:?}", cookie.is_some());
            }
        }
    }
}

#[test]
fn mcp_account_ui_locale_values_render_verbatim() {
    let en = bundle("en.toml");
    let zh = bundle("zh-TW.toml");
    let ours = |m: &std::collections::BTreeMap<String, String>| -> Vec<(String, String)> {
        m.iter()
            .filter(|(k, _)| {
                k.starts_with("mcp_connect.")
                    || k.starts_with("mcp_diag.")
                    || k.as_str() == "settings.mcp_grants.connect_link"
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let (e, z) = (ours(&en), ours(&zh));
    assert_eq!(
        e.iter().map(|x| &x.0).collect::<Vec<_>>(),
        z.iter().map(|x| &x.0).collect::<Vec<_>>()
    );
    for (lang, list) in [("en", &e), ("zh-TW", &z)] {
        for (k, v) in list {
            for bad in ["'", "\"", "&", "<", ">", "\\", "\n", "\r", "!!", "429"] {
                assert!(!v.contains(bad), "{lang} `{k}` contains {bad:?}");
            }
            assert!(!v.trim().is_empty(), "{lang} `{k}` is empty");
        }
    }
}

// ─── the diagnostics page ────────────────────────────────────────────────────

#[tokio::test]
async fn diagnostics_page_is_owner_only() {
    let fx = mo::fixture(true).await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    let s = session(&fx, fx.owner_id).await;
    assert_eq!(
        get_page(&fx.app, "/admin/mcp/diagnostics", Some(&s))
            .await
            .status(),
        StatusCode::OK
    );
    for id in [a, m] {
        let s = session(&fx, id).await;
        let reference =
            mo::response_snapshot(get_page(&fx.app, "/admin/quota-requests", Some(&s)).await).await;
        assert_eq!(reference.0, StatusCode::FORBIDDEN);
        let got =
            mo::response_snapshot(get_page(&fx.app, "/admin/mcp/diagnostics", Some(&s)).await)
                .await;
        assert_eq!(
            got, reference,
            "admin {id}: same answer as another owner-only page"
        );
        let v: serde_json::Value = serde_json::from_slice(&got.2).unwrap();
        assert_eq!(v["error_code"], "OWNER_REQUIRED");
        // The PAT arm of admin_session_layer must reach the same role check.
        let pat = format!("Bearer {}", known_pat(&fx, id).await);
        let h = [("authorization", pat.as_str()), ("accept", "text/html")];
        let reference =
            mo::response_snapshot(get_with(&fx.app, "/admin/quota-requests", &h).await).await;
        assert_eq!(reference.0, StatusCode::FORBIDDEN);
        let got =
            mo::response_snapshot(get_with(&fx.app, "/admin/mcp/diagnostics", &h).await).await;
        assert_eq!(
            got, reference,
            "admin {id} PAT: same answer as another owner-only page"
        );
    }
    let pat = format!("Bearer {}", known_pat(&fx, fx.owner_id).await);
    let r = get_with(
        &fx.app,
        "/admin/mcp/diagnostics",
        &[("authorization", pat.as_str())],
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "owner PAT");
}

#[tokio::test]
async fn diagnostics_page_embeds_no_credential() {
    let fx = mo::fixture(true).await;
    let secrets = seed_secrets(&fx).await;
    let s = session(&fx, fx.owner_id).await;
    let r = get_page(&fx.app, "/admin/mcp/diagnostics", Some(&s)).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "the page must render for the negatives to mean anything"
    );
    let b = body(r).await;
    assert!(b.contains("mcp-diag-data"));
    for (i, secret) in secrets.iter().enumerate() {
        assert!(!b.contains(secret.as_str()), "credential #{i} on the page");
    }
    for prefix in ["drust_pat_", "drust_mcpat_", "drust_mcprt_", "drust_upl_"] {
        assert!(!b.contains(prefix), "{prefix}");
    }
}

/// Regression guard only: in the full app a layered fallback is replaced by
/// later merges, so this cannot tell route_layer from layer — the lib test
/// diagnostics_owner_gate_wraps_its_route_and_not_the_fallback does.
#[tokio::test]
async fn unknown_mcp_paths_stay_not_found() {
    let fx = mo::fixture(true).await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    let s = session(&fx, m).await;
    let never =
        mo::response_snapshot(get_page(&fx.app, "/admin/nonexistent", Some(&s)).await).await;
    assert_eq!(never.0, StatusCode::NOT_FOUND);
    for uri in ["/admin/mcp/nonexistent", "/admin/mcp/diagnostics/x"] {
        assert_eq!(
            mo::response_snapshot(get_page(&fx.app, uri, Some(&s)).await).await,
            never,
            "{uri}"
        );
    }
}

fn island(page: &str) -> serde_json::Value {
    const OPEN: &str = r#"<script id="mcp-diag-data" type="application/json">"#;
    let start = page.find(OPEN).expect("diag_json island") + OPEN.len();
    let end = start + page[start..].find("</script>").unwrap();
    serde_json::from_str(&page[start..end]).unwrap()
}

#[tokio::test]
async fn diagnostics_json_matches_the_check_table() {
    let fx = mo::fixture(true).await;
    let s = session(&fx, fx.owner_id).await;
    let b = body(get_page(&fx.app, "/admin/mcp/diagnostics", Some(&s)).await).await;
    let cfg = drust::mgmt::mcp_oauth::config::McpOauthConfig::for_tests(mo::PUBLIC_URL);
    let v = island(&b);
    assert_eq!(
        v,
        drust::mgmt::mcp_oauth::connect::diagnostics_json(&cfg).unwrap()
    );
    let urls: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["url"].as_str().unwrap())
        .collect();
    assert_eq!(
        urls,
        [
            "https://drust.test/drust/mcp",
            "https://drust.test/drust/.well-known/oauth-protected-resource/mcp",
            "https://drust.test/.well-known/oauth-protected-resource/drust/mcp",
            "https://drust.test/.well-known/oauth-authorization-server/drust",
            "https://drust.test/drust/.well-known/oauth-authorization-server",
            "https://drust.test/drust/oauth/token",
        ]
    );
    assert!(!v.to_string().contains("drust_"));
    assert!(
        b.contains(&format!("<code>{}</code>", mo::RESOURCE))
            && b.contains(&format!("<code>{}</code>", mo::ISSUER))
    );
    for id in ["mcp", "prm", "prm_root", "as_root", "as_base", "token"] {
        assert!(
            b.contains(&format!("data-diag-result=\"{id}\"")),
            "{id} row"
        );
    }
}

#[tokio::test]
async fn diagnostics_page_script_never_sends_credentials() {
    let fx = mo::fixture(true).await;
    let s = session(&fx, fx.owner_id).await;
    let b = body(get_page(&fx.app, "/admin/mcp/diagnostics", Some(&s)).await).await;
    for needle in [
        "redirect: 'manual'",
        "cache: 'no-store'",
        "credentials: 'omit'",
        "location.origin !== d.origin",
        "'opaqueredirect'",
        "fetch(c.url, opts)",
    ] {
        assert!(b.contains(needle), "{needle}");
    }
    assert_eq!(b.matches("fetch(c.url, opts)").count(), 1);
    assert!(!b.contains("!!"));
}

#[tokio::test]
async fn connect_page_links_to_diagnostics_for_owners_only() {
    let fx = mo::fixture(true).await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    const LINK: &str = "href=\"/drust/admin/mcp/diagnostics\"";
    let owner = body(
        get_page(
            &fx.app,
            "/admin/mcp",
            Some(&session(&fx, fx.owner_id).await),
        )
        .await,
    )
    .await;
    let member = body(get_page(&fx.app, "/admin/mcp", Some(&session(&fx, m).await)).await).await;
    assert!(owner.contains(LINK));
    assert!(!member.contains(LINK));
}

#[tokio::test]
async fn disabled_diagnostics_page_shows_the_reason_to_owners() {
    // The diagnostics page is mounted whatever the switch says: with MCP off
    // the owner sees why, everyone else gets the owner-only answer, and a
    // caller with no credential gets what any protected page gives it.
    use drust::mgmt::mcp_oauth::config::{McpOauthConfig, McpOauthEnv};
    use drust::mgmt::mcp_oauth::connect::disabled_reason_key;
    const RAW_URL: &str = "https://zqx-public.test";
    let on_without_url = McpOauthConfig::from_parts(
        &McpOauthEnv {
            mode: Some("on"),
            public_url: None,
            ..Default::default()
        },
        "/drust",
        [1; 32],
        [2; 32],
    );
    let auto_under_base = McpOauthConfig::from_parts(
        &McpOauthEnv {
            mode: Some("auto"),
            public_url: Some(RAW_URL),
            ..Default::default()
        },
        "/drust",
        [1; 32],
        [2; 32],
    );
    let en = bundle("en.toml");
    for cfg in [McpOauthConfig::disabled(), on_without_url, auto_under_base] {
        let reason = cfg.disabled_reason().expect("disabled").clone();
        let sentence = esc(&en[disabled_reason_key(&reason)]);
        let fx = mo::fixture_with(cfg).await;
        let a = mo::add_admin(&fx, "alice", "", "admin").await;
        let m = mo::add_admin(&fx, "mia", "", "member").await;

        let s = session(&fx, fx.owner_id).await;
        let r = get_page(&fx.app, "/admin/mcp/diagnostics", Some(&s)).await;
        assert_eq!(r.status(), StatusCode::OK, "{reason:?}");
        let page = body(r).await;
        assert!(page.contains(&sentence), "{reason:?}: reason sentence");
        assert!(!page.contains("drust_"), "{reason:?}: names a credential");
        assert!(
            !page.contains("zqx-public"),
            "{reason:?}: echoes DRUST_PUBLIC_URL"
        );

        for id in [a, m] {
            let s = session(&fx, id).await;
            let reference =
                mo::response_snapshot(get_page(&fx.app, "/admin/quota-requests", Some(&s)).await)
                    .await;
            assert_eq!(reference.0, StatusCode::FORBIDDEN);
            let got =
                mo::response_snapshot(get_page(&fx.app, "/admin/mcp/diagnostics", Some(&s)).await)
                    .await;
            assert_eq!(got, reference, "{reason:?}: admin {id}");
        }

        for accept in ["text/html", "application/json"] {
            let h = [("accept", accept)];
            let reference =
                mo::response_snapshot(get_with(&fx.app, "/admin/quota-requests", &h).await).await;
            let got =
                mo::response_snapshot(get_with(&fx.app, "/admin/mcp/diagnostics", &h).await).await;
            assert_eq!(got, reference, "{reason:?}: no credential, {accept}");
        }
    }
}

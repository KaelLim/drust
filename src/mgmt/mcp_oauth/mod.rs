//! MCP OAuth authorization server. Routes are mounted only when
//! `config::McpOauthConfig::enabled()`; with MCP off no route or page changes.
//! The exceptions with MCP off: the admin CHANGELOG viewer shows these release
//! notes, the `admin.team.remove` audit row gains `revoked_mcp_grants` (0), and
//! `login_submit`'s cross-site refusal is always on. Tables:
//! `db::migrations::SQL_CREATE_MCP_OAUTH_IF_NOT_EXISTS`. Release notes: CHANGELOG.md.
pub mod account_routes;
pub mod authorize;
pub mod caller;
pub mod clients;
pub mod config;
pub mod connect;
pub mod consent;
pub mod envelope;
pub mod metadata;
pub mod oauth_error_layer;
pub mod params;
pub mod pkce;
pub(crate) mod prm;
pub mod redirect;
pub mod refresh;
pub mod revoke;
pub mod rl;
pub(crate) mod route_layer;
pub(crate) mod rs_layer;
pub mod store;
pub mod sweep;
pub mod token;
pub mod tokens;
pub mod ui;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn;
use axum::routing::{get, post};

use crate::mgmt::routes::MgmtState;

/// Unauthenticated OAuth AS routes, already `with_state`. Mounted by
/// `MgmtState::with_data_dir` ONLY when `McpOauthConfig::enabled()`.
///
/// `route_layer`, never `layer`: `Router::layer` also wraps this router's
/// default 404 fallback, and `merge` keeps the merged-in side's default
/// fallback, so `layer` would turn unmatched admin-plane paths into OAuth JSON
/// the moment the merge order changes. `route_layer` wraps each route including
/// its own 405 — exactly these two endpoints. The metadata route sits outside
/// the error layer on purpose: it only answers 200 and is cacheable. So does
/// `GET /oauth/authorize`: before redirect validation its answer is an HTML
/// page, after it a 303, and neither may be rewritten to JSON.
pub fn public_routes(state: &MgmtState) -> Router {
    let oauth_api = Router::new()
        .route("/oauth/token", post(token::token))
        .route("/oauth/revoke", post(revoke::revoke))
        .route_layer(DefaultBodyLimit::max(token::OAUTH_BODY_LIMIT))
        // Added last = outermost: it also sees the body limit's 413.
        .route_layer(from_fn(oauth_error_layer::oauth_error_layer));
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::metadata),
        )
        .route("/oauth/authorize", get(authorize::authorize))
        .merge(oauth_api)
        .with_state(state.clone())
}

/// Consent routes, already `with_state`. `MgmtState::with_data_dir`
/// merges them into `protected` ONLY when `McpOauthConfig::enabled()`, so they
/// sit under `admin_session_layer` (`AdminId` + `AuthMethod`), the profile and
/// inner theme layers, and inside `frame_guard_layers`.
pub fn session_routes(state: &MgmtState) -> Router {
    Router::new()
        .route("/oauth/consent", get(consent::consent_page))
        .route("/oauth/consent/approve", post(consent::consent_approve))
        .route("/oauth/consent/deny", post(consent::consent_deny))
        .with_state(state.clone())
}

/// Settings-page revoke routes, already `with_state`.
/// `MgmtState::with_data_dir` merges them into `settings_router` (after its
/// `.with_state`) ONLY when `McpOauthConfig::enabled()`, so they sit inside
/// `protected` (`admin_session_layer`: cookie or `drust_pat_*`).
pub fn settings_routes(state: &MgmtState) -> Router {
    Router::new()
        .route(
            "/admin/settings/mcp-grants/revoke-all",
            post(ui::settings_revoke_all),
        )
        .route(
            "/admin/settings/mcp-grants/{id}/revoke",
            post(ui::settings_revoke),
        )
        .with_state(state.clone())
}

/// Team-page revoke route, already `with_state`. Merged into
/// `team_router` after its `.with_state` (so after `require_sees_team_layer`,
/// which gates only GET anyway) ONLY when enabled; the authority matrix is
/// `ui::team_authority`, inside the handler.
pub fn team_routes(state: &MgmtState) -> Router {
    Router::new()
        .route(
            "/admin/team/{id}/mcp-grants",
            axum::routing::delete(ui::team_revoke_mcp),
        )
        .with_state(state.clone())
}

/// "Connect Claude Code", already `with_state`. `MgmtState::with_data_dir`
/// merges it into `settings_router` ONLY when `McpOauthConfig::enabled()`: a
/// personal page for every role, like `/admin/settings`, so no
/// `require_owner_layer`.
pub fn connect_routes(state: &MgmtState) -> Router {
    Router::new()
        .route("/admin/mcp", get(connect::connect_page))
        .with_state(state.clone())
}

/// Owner-only MCP connection diagnostics, already `with_state`: a host-wide
/// page with no `{id}`, so it carries `require_owner_layer` (CLAUDE.md
/// invariant 8). `route_layer`, never `layer`: `layer` would also wrap this
/// router's default fallback and gate unmatched paths; once merged into the
/// app that mistake is invisible, so a test drives this router alone. Always
/// merged into the protected router; while MCP is off it shows why.
pub fn diagnostics_routes(state: &MgmtState) -> Router {
    Router::new()
        .route("/admin/mcp/diagnostics", get(connect::diagnostics_page))
        .route_layer(from_fn(crate::mgmt::tenant_authz::require_owner_layer))
        .with_state(state.clone())
}

/// en and zh-TW must carry the same keys under every MCP OAuth prefix (build.rs
/// only checks en).
#[cfg(test)]
mod i18n_parity {
    use std::collections::BTreeMap;

    const PREFIXES: &[&str] = &[
        "mcp_oauth.",
        "settings.mcp_grants.",
        "admin_team.mcp.",
        "mcp_connect.",
        "mcp_diag.",
    ];

    fn flatten(prefix: &str, v: &toml::Value, out: &mut BTreeMap<String, String>) {
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

    fn keys(src: &str) -> BTreeMap<String, String> {
        let v: toml::Value = toml::from_str(src).expect("locale bundle parses");
        let mut out = BTreeMap::new();
        flatten("", &v, &mut out);
        out
    }

    #[test]
    fn mcp_oauth_locale_sections_have_identical_keys() {
        let en = keys(include_str!("../../../locales/en.toml"));
        let zh = keys(include_str!("../../../locales/zh-TW.toml"));
        for p in PREFIXES {
            let e: Vec<_> = en.keys().filter(|k| k.starts_with(p)).collect();
            let z: Vec<_> = zh.keys().filter(|k| k.starts_with(p)).collect();
            assert_eq!(e, z, "en and zh-TW disagree under `{p}`");
        }
        // Anti-vacuous: the error page section must exist.
        assert!(en.keys().any(|k| k.starts_with("mcp_oauth.error.")));
        // No empty translation.
        for (k, v) in zh
            .iter()
            .filter(|(k, _)| PREFIXES.iter().any(|p| k.starts_with(p)))
        {
            assert!(!v.trim().is_empty(), "zh-TW `{k}` is empty");
        }
    }
}

/// Source pins over this directory's credential-handling files. Every needle is
/// matched against comment-stripped production code (`srcpin`), so a comment
/// is never a hiding place and a pin's own literals never count.
#[cfg(test)]
mod source_pins {
    use crate::tenant::rooms::srcpin::{code_only, production_half};

    /// `AuditEntry`'s fields: `entry.<field> = …;` is an audit write.
    const AUDIT_FIELDS: &[&str] = &[
        "ts",
        "tenant",
        "token_hint",
        "op",
        "status",
        "duration_ms",
        "collection",
        "sql_hash",
        "record_id",
        "error_code",
        "error_message",
        "auth_method",
        "oauth_email",
        "oauth_error_code",
        "actor_admin_id",
        "actor_email_snapshot",
        "extra",
    ];

    fn is_ident(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'_'
    }

    /// The index one past the bracket that closes `s[open]`, skipping string
    /// and char literals. Unbalanced input runs to the end (fails loudly).
    fn close_of(s: &[u8], open: usize) -> usize {
        let (o, c) = (s[open], if s[open] == b'(' { b')' } else { b'}' });
        let (mut depth, mut i) = (0usize, open);
        while i < s.len() {
            match s[i] {
                b'"' => {
                    i += 1;
                    while i < s.len() && s[i] != b'"' {
                        i += if s[i] == b'\\' { 2 } else { 1 };
                    }
                }
                b if b == o => depth += 1,
                b if b == c => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        s.len()
    }

    /// Every log, print or audit site in `code`: the text from its opener to
    /// the bracket that closes its argument list (or the `;` that ends a field
    /// assignment).
    fn sites(code: &str) -> Vec<&str> {
        let b = code.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            // Every opener is ASCII, so a byte inside a multi-byte character
            // starts nothing (and `code[i..]` would not be a valid slice).
            if !code.is_char_boundary(i) {
                i += 1;
                continue;
            }
            let boundary = i == 0 || !is_ident(b[i - 1]);
            let rest = &code[i..];
            // Macros and calls whose arguments reach a log or an audit row.
            let call = boundary
                && [
                    "tracing::",
                    "log::",
                    "println!",
                    "eprintln!",
                    "dbg!",
                    "with_extra(",
                    "AuditEntry",
                ]
                .iter()
                .any(|o| rest.starts_with(o));
            // `audit…(`: a module-local audit helper call (or its signature).
            let helper = boundary && rest.starts_with("audit") && {
                let n = rest.bytes().take_while(|c| is_ident(*c)).count();
                rest.as_bytes().get(n) == Some(&b'(')
            };
            if (call || helper)
                && let Some(open) = rest.find(['(', '{'])
            {
                let end = close_of(rest.as_bytes(), open);
                out.push(&rest[..end]);
                i += end;
                continue;
            }
            if b[i] == b'.' {
                let n = rest[1..].bytes().take_while(|c| is_ident(*c)).count();
                let field = &rest[1..1 + n];
                let after = rest[1 + n..].trim_start();
                if AUDIT_FIELDS.contains(&field)
                    && after.starts_with('=')
                    && !after.starts_with("==")
                {
                    let end = rest.find(';').unwrap_or(rest.len());
                    out.push(&rest[..end]);
                    i += end;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// The identifiers a site can put into its output: every identifier of
    /// its code, plus inline format captures (`{name}`, `{name:?}`) inside
    /// its string literals. Other string text (a log message) does not count.
    fn idents(site: &str) -> Vec<&str> {
        let b = site.as_bytes();
        let mut out = Vec::new();
        let (mut i, mut in_str) = (0, false);
        while i < b.len() {
            if in_str {
                match b[i] {
                    b'\\' => i += 1,
                    b'"' => in_str = false,
                    b'{' if b.get(i + 1).is_some_and(|c| is_ident(*c)) => {
                        let n = site[i + 1..].bytes().take_while(|c| is_ident(*c)).count();
                        out.push(&site[i + 1..i + 1 + n]);
                        i += n;
                    }
                    _ => {}
                }
                i += 1;
            } else if b[i] == b'"' {
                in_str = true;
                i += 1;
            } else if is_ident(b[i]) {
                let n = site[i..].bytes().take_while(|c| is_ident(*c)).count();
                out.push(&site[i..i + n]);
                i += n;
            } else {
                i += 1;
            }
        }
        out
    }

    /// `(sites scanned, violations)` for `src` with `banned` identifiers.
    fn scan(src: &str, banned: &[&str]) -> (usize, Vec<String>) {
        let stripped = code_only(src);
        let prod = production_half(&stripped);
        let mut bad = Vec::new();
        let found = sites(prod);
        for site in &found {
            for id in idents(site) {
                if banned.contains(&id) {
                    bad.push(format!("`{id}` in: {site}"));
                }
            }
        }
        (found.len(), bad)
    }

    /// No identifier that holds a plaintext authorization code, verifier or
    /// token (or a value carrying one: the parsed form, the redeem request, the
    /// issued pair) appears in a `tracing::`/`log::` call, `println!`,
    /// `eprintln!`, `dbg!`, `with_extra(`, an `AuditEntry` constructor or field
    /// assignment, or a module-local `audit…(` helper call. Identifiers are
    /// matched whole, so `locale` or `grant_id` do not count; log messages may
    /// therefore use the words.
    #[test]
    fn plaintext_code_never_reaches_logs_or_audit() {
        let files: [(&str, &str, &[&str], usize); 9] = [
            (
                "consent.rs",
                include_str!("consent.rs"),
                &["code", "loc", "location", "csrf", "body"],
                5,
            ),
            (
                "token.rs",
                include_str!("token.rs"),
                &[
                    "code",
                    "presented",
                    "hash",
                    "p",
                    "req",
                    "t",
                    "tokens",
                    "body",
                    "verifier",
                    "refresh_token",
                    "access_token",
                ],
                8,
            ),
            (
                "refresh.rs",
                include_str!("refresh.rs"),
                &[
                    "presented_hash",
                    "token_hash",
                    "t",
                    "tokens",
                    "refresh_token",
                    "access_token",
                ],
                2,
            ),
            (
                "revoke.rs",
                include_str!("revoke.rs"),
                &["presented", "p", "body", "token"],
                4,
            ),
            (
                "rs_layer.rs",
                include_str!("rs_layer.rs"),
                &[
                    "token",
                    "raw",
                    "req",
                    "parts",
                    "headers",
                    "access",
                    "bearer",
                    "auth",
                    "authorization",
                    "value",
                    "hv",
                    "cookie",
                ],
                7,
            ),
            (
                "account_audit.rs",
                include_str!("../../mcp/account_audit.rs"),
                &["token", "access", "bearer", "ticket", "secret", "password"],
                4,
            ),
            // No log or audit site today; the list applies to the first one added.
            (
                "store.rs",
                include_str!("store.rs"),
                &["ticket", "token", "presented", "ticket_hash", "hash"],
                0,
            ),
            (
                "uploads/ticket.rs",
                include_str!("../../tenant/uploads/ticket.rs"),
                &["presented", "ticket", "bearer", "ticket_hash", "hash"],
                12,
            ),
            (
                "account.rs",
                include_str!("../../mcp/account.rs"),
                &[
                    "issued",
                    "bearer",
                    "reply",
                    "plaintext",
                    "ticket",
                    "authorization",
                ],
                22,
            ),
        ];
        for (name, src, banned, min) in files {
            let (n, bad) = scan(src, banned);
            assert!(bad.is_empty(), "{name}: {bad:#?}");
            assert!(
                n >= min,
                "{name}: only {n} log/audit sites scanned (want >= {min})"
            );
        }
    }

    /// The entry gates read caller-controlled Host and Origin strings and
    /// write no log line at all, so neither can reach a log.
    #[test]
    fn entry_gates_write_no_log_lines() {
        let (n, _) = scan(include_str!("route_layer.rs"), &[]);
        assert_eq!(n, 0, "route_layer.rs: {n} log/audit sites, want 0");
    }

    /// The scanner itself can fail: each planted leak is caught, and the same
    /// text in a comment or as plain message words is not.
    #[test]
    fn the_hygiene_scanner_flags_planted_leaks() {
        let bad = r#"
fn f() {
    tracing::warn!(code = %code, "x");
    tracing::debug!("got {code:?} here");
    e.actor_email_snapshot = Some(code.to_string());
    e = e.with_extra(serde_json::json!({ "c": code }));
    let e = crate::safety::audit::AuditEntry::failure("-", "-", "op", 0, "x", code);
    audit_thing(s, code).await;
    eprintln!("{}", code);
    dbg!(code);
    log::info!("{}", code);
}
"#;
        let (n, found) = scan(bad, &["code"]);
        assert_eq!(n, 9, "sites: {found:#?}");
        // Every site is flagged; the first one twice (field and value).
        assert_eq!(found.len(), 10, "{found:#?}");
        let good = r#"
fn f() {
    // tracing::warn!(code = %code);
    tracing::warn!(grant_id = g, "authorization code replay");
    e.auth_method = Some("mcp_oauth".to_string());
    if x.status == code { }
}
"#;
        let (n, found) = scan(good, &["code"]);
        assert_eq!(n, 2, "a comment and a comparison are not sites");
        assert!(found.is_empty(), "{found:#?}");
    }

    /// `GrantOwner::caller` trusts the `AdminId` it is handed, so under this
    /// directory `AdminId(` appears only in an extractor's destructuring
    /// pattern (`Extension(AdminId(…))`), never built from a path, form or
    /// query value.
    #[test]
    fn admin_id_is_only_ever_destructured_from_the_extension() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mgmt/mcp_oauth");
        let mut files = Vec::new();
        crate::tenant::rooms::srcpin::collect_rs_files(&dir, &mut files);
        let mut seen = 0;
        for f in files {
            let src = std::fs::read_to_string(&f).unwrap();
            let stripped = code_only(&src);
            let prod = production_half(&stripped);
            let b = prod.as_bytes();
            for (i, _) in prod.match_indices("AdminId(") {
                if i > 0 && is_ident(b[i - 1]) {
                    continue; // another identifier ending in AdminId
                }
                seen += 1;
                assert!(
                    prod[..i].ends_with("Extension("),
                    "{}: `AdminId(` outside `Extension(AdminId(`: {}",
                    f.display(),
                    &prod[i.saturating_sub(40)..(i + 40).min(prod.len())]
                );
            }
        }
        assert!(seen >= 4, "only {seen} AdminId( sites found");
    }

    /// The no-post-commit-step claim for MCP OAuth revocation holds only while
    /// no MCP token is cached: a cache added here makes every revoke_mcp_grant
    /// caller responsible for evicting it. Each file's last production item is
    /// an anchor: a `#[cfg(test)]` item placed above production code would cut
    /// the scanned half short and hide what follows it.
    #[test]
    fn mcp_tokens_never_enter_a_cache() {
        let files = [
            (
                "rs_layer.rs",
                include_str!("rs_layer.rs"),
                "async fn mcp_oauth_auth_layer(",
            ),
            (
                "caller.rs",
                include_str!("caller.rs"),
                "pub fn admin_label(",
            ),
            (
                "store.rs",
                include_str!("store.rs"),
                "pub fn issue_upload_ticket_for_tests(",
            ),
            (
                "account_routes.rs",
                include_str!("account_routes.rs"),
                "pub fn account_routes(",
            ),
            (
                "../../mcp/account.rs",
                include_str!("../../mcp/account.rs"),
                "async fn call_tool(",
            ),
        ];
        for (name, src, anchor) in files {
            let code = code_only(src);
            let prod = production_half(&code);
            assert!(prod.contains(anchor), "{name}: scan stops before {anchor}");
            for needle in ["DashMap", "auth_cache", "moka"] {
                assert!(!prod.contains(needle), "{name} names {needle}");
            }
        }
    }

    /// rmcp handlers hold a RequestContext that can reach the peer; the push
    /// scan (mcp::handler capabilities_tests) covers src/mcp only, so no
    /// handler may live in this directory.
    #[test]
    fn no_mcp_handler_lives_under_mcp_oauth() {
        let needles = [concat!("Server", "Handler"), concat!("Request", "Context")];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mgmt/mcp_oauth");
        let mut files = Vec::new();
        crate::tenant::rooms::srcpin::collect_rs_files(&root, &mut files);
        assert!(
            files.len() > 20,
            "scan found too few files: {}",
            files.len()
        );
        for f in &files {
            let code = code_only(&std::fs::read_to_string(f).unwrap());
            for n in needles {
                assert!(
                    !production_half(&code).contains(n),
                    "{} names {n}",
                    f.display()
                );
            }
        }
    }

    /// `production_half` stops at a file's first `#[cfg(test)]`, so a
    /// test-only item above production code would silently shorten every pin
    /// over that file; every test-only item here must trail the production
    /// code.
    #[test]
    fn test_only_items_trail_production_code() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        crate::tenant::rooms::srcpin::collect_rs_files(
            &manifest.join("src/mgmt/mcp_oauth"),
            &mut files,
        );
        files.push(manifest.join("src/mcp/account.rs"));
        assert!(
            files.len() > 20,
            "scan found too few files: {}",
            files.len()
        );
        for f in &files {
            let code = code_only(&std::fs::read_to_string(f).unwrap());
            if let Some((line, text)) =
                crate::tenant::rooms::srcpin::production_after_test_gate(&code)
            {
                panic!(
                    "{}:{line}: `{}` follows the file's first #[cfg(test)] and is not a \
                     test-only item (or its shape cannot be classified); move test-only items \
                     below the last production item",
                    f.display(),
                    text.trim()
                );
            }
        }
    }
}

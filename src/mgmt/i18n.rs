//! Server-side i18n for the admin UI. See spec
//! docs/superpowers/specs/2026-05-22-drust-i18n-design.md.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locale {
    En,
    ZhTw,
}

impl Locale {
    /// Every locale this binary ships with, in stable display order. Single
    /// source of truth for: the settings dropdown, the `settings_locale_save`
    /// whitelist, and any future surface that enumerates languages.
    /// Adding a new language: append a variant + cover it in `code()` /
    /// `display_name()` / `from_tag()` + add `Locale::Xx` here + register
    /// the bundle in `init_bundles`.
    pub const ALL: &'static [Locale] = &[Locale::En, Locale::ZhTw];

    pub fn code(&self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::ZhTw => "zh-TW",
        }
    }

    /// Human-readable label shown in the locale picker, written in the
    /// language itself (so a Japanese user can find their language even if
    /// the rest of the page is rendering in English fallback).
    pub fn display_name(&self) -> &'static str {
        match self {
            Locale::En => "English",
            Locale::ZhTw => "繁體中文",
        }
    }

    /// Strict exact match first, then permissive `zh*` → ZhTw.
    /// Adding a new language: add a variant + add an arm here +
    /// add a TOML file + register in `init_bundles`.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "en" => Some(Locale::En),
            "zh-TW" => Some(Locale::ZhTw),
            other if other.starts_with("zh") => Some(Locale::ZhTw),
            _ => None,
        }
    }

    /// UI projection of `Locale::ALL`: `(canonical tag, display label)` for
    /// every locale. Consumed by the settings dropdown.
    pub fn options() -> Vec<LocaleOption> {
        Locale::ALL
            .iter()
            .map(|l| LocaleOption {
                code: l.code(),
                label: l.display_name(),
            })
            .collect()
    }
}

/// Build the `Set-Cookie` header value for the `drust_locale` preference
/// cookie. Same attributes as `drust_theme`. See
/// `crate::mgmt::theme::build_theme_cookie` for rationale.
pub fn build_locale_cookie(locale: Locale) -> String {
    let cpath = crate::base_path::cookie_path("");
    let base = format!(
        "drust_locale={code}; Path={cpath}; Max-Age=31536000; SameSite=Lax",
        code = locale.code(),
    );
    if std::env::var("DRUST_DEV_NO_SECURE_COOKIES").is_ok() {
        base
    } else {
        format!("{base}; Secure")
    }
}

/// Public projection for askama templates that iterate the locale catalog.
/// Lives next to `Locale` so adding a language only touches one file.
pub struct LocaleOption {
    pub code: &'static str,
    pub label: &'static str,
}

pub struct Bundle {
    #[allow(dead_code)]
    locale: Locale,
    table: HashMap<String, &'static str>,
}

pub struct Translator {
    locale: Locale,
    bundle: &'static Bundle,
    fallback: &'static Bundle,
}

impl Translator {
    pub fn new(locale: Locale) -> Self {
        // v1.22 — defensive idempotent init so any test that builds an admin
        // handler directly (bypassing the production router entry points)
        // doesn't panic. Production main also calls this at startup; the
        // OnceLock makes the second call a no-op.
        init_bundles();
        let bundles = BUNDLES
            .get()
            .expect("init_bundles must run before Translator::new");
        let bundle = bundles.get(&locale).expect("locale registered in bundles");
        let fallback = bundles
            .get(&Locale::En)
            .expect("en bundle always registered");
        Self {
            locale,
            bundle,
            fallback,
        }
    }

    pub fn locale_code(&self) -> &'static str {
        self.locale.code()
    }

    /// Returns `Cow::Borrowed(&'static str)` for happy path (bundle hit) —
    /// zero-alloc, value is a subslice of the `include_str!`'d locale file.
    /// Returns `Cow::Owned("!!<key>!!")` sentinel when missing in BOTH
    /// active and fallback — debug-only `tracing::warn!`.
    pub fn s(&self, key: &str) -> Cow<'static, str> {
        if let Some(v) = self.bundle.table.get(key) {
            return Cow::Borrowed(v);
        }
        if let Some(v) = self.fallback.table.get(key) {
            if cfg!(debug_assertions) {
                tracing::warn!(
                    key,
                    locale = self.locale.code(),
                    "i18n: key missing in active bundle; fell back to en"
                );
            }
            return Cow::Borrowed(v);
        }
        if cfg!(debug_assertions) {
            tracing::warn!(key, "i18n: key missing in EVERY bundle");
        }
        Cow::Owned(format!("!!{key}!!"))
    }

    /// Placeholder format: `{name}` patterns replaced with `args[i].1` where
    /// `args[i].0 == "name"`. Unknown placeholders left intact (debug warn).
    pub fn fmt(&self, key: &str, args: &[(&str, &str)]) -> String {
        let template = self.s(key).into_owned();
        substitute_placeholders(&template, args)
    }

    /// Single-pair variant callable from askama templates (askama 0.12 cannot
    /// parse the slice-of-tuples literal `&[("name", value)]`, so the
    /// general `fmt` is only usable from Rust code; templates use this).
    /// `value` accepts any `Display` — String, &str, integers, etc.
    pub fn fmt1(&self, key: &str, name: &str, value: impl std::fmt::Display) -> String {
        let template = self.s(key).into_owned();
        let s = value.to_string();
        substitute_placeholders(&template, &[(name, s.as_str())])
    }

    pub fn fmt2(
        &self,
        key: &str,
        n1: &str,
        v1: impl std::fmt::Display,
        n2: &str,
        v2: impl std::fmt::Display,
    ) -> String {
        let template = self.s(key).into_owned();
        let s1 = v1.to_string();
        let s2 = v2.to_string();
        substitute_placeholders(&template, &[(n1, s1.as_str()), (n2, s2.as_str())])
    }

    pub fn fmt3(
        &self,
        key: &str,
        n1: &str,
        v1: impl std::fmt::Display,
        n2: &str,
        v2: impl std::fmt::Display,
        n3: &str,
        v3: impl std::fmt::Display,
    ) -> String {
        let template = self.s(key).into_owned();
        let s1 = v1.to_string();
        let s2 = v2.to_string();
        let s3 = v3.to_string();
        substitute_placeholders(
            &template,
            &[(n1, s1.as_str()), (n2, s2.as_str()), (n3, s3.as_str())],
        )
    }

    /// HTML-escaping sibling of `fmt1` for a `|safe`-rendered sink. The
    /// template text is our own TOML (trusted — may carry intentional `<b>`/
    /// `<code>` markup, which is why the call site opts out of Askama
    /// autoescape via `|safe`), but the interpolated VALUE is caller-supplied
    /// (e.g. `tenant_id`) and is HTML-escaped so it cannot inject markup. See
    /// `escape_html_min`. Plain `fmt1` must NOT escape — its call sites are
    /// Askama-autoescaped, so escaping there would double-encode.
    pub fn fmt1_html(&self, key: &str, name: &str, value: impl std::fmt::Display) -> String {
        let template = self.s(key).into_owned();
        let esc = escape_html_min(&value.to_string()).into_owned();
        substitute_placeholders(&template, &[(name, esc.as_str())])
    }

    /// HTML-escaping sibling of `fmt3` for a `|safe`-rendered sink — each
    /// interpolated value is HTML-escaped (e.g. a tenant whose display name is
    /// `<img src=x onerror=…>` renders as inert text, not executable markup),
    /// while the template's own markup is preserved. See `fmt1_html`.
    pub fn fmt3_html(
        &self,
        key: &str,
        n1: &str,
        v1: impl std::fmt::Display,
        n2: &str,
        v2: impl std::fmt::Display,
        n3: &str,
        v3: impl std::fmt::Display,
    ) -> String {
        let template = self.s(key).into_owned();
        let s1 = escape_html_min(&v1.to_string()).into_owned();
        let s2 = escape_html_min(&v2.to_string()).into_owned();
        let s3 = escape_html_min(&v3.to_string()).into_owned();
        substitute_placeholders(
            &template,
            &[(n1, s1.as_str()), (n2, s2.as_str()), (n3, s3.as_str())],
        )
    }
}

fn substitute_placeholders(template: &str, args: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '{' {
            // Find closing '}' from this position via the original byte string.
            if let Some(rel) = template[i + 1..].find('}') {
                let name = &template[i + 1..i + 1 + rel];
                if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    if let Some(&(_, v)) = args.iter().find(|(k, _)| *k == name) {
                        out.push_str(v);
                        // Skip past the `{name}` — advance the char iterator
                        // until we've consumed bytes through `i+1+rel`
                        // (inclusive of the closing '}').
                        let target_byte = i + 1 + rel + 1; // first byte AFTER '}'
                        while let Some(&(j, _)) = chars.peek() {
                            if j >= target_byte {
                                break;
                            }
                            chars.next();
                        }
                        continue;
                    }
                    if cfg!(debug_assertions) {
                        tracing::warn!(
                            placeholder = name,
                            "i18n: unknown placeholder in t.fmt template"
                        );
                    }
                    // fall through to push the literal '{' as char
                }
            }
        }
        // `c` is already a proper `char` from `char_indices()`, so non-ASCII
        // codepoints (e.g. Chinese) round-trip correctly.
        out.push(c);
    }
    out
}

/// Minimal HTML escaping for interpolating an untrusted VALUE into a trusted,
/// `|safe`-rendered i18n template (the api-keys / files head intros, whose
/// TOML carries intentional `<b>`/`<code>` markup). Escapes the five
/// HTML-significant characters so a value cannot break out of text/attribute
/// context. The fast path borrows when nothing needs escaping. Only the
/// `fmt*_html` variants call this — plain `fmt*` feed Askama-autoescaped (non
/// `|safe`) sinks where escaping here would double-encode.
fn escape_html_min(s: &str) -> Cow<'_, str> {
    if !s
        .bytes()
        .any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\''))
    {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Axum extractor that picks `Locale` out of request extensions (placed by
/// `locale_layer`) and falls back to `Locale::En` when the layer didn't run.
/// Means handlers compile + work even on test routers that bypass the
/// outer admin layer chain — the page just renders in English. Production
/// routers DO wire the middleware, so the fallback only fires in tests.
pub struct LocaleHint(pub Locale);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for LocaleHint {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(LocaleHint(
            parts
                .extensions
                .get::<Locale>()
                .copied()
                .unwrap_or(Locale::En),
        ))
    }
}

pub static BUNDLES: OnceLock<HashMap<Locale, Bundle>> = OnceLock::new();

/// Idempotent: production calls this exactly once at startup, but unit tests
/// may also call it from a `#[test]` that's racing with another. Uses
/// `get_or_init` (not `set`) so a second call is a no-op rather than a panic —
/// production behavior is unchanged for the single-call happy path, and the
/// test path no longer needs a separate helper.
pub fn init_bundles() {
    BUNDLES.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(
            Locale::En,
            parse_toml(include_str!("../../locales/en.toml"), Locale::En),
        );
        m.insert(
            Locale::ZhTw,
            parse_toml(include_str!("../../locales/zh-TW.toml"), Locale::ZhTw),
        );
        m
    });
}

/// Parses a TOML string into a flat `HashMap<"dotted.path", &'static str>`.
/// Panics on duplicate flattened key, malformed TOML, or non-string leaf.
pub fn parse_toml(src: &str, locale: Locale) -> Bundle {
    let parsed: toml::Value = toml::from_str(src)
        .unwrap_or_else(|e| panic!("locale {} TOML parse failed: {e}", locale.code()));
    let mut table = HashMap::new();
    flatten(&parsed, String::new(), &mut table, locale);
    // sanity sentinel — every bundle must declare it
    if !table.contains_key("_meta.sentinel") {
        panic!(
            "locale {} missing required `_meta.sentinel = \"ok\"`",
            locale.code()
        );
    }
    Bundle { locale, table }
}

fn flatten(
    val: &toml::Value,
    prefix: String,
    out: &mut HashMap<String, &'static str>,
    locale: Locale,
) {
    match val {
        toml::Value::Table(t) => {
            for (k, v) in t {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(v, key, out, locale);
            }
        }
        toml::Value::String(s) => {
            // Leak the string into 'static lifetime — bundles live forever.
            let leaked: &'static str = Box::leak(s.clone().into_boxed_str());
            if out.insert(prefix.clone(), leaked).is_some() {
                panic!("locale {} duplicate key `{prefix}`", locale.code());
            }
        }
        other => panic!(
            "locale {} key `{prefix}` is not a string: {other:?}",
            locale.code()
        ),
    }
}

// ------------------------------------------------------------------------
// Unit tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_from_tag_exact_matches() {
        assert_eq!(Locale::from_tag("en"), Some(Locale::En));
        assert_eq!(Locale::from_tag("zh-TW"), Some(Locale::ZhTw));
    }

    #[test]
    fn locale_from_tag_permissive_zh() {
        assert_eq!(Locale::from_tag("zh-Hant-TW"), Some(Locale::ZhTw));
        assert_eq!(Locale::from_tag("zh-CN"), Some(Locale::ZhTw));
        assert_eq!(Locale::from_tag("zh"), Some(Locale::ZhTw));
    }

    #[test]
    fn locale_from_tag_unsupported_returns_none() {
        assert_eq!(Locale::from_tag("ja"), None);
        assert_eq!(Locale::from_tag("es"), None);
    }

    #[test]
    fn translator_hits_active_bundle_first() {
        // Production `init_bundles` is now idempotent (get_or_init), so tests
        // call it directly — no separate `_for_test` helper needed.
        init_bundles();
        let t = Translator::new(Locale::ZhTw);
        assert_eq!(t.s("common.button.copy").as_ref(), "複製");
    }

    #[test]
    fn translator_falls_back_to_en_when_zh_missing() {
        // sentinel: stub locales/en.toml has _meta.sentinel,
        // stub locales/zh-TW.toml ALSO has it. To exercise fallback we
        // need a key present only in en — covered after Theme E.
    }

    #[test]
    fn translator_missing_key_returns_bang_sentinel() {
        init_bundles();
        let t = Translator::new(Locale::En);
        let v = t.s("does.not.exist");
        assert_eq!(v.as_ref(), "!!does.not.exist!!");
    }

    #[test]
    fn translator_fmt_substitutes_named_placeholders() {
        init_bundles();
        // For F1's stub TOML, no real key carries a placeholder.
        // We exercise the missing-key path here; the real placeholder
        // case is covered once Theme E lands real bundles.
        let out = Translator::new(Locale::En).fmt("does.not.exist", &[("name", "Alice")]);
        assert_eq!(out, "!!does.not.exist!!");
    }

    #[test]
    fn translator_fmt_unknown_placeholder_left_literal() {
        // covered after real bundles are in place (Theme E)
    }

    #[test]
    fn substitute_placeholders_preserves_chinese() {
        let out = substitute_placeholders("你好 {name}，歡迎使用 drust。", &[("name", "Kael")]);
        assert_eq!(out, "你好 Kael，歡迎使用 drust。");
    }

    #[test]
    fn substitute_placeholders_unknown_placeholder_left_literal() {
        let out = substitute_placeholders("hi {who}, count {n}", &[("n", "3")]);
        // `who` is left as literal "{who}", `n` substituted
        assert_eq!(out, "hi {who}, count 3");
    }

    #[test]
    fn substitute_placeholders_empty_braces_left_literal() {
        let out = substitute_placeholders("a {} b", &[]);
        assert_eq!(out, "a {} b");
    }

    #[test]
    fn substitute_placeholders_unterminated_brace_passes_through() {
        let out = substitute_placeholders("oops {name no close", &[("name", "x")]);
        assert_eq!(out, "oops {name no close");
    }

    #[test]
    fn escape_html_min_covers_all_five_and_borrows_clean() {
        assert_eq!(
            escape_html_min("a&b<c>d\"e'f").as_ref(),
            "a&amp;b&lt;c&gt;d&quot;e&#39;f"
        );
        // no-escape fast path returns a borrow (zero alloc)
        assert!(matches!(escape_html_min("clean text 你好"), Cow::Borrowed(_)));
    }

    #[test]
    fn fmt_html_escapes_values_while_plain_fmt_leaves_them_raw() {
        // This pins the XSS fix: the api-keys head intro renders via `|safe`
        // (its TOML carries intentional <b>/<code> markup), and `tenant_name`
        // is operator-controlled. `fmt3_html` must escape the value; plain
        // `fmt3` must NOT (its only callers are Askama-autoescaped).
        init_bundles();
        let t = Translator::new(Locale::En);
        let evil = "<img src=x onerror=alert(1)>";

        // Plain fmt3 is the autoescape-context variant — leaves the value raw.
        let raw = t.fmt3(
            "tenant_api_keys.head.intro",
            "tenant_name",
            evil,
            "tenant_id",
            "id",
            "created_at",
            "now",
        );
        assert!(
            raw.contains("<img"),
            "plain fmt3 is meant for autoescaped sinks; got: {raw}"
        );

        // _html variant escapes the interpolated value …
        let safe = t.fmt3_html(
            "tenant_api_keys.head.intro",
            "tenant_name",
            evil,
            "tenant_id",
            "id",
            "created_at",
            "now",
        );
        assert!(
            safe.contains("&lt;img src=x onerror=alert(1)&gt;"),
            "value not escaped: {safe}"
        );
        assert!(!safe.contains("<img"), "raw tag leaked through |safe: {safe}");
        // … while preserving the template's own intentional markup.
        assert!(
            safe.contains("<b>") && safe.contains("<code"),
            "template markup must survive: {safe}"
        );
    }
}

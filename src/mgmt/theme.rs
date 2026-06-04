//! Server-side theming for the admin UI. See spec
//! docs/superpowers/specs/2026-05-23-drust-theme-design.md.
//!
//! Pattern mirrors src/mgmt/i18n.rs:
//!   Locale → Theme
//!   en/zh-TW bundles → cozy-dark/soft-light/system palettes
//!   t.s("key") → palette.ui["bg"] / palette.mascot[&'B']
//!
//! Theme::System is the one exception: it does NOT have its own palette.
//! palette_for(Theme::System) returns ResolvedPalette::System carrying
//! references to soft-light + cozy-dark palettes; downstream renders the
//! `@media (prefers-color-scheme: dark)` CSS branch.

use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Theme {
    /// Auto-switch by `prefers-color-scheme`. CSS uses an `@media` block;
    /// mascot palette branches client-side via `window.matchMedia` once at
    /// page boot. Pairs with the static themes named in `themes/system.toml`.
    System,
    /// Warm charcoal + apricot accent. v1.22 visual state, preserved
    /// pixel-identical via `themes/cozy-dark.toml`.
    CozyDark,
    /// Warm cream + rust accent. New in v1.23.
    SoftLight,
}

impl Theme {
    /// Every theme this binary ships with, in stable display order. Single
    /// source of truth for the settings dropdown, the `settings_theme_save`
    /// whitelist, and any future surface that enumerates themes.
    /// Adding a new theme: append a variant + cover `code()` /
    /// `display_name()` / `from_tag()` + add a `themes/<code>.toml` +
    /// register in `init_palettes`.
    pub const ALL: &'static [Theme] = &[Theme::System, Theme::CozyDark, Theme::SoftLight];

    pub fn code(&self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::CozyDark => "cozy-dark",
            Theme::SoftLight => "soft-light",
        }
    }

    /// Human-readable label shown in the picker. Hard-coded English brand
    /// strings, identical across locales (theme names don't translate — same
    /// posture as Locale::display_name).
    pub fn display_name(&self) -> &'static str {
        match self {
            Theme::System => "System (auto)",
            Theme::CozyDark => "Cozy Dark",
            Theme::SoftLight => "Soft Light",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "system" => Some(Theme::System),
            "cozy-dark" => Some(Theme::CozyDark),
            "soft-light" => Some(Theme::SoftLight),
            _ => None,
        }
    }

    /// UI projection of `Theme::ALL`: `(canonical code, display label)` for
    /// every theme. Consumed by the settings dropdown.
    pub fn options() -> Vec<ThemeOption> {
        Theme::ALL
            .iter()
            .map(|t| ThemeOption {
                code: t.code(),
                label: t.display_name(),
            })
            .collect()
    }
}

/// Build the `Set-Cookie` header value for the `drust_theme` preference
/// cookie. Aligned with `drust_session` attributes: `Path=/drust` (no
/// leak to /t/<id>/... tenant routes), `SameSite=Lax` (Strict breaks
/// OAuth callback chain — see project memory), `Secure` (production).
///
/// `DRUST_DEV_NO_SECURE_COOKIES=1` strips the `Secure` attribute so
/// dev workflow on plain-HTTP `127.0.0.1:47826` accepts cookie writes.
/// MUST NOT be set in production.
pub fn build_theme_cookie(theme: Theme) -> String {
    let base = format!(
        "drust_theme={code}; Path=/drust; Max-Age=31536000; SameSite=Lax",
        code = theme.code(),
    );
    if std::env::var("DRUST_DEV_NO_SECURE_COOKIES").is_ok() {
        base
    } else {
        format!("{base}; Secure")
    }
}

/// Public projection for askama templates that iterate the theme catalog.
/// Lives next to `Theme` so adding a theme only touches one file.
pub struct ThemeOption {
    pub code: &'static str,
    pub label: &'static str,
}

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Palette + ResolvedPalette + palette_for
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Palette {
    /// 12 keys: bg, bg-deep, surface, surface-2, surface-3, border,
    /// border-mid, border-strong, fg, fg-2, muted, muted-2.
    pub ui: BTreeMap<&'static str, &'static str>,
    /// 10 keys: accent, accent-2, accent-soft, accent-border, rust, warn,
    /// danger, info, mint, lilac.
    pub accent: BTreeMap<&'static str, &'static str>,
    /// 7 keys: B body, E eye, P nose, Z sleep z, R red/oops, S star, H
    /// rosier pink (synonym of P).
    pub mascot: BTreeMap<char, &'static str>,
}

#[derive(Debug)]
pub struct SystemPalette {
    pub light: &'static Palette,
    pub dark: &'static Palette,
}

#[derive(Debug)]
pub enum ResolvedPalette {
    Static(&'static Palette),
    System(SystemPalette),
}

pub static PALETTES: OnceLock<HashMap<Theme, Palette>> = OnceLock::new();

/// Idempotent: production calls this once at startup; tests may also call
/// it directly. Uses `get_or_init` so a second call is a no-op.
pub fn init_palettes() {
    PALETTES.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(
            Theme::CozyDark,
            parse_palette(include_str!("../../themes/cozy-dark.toml"), Theme::CozyDark),
        );
        m.insert(
            Theme::SoftLight,
            parse_palette(include_str!("../../themes/soft-light.toml"), Theme::SoftLight),
        );
        // Theme::System has no Palette of its own — its partners are
        // looked up from `themes/system.toml` at resolve time. Including
        // a stub here would invite accidental indirect reads.
        m
    });
}

/// Resolve the runtime palette for a theme. Panics if `init_palettes`
/// hasn't run AND a static partner is somehow missing (only possible if a
/// dev added a Theme variant without registering its TOML in
/// `init_palettes` — `build.rs` should have caught that already).
pub fn palette_for(theme: Theme) -> ResolvedPalette {
    init_palettes();
    let palettes = PALETTES.get().expect("init_palettes must run before palette_for");
    match theme {
        Theme::System => {
            let (light, dark) = system_partners();
            ResolvedPalette::System(SystemPalette {
                light: palettes.get(&light).unwrap_or_else(|| {
                    panic!("system.toml [system].light = `{}` but palette not loaded", light.code())
                }),
                dark: palettes.get(&dark).unwrap_or_else(|| {
                    panic!("system.toml [system].dark = `{}` but palette not loaded", dark.code())
                }),
            })
        }
        other => ResolvedPalette::Static(
            palettes
                .get(&other)
                .unwrap_or_else(|| panic!("palette for `{}` not loaded", other.code())),
        ),
    }
}

/// Parse the `[system]` section of `themes/system.toml` once and cache the
/// resolved partner pair. Build.rs validates the references at compile
/// time, so unwrap is safe.
fn system_partners() -> (Theme, Theme) {
    static SYS: OnceLock<(Theme, Theme)> = OnceLock::new();
    *SYS.get_or_init(|| {
        let src = include_str!("../../themes/system.toml");
        let val: toml::Value =
            toml::from_str(src).expect("themes/system.toml parse (build.rs should have caught)");
        let sys = val
            .get("system")
            .and_then(|v| v.as_table())
            .expect("themes/system.toml missing [system]");
        let light_code = sys
            .get("light")
            .and_then(|v| v.as_str())
            .expect("themes/system.toml [system].light missing");
        let dark_code = sys
            .get("dark")
            .and_then(|v| v.as_str())
            .expect("themes/system.toml [system].dark missing");
        (
            Theme::from_tag(light_code).expect("system.toml light partner unknown"),
            Theme::from_tag(dark_code).expect("system.toml dark partner unknown"),
        )
    })
}

/// Parse one static-theme TOML into a Palette. Panics on missing required
/// keys; build.rs runs the same checks pre-compile, so the panics are
/// developer-only safety nets.
fn parse_palette(src: &str, theme: Theme) -> Palette {
    let val: toml::Value =
        toml::from_str(src).unwrap_or_else(|e| panic!("theme {} TOML parse: {e}", theme.code()));

    let mut ui = BTreeMap::new();
    let ui_tab = val
        .get("ui")
        .and_then(|v| v.as_table())
        .unwrap_or_else(|| panic!("theme {} missing [ui]", theme.code()));
    for (k, v) in ui_tab {
        let s = v
            .as_str()
            .unwrap_or_else(|| panic!("theme {} [ui].{k} is not a string", theme.code()));
        let leaked_k: &'static str = Box::leak(k.clone().into_boxed_str());
        let leaked_v: &'static str = Box::leak(s.to_string().into_boxed_str());
        ui.insert(leaked_k, leaked_v);
    }

    let mut accent = BTreeMap::new();
    let accent_tab = val
        .get("accent")
        .and_then(|v| v.as_table())
        .unwrap_or_else(|| panic!("theme {} missing [accent]", theme.code()));
    for (k, v) in accent_tab {
        let s = v
            .as_str()
            .unwrap_or_else(|| panic!("theme {} [accent].{k} is not a string", theme.code()));
        let leaked_k: &'static str = Box::leak(k.clone().into_boxed_str());
        let leaked_v: &'static str = Box::leak(s.to_string().into_boxed_str());
        accent.insert(leaked_k, leaked_v);
    }

    let mut mascot = BTreeMap::new();
    let mascot_tab = val
        .get("mascot")
        .and_then(|v| v.as_table())
        .unwrap_or_else(|| panic!("theme {} missing [mascot]", theme.code()));
    for (k, v) in mascot_tab {
        let s = v
            .as_str()
            .unwrap_or_else(|| panic!("theme {} [mascot].{k} is not a string", theme.code()));
        let ch = k
            .chars()
            .next()
            .filter(|_| k.chars().count() == 1)
            .unwrap_or_else(|| panic!("theme {} [mascot] key `{k}` must be single char", theme.code()));
        let leaked_v: &'static str = Box::leak(s.to_string().into_boxed_str());
        mascot.insert(ch, leaked_v);
    }

    Palette { ui, accent, mascot }
}

// ---------------------------------------------------------------------------
// Axum extractor — picks Theme out of request extensions (placed by
// `theme_layer`), falls back to Theme::System if the layer didn't run
// (e.g. unit tests bypassing the outer admin chain).
// ---------------------------------------------------------------------------

pub struct ThemeHint(pub Theme);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ThemeHint {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(ThemeHint(
            parts
                .extensions
                .get::<Theme>()
                .copied()
                .unwrap_or(Theme::System),
        ))
    }
}

/// Bundle of fields every admin Template struct needs to render
/// _styles.html + _theme_palette.html correctly. Constructed once per
/// request by the handler, then spread into the Template struct via the
/// `From<&ThemeRenderCtx>` impls each consumer template needs.
///
/// We could shove a `pub theme_ctx: ThemeRenderCtx` field on every struct
/// instead — but askama 0.12 cannot dot-traverse into a sub-struct from
/// `{% include %}`d partials cleanly, so keeping the fields flat on the
/// Template struct is cheaper than fighting the parser.
pub struct ThemeRenderCtx {
    pub palette_resolved: ResolvedPalette,
    pub mascot_json_static: String,
    pub mascot_json_light: String,
    pub mascot_json_dark: String,
}

impl ThemeRenderCtx {
    pub fn build(theme: Theme) -> Self {
        let resolved = palette_for(theme);
        let (s, l, d) = match &resolved {
            ResolvedPalette::Static(p) => (mascot_to_json(&p.mascot), String::new(), String::new()),
            ResolvedPalette::System(sys) => (
                String::new(),
                mascot_to_json(&sys.light.mascot),
                mascot_to_json(&sys.dark.mascot),
            ),
        };
        ThemeRenderCtx {
            palette_resolved: resolved,
            mascot_json_static: s,
            mascot_json_light: l,
            mascot_json_dark: d,
        }
    }
}

fn mascot_to_json(m: &BTreeMap<char, &'static str>) -> String {
    // Map<char, &str> → JSON object. char keys serialize as 1-char strings.
    // Route through the canonical <script>-safe escaper so this island obeys
    // the same invariant as every other JSON-into-<script> embed (the
    // `_theme_palette.html` `|safe` interpolation). Palette values are
    // compile-time hex today, so the escaper is a no-op — but it makes a
    // future non-hex mascot value inert rather than a `</script>` breakout.
    let map: serde_json::Map<String, serde_json::Value> = m
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String((*v).to_string())))
        .collect();
    crate::mgmt::script_json::json_for_script(&map)
}

/// Serialize one Palette into a JSON object with `ui`/`accent`/`mascot`
/// sub-tables, used by the v1.23 settings page's live theme-preview JS.
fn palette_to_json_value(p: &Palette) -> serde_json::Value {
    use serde_json::Value;
    fn str_map(m: &BTreeMap<&'static str, &'static str>) -> serde_json::Map<String, Value> {
        m.iter()
            .map(|(k, v)| ((*k).to_string(), Value::String((*v).to_string())))
            .collect()
    }
    fn char_map(m: &BTreeMap<char, &'static str>) -> serde_json::Map<String, Value> {
        m.iter()
            .map(|(k, v)| (k.to_string(), Value::String((*v).to_string())))
            .collect()
    }
    serde_json::json!({
        "ui":     str_map(&p.ui),
        "accent": str_map(&p.accent),
        "mascot": char_map(&p.mascot),
    })
}

/// Build a JSON string containing every theme's palette for the v1.23
/// settings page client-side live-preview. Shape:
///   { "cozy-dark": {ui,accent,mascot}, "soft-light": {...},
///     "system":   { "light": {...}, "dark": {...} } }
/// The settings JS reads this on load + applies inline CSS overrides on
/// theme-select change, restores on Cancel.
pub fn build_all_themes_json() -> String {
    use serde_json::Value;
    let mut top = serde_json::Map::new();
    for t in Theme::ALL {
        let entry = match palette_for(*t) {
            ResolvedPalette::Static(p) => palette_to_json_value(p),
            ResolvedPalette::System(sys) => serde_json::json!({
                "light": palette_to_json_value(sys.light),
                "dark":  palette_to_json_value(sys.dark),
            }),
        };
        top.insert(t.code().to_string(), entry);
    }
    serde_json::to_string(&Value::Object(top)).expect("serialize all themes")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trip_for_every_variant() {
        for t in Theme::ALL {
            assert_eq!(Theme::from_tag(t.code()), Some(*t));
        }
    }

    #[test]
    fn all_contains_three_variants() {
        // Adding a new theme MUST bump this number — forces a touch of
        // Theme::ALL alongside the new variant, which forces from_tag /
        // code / display_name updates too.
        assert_eq!(Theme::ALL.len(), 3);
    }

    #[test]
    fn from_tag_unknown_returns_none() {
        assert_eq!(Theme::from_tag("ocean"), None);
        assert_eq!(Theme::from_tag(""), None);
        assert_eq!(Theme::from_tag("Cozy-Dark"), None); // case-sensitive
    }

    #[test]
    fn options_preserves_all_order() {
        let opts = Theme::options();
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0].code, "system");
        assert_eq!(opts[0].label, "System (auto)");
        assert_eq!(opts[1].code, "cozy-dark");
        assert_eq!(opts[2].code, "soft-light");
    }

    #[test]
    fn display_names_are_brand_strings_not_translation_keys() {
        // Sanity check: no theme display_name looks like a t.s() key.
        for t in Theme::ALL {
            let n = t.display_name();
            assert!(!n.contains('.'), "{n} looks like a key");
            assert!(!n.is_empty());
        }
    }

    #[test]
    fn init_palettes_is_idempotent() {
        init_palettes();
        init_palettes(); // second call: no panic
        let pal = PALETTES.get().expect("loaded");
        assert!(pal.contains_key(&Theme::CozyDark));
        assert!(pal.contains_key(&Theme::SoftLight));
        // System is NOT in PALETTES — it's resolved on demand from partners.
        assert!(!pal.contains_key(&Theme::System));
    }

    #[test]
    fn static_palette_has_full_tables() {
        match palette_for(Theme::CozyDark) {
            ResolvedPalette::Static(p) => {
                assert_eq!(p.ui.len(), 12, "ui keys");
                assert_eq!(p.accent.len(), 10, "accent keys");
                assert_eq!(p.mascot.len(), 7, "mascot keys");
                // Spot-check three known values from cozy-dark.toml.
                assert_eq!(*p.ui.get("bg").expect("bg"), "#1c1816");
                assert_eq!(*p.accent.get("accent").expect("accent"), "#e8a17c");
                assert_eq!(*p.mascot.get(&'B').expect("B"), "#0a0a0a");
            }
            _ => panic!("CozyDark must resolve to Static"),
        }
    }

    #[test]
    fn system_palette_resolves_to_two_partners() {
        match palette_for(Theme::System) {
            ResolvedPalette::System(sys) => {
                assert_eq!(*sys.light.ui.get("bg").expect("light bg"), "#faf4e8");
                assert_eq!(*sys.dark.ui.get("bg").expect("dark bg"), "#1c1816");
            }
            _ => panic!("System must resolve to System"),
        }
    }

    #[test]
    fn soft_light_mascot_body_is_brown_not_black() {
        // Regression: the visual distinguisher between dark and light is
        // that the mascot body changes. If anyone accidentally copies the
        // dark body color into soft-light.toml, this catches it.
        let pal = match palette_for(Theme::SoftLight) {
            ResolvedPalette::Static(p) => p,
            _ => panic!("static"),
        };
        let body = *pal.mascot.get(&'B').expect("B");
        assert_ne!(body, "#0a0a0a", "soft-light must not share body with cozy-dark");
    }

    #[test]
    fn all_themes_json_is_script_safe_and_still_valid_json() {
        let raw = build_all_themes_json();
        let safe = crate::mgmt::script_json::escape_json_for_script(&raw);
        assert!(!safe.contains("</"), "no live `</` may survive in the embed");
        // Escaping must not corrupt the payload — it still parses.
        let _: serde_json::Value = serde_json::from_str(&safe).expect("escaped themes JSON must parse");
    }

    #[test]
    fn mascot_to_json_is_script_safe_and_still_valid_json() {
        // Real palettes are hex-only, so feed a hostile value to prove the
        // canonical escaper is actually wired in: a `</script>` breakout must
        // come back inert yet still JSON.parse to the original string.
        let mut m: BTreeMap<char, &'static str> = BTreeMap::new();
        m.insert('x', "</script><img src=x onerror=alert(1)>");
        let out = mascot_to_json(&m);
        assert!(!out.contains("</"), "no live `</` may survive in the embed");
        let parsed: serde_json::Value =
            serde_json::from_str(&out).expect("escaped mascot JSON must parse");
        assert_eq!(
            parsed["x"], "</script><img src=x onerror=alert(1)>",
            "escaping must be lossless under JSON.parse"
        );
    }
}

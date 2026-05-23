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

/// Public projection for askama templates that iterate the theme catalog.
/// Lives next to `Theme` so adding a theme only touches one file.
pub struct ThemeOption {
    pub code: &'static str,
    pub label: &'static str,
}

// ---------------------------------------------------------------------------
// Palette + ResolvedPalette + palette_for — added in Task 3.
// (Stubs left here so the file compiles standalone; real impl in Task 3.)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) static PALETTES: OnceLock<()> = OnceLock::new();

// ---------------------------------------------------------------------------
// ThemeHint extractor — added in Task 6.
// ---------------------------------------------------------------------------

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
}

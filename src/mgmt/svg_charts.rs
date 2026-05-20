//! v1.17 — server-side SVG chart helpers for the audit log dashboard.
//!
//! All functions in this module are pure, deterministic, and depend
//! only on `std::fmt::Write`. Output is inline SVG markup with a fixed
//! viewBox so the CSS layer can scale via `width:100%`. Colors use
//! CSS custom properties (`var(--ok)` etc) with hex fallbacks; this
//! lets the admin design tokens drive theming without recompilation.

#[allow(unused_imports)]
use crate::mgmt::audit::{LatencyHistogram, TimeBucket};

pub(crate) const VIEWBOX_W: i32 = 800;
pub(crate) const VIEWBOX_H: i32 = 240;
pub(crate) const COLOR_2XX: &str = "var(--ok, #2ea043)";
pub(crate) const COLOR_4XX: &str = "var(--warn, #d29922)";
pub(crate) const COLOR_5XX: &str = "var(--err, #f85149)";
pub(crate) const COLOR_MUTED: &str = "var(--muted, #7d8590)";
pub(crate) const COLOR_ACCENT: &str = "var(--accent, #58a6ff)";

/// Build the empty-data placeholder SVG every chart function returns
/// when fed an empty input. Centralised so the no-data UX is uniform.
pub(crate) fn no_data_svg() -> String {
    format!(
        r#"<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" class="chart"><text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle" fill="{muted}" font-family="sans-serif" font-size="14">no data in this window</text></svg>"#,
        w = VIEWBOX_W,
        h = VIEWBOX_H,
        cx = VIEWBOX_W / 2,
        cy = VIEWBOX_H / 2,
        muted = COLOR_MUTED,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_data_svg_contains_expected_marker() {
        let s = no_data_svg();
        assert!(s.contains("<svg"));
        assert!(s.contains("no data in this window"));
        assert!(s.contains(VIEWBOX_W.to_string().as_str()));
    }
}

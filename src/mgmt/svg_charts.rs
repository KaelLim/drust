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

/// Render a stacked-area chart: 2xx (green) at bottom, 4xx (amber)
/// middle, 5xx (red) top. X axis = bucket index left to right (no
/// labels — surrounding UI carries the time range). Y axis = total
/// stack height, auto-scaled. The peak fills 80% of the viewBox
/// height so the top doesn't kiss the card edge.
pub fn stacked_area_chart(buckets: &[TimeBucket]) -> String {
    if buckets.is_empty() {
        return no_data_svg();
    }
    let max_total: u32 = buckets
        .iter()
        .map(|b| b.count_2xx + b.count_4xx + b.count_5xx)
        .max()
        .unwrap_or(0);
    if max_total == 0 {
        return no_data_svg();
    }
    let n = buckets.len();
    let plot_h = (VIEWBOX_H as f64) * 0.8;
    let baseline = VIEWBOX_H as f64; // y grows down; baseline at bottom
    // X coordinate for bucket i.
    let x_at = |i: usize| (i as f64) * (VIEWBOX_W as f64) / (n.saturating_sub(1).max(1) as f64);
    // Map count → pixel height from baseline.
    let h_at = |c: u32| (c as f64) * plot_h / (max_total as f64);

    // Build three polygons: from baseline up through each layer.
    // Each polygon is `M x0,baseline L x0,y0 L x1,y1 ... L xN,baseline Z`
    // where y_i = baseline - cumulative_height_through_this_layer.
    let build_path = |layer_top: Box<dyn Fn(&TimeBucket) -> u32>, color: &str| -> String {
        let mut d = String::new();
        d.push_str(&format!("M0,{baseline} "));
        for (i, b) in buckets.iter().enumerate() {
            let top_h = h_at(layer_top(b));
            d.push_str(&format!("L{:.2},{:.2} ", x_at(i), baseline - top_h));
        }
        d.push_str(&format!(
            "L{:.2},{baseline} Z",
            x_at(n.saturating_sub(1))
        ));
        format!(r#"<path d="{d}" fill="{color}" />"#)
    };

    // Painting order: SVG paints in document order, so we draw 5xx
    // (largest cumulative envelope) first, then 4xx on top, then 2xx
    // on top of that. Each polygon goes from baseline up to its own
    // cumulative top, so occlusion produces the correct visual stack:
    // 2xx green at the bottom, 4xx amber middle, 5xx red top.
    let path_2xx = build_path(Box::new(|b| b.count_2xx), COLOR_2XX);
    let path_4xx = build_path(Box::new(|b| b.count_2xx + b.count_4xx), COLOR_4XX);
    let path_5xx = build_path(
        Box::new(|b| b.count_2xx + b.count_4xx + b.count_5xx),
        COLOR_5XX,
    );

    format!(
        r#"<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" class="chart">{p5}{p4}{p2}</svg>"#,
        w = VIEWBOX_W,
        h = VIEWBOX_H,
        p5 = path_5xx,
        p4 = path_4xx,
        p2 = path_2xx,
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

    #[test]
    fn stacked_area_chart_empty_renders_no_data_placeholder() {
        let svg = stacked_area_chart(&[]);
        assert!(svg.contains("no data"));
    }

    #[test]
    fn stacked_area_chart_renders_three_paths() {
        let buckets = vec![
            TimeBucket {
                ts_unix: 0,
                count_2xx: 5,
                count_4xx: 2,
                count_5xx: 1,
            },
            TimeBucket {
                ts_unix: 60,
                count_2xx: 3,
                count_4xx: 4,
                count_5xx: 0,
            },
        ];
        let svg = stacked_area_chart(&buckets);
        // Three filled <path> elements, one per status class.
        let path_count = svg.matches("<path").count();
        assert_eq!(path_count, 3, "expected 3 paths, got SVG:\n{svg}");
    }

    #[test]
    fn stacked_area_chart_uses_status_colors() {
        let buckets = vec![TimeBucket {
            ts_unix: 0,
            count_2xx: 1,
            count_4xx: 1,
            count_5xx: 1,
        }];
        let svg = stacked_area_chart(&buckets);
        assert!(svg.contains(COLOR_2XX), "2xx color missing");
        assert!(svg.contains(COLOR_4XX), "4xx color missing");
        assert!(svg.contains(COLOR_5XX), "5xx color missing");
    }
}

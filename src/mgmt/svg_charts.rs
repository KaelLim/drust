//! v1.17 — server-side SVG chart helpers for the audit log dashboard.
//!
//! All functions in this module are pure, deterministic, and depend
//! only on `std::fmt::Write`. Output is inline SVG markup with a fixed
//! viewBox so the CSS layer can scale via `width:100%`. Colors use
//! CSS custom properties (`var(--ok)` etc) with hex fallbacks; this
//! lets the admin design tokens drive theming without recompilation.

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

/// Render horizontal bars: one row per item, each row a label (left),
/// a filled rect (middle), and the count (right). Used by both Top
/// error codes and Top tenants charts — the page handler converts
/// its typed input into `Vec<(String, u32)>` before calling.
///
/// If `items.len() > 10`, displays the first 10 and appends an
/// "+N more not shown" row to keep the chart legible.
pub fn horizontal_bars(items: &[(String, u32)]) -> String {
    if items.is_empty() {
        return no_data_svg();
    }
    let truncated = items.len() > 10;
    let shown: &[(String, u32)] = if truncated { &items[..10] } else { items };
    let max_count = shown.iter().map(|(_, c)| *c).max().unwrap_or(1).max(1);

    // Layout:
    // label column: 0..240 px (30%)
    // bar area:    250..720 px (~59%)
    // count column: 730..800 px (right-aligned)
    let label_x = 8;
    let bar_x = 250;
    let bar_max_w: f64 = 470.0;
    let count_x = VIEWBOX_W - 8;
    let row_h: f64 = if truncated {
        // 10 bars + 1 "more" row = 11 rows total
        VIEWBOX_H as f64 / 11.0
    } else {
        VIEWBOX_H as f64 / shown.len() as f64
    };
    let bar_h = row_h * 0.6;

    let mut body = String::new();
    for (i, (label, count)) in shown.iter().enumerate() {
        let row_top = (i as f64) * row_h;
        let row_mid = row_top + row_h / 2.0;
        let bar_y = row_top + (row_h - bar_h) / 2.0;
        let bar_w = (*count as f64) / (max_count as f64) * bar_max_w;
        body.push_str(&format!(
            r#"<text x="{label_x}" y="{row_mid:.1}" dominant-baseline="middle" fill="{COLOR_MUTED}" font-family="sans-serif" font-size="13">{label}</text>"#,
            label = xml_escape(label),
        ));
        body.push_str(&format!(
            r#"<rect x="{bar_x}" y="{bar_y:.1}" width="{bar_w:.2}" height="{bar_h:.1}" fill="{COLOR_ACCENT}" rx="2" />"#,
        ));
        body.push_str(&format!(
            r#"<text x="{count_x}" y="{row_mid:.1}" text-anchor="end" dominant-baseline="middle" fill="{COLOR_MUTED}" font-family="sans-serif" font-size="13">{count}</text>"#,
        ));
    }
    if truncated {
        let extra = items.len() - 10;
        let row_top = 10.0 * row_h;
        let row_mid = row_top + row_h / 2.0;
        body.push_str(&format!(
            r#"<text x="{label_x}" y="{row_mid:.1}" dominant-baseline="middle" fill="{COLOR_MUTED}" font-family="sans-serif" font-size="12" font-style="italic">+{extra} more not shown</text>"#,
        ));
    }

    format!(
        r#"<svg viewBox="0 0 {VIEWBOX_W} {VIEWBOX_H}" xmlns="http://www.w3.org/2000/svg" class="chart">{body}</svg>"#,
    )
}

/// XML-escape a label so user-supplied data (error_code strings,
/// tenant IDs) cannot break the SVG markup.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Render the 6-bucket latency histogram with p50/p95/p99 marker
/// lines. Bars colored by band: first three (≤200 ms) green, fourth
/// (200–1000) amber, fifth and sixth (1s+) red. X-axis labels show
/// upper bound of each band.
pub fn histogram_with_percentiles(hist: &LatencyHistogram) -> String {
    let total: u32 = hist.buckets.iter().sum();
    if total == 0 {
        return no_data_svg();
    }
    let max_count = *hist.buckets.iter().max().unwrap_or(&1).max(&1);

    // Reserve top 10% for percentile labels, bottom 18% for x-axis
    // labels. Bars live in the middle ~72%.
    let top_pad = (VIEWBOX_H as f64) * 0.10;
    let bottom_pad = (VIEWBOX_H as f64) * 0.18;
    let plot_h = VIEWBOX_H as f64 - top_pad - bottom_pad;
    let baseline = VIEWBOX_H as f64 - bottom_pad;

    let band_w = (VIEWBOX_W as f64) / 6.0;
    let bar_w = band_w * 0.7;
    let bar_pad = (band_w - bar_w) / 2.0;

    let band_colors = [
        COLOR_2XX, COLOR_2XX, COLOR_2XX, COLOR_4XX, COLOR_5XX, COLOR_5XX,
    ];
    let band_labels = ["10ms", "50ms", "200ms", "1s", "5s", "∞"];

    let mut body = String::new();

    // Bars
    for (i, &count) in hist.buckets.iter().enumerate() {
        let h = if max_count > 0 {
            (count as f64) / (max_count as f64) * plot_h
        } else {
            0.0
        };
        let x = (i as f64) * band_w + bar_pad;
        let y = baseline - h;
        body.push_str(&format!(
            r#"<rect x="{x:.2}" y="{y:.2}" width="{bar_w:.2}" height="{h:.2}" fill="{c}" rx="2" />"#,
            c = band_colors[i],
        ));
        // Band upper-bound label
        body.push_str(&format!(
            r#"<text x="{lx:.1}" y="{ly:.1}" text-anchor="middle" fill="{COLOR_MUTED}" font-family="sans-serif" font-size="11">{lbl}</text>"#,
            lx = (i as f64) * band_w + band_w / 2.0,
            ly = baseline + 14.0,
            lbl = band_labels[i],
        ));
    }

    // Percentile marker lines. Convert ms → x by mapping into the
    // log-scale axis: each band covers one ×~5 multiplier
    // (10→50→200→1000→5000), so an evenly-spaced log scale aligns
    // band edges to multiples of band_w.
    let x_for_ms = |ms: u64| -> f64 {
        let edges_ms: [u64; 7] = [0, 10, 50, 200, 1000, 5000, u64::MAX];
        for i in 0..6 {
            let lo = edges_ms[i];
            let hi = edges_ms[i + 1];
            if ms <= hi {
                let base = (i as f64) * band_w;
                if hi == u64::MAX {
                    return base + band_w / 2.0; // can't interpolate ∞
                }
                let span = (hi - lo) as f64;
                let frac = if span > 0.0 {
                    (ms.saturating_sub(lo) as f64) / span
                } else {
                    0.0
                };
                return base + frac * band_w;
            }
        }
        VIEWBOX_W as f64
    };

    for (label, ms) in [("p50", hist.p50_ms), ("p95", hist.p95_ms), ("p99", hist.p99_ms)] {
        let x = x_for_ms(ms);
        body.push_str(&format!(
            r#"<line x1="{x:.1}" y1="{top_pad:.1}" x2="{x:.1}" y2="{baseline:.1}" stroke="{COLOR_MUTED}" stroke-width="1" stroke-dasharray="4 3" />"#,
        ));
        body.push_str(&format!(
            r#"<text x="{x:.1}" y="{ly:.1}" text-anchor="middle" fill="{COLOR_MUTED}" font-family="sans-serif" font-size="10">{label}</text>"#,
            ly = top_pad - 4.0,
        ));
    }

    format!(
        r#"<svg viewBox="0 0 {VIEWBOX_W} {VIEWBOX_H}" xmlns="http://www.w3.org/2000/svg" class="chart">{body}</svg>"#,
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

    #[test]
    fn horizontal_bars_empty_renders_placeholder() {
        let svg = horizontal_bars(&[]);
        assert!(svg.contains("no data"));
    }

    #[test]
    fn horizontal_bars_truncates_at_10() {
        let items: Vec<(String, u32)> = (0..15)
            .map(|i| (format!("code-{i:02}"), 1))
            .collect();
        let svg = horizontal_bars(&items);
        assert!(
            svg.contains("+5 more not shown"),
            "expected truncation marker, got SVG:\n{svg}"
        );
    }

    #[test]
    fn horizontal_bars_rect_widths_proportional() {
        let items = vec![("a".to_string(), 100), ("b".to_string(), 50)];
        let svg = horizontal_bars(&items);
        // Both rects should appear; "a" should have ~2× the width of "b".
        // We grep for two rect elements and inspect their `width="..."`.
        let mut widths: Vec<f64> = Vec::new();
        for cap in svg.split("<rect").skip(1) {
            // Find width="..."
            let after = match cap.split_once(r#"width=""#) {
                Some(x) => x.1,
                None => continue,
            };
            let end = after.find('"').unwrap();
            let w: f64 = after[..end].parse().unwrap();
            widths.push(w);
        }
        assert_eq!(widths.len(), 2, "expected 2 rect widths, got {widths:?}");
        let ratio = widths[0] / widths[1];
        assert!(
            (ratio - 2.0).abs() < 0.01,
            "expected ratio ~2.0, got {ratio} from widths {widths:?}"
        );
    }

    #[test]
    fn histogram_with_percentiles_renders_six_bars() {
        let hist = LatencyHistogram {
            buckets: [5, 10, 15, 3, 1, 0],
            p50_ms: 30,
            p95_ms: 800,
            p99_ms: 3000,
        };
        let svg = histogram_with_percentiles(&hist);
        let rect_count = svg.matches("<rect").count();
        assert_eq!(rect_count, 6, "expected 6 bars, got SVG:\n{svg}");
    }

    #[test]
    fn histogram_with_percentiles_shows_three_marker_lines() {
        let hist = LatencyHistogram {
            buckets: [1, 1, 1, 1, 1, 1],
            p50_ms: 30,
            p95_ms: 800,
            p99_ms: 3000,
        };
        let svg = histogram_with_percentiles(&hist);
        let dash_count = svg.matches("stroke-dasharray").count();
        assert_eq!(dash_count, 3, "expected 3 dashed percentile lines");
    }

    #[test]
    fn histogram_with_percentiles_empty_renders_placeholder() {
        let hist = LatencyHistogram::default();
        let svg = histogram_with_percentiles(&hist);
        assert!(svg.contains("no data"));
    }
}

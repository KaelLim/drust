// Compile-time admin-UI consistency gates (spec 2026-07-20).
//
// PURE functions only — no I/O, no `panic!`. `build.rs` does the file
// reading and turns violations into a build failure; the same file is
// mounted into the lib under `cfg(test)` (`src/lib.rs`) so the suite can
// exercise every rule. build.rs itself is never covered by `cargo test`,
// which is why the logic lives here instead of inline in build.rs.
//
// NOTE: plain `//` comments, NOT `//!` module docs. build.rs pulls this file
// in with `include!`, which splices it in *after* items — an inner doc
// comment there is a hard parse error (E0753).

/// One rule violation. `file` is the template's file name (not a full path),
/// `line` is 1-indexed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub file: String,
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
}

impl Violation {
    #[allow(dead_code)]
    fn new(file: &str, line: usize, rule: &'static str, message: String) -> Self {
        Violation {
            file: file.to_string(),
            line,
            rule,
            message,
        }
    }
}

/// Files that legitimately define colours and icons — the source of the
/// design tokens themselves. Gate 1 (raw hex) does not scan these.
#[allow(dead_code)]
pub const COLOUR_SOURCE_FILES: &[&str] = &[
    "_styles.html",
    "_theme_palette.html",
    "_mascot.html",
    "_icons.html",
    "_favicon.html",
];

/// Concatenate the contents of every `<style>…</style>` block in a template.
///
/// The class gate must compare against CSS ONLY. Handing it whole template
/// source would let JS property access masquerade as a class definition —
/// `el.classList.add(…)` contains `.classList`, which would register
/// "classList" as a defined class and mask a genuine ghost.
pub fn extract_style_blocks(content: &str) -> String {
    let mut out = String::new();
    let mut rest = content;
    while let Some(open) = rest.find("<style") {
        let after_tag = match rest[open..].find('>') {
            Some(gt) => open + gt + 1,
            None => break,
        };
        let close = match rest[after_tag..].find("</style>") {
            Some(c) => after_tag + c,
            None => break,
        };
        out.push_str(&rest[after_tag..close]);
        out.push('\n');
        rest = &rest[close + "</style>".len()..];
    }
    out
}

/// True iff `s[at..]` starts a CSS colour literal: `#` followed by exactly
/// 3, 4, 6, or 8 hex digits and then an IDENTIFIER boundary. This rejects
/// `#anchor` (letters outside a-f), `#12345` (5 digits — not a colour), and
/// `#badge-minis` (`bad` is a valid 3-digit run, but the `g` that follows
/// makes it an identifier, not a colour — `design.html:75` is exactly this
/// shape). A real colour is always followed by CSS punctuation (`;`, `"`,
/// `)`, whitespace, end-of-line), never by an identifier character.
fn hex_colour_len_at(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'#') {
        return None;
    }
    let mut n = 0;
    while let Some(b) = bytes.get(at + 1 + n) {
        if b.is_ascii_hexdigit() {
            n += 1;
        } else {
            break;
        }
    }
    // A trailing hex-digit run longer than 8 is not a colour either.
    if !matches!(n, 3 | 4 | 6 | 8) {
        return None;
    }
    // The run must END the identifier. Anything alphanumeric / `-` / `_`
    // after it means we are inside a longer name (an anchor, an id, a class).
    match bytes.get(at + 1 + n) {
        None => Some(n),
        Some(b) if !(b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_') => Some(n),
        Some(_) => None,
    }
}

/// Gate 1 — a page template must express colour through design tokens
/// (`var(--accent)`), never a raw hex literal. `COLOUR_SOURCE_FILES` are the
/// definition sites and are skipped. Brand-logo SVGs (Google, GitHub) belong
/// in `_icons.html`, which is a colour source — move them there rather than
/// tokenising a third party's brand colour.
pub fn check_raw_hex(file: &str, content: &str) -> Vec<Violation> {
    if COLOUR_SOURCE_FILES.contains(&file) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let bytes = line.as_bytes();
        for at in 0..bytes.len() {
            if let Some(n) = hex_colour_len_at(bytes, at) {
                let lit = &line[at..at + 1 + n];
                out.push(Violation::new(
                    file,
                    idx + 1,
                    "raw-hex",
                    format!(
                        "raw colour literal `{lit}` — use a design token \
                         (`var(--danger)`, `var(--fg)`, …) declared in \
                         _styles.html, or move a brand-logo SVG into _icons.html"
                    ),
                ));
            }
        }
    }
    out
}

/// Run every gate. `templates` is `(file_name, content)` for every
/// `src/mgmt/templates/*.html`; `css` is the concatenated CSS source (see
/// `extract_style_blocks`) used by the cross-file class gate. Returns every
/// violation found, in file order.
pub fn scan_all(templates: &[(String, String)], css: &str) -> Vec<Violation> {
    let _ = css;
    let mut out = Vec::new();
    for (file, body) in templates {
        out.extend(check_raw_hex(file, body));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_all_on_clean_input_is_empty() {
        let templates = vec![("page.html".to_string(), "<div>ok</div>".to_string())];
        assert!(scan_all(&templates, ".btn{}").is_empty());
    }

    #[test]
    fn style_blocks_extracted_without_surrounding_markup() {
        let src = "<div class=\"x\">a</div>\n<style>\n.foo{color:red}\n</style>\n\
                   <script>el.classList.add('y')</script>\n<style>.bar{}</style>";
        let css = extract_style_blocks(src);
        assert!(css.contains(".foo{color:red}"));
        assert!(css.contains(".bar{}"));
        // JS property access must NOT leak into the CSS view.
        assert!(
            !css.contains("classList"),
            "script content must not be treated as CSS"
        );
    }

    #[test]
    fn raw_hex_flagged_in_pages_but_not_in_colour_sources() {
        let bad = r#"<div style="color:#7d1f1f">x</div>"#;
        let v = check_raw_hex("collection_rows.html", bad);
        assert_eq!(v.len(), 1, "page template raw hex must be flagged");
        assert_eq!(v[0].line, 1);
        assert_eq!(v[0].rule, "raw-hex");

        // colour source files are the definition site — never flagged
        for src in COLOUR_SOURCE_FILES {
            assert!(
                check_raw_hex(src, bad).is_empty(),
                "{src} is a colour source and must not be flagged"
            );
        }
    }

    #[test]
    fn raw_hex_reports_correct_line_and_ignores_non_colour_hashes() {
        let content = "line one\n<a href=\"#anchor\">x</a>\n<b style=\"color:#fff\">y</b>\n";
        let v = check_raw_hex("page.html", content);
        assert_eq!(v.len(), 1, "#anchor is not a colour literal");
        assert_eq!(v[0].line, 3);
    }

    #[test]
    fn raw_hex_ignores_anchors_whose_prefix_is_a_valid_hex_run() {
        // `#badge-minis` opens with `bad` -- three valid hex digits -- but the
        // `g` that follows makes it an identifier, not a colour. This is the
        // literal shape at design.html:75; without the trailing identifier
        // boundary the gate flags a fifth file that has no colour leak at all.
        for anchor in [
            r##"<a href="#badge-minis">x</a>"##,
            r##"<a href="#face-cards">x</a>"##,
            r##"<a href="#decaf_notes">x</a>"##,
        ] {
            assert!(
                check_raw_hex("design.html", anchor).is_empty(),
                "anchor must not be read as a colour: {anchor}"
            );
        }
        // ...while a genuine literal at the same shape still trips.
        assert_eq!(check_raw_hex("design.html", "color:#bad;").len(), 1);
    }
}

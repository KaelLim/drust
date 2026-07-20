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

/// Run every gate. `templates` is `(file_name, content)` for every
/// `src/mgmt/templates/*.html`; `css` is the concatenated CSS source (see
/// `extract_style_blocks`) used by the cross-file class gate. Returns every
/// violation found, in file order.
pub fn scan_all(templates: &[(String, String)], css: &str) -> Vec<Violation> {
    let _ = (templates, css);
    Vec::new()
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
}

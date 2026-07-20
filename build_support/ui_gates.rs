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

/// Rules that REPORT but do not fail the build yet — the declared staging
/// list for a gate whose migration task has not landed.
///
/// The plan's hard ordering rule is "implement + test the scanner, migrate
/// the violations, THEN enforce": a gate that panics before its call sites
/// are clean deadlocks the repo — `cargo build`, `cargo test` and the
/// migration's own verification command all stop working. Staging the rule
/// here keeps it wired and printing every violation (so the migration has
/// its worklist) while the build stays green.
///
/// A rule leaves this list in the SAME commit that fixes its last violation.
/// The list is expected to be empty in steady state.
#[allow(dead_code)]
pub const WARN_ONLY_RULES: &[&str] = &["button-convention"];

/// The four BEM-style button classes retired in favour of the modifier form.
/// `.btn.icon` never had a BEM alias, so `btn-icon` is not listed.
const RETIRED_BUTTON_CLASSES: &[&str] = &["btn-sm", "btn-ghost", "btn-primary", "btn-danger"];

/// True iff the byte at `at` starts a whole identifier token — i.e. the
/// preceding byte is not part of a CSS identifier. Together with the trailing
/// check this stops `btn-sm` from matching inside `filepick-btn-smart`.
fn is_ident_boundary(bytes: &[u8], at: usize) -> bool {
    match at.checked_sub(1).and_then(|i| bytes.get(i)) {
        None => true,
        Some(b) => !(b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_'),
    }
}

/// Gate 4 — the canonical button form is the modifier style
/// (`class="btn sm ghost"`). The BEM aliases are retired; using one is a
/// build failure. Scans the WHOLE file including `<script>` blocks, because
/// `el.className = 'btn btn-sm'` puts the retired class back into the DOM at
/// runtime — migrating markup alone is not enough. Modifier ORDER is not
/// enforced; only the retired names are banned.
///
/// Two shapes are rejected. The literal one (`btn-ghost` appearing verbatim)
/// and the CONCATENATED one — a `btn-` token whose next byte cannot continue
/// a CSS identifier, i.e. the prefix half of a name completed elsewhere. The
/// retired class never appears whole in that source, so the literal scan
/// alone reports green while the DOM still receives `btn btn-ghost` at
/// runtime (`_modal.html`'s action builder was exactly this). A gate that
/// misses the dynamic builder is worse than no gate: it certifies a migration
/// that silently dropped styling.
///
/// The terminator test is "not an identifier character" rather than a quote
/// list, because the completion can be spliced in by anything: `'btn-' +
/// variant` (quote), `` `btn-${variant}` `` (JS template literal), and
/// `class="btn-{{ variant }}"` (Askama) are all live shapes in these
/// templates, and only the first ends in a quote. The unchanged leading
/// `is_ident_boundary` check keeps `filepick-btn-` and `--btn-radius` quiet.
pub fn check_button_convention(file: &str, content: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let bytes = line.as_bytes();

        // Concatenation prefix: `btn-` whose very next byte cannot continue a
        // CSS identifier — a quote, `$`, `{`, `+`, whitespace, end-of-line.
        // `'btn-ghost'` is NOT matched here (the next byte is `g`) — that
        // shape is the literal scan's job, so no double-reporting.
        let mut from = 0;
        while let Some(rel) = line[from..].find("btn-") {
            let at = from + rel;
            let end = at + "btn-".len();
            let terminated_by_non_ident = match bytes.get(end) {
                None => true,
                Some(b) => !(b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_'),
            };
            if is_ident_boundary(bytes, at) && terminated_by_non_ident {
                out.push(Violation::new(
                    file,
                    idx + 1,
                    "button-convention",
                    "retired button class built by concatenation or interpolation \
                     (`'btn-' + …`, `` `btn-${…}` ``, `btn-{{ … }}`) — splice the \
                     modifier alone (`a.variant || 'ghost'`) and let the `btn` base \
                     class carry it. The retired name never appears whole in the \
                     source, so nothing else in this gate can see it."
                        .to_string(),
                ));
            }
            from = end;
        }

        for retired in RETIRED_BUTTON_CLASSES {
            let mut from = 0;
            while let Some(rel) = line[from..].find(retired) {
                let at = from + rel;
                let end = at + retired.len();
                let leading_ok = is_ident_boundary(bytes, at);
                let trailing_ok = match bytes.get(end) {
                    None => true,
                    Some(b) => !(b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_'),
                };
                if leading_ok && trailing_ok {
                    out.push(Violation::new(
                        file,
                        idx + 1,
                        "button-convention",
                        format!(
                            "retired button class `{retired}` — use the modifier form \
                             (`btn sm`, `btn ghost`, `btn primary`, `btn danger`). \
                             This applies inside <script> string literals too."
                        ),
                    ));
                }
                from = end;
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
        out.extend(check_button_convention(file, body));
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

    #[test]
    fn bem_button_classes_flagged_everywhere_including_js() {
        let html = r#"<button class="btn btn-sm btn-ghost">x</button>"#;
        let v = check_button_convention("page.html", html);
        assert_eq!(v.len(), 2, "btn-sm and btn-ghost are both violations");
        assert_eq!(v[0].rule, "button-convention");

        // JS string literals reassign className at runtime -- migrating the
        // markup without the script would let the old class back into the DOM.
        let js = "  el.className = 'btn btn-sm btn-ghost';";
        assert_eq!(check_button_convention("page.html", js).len(), 2);
    }

    #[test]
    fn canonical_modifier_buttons_are_clean() {
        for ok in [
            r#"<button class="btn sm ghost">x</button>"#,
            r#"<button class="btn primary">x</button>"#,
            r#"<a class="btn sm icon danger">x</a>"#,
            "el.className = 'btn sm ghost';",
            // The concatenated builder, migrated: the modifier alone is
            // joined, the `btn` base class carries it.
            "var variant = a.variant || 'ghost';",
            "b.className = 'btn ' + (variant || 'ghost');",
        ] {
            assert!(
                check_button_convention("page.html", ok).is_empty(),
                "canonical form must pass: {ok}"
            );
        }
    }

    #[test]
    fn retired_button_class_built_by_concatenation_is_flagged() {
        // `_modal.html`'s action builder: the retired class never appears
        // whole in the source, so a literal-only scan reports green while the
        // DOM still gets `btn btn-ghost`. Flagging the `'btn-'` prefix is what
        // closes the gap by construction rather than by memory.
        for bad in [
            "var variant = 'btn-' + (a.variant || 'ghost');",
            r#"el.className = "btn-" + variant;"#,
            "el.className = `btn-` + variant;",
            // JS template-literal interpolation: the byte after `btn-` is `$`,
            // not a quote. `collection_rows.html` builds `class="…"` markup
            // exactly this way, so a quote-only terminator misses it.
            "el.className = `btn-${variant}`;",
            "el.className = `btn-${a.variant || 'ghost'}`;",
            // Askama expression interpolation inside a class attribute --
            // `av-{{ … }}` / `op-{{ … }}` are established idioms in these
            // templates, so the button equivalent must not build green.
            "<button class=\"btn btn-{{ variant }}\">x</button>",
        ] {
            let v = check_button_convention("_modal.html", bad);
            assert_eq!(v.len(), 1, "concatenation prefix must be flagged: {bad}");
            assert_eq!(v[0].rule, "button-convention");
        }

        // A whole retired literal is reported ONCE, by the literal scan --
        // the prefix rule must not double-count it.
        let v = check_button_convention("_modal.html", "x = 'btn-ghost';");
        assert_eq!(v.len(), 1, "literal form must not be double-reported");
    }

    #[test]
    fn button_gate_does_not_match_unrelated_identifiers() {
        // `.btn-sm` as a substring of a longer identifier is not a button class.
        for ok in [
            r#"<div class="filepick-btn-label">x</div>"#,
            r#"<div class="btn-smart-thing">x</div>"#,
            // Quote-terminated, but `btn` is the tail of a longer identifier
            // -- not a button class being built.
            r#"<div class="filepick-btn-">x</div>"#,
        ] {
            assert!(
                check_button_convention("page.html", ok).is_empty(),
                "must not over-match: {ok}"
            );
        }
    }
}

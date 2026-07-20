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
pub const WARN_ONLY_RULES: &[&str] = &["unsafe-safe-filter"];

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

/// Gate 5 — `|safe` disables askama's automatic HTML escaping, so every use
/// is an XSS surface. Only three producers are provably safe:
///
///   1. a variable whose name carries the `json` segment — produced by the
///      canonical escaper in `src/mgmt/script_json.rs` (plus the one
///      historically-named `i18n_js`, same escaper, see below)
///   2. `t.s("...")` — the i18n bundle is an `include_str!` compile-time
///      constant with no user input
///   3. `t.fmt<N>_html(...)` — HTML-escapes every interpolated argument
///      (`src/mgmt/i18n.rs:207`)
///
/// Everything else fails the build. In particular `t.fmt<N>(...)|safe`
/// (no `_html` suffix) does NOT escape its arguments; that one-character
/// difference reintroduces the v1.49.3 HIGH stored-XSS, and no runtime test
/// catches it.
///
/// NOTE: this scans the template source for the `safe` FILTER. It is
/// unrelated to askama's internal `filters::Safe` wrapping of `{% call %}`
/// caller bodies, which never appears in template source.
pub fn check_safe_filter(file: &str, content: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let mut from = 0;
        while let Some((at, end)) = find_safe_filter(line, from) {
            let expr = extract_producer_expr(line, at);
            if !expr.is_some_and(is_allowlisted_safe_producer) {
                // On a rejected span (`None`) the pipe did not belong to a
                // well-formed `{{ … }}` at all; show the raw pre-pipe text so
                // the message still points at the offending site.
                let expr = expr.unwrap_or_else(|| line[..at].trim());
                out.push(Violation::new(
                    file,
                    idx + 1,
                    "unsafe-safe-filter",
                    format!(
                        "`{expr}|safe` is not an allowlisted safe producer. Allowed: \
                         a `json`-segment variable (script_json.rs escaper), `t.s(\"…\")` \
                         (compile-time bundle), or `t.fmt<N>_html(…)` (escapes every \
                         argument). Note `t.fmt<N>(…)` WITHOUT the `_html` suffix does \
                         not escape and must never be piped to `|safe`."
                    ),
                ));
            }
            from = end;
        }
    }
    out
}

/// Locate the next `safe`-filter site in `line` at or after `from`, returning
/// `(pipe_index, end_index)` — the byte offset of the `|` and the offset just
/// past the `safe` identifier.
///
/// This must NOT be a `find("|safe")` literal scan. askama accepts arbitrary
/// whitespace around the filter pipe — `Expr::filtered` wraps it in
/// `opt(ws(filter))` and `Filter::parse` opens with `ws(path_or_identifier)`
/// (askama_parser 0.16) — so `{{ x | safe }}`, `{{ x| safe }}` and
/// `{{ x |safe }}` all disable escaping while being invisible to a literal
/// match. That is an under-match of exactly the construct this gate exists to
/// block, and it is worse than no gate: once the migration lands, a zero
/// violation count could mean "clean" or "not looking", and a single space
/// introduced by a reformat silently reopens the v1.49.3 stored-XSS surface.
///
/// The trailing boundary keeps `|safely` / `|safe_thing` from matching, and
/// `||` (JS logical-or) / `|=` are skipped — neither opens a filter.
fn find_safe_filter(line: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] != b'|' {
            i += 1;
            continue;
        }
        if matches!(bytes.get(i + 1), Some(b'|') | Some(b'=')) {
            i += 2;
            continue;
        }
        let mut q = i + 1;
        while matches!(bytes.get(q), Some(b) if b.is_ascii_whitespace()) {
            q += 1;
        }
        if line[q..].starts_with("safe") {
            let end = q + "safe".len();
            // `-` is NOT a name continuation: askama filter names are Rust
            // identifiers, so a `-` right after `safe` is the closing
            // whitespace-control marker (`{{ x|safe-}}`) — a real safe filter
            // that must stay visible to the gate.
            let terminated = match bytes.get(end) {
                None => true,
                Some(b) => !(b.is_ascii_alphanumeric() || *b == b'_'),
            };
            if terminated {
                return Some((i, end));
            }
        }
        i += 1;
    }
    None
}

/// Extract the producer expression that the `|safe` at byte offset `at` filters
/// — the text between the enclosing `{{` and the pipe.
///
/// Returns `None` when the pipe does not belong to a well-formed `{{ … }}`
/// expression, which the caller treats as NOT allowlisted (fail closed).
///
/// Two shapes make the naive `rfind("{{")` wrong:
///
///   * `rfind` happily latches onto an unrelated EARLIER expression when the
///     pipe lives in a `{% … %}` tag later on the same line. The span
///     `t.s("hdr") }}{% call card(body_html` starts with `t.s(` and would be
///     allowlisted while `body_html` renders raw — and `{% call %}` with
///     expression arguments is a live idiom here (`tenant_api_keys.html:77`).
///     Any `}}`, `{%` or `%}` INSIDE the span proves the pipe belongs to a
///     different construct, so the span is rejected.
///   * askama's whitespace-control markers `-` / `+` / `~` are all valid
///     immediately after `{{` (askama_parser 0.16 `node.rs:509-511` →
///     Suppress / Preserve / Minimize). Left in the span the marker breaks the
///     identifier test and turns every legitimate safe producer red. Exactly
///     one leading marker byte is skipped; the trailing marker sits after the
///     filter name and is handled by `find_safe_filter`'s terminator.
fn extract_producer_expr(line: &str, at: usize) -> Option<&str> {
    let open = line[..at].rfind("{{")?;
    let span = &line[open + 2..at];
    if span.contains("}}") || span.contains("{%") || span.contains("%}") {
        return None;
    }
    // Skip a single whitespace-control marker, which is only a marker when it
    // sits flush against the `{{`.
    let span = match span.as_bytes().first() {
        Some(b'-') | Some(b'+') | Some(b'~') => &span[1..],
        _ => span,
    };
    Some(span.trim())
}

/// The IMMEDIATE left operand of the filter pipe — the only thing `|safe`
/// actually wraps.
///
/// askama binds the filter TIGHTER than the binary operators: askama_parser
/// 0.16 `expr.rs:447` layers `addsub -> concat -> muldivmod -> … -> filtered`,
/// so in `a ~ b|safe` the `|safe` applies to `b` ALONE and `a` is escaped
/// normally. Validating the whole `{{`-to-pipe span therefore lets a safe
/// PREFIX launder an unsafe operand — `{{ t.s("a") ~ body_html|safe }}` matches
/// the `t.s(` arm while rendering `body_html` raw.
///
/// Splitting tracks bracket depth and string literals so an operator inside a
/// call argument (`t.s("a-b")`) is not a split point.
fn pipe_left_operand(expr: &str) -> &str {
    let bytes = expr.as_bytes();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth = depth.saturating_sub(1),
                b'~' | b'+' | b'-' | b'*' | b'/' | b'%' if depth == 0 => start = i + 1,
                _ => {}
            },
        }
        i += 1;
    }
    expr[start..].trim()
}

/// True when the parenthesis opened at `open` closes at the very END of `expr`
/// — i.e. `expr` is exactly one call and nothing is appended to it.
///
/// The allowlist arms must match the WHOLE operand. A prefix-only test ignores
/// everything after the first `(`, so a trailing method chain or operator is
/// invisible — and it is precisely the appended part that renders raw:
/// `t.fmt1_html("k","n",v).replace("&amp;","&")|safe` un-escapes the very
/// output the `_html` variant escaped.
fn call_closes_at_end(expr: &str, open: usize) -> bool {
    let bytes = expr.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1 == bytes.len();
                    }
                }
                _ => {}
            },
        }
        i += 1;
    }
    false
}

/// True when the first non-whitespace byte after the paren at `open` is a
/// double quote — i.e. the call's first argument is a compile-time literal.
fn first_arg_is_literal(expr: &str, open: usize) -> bool {
    expr[open + 1..].trim_start().starts_with('"')
}

/// The provably-safe `|safe` producers. See `check_safe_filter`.
fn is_allowlisted_safe_producer(expr: &str) -> bool {
    // `|safe` wraps only the pipe's immediate left operand, never the whole
    // expression -- see `pipe_left_operand`.
    let expr = pipe_left_operand(expr);
    // 1. A variable carrying the `json` segment — the canonical
    //    script_json.rs escaper. The marker must be a whole
    //    underscore-delimited segment, not a mere suffix: `mascot_json_static`
    //    / `mascot_json_light` / `mascot_json_dark` (theme.rs) put the
    //    variant AFTER the marker, and a suffix-only rule flags all three.
    //    Segment matching also keeps `jsonish_markup` out.
    if !expr.is_empty()
        && expr.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && expr.split('_').any(|seg| seg == "json")
    {
        return true;
    }
    // 1b. `i18n_js` — the SAME escaper (`script_json::escape_json_for_script`
    //     in tenant_broadcast.rs) under a name that predates the convention.
    //     Recorded as a named exception rather than widening the shape rule to
    //     `_js`, which would admit any script-shaped variable.
    if expr == "i18n_js" {
        return true;
    }
    // 2. `t.s("…")` — compile-time i18n bundle, no user input. The key MUST be
    //    a literal: `Translator::s` echoes an unknown key back verbatim as
    //    `!!{key}!!` (`src/mgmt/i18n.rs:146`), so a runtime-valued key like
    //    `t.s(user_key)` reflects caller-controlled bytes unescaped.
    if expr.starts_with("t.s(") {
        let open = "t.s".len();
        return first_arg_is_literal(expr, open) && call_closes_at_end(expr, open);
    }
    // 3. `t.fmt<N>_html(…)` — escapes every interpolated argument. The
    //    `_html(` suffix check is what separates it from the unescaping
    //    `t.fmt<N>(…)` sibling.
    if expr.starts_with("t.fmt") {
        return match expr.find('(') {
            Some(open) => expr[..open].ends_with("_html") && call_closes_at_end(expr, open),
            None => false,
        };
    }
    false
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
        out.extend(check_safe_filter(file, body));
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
    fn safe_filter_allows_only_the_three_safe_producers() {
        for ok in [
            r#"const f = {{ fields_json|safe }};"#,
            r#"<p>{{ t.s("some.key")|safe }}</p>"#,
            r#"<p>{{ t.fmt1_html("k", "n", v)|safe }}</p>"#,
            r#"<p>{{ t.fmt3_html("k", "a", x, "b", y, "c", z)|safe }}</p>"#,
        ] {
            assert!(
                check_safe_filter("page.html", ok).is_empty(),
                "allowlisted safe producer must pass: {ok}"
            );
        }
    }

    #[test]
    fn safe_filter_rejects_the_non_escaping_fmt_variants() {
        // fmt<N> does NOT escape its interpolated args; fmt<N>_html does.
        // Confusing the two reintroduces the v1.49.3 stored-XSS.
        let bad = r#"<p>{{ t.fmt1("k", "name", tenant_name)|safe }}</p>"#;
        let v = check_safe_filter("page.html", bad);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, "unsafe-safe-filter");
        assert!(
            v[0].message.contains("_html"),
            "message must point at the fix"
        );
    }

    #[test]
    fn safe_filter_rejects_arbitrary_expressions() {
        let bad = r#"<div>{{ body_html|safe }}</div>"#;
        assert_eq!(check_safe_filter("page.html", bad).len(), 1);
    }

    #[test]
    fn safe_filter_sees_through_whitespace_around_the_pipe() {
        // askama accepts whitespace on BOTH sides of the filter pipe, and every
        // spaced form renders the producer unescaped exactly like `|safe`. A
        // literal `find("|safe")` scan misses all of them -- one stray space
        // from a reformat would carry the v1.49.3 stored-XSS straight through a
        // gate reporting green.
        for bad in [
            r#"<div>{{ body_html | safe }}</div>"#,
            r#"<div>{{ body_html| safe }}</div>"#,
            r#"<div>{{ body_html |safe }}</div>"#,
            "<div>{{ body_html|\tsafe }}</div>",
            r#"<div>{{ body_html |  safe }}</div>"#,
            // The non-escaping fmt sibling -- the exact v1.49.3 shape -- must
            // stay flagged when spaced too.
            r#"<p>{{ t.fmt1("k", "name", n) | safe }}</p>"#,
        ] {
            let v = check_safe_filter("page.html", bad);
            assert_eq!(v.len(), 1, "spaced safe filter must be flagged: {bad}");
            assert_eq!(v[0].rule, "unsafe-safe-filter");
        }

        // ...and the allowlist is applied to the spaced form identically, so
        // closing the under-match does not turn the safe producers red.
        for ok in [
            r#"const f = {{ fields_json | safe }};"#,
            r#"<p>{{ t.s("some.key") | safe }}</p>"#,
            r#"<p>{{ t.fmt1_html("k", "n", v) | safe }}</p>"#,
        ] {
            assert!(
                check_safe_filter("page.html", ok).is_empty(),
                "allowlisted producer must still pass when spaced: {ok}"
            );
        }
    }

    #[test]
    fn safe_filter_does_not_match_other_filters_or_operators() {
        // `safe` must be a WHOLE filter name, and `||` / `|=` are JS operators
        // inside <script> blocks, not askama filter pipes.
        for ok in [
            r#"<div>{{ x|safelike }}</div>"#,
            r#"<div>{{ x | safely }}</div>"#,
            r#"<div>{{ x|safe_html }}</div>"#,
            "  var v = a.variant || safe;",
            "  mask |= safe;",
        ] {
            assert!(
                check_safe_filter("page.html", ok).is_empty(),
                "must not over-match: {ok}"
            );
        }
    }

    #[test]
    fn safe_filter_accepts_the_escapers_real_output_names() {
        // The escaper's output is not always named `*_json`. `mascot_json_*`
        // (theme.rs, compile-time palette TOML) carries a suffix after the
        // marker, and `i18n_js` (tenant_broadcast.rs) is escaped by
        // `script_json::escape_json_for_script` but named `_js`. A rule that
        // only accepts a `_json` SUFFIX flags four live, provably-safe sites
        // and would leave gate 5 red after its migration task cleans the two
        // genuine ones.
        for ok in [
            r#"window.P = {{ mascot_json_static|safe }};"#,
            r#"  ? {{ mascot_json_dark|safe }}"#,
            r#"  : {{ mascot_json_light|safe }};"#,
            r#"  const I18N = {{ i18n_js|safe }};"#,
        ] {
            assert!(
                check_safe_filter("page.html", ok).is_empty(),
                "real escaper output must pass: {ok}"
            );
        }
        // ...but the marker must be a whole segment, not a substring: a
        // variable merely CONTAINING the letters is not the escaper's output.
        assert_eq!(
            check_safe_filter("page.html", "{{ jsonish_markup|safe }}").len(),
            1
        );
    }

    #[test]
    fn safe_filter_validates_only_the_pipes_immediate_left_operand() {
        // askama binds the filter TIGHTER than the binary operators
        // (askama_parser 0.16 expr.rs: addsub -> concat -> muldivmod -> …
        // -> filtered), so in `a ~ b|safe` the `|safe` wraps `b` ALONE. Handing
        // the whole `{{`-to-pipe span to the allowlist lets a safe PREFIX
        // launder an unsafe operand: the span matches the `t.s(` / `t.fmt` arm
        // while the right operand renders raw.
        for bad in [
            r#"<p>{{ t.s("a") ~ body_html|safe }}</p>"#,
            r#"<p>{{ t.fmt1_html("k", "n", v) ~ evil_raw|safe }}</p>"#,
            r#"<p>{{ fields_json ~ body_html|safe }}</p>"#,
            r#"<p>{{ t.s("a") + body_html|safe }}</p>"#,
        ] {
            let v = check_safe_filter("page.html", bad);
            assert_eq!(v.len(), 1, "right operand of a concat is raw: {bad}");
            assert_eq!(v[0].rule, "unsafe-safe-filter");
        }

        // ...and a safe producer sitting as the RIGHT operand still passes --
        // that operand is the one `|safe` actually wraps.
        for ok in [
            r#"<p>{{ prefix ~ t.s("a.b")|safe }}</p>"#,
            r#"<p>{{ a ~ fields_json|safe }}</p>"#,
            // An operator INSIDE a string argument is not a split point.
            r#"<p>{{ t.s("a-b.c")|safe }}</p>"#,
            r#"<p>{{ t.fmt1_html("a-b", "n", v)|safe }}</p>"#,
        ] {
            assert!(
                check_safe_filter("page.html", ok).is_empty(),
                "operand-level allowlist must still pass: {ok}"
            );
        }
    }

    #[test]
    fn safe_filter_rejects_trailing_chains_after_an_allowlisted_call() {
        // The allowlist arms must match the WHOLE operand. A prefix-only test
        // ignores everything after the first `(`, so any chain or operator
        // appended to a safe call is invisible -- and the appended part is
        // exactly what renders raw.
        for bad in [
            r#"<p>{{ t.fmt1_html("k","n",v).replace("&amp;","&")|safe }}</p>"#,
            r#"<p>{{ t.s("k").replace("&amp;","&")|safe }}</p>"#,
            r#"<p>{{ t.fmt1_html("k","n",v) + evil|safe }}</p>"#,
            r#"<p>{{ t.s("k") + body_html|safe }}</p>"#,
        ] {
            let v = check_safe_filter("page.html", bad);
            assert_eq!(v.len(), 1, "trailing chain must be flagged: {bad}");
            assert_eq!(v[0].rule, "unsafe-safe-filter");
        }
    }

    #[test]
    fn safe_filter_requires_a_literal_key_for_the_t_s_arm() {
        // `t.s` echoes an unknown key back verbatim -- `!!{key}!!`
        // (src/mgmt/i18n.rs:146) -- so a RUNTIME-valued key is reflected
        // unescaped. Only the compile-time literal form the doc comment
        // declares is provably safe.
        for bad in [
            r#"<p>{{ t.s(user_key)|safe }}</p>"#,
            r#"<p>{{ t.s(row.key)|safe }}</p>"#,
        ] {
            let v = check_safe_filter("page.html", bad);
            assert_eq!(v.len(), 1, "non-literal i18n key must be flagged: {bad}");
            assert_eq!(v[0].rule, "unsafe-safe-filter");
        }
    }

    #[test]
    fn safe_filter_does_not_borrow_an_earlier_expression_on_the_same_line() {
        // `rfind("{{")` latches onto an unrelated EARLIER expression when the
        // pipe lives in a `{% … %}` tag later on the line, so the span becomes
        // `t.s("hdr") }}{% call card(body_html` and passes the `t.s(` arm.
        // `{% call %}` with expression arguments is a live idiom here
        // (tenant_api_keys.html:77-78).
        for bad in [
            r#"{{ t.s("hdr") }}{% call card(body_html|safe) %}{% endcall %}"#,
            r#"{{ t.s("hdr") }}{% let m = body_html|safe %}"#,
            r#"{{ fields_json|safe }} {{ t.s("x") }}{% let m = evil|safe %}"#,
        ] {
            let v = check_safe_filter("page.html", bad);
            assert_eq!(v.len(), 1, "cross-construct span must be flagged: {bad}");
            assert_eq!(v[0].rule, "unsafe-safe-filter");
        }
    }

    #[test]
    fn safe_filter_tolerates_askama_whitespace_control_markers() {
        // `-` / `+` / `~` are all valid immediately after `{{`
        // (askama_parser 0.16 node.rs:509-511 -> Suppress / Preserve /
        // Minimize). Left in the extracted expression they break the
        // identifier test and turn every legitimate safe producer red.
        for ok in [
            r#"{{- fields_json|safe -}}"#,
            r#"{{~ fields_json|safe ~}}"#,
            r#"{{+ t.s("a.b")|safe +}}"#,
            r#"{{- t.fmt1_html("k","n",v)|safe }}"#,
        ] {
            assert!(
                check_safe_filter("page.html", ok).is_empty(),
                "whitespace-control marker must not turn a safe producer red: {ok}"
            );
        }

        // ...and the marker must not hide an UNSAFE producer either. A `-}}`
        // with no space still terminates the filter name.
        for bad in [
            r#"{{- body_html|safe -}}"#,
            r#"{{ body_html|safe-}}"#,
            r#"{{~ t.fmt1("k","n",v)|safe ~}}"#,
        ] {
            let v = check_safe_filter("page.html", bad);
            assert_eq!(v.len(), 1, "marker must not hide a violation: {bad}");
        }
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

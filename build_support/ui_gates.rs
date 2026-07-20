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
pub const WARN_ONLY_RULES: &[&str] = &["missing-view-head"];

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
///     `t.s("hdr") }}{% call card(user_supplied_markup` starts with `t.s(` and would be
///     allowlisted while `user_supplied_markup` renders raw — and `{% call %}` with
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
/// PREFIX launder an unsafe operand — `{{ t.s("a") ~ user_supplied_markup|safe }}` matches
/// the `t.s(` arm while rendering `user_supplied_markup` raw.
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
    // 4. `body_html` — the CHANGELOG viewer's rendered markdown
    //    (`src/mgmt/docs.rs::changelog_page`). The source is the repo's own
    //    `CHANGELOG.md`, read from the process CWD and shipped with the
    //    binary; it is operator-controlled, never tenant input, and the route
    //    (`/admin/_docs/changelog`) sits behind the admin-session layer.
    //    pulldown-cmark passes raw HTML through, so this MUST stay a single
    //    named exception tied to that one handler — never a `_html` shape
    //    rule, which would admit any variable a later handler happens to name
    //    that way. Adding a fifth entry here is a deliberate, reviewed act.
    if expr == "body_html" {
        return true;
    }
    false
}

/// The in-template declaration that exempts a page from gate 2.
///
/// It is an askama COMMENT, deliberately — NOT a `{% block %}`. `login.html`
/// is the one page template that does not `{% extends "_base.html" %}`, and in
/// askama 0.16 a `{% block %}` in a ROOT (non-extending) template renders its
/// body inline: `{% block page_kind %}standalone{% endblock %}<p>hi</p>`
/// renders as `standalone<p>hi</p>`, i.e. the marker would ship the literal
/// word "standalone" onto the login screen. (In a CHILD template an unmatched
/// block is silently dropped, which is why the hazard is easy to miss.) A
/// comment is inert in every template, extending or not — see
/// `standalone_marker_is_inert_in_a_root_template`.
pub const STANDALONE_MARKER: &str = "{# page-kind: standalone #}";

/// The ONE macro path that satisfies gate 2. Matched exactly, never by
/// substring or prefix. If a variant head macro is ever legitimate, add it to
/// a named list here — a `view_head*` prefix rule would let any future sibling
/// ungovern every page that adopts it, without the gate ever going red.
const VIEW_HEAD_MACRO: &str = "ui::view_head";

/// Blank out every region askama and the browser both ignore: HTML comments
/// and the BODIES of `<script>` / `<style>` elements. Blanked bytes become
/// spaces, so byte offsets and line numbers are preserved.
///
/// Askama comments are deliberately left intact — `STANDALONE_MARKER` is one,
/// and the view_head scan blanks them separately after the marker test.
fn blank_non_executing(content: &str) -> String {
    let mut out = content.as_bytes().to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for b in &mut out[from..to] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    let mut i = 0usize;
    while i < content.len() {
        let rest = &content[i..];
        if let Some(after) = rest.strip_prefix("<!--") {
            let end = after
                .find("-->")
                .map(|p| i + 4 + p + 3)
                .unwrap_or(content.len());
            blank(&mut out, i, end);
            i = end;
            continue;
        }
        let mut matched = None;
        for (open, close) in [("<script", "</script>"), ("<style", "</style>")] {
            if !rest.starts_with(open) {
                continue;
            }
            // `<scriptish>` is not a `<script>`; require a tag-name boundary.
            let next = rest.as_bytes().get(open.len());
            if next.is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-') {
                continue;
            }
            matched = Some(close);
            break;
        }
        if let Some(close) = matched {
            // Body starts after the open tag's `>`; if either delimiter is
            // missing the file is malformed — blank to EOF and stop.
            let body_start = match rest.find('>') {
                Some(gt) => i + gt + 1,
                None => {
                    blank(&mut out, i, content.len());
                    break;
                }
            };
            let body_end = content[body_start..]
                .find(close)
                .map(|p| body_start + p)
                .unwrap_or(content.len());
            blank(&mut out, body_start, body_end);
            i = body_end;
            continue;
        }
        // Advance a whole char so multi-byte text can never split a boundary.
        i += rest.chars().next().map(char::len_utf8).unwrap_or(1);
    }
    String::from_utf8(out).expect("blanking replaces whole regions with ASCII")
}

/// Every `{#delim … delim#}`-style span in `content` as `(start, end)` byte
/// offsets covering the delimiters, given the opening/closing delimiter pair.
fn delimited_spans(content: &str, open: &str, close: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(p) = content[i..].find(open) {
        let start = i + p;
        let after = start + open.len();
        let end = match content[after..].find(close) {
            Some(q) => after + q + close.len(),
            None => break,
        };
        out.push((start, end));
        i = end;
    }
    out
}

/// Strip a span's delimiters and askama's optional `-` whitespace-control
/// markers, returning the trimmed inner text.
fn span_inner<'a>(span: &'a str, open: &str, close: &str) -> &'a str {
    let s = span
        .strip_prefix(open)
        .unwrap_or(span)
        .strip_suffix(close)
        .unwrap_or(span);
    s.trim()
        .trim_start_matches('-')
        .trim_end_matches('-')
        .trim()
}

/// True iff an askama comment's inner text declares the standalone page kind.
///
/// Tolerant of whitespace and of askama's `{#-` / `-#}` whitespace-control
/// spelling (house style — `tenant_settings.html` uses the `{%-` form), so a
/// developer following the existing convention is not blocked by spacing.
fn is_standalone_declaration(inner: &str) -> bool {
    match inner.split_once(':') {
        Some((k, v)) => k.trim() == "page-kind" && v.trim() == "standalone",
        None => false,
    }
}

/// Extract the TARGET of an askama `{% call … %}` tag: the path between the
/// `call` keyword and the argument list's `(`, with all whitespace removed so
/// `ui :: view_head` normalises onto `ui::view_head`.
///
/// Returns `None` for a tag that is not a `call`, or for a `call` with no
/// argument list. The caller must compare the result EXACTLY — a `contains`
/// test would accept both `ui::note("see ui::view_head …")` (the token buried
/// in a string argument) and a future `ui::view_head_compact` sibling by
/// prefix, silently ungoverning the page in either case.
fn call_target(inner: &str) -> Option<String> {
    let rest = inner.strip_prefix("call")?;
    if !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let (path, _) = rest.split_once('(')?;
    Some(path.split_whitespace().collect())
}

/// Gate 2 — every PAGE template must render the canonical header via
/// `{% call ui::view_head(…) %}`. A page that legitimately has no header
/// (the login screen, the design showcase) declares so IN ITSELF with
/// `STANDALONE_MARKER`.
///
/// The exemption deliberately lives in the template rather than a list in
/// build.rs: a list grows as "just add it to the list" becomes habit, whereas
/// a template that forgets to declare stays governed — fail-closed.
///
/// BOTH probes are syntax-aware, not `contains` over raw text. A bare
/// substring test counts every non-executing occurrence — a commented-out
/// call left over from debugging, a JS string, an HTML attribute, a CSS
/// comment, or plain prose naming the macro — and `design.html` /
/// `tenant_docs.html` are exactly the templates that would mention it in
/// prose and thereby silently ungovern themselves. So: HTML comments and
/// `<script>` / `<style>` bodies are blanked first; the marker must then be a
/// real askama comment, and the call must sit inside a real `{% … %}` tag
/// whose TARGET is exactly `ui::view_head` — not merely a tag whose body
/// mentions the token, which `{% call ui::code_sample("… ui::view_head …") %}`
/// on the showcase page would satisfy, and not a `view_head*` prefix, which a
/// future `ui::view_head_compact` sibling would satisfy.
///
/// Files whose name starts with `_` are partials, not pages, and are skipped.
pub fn check_view_head(file: &str, content: &str) -> Vec<Violation> {
    if file.starts_with('_') {
        return Vec::new();
    }
    let live = blank_non_executing(content);

    // Exemption: a genuine askama comment declaring the page kind. Quoting
    // the marker inside an HTML comment or a script body no longer counts —
    // those regions are already blanked.
    let comments = delimited_spans(&live, "{#", "#}");
    for &(s, e) in &comments {
        if is_standalone_declaration(span_inner(&live[s..e], "{#", "#}")) {
            return Vec::new();
        }
    }

    // The call must be executed, so blank askama comments too, then require
    // the token inside a `{% call … %}` tag rather than anywhere in the file.
    let mut exec = live.clone().into_bytes();
    for &(s, e) in &comments {
        for b in &mut exec[s..e] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    }
    let exec = String::from_utf8(exec).expect("blanking replaces whole spans with ASCII");
    for (s, e) in delimited_spans(&exec, "{%", "%}") {
        let inner = span_inner(&exec[s..e], "{%", "%}");
        if call_target(inner).as_deref() == Some(VIEW_HEAD_MACRO) {
            return Vec::new();
        }
    }

    vec![Violation::new(
        file,
        1,
        "missing-view-head",
        format!(
            "page template does not render `{{% call ui::view_head(eyebrow, title, sub) %}}`. \
             Import the library with `{{% import \"_ui.html\" as ui %}}` and call it, or — if \
             this page genuinely has no header — declare `{STANDALONE_MARKER}` \
             (an askama comment, so it renders nothing even on a page that does not \
             `{{% extends %}}`)."
        ),
    )]
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
        out.extend(check_view_head(file, body));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_all_on_clean_input_is_empty() {
        // A clean PAGE must satisfy every gate, gate 2 included — so the
        // fixture renders the canonical header. Dropping the `{% call %}`
        // here would make the fixture a gate-2 violation rather than the
        // "no rule fires" baseline this test exists to pin.
        let clean = "{% call ui::view_head(a, b, c) %}{% endcall %}\n<div>ok</div>";
        let templates = vec![("page.html".to_string(), clean.to_string())];
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
        let bad = r#"<div>{{ user_supplied_markup|safe }}</div>"#;
        assert_eq!(check_safe_filter("page.html", bad).len(), 1);
    }

    #[test]
    fn safe_filter_allows_the_named_body_html_exception_only_exactly() {
        // `body_html` (tenant_docs.html) renders CHANGELOG.md markdown from
        // the repo, not tenant input -- a named exception, allowlisted whole.
        assert!(
            check_safe_filter("page.html", r#"<div>{{ body_html|safe }}</div>"#).is_empty(),
            "the named exception must pass"
        );
        // It is a NAME match, never a shape rule: a look-alike variable that
        // merely ends in `_html` is a different value from a different
        // handler and stays flagged.
        for bad in [
            r#"<div>{{ other_body_html|safe }}</div>"#,
            r#"<div>{{ body_html_extra|safe }}</div>"#,
            r#"<div>{{ notes_html|safe }}</div>"#,
            // ...and it cannot launder a raw right-hand operand either.
            r#"<div>{{ body_html ~ evil_raw|safe }}</div>"#,
        ] {
            let v = check_safe_filter("page.html", bad);
            assert_eq!(v.len(), 1, "must stay flagged: {bad}");
            assert_eq!(v[0].rule, "unsafe-safe-filter");
        }
    }

    #[test]
    fn safe_filter_sees_through_whitespace_around_the_pipe() {
        // askama accepts whitespace on BOTH sides of the filter pipe, and every
        // spaced form renders the producer unescaped exactly like `|safe`. A
        // literal `find("|safe")` scan misses all of them -- one stray space
        // from a reformat would carry the v1.49.3 stored-XSS straight through a
        // gate reporting green.
        for bad in [
            r#"<div>{{ user_supplied_markup | safe }}</div>"#,
            r#"<div>{{ user_supplied_markup| safe }}</div>"#,
            r#"<div>{{ user_supplied_markup |safe }}</div>"#,
            "<div>{{ user_supplied_markup|\tsafe }}</div>",
            r#"<div>{{ user_supplied_markup |  safe }}</div>"#,
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
            r#"<p>{{ t.s("a") ~ user_supplied_markup|safe }}</p>"#,
            r#"<p>{{ t.fmt1_html("k", "n", v) ~ evil_raw|safe }}</p>"#,
            r#"<p>{{ fields_json ~ user_supplied_markup|safe }}</p>"#,
            r#"<p>{{ t.s("a") + user_supplied_markup|safe }}</p>"#,
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
            r#"<p>{{ t.s("k") + user_supplied_markup|safe }}</p>"#,
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
        // `t.s("hdr") }}{% call card(user_supplied_markup` and passes the `t.s(` arm.
        // `{% call %}` with expression arguments is a live idiom here
        // (tenant_api_keys.html:77-78).
        for bad in [
            r#"{{ t.s("hdr") }}{% call card(user_supplied_markup|safe) %}{% endcall %}"#,
            r#"{{ t.s("hdr") }}{% let m = user_supplied_markup|safe %}"#,
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
            r#"{{- user_supplied_markup|safe -}}"#,
            r#"{{ user_supplied_markup|safe-}}"#,
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

    #[test]
    fn page_without_view_head_is_flagged() {
        let page = "{% extends \"_base.html\" %}\n<div>content</div>\n";
        let v = check_view_head("tenants_list.html", page);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, "missing-view-head");
    }

    #[test]
    fn page_calling_view_head_is_clean() {
        let page = "{% import \"_ui.html\" as ui %}\n\
                    {% call ui::view_head(a, b, c) %}{% endcall %}\n";
        assert!(check_view_head("tenants_list.html", page).is_empty());
    }

    #[test]
    fn standalone_declaration_exempts_a_page() {
        // login.html / design.html legitimately have no view head. The
        // exemption is DECLARED IN THE TEMPLATE, never in a build.rs list --
        // a new page that forgets to declare is governed (fail-closed).
        let page = format!("{STANDALONE_MARKER}\n<div>x</div>\n");
        assert!(check_view_head("login.html", &page).is_empty());
    }

    /// The marker must render NOTHING on `login.html`, which is the one page
    /// template that does not `{% extends "_base.html" %}`. A `{% block %}`
    /// would render its body inline there and ship the literal word
    /// "standalone" onto the login screen; an askama comment cannot.
    #[test]
    fn standalone_marker_is_inert_in_a_root_template() {
        use askama::Template;

        #[derive(Template)]
        #[template(source = "{# page-kind: standalone #}<p>hello</p>", ext = "html")]
        struct RootProbe;

        assert_eq!(RootProbe.render().expect("render probe"), "<p>hello</p>");
    }

    #[test]
    fn standalone_declaration_tolerates_askama_spellings() {
        // Whitespace-control markers are house style in this repo
        // (tenant_settings.html uses `{%- if -%}`), so a developer writing the
        // exemption that way must not be blocked over spacing.
        for spelling in [
            "{#- page-kind: standalone -#}",
            "{#page-kind:standalone#}",
            "{#   page-kind :  standalone   #}",
        ] {
            let page = format!("{spelling}\n<div>x</div>\n");
            assert!(
                check_view_head("login.html", &page).is_empty(),
                "must accept: {spelling}"
            );
        }
    }

    #[test]
    fn non_executing_mentions_do_not_satisfy_the_gate() {
        // A bare `content.contains("ui::view_head(")` counts every one of
        // these, exempting a page that renders NO header. design.html and
        // tenant_docs.html are exactly the templates that mention the macro
        // in prose.
        for page in [
            "{% extends \"_base.html\" %}\n\
             <!-- TODO restore {% call ui::view_head(a, b, c) %}{% endcall %} -->\n",
            "{% extends \"_base.html\" %}\n\
             {# {% call ui::view_head(a, b, c) %}{% endcall %} #}\n",
            "{% extends \"_base.html\" %}\n\
             <script>const HINT = \"ui::view_head(\";</script>\n",
            "{% extends \"_base.html\" %}\n<div data-doc=\"ui::view_head(\">x</div>\n",
            "{% extends \"_base.html\" %}\n\
             <style>/* header comes from ui::view_head( */ .a{}</style>\n",
            "{% extends \"_base.html\" %}\n\
             <p>Every page should call ui::view_head(eyebrow, title).</p>\n",
        ] {
            let v = check_view_head("design.html", page);
            assert_eq!(v.len(), 1, "must stay governed: {page}");
            assert_eq!(v[0].rule, "missing-view-head");
        }
    }

    #[test]
    fn a_different_macro_quoting_the_token_does_not_satisfy_the_gate() {
        // design.html is the component-library showcase -- the page most
        // likely to render a worked example OF view_head through some other
        // macro. Matching the tag BODY rather than the call TARGET would ship
        // that page with no header at all.
        for page in [
            "{% extends \"_base.html\" %}\n\
             {% call ui::note(\"see ui::view_head for the header\") %}{% endcall %}\n",
            "{% extends \"_base.html\" %}\n\
             {% call ui::code_sample(\"{% call ui::view_head(a, b, c) %}\") %}{% endcall %}\n",
        ] {
            let v = check_view_head("design.html", page);
            assert_eq!(v.len(), 1, "must stay governed: {page}");
            assert_eq!(v[0].rule, "missing-view-head");
        }
    }

    #[test]
    fn a_sibling_macro_sharing_the_name_prefix_does_not_satisfy_the_gate() {
        // `_ui.html` has one macro today; `view_head_compact` / `view_head_v2`
        // are the obvious next move. A prefix match would stop governing every
        // page that adopts one, while still reporting green.
        for page in [
            "{% extends \"_base.html\" %}\n{% call ui::view_head_compact(a, b) %}{% endcall %}\n",
            "{% extends \"_base.html\" %}\n{% call ui::view_head_v2(a, b, c) %}{% endcall %}\n",
        ] {
            let v = check_view_head("tenants_list.html", page);
            assert_eq!(v.len(), 1, "must stay governed: {page}");
            assert_eq!(v[0].rule, "missing-view-head");
        }
    }

    #[test]
    fn call_target_is_whitespace_normalised() {
        // House style uses whitespace-control markers and developers space
        // paths inconsistently; neither must fail a page that DOES render the
        // canonical header.
        for page in [
            "{%- call ui::view_head(a, b, c) -%}{% endcall %}\n",
            "{% call  ui :: view_head (a, b, c) %}{% endcall %}\n",
        ] {
            assert!(
                check_view_head("tenants_list.html", page).is_empty(),
                "must accept: {page}"
            );
        }
    }

    #[test]
    fn quoted_standalone_marker_does_not_exempt() {
        // Documenting the exemption must not silently ungovern the page that
        // documents it -- the "just add it to the list" failure mode the
        // in-template design exists to avoid.
        for page in [
            format!("{{% extends \"_base.html\" %}}\n<!-- {STANDALONE_MARKER} -->\n"),
            format!(
                "{{% extends \"_base.html\" %}}\n<script>x = \"{STANDALONE_MARKER}\";</script>\n"
            ),
            format!(
                "{{% extends \"_base.html\" %}}\n<style>/* {STANDALONE_MARKER} */ .a{{}}</style>\n"
            ),
        ] {
            let v = check_view_head("tenant_docs.html", &page);
            assert_eq!(v.len(), 1, "must stay governed: {page}");
        }
    }

    #[test]
    fn partials_and_the_library_itself_are_not_pages() {
        for f in ["_modal.html", "_ui.html", "_admin_sidebar.html"] {
            assert!(
                check_view_head(f, "<div>x</div>").is_empty(),
                "{f} is a partial, not a page"
            );
        }
    }
}

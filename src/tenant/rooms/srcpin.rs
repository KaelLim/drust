//! Test-only source scanner for the STRUCTURAL PINS (#955, #975).
//!
//! Several ordering invariants are pinned by reading their own function's
//! source text, because no behavioural test can see them:
//! `bus::evict_tenant_bumps_epoch_before_dropping_channels` and its host-wide
//! sibling (the epoch bump(s) must precede the channel teardown),
//! `ws::epoch_checkpoints_sit_before_dispatch_and_on_the_keepalive_tick` (the
//! eviction baseline is captured once pre-upgrade, and each checkpoint breaks
//! the conn loop), and `crate::mgmt::pat_evict_pin` (every PAT-revocation site
//! clears the auth cache BEFORE it evicts rooms sockets). The last one lives
//! outside `rooms`, which is why [`code_only`], [`production_half`] and
//! [`prod_fn_body`] are `pub(crate)` rather than private to this module.
//!
//! Both pins matched needles against RAW source, which makes a COMMENT a
//! hiding place. Measured on this branch, all three green with the feature
//! broken:
//!
//! 1. `if check_epoch_evicted(…).await { /* no break */ }` — the reviewer's
//!    own mutant. `body.contains("break")` matched the word inside the
//!    comment, so the evicted socket still landed one more op.
//! 2. `// if check_epoch_evicted(…).await { break; }` — checkpoint (a)
//!    commented out entirely. `find("check_epoch_evicted(")` matched the
//!    commented-out call, so the pin anchored on a checkpoint that no longer
//!    existed.
//! 3. `// self.bump_epoch(tenant);` left above `channels.remove` with the real
//!    call moved BELOW it. `find` returns the first occurrence, which was the
//!    comment, so the ORDER LOAD-BEARING invariant read as satisfied while it
//!    was inverted.
//!
//! [`code_only`] removes that hiding place: every pin needle is matched
//! against code only. It is the pins' own tool, so it carries its own tests —
//! a scanner that silently stopped stripping would restore all three holes at
//! once.

/// Blank out every Rust comment, leaving code and string literals intact.
///
/// Comment bytes become spaces (newlines survive) so the result stays
/// positionally comparable to the input and no two tokens fuse. String
/// literals — ordinary, raw (`r#"…"#`) and the `'"'` char literal — are
/// copied verbatim, so a `//` or `/*` INSIDE a string cannot swallow the code
/// that follows it (that would make a needle vanish and the pin fail closed,
/// noisily, but a pin that cries wolf gets deleted).
///
/// Not a Rust parser, and does not need to be: the only inputs are this
/// module's two sibling files, and the failure direction of any mis-scan is a
/// visible pin failure, never a silent pass.
pub(crate) fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;

    while i < b.len() {
        // Raw string `r"…"` / `r#"…"#`, and the byte forms `br"…"` /
        // `br#"…"#` — checked before the bare-`"` arm so the hashes are
        // consumed with it. Missing the `br` form put the scanner out of phase
        // for the rest of the file: the `"#` closer opened a phantom string,
        // and a later `"http://…"` then read as a comment and was blanked.
        if b[i] == b'r'
            && raw_prefix_ok(b, i)
            && let Some(end) = raw_string_end(b, i)
        {
            out.extend_from_slice(&b[i..end]);
            i = end;
            continue;
        }

        // Char literal `'x'` / `'\n'` — only matched in that exact shape, so a
        // lifetime (`'a`, which has no closing quote) is left alone. This
        // exists for `'"'`, which would otherwise open a phantom string and
        // stop the scanner stripping comments from there on.
        if b[i] == b'\''
            && let Some(end) = char_literal_end(b, i)
        {
            out.extend_from_slice(&b[i..end]);
            i = end;
            continue;
        }

        if b[i] == b'"' {
            let end = string_end(b, i);
            out.extend_from_slice(&b[i..end]);
            i = end;
            continue;
        }

        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }

        if b[i..].starts_with(b"/*") {
            // Rust block comments nest.
            let mut depth = 1usize;
            out.extend_from_slice(b"  ");
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else {
                    out.push(if b[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
            continue;
        }

        out.push(b[i]);
        i += 1;
    }

    // Only ASCII comment bytes were replaced (by ASCII spaces); every other
    // byte was copied verbatim, so UTF-8 boundaries are preserved.
    String::from_utf8(out).expect("code_only preserves UTF-8 boundaries")
}

/// The half of a stripped source file that is NOT `#[cfg(test)]`.
///
/// Load-bearing, not tidiness. [`code_only`] preserves string literals
/// verbatim, so every pin's own needle constants are a SECOND occurrence of
/// the text they search for. A pin that scanned the whole file therefore had
/// an UNFIREABLE "signature changed" expect — a #975 T1 review MEASURED it:
/// renaming the production `pub fn evict_all_tenants` to `pub(crate) fn` AND
/// fully inverting its body left `cargo test --lib rooms::bus` at 16 passed /
/// 0 failed, because `find` had re-anchored on the test's own literal and the
/// pin then validated the TEST function's source. Cutting the test half off
/// first makes a rename fail CLOSED.
pub(crate) fn production_half(stripped: &str) -> &str {
    stripped
        .split("#[cfg(test)]")
        .next()
        .expect("split always yields at least one segment")
}

/// The attribute that makes an item test-only, exactly as rustfmt writes it.
const TEST_GATE: &str = "#[cfg(test)]";

/// The first top-level item that follows a stripped file's first
/// `#[cfg(test)]` and is NOT itself gated by `#[cfg(test)]`, as
/// `(1-based line, line text)`; `None` when the file is fine.
///
/// [`production_half`] is "the production code of this file" only while no
/// production item follows a test-only one: an early `#[cfg(test)] const`
/// silently hides everything below it from every pin that scans the file.
/// This is the check that keeps that true. A file with no `#[cfg(test)]` is
/// fine, and so is any number of trailing test-only items.
///
/// Input is [`code_only`] output of a rustfmt-formatted file: top-level items
/// start at column 0 and end at the `;` or the closing `}` that brings the
/// bracket depth back to zero, so a column-0 `where` or `{` line and every
/// attribute line belong to the item they precede. String and char literals
/// are skipped, so a column-0 line inside a test's multi-line string is body
/// text, not an item. Fails CLOSED: a first `#[cfg(test)]` that is not a
/// top-level item attribute (inside a function, a string or an `impl`), an
/// item after it that does not start at column 0, unbalanced brackets and an
/// unterminated item are all reported, never passed.
pub(crate) fn production_after_test_gate(stripped: &str) -> Option<(usize, String)> {
    let gate = stripped.find(TEST_GATE)?;
    let items = match top_level_items(stripped) {
        Ok(items) => items,
        Err(at) => return Some(line_at(stripped, at)),
    };
    let Some(first) = items
        .iter()
        .position(|it| it.attrs.iter().any(|&(start, _)| start == gate))
    else {
        // The first gate is not a top-level attribute, yet `production_half`
        // still cuts there.
        return Some(line_at(stripped, gate));
    };
    for it in &items[first..] {
        if it.start != 0 && stripped.as_bytes()[it.start - 1] != b'\n' {
            return Some(line_at(stripped, it.start));
        }
        if !it.attrs.iter().any(|&(s, e)| is_test_gate(&stripped[s..e])) {
            return Some(line_at(stripped, it.body));
        }
    }
    None
}

/// One top-level item: where it starts (its first attribute, if any), its
/// attributes as byte ranges, and where its first non-attribute token is.
struct TopItem {
    start: usize,
    attrs: Vec<(usize, usize)>,
    body: usize,
}

fn is_test_gate(attr: &str) -> bool {
    attr.split_whitespace().collect::<String>() == TEST_GATE
}

fn line_at(s: &str, at: usize) -> (usize, String) {
    let line_start = s[..at].rfind('\n').map_or(0, |nl| nl + 1);
    let line_end = s[at..].find('\n').map_or(s.len(), |nl| at + nl);
    (
        s[..at].matches('\n').count() + 1,
        s[line_start..line_end].trim_end().to_string(),
    )
}

/// Split stripped source into its top-level items, or `Err(offset)` at the
/// first place the shape cannot be classified.
fn top_level_items(s: &str) -> Result<Vec<TopItem>, usize> {
    let b = s.as_bytes();
    let skip_ws = |mut i: usize| {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    let mut items = Vec::new();
    let mut i = skip_ws(0);
    while i < b.len() {
        let start = i;
        let mut attrs = Vec::new();
        while b[i] == b'#' {
            let open = if b.get(i + 1) == Some(&b'!') {
                i + 2
            } else {
                i + 1
            };
            if b.get(open) != Some(&b'[') {
                return Err(i);
            }
            let end = bracket_group_end(s, open)?;
            attrs.push((i, end));
            i = skip_ws(end);
            if i >= b.len() {
                return Err(start); // an attribute with no item under it
            }
        }
        let body = i;
        i = item_end(s, body)?;
        items.push(TopItem { start, attrs, body });
        i = skip_ws(i);
    }
    Ok(items)
}

/// One past the bracket that closes the group opened at `open`.
fn bracket_group_end(s: &str, open: usize) -> Result<usize, usize> {
    let b = s.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut i = open;
    while i < b.len() {
        if let Some(end) = literal_end(s, i) {
            i = end;
            continue;
        }
        match b[i] {
            b'(' | b'[' | b'{' => stack.push(b[i]),
            c @ (b')' | b']' | b'}') => {
                if stack.pop() != Some(opener_of(c)) {
                    return Err(i);
                }
                if stack.is_empty() {
                    return Ok(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err(open)
}

/// One past the end of the item whose first token is at `body`: the `;` at
/// depth zero, or the `}` that brings the depth back to zero (plus a `;`
/// directly after it, as in `use a::{b, c};` or `const X: S = S { .. };`).
fn item_end(s: &str, body: usize) -> Result<usize, usize> {
    let b = s.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut i = body;
    while i < b.len() {
        if let Some(end) = literal_end(s, i) {
            i = end;
            continue;
        }
        match b[i] {
            b'(' | b'[' | b'{' => stack.push(b[i]),
            c @ (b')' | b']' | b'}') => {
                if stack.pop() != Some(opener_of(c)) {
                    return Err(i);
                }
                if c == b'}' && stack.is_empty() {
                    let mut k = i + 1;
                    while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
                        k += 1;
                    }
                    return Ok(if b.get(k) == Some(&b';') {
                        k + 1
                    } else {
                        i + 1
                    });
                }
            }
            b';' if stack.is_empty() => return Ok(i + 1),
            _ => {}
        }
        i += 1;
    }
    Err(body)
}

fn opener_of(close: u8) -> u8 {
    match close {
        b')' => b'(',
        b']' => b'[',
        _ => b'{',
    }
}

/// One past the string, raw string, byte string or char literal starting at
/// `i`, or `None` when no literal starts there (a lifetime is not one).
fn literal_end(s: &str, i: usize) -> Option<usize> {
    let b = s.as_bytes();
    match b[i] {
        b'"' => Some(string_end(b, i)),
        b'r' if raw_prefix_ok(b, i) => raw_string_end(b, i),
        b'\'' => {
            let rest = &s[i + 1..];
            let inner = if let Some(esc) = rest.strip_prefix('\\') {
                if let Some(unicode) = esc.strip_prefix("u{") {
                    3 + unicode.find('}')? + 1
                } else {
                    1 + esc.chars().next()?.len_utf8()
                }
            } else {
                rest.chars().next()?.len_utf8()
            };
            (b.get(i + 1 + inner) == Some(&b'\'')).then_some(i + 2 + inner)
        }
        _ => None,
    }
}

/// Slice out ONE PRODUCTION function's comment-stripped body text.
///
/// `head` is matched against [`production_half`] and must be UNIQUE there —
/// a head that matches twice cannot say which function the pin anchored on,
/// so it panics rather than picking the first.
pub(crate) fn prod_fn_body<'a>(stripped: &'a str, head: &str) -> &'a str {
    let prod = production_half(stripped);
    let start = prod.find(head).unwrap_or_else(|| {
        panic!(
            "`{head}` not found in the production half of the pinned file — the signature \
             changed (or the fn moved below `#[cfg(test)]`); update this structural pin"
        )
    });
    assert!(
        !prod[start + head.len()..].contains(head),
        "`{head}` occurs more than once in the production half — a structural pin cannot tell \
         which of them it anchored on; make the head unique or split the pin"
    );

    // The closing brace sits at the head's OWN indentation, so derive the
    // terminator rather than taking it as a parameter. The two failure
    // directions are not symmetric: a method marker (`\n    }\n`) used on a
    // top-level fn cuts the body short — fail CLOSED, a visible panic — but a
    // top-level marker (`\n}\n`) used on a method runs past the fn to the end
    // of its `impl` block and silently pins the wrong text. Deriving removes
    // the fail-OPEN direction, which is the whole failure class these pins
    // exist to close.
    let line_start = prod[..start].rfind('\n').map_or(0, |nl| nl + 1);
    let indent = &prod[line_start..start];
    assert!(
        indent.bytes().all(|b| b == b' '),
        "the pinned head `{head}` must start its own line, but the text before it on that \
         line was {indent:?}"
    );
    let terminator = format!("\n{indent}}}\n");

    let rest = &prod[start..];
    let end = rest
        .find(&terminator)
        .unwrap_or_else(|| panic!("could not find the end of the body of `{head}`"));
    &rest[..end]
}

/// Whether the `r` at `i` can open a raw string: not the tail of an
/// identifier, except for the `b` of a raw byte string (`br"…"`).
fn raw_prefix_ok(b: &[u8], i: usize) -> bool {
    match i.checked_sub(1) {
        None => true,
        Some(p) if b[p] == b'b' => !is_ident_byte(b, p.wrapping_sub(1)),
        Some(p) => !is_ident_byte(b, p),
    }
}

fn is_ident_byte(b: &[u8], i: usize) -> bool {
    b.get(i)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// Index one past the closing quote of the ordinary string starting at `i`.
fn string_end(b: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

/// Index one past the closing `"#…` of the raw string starting at `i`, or
/// `None` if `i` is not the start of one.
fn raw_string_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    let mut hashes = 0usize;
    while b.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if b.get(j) != Some(&b'"') {
        return None;
    }
    let mut term = Vec::with_capacity(hashes + 1);
    term.push(b'"');
    term.extend(std::iter::repeat_n(b'#', hashes));
    let mut k = j + 1;
    while k < b.len() {
        if b[k..].starts_with(&term) {
            return Some(k + term.len());
        }
        k += 1;
    }
    Some(b.len())
}

/// Index one past the closing `'` of a char literal starting at `i`, or `None`
/// when this quote is a lifetime.
fn char_literal_end(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i + 1) == Some(&b'\\') {
        // `'\n'`, `'\''`, `'\\'` … (not `'\u{1F600}'`, which no pinned file uses)
        return (b.get(i + 3) == Some(&b'\'')).then_some(i + 4);
    }
    (b.get(i + 2) == Some(&b'\'')).then_some(i + 3)
}

/// Every `.rs` file at or below `dir`, recursively. Panics rather than skipping
/// an unreadable directory: a walk that quietly covers less than the tree is
/// exactly the vacuous pass a tree-wide pin must not have. Shared by
/// `mgmt::pat_evict_pin` and `safety::ip`'s client-IP consumer pin.
pub(crate) fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("cannot walk {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::code_only;

    /// The three measured mutants, as scanner-level assertions: after
    /// stripping, a needle that survives is a needle that is really in the
    /// code.
    #[test]
    fn code_only_blanks_comments_and_keeps_code() {
        let src = "\
fn f() {
    if c() { break; } // no break
    // if c() { break; }
    /* self.bump_epoch(t); */
    self.channels.remove(t);
    self.bump_epoch(t);
}
";
        let out = code_only(src);
        assert_eq!(
            out.matches("break").count(),
            1,
            "mutants 1+2: only the real break must survive, got:\n{out}"
        );
        assert!(
            out.find("self.bump_epoch(t);").unwrap()
                > out.find("self.channels.remove(t);").unwrap(),
            "mutant 3: the commented-out bump must not be found before the teardown:\n{out}"
        );
        assert_eq!(
            out.lines().count(),
            src.lines().count(),
            "line structure must survive so the stripped text stays readable in a failure"
        );
    }

    #[test]
    fn code_only_keeps_string_and_char_literals_whole() {
        let src = "let a = \"not // a comment\"; let q = '\"'; let b = 1; // gone\n";
        let out = code_only(src);
        assert!(out.contains("\"not // a comment\""), "{out}");
        assert!(
            out.contains("let b = 1;"),
            "a quote inside a char literal must not open a phantom string: {out}"
        );
        assert!(!out.contains("gone"), "{out}");
    }

    #[test]
    fn code_only_keeps_raw_strings_and_nests_block_comments() {
        let src = "let s = r#\"a // b /* c */\"#; /* x /* y */ z */ let d = 2;\n";
        let out = code_only(src);
        assert!(out.contains("r#\"a // b /* c */\"#;"), "{out}");
        assert!(
            !out.contains(" y "),
            "nested block comment not stripped: {out}"
        );
        assert!(
            out.contains("let d = 2;"),
            "the nested comment must end at the OUTER close: {out}"
        );
    }

    fn after_gate(src: &str) -> Option<(usize, String)> {
        super::production_after_test_gate(&code_only(src))
    }

    #[test]
    fn a_gated_const_above_an_ungated_fn_is_reported() {
        let src = "\
const A: u8 = 1;
#[cfg(test)]
const ALL: &[u8] = &[
    A,
];

/// Doc.
pub fn later(x: u8) -> u8 {
    x
}
";
        assert_eq!(
            after_gate(src),
            Some((8, "pub fn later(x: u8) -> u8 {".to_string()))
        );
    }

    #[test]
    fn production_then_a_gated_impl_then_gated_modules_is_fine() {
        let src = "\
pub struct S;

impl S {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
impl S {
    fn probe(&self) -> u8 {
        1
    }
}

#[cfg(test)]
const ORACLE: &str = \"x\";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t() {
        let src = \"
fn f() {
    #[cfg(test)]
}
\";
        let q = '\"';
        let _ = (src, q, '{', '\\u{FFFD}');
    }
}

#[cfg(test)]
mod more_tests {}
";
        assert_eq!(after_gate(src), None);
    }

    #[test]
    fn a_file_without_a_test_gate_is_fine() {
        assert_eq!(after_gate("pub fn f() {}\n\nconst X: u8 = 1;\n"), None);
        assert_eq!(after_gate(""), None);
    }

    #[test]
    fn a_gated_one_line_item_then_an_ungated_multi_line_item_is_reported() {
        let src = "\
pub fn f() {}

#[cfg(test)]
const X: u8 = 1;
#[allow(dead_code)]
pub(crate) struct Later {
    a: u8,
}
";
        assert_eq!(
            after_gate(src),
            Some((6, "pub(crate) struct Later {".to_string()))
        );
    }

    #[test]
    fn where_clauses_and_multi_line_signatures_are_one_item() {
        let src = "\
pub fn f() {}

#[cfg(test)]
impl<T> From<T> for Wrapper
where
    T: Clone,
{
    fn from(t: T) -> Self {
        Wrapper
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn helper(
    a: u8,
    b: u8,
) -> u8
where
    u8: Copy,
{
    a + b
}

#[cfg(test)]
mod tests {}
";
        assert_eq!(after_gate(src), None);
        // The same shape with the second item ungated is still caught, at the
        // line of its `fn`, not at a column-0 `where` or `{`.
        let ungated = src.replacen(
            "#[cfg(test)]\n#[allow(clippy::too_many_arguments)]",
            "#[allow(clippy::too_many_arguments)]",
            1,
        );
        assert_eq!(after_gate(&ungated), Some((14, "fn helper(".to_string())));
    }

    /// Fails closed on every shape it cannot classify.
    #[test]
    fn unclassifiable_shapes_are_reported_not_passed() {
        // A first gate inside a function: `production_half` still cuts there.
        let nested = "fn f() {\n    #[cfg(test)]\n    let x = 1;\n}\n\nfn g() {}\n";
        assert_eq!(
            after_gate(nested),
            Some((2, "    #[cfg(test)]".to_string()))
        );
        // A first gate that is only text in a production string literal.
        let in_string = "const S: &str = \"#[cfg(test)]\";\nfn g() {}\n";
        assert_eq!(after_gate(in_string).map(|(l, _)| l), Some(1));
        // `cfg(any(test, ..))` is not test-only.
        let any = "#[cfg(test)]\nfn a() {}\n#[cfg(any(test, unix))]\nfn b() {}\n";
        assert_eq!(after_gate(any), Some((4, "fn b() {}".to_string())));
        // An item after the gate that does not start at column 0.
        let indented = "#[cfg(test)]\nfn a() {} fn b() {}\n";
        assert_eq!(after_gate(indented).map(|(l, _)| l), Some(2));
        // Unbalanced brackets and an unterminated item.
        assert!(after_gate("#[cfg(test)]\nmod tests {\n    fn a() {}\n").is_some());
        assert!(after_gate("#[cfg(test)]\nmod tests {\n    )\n}\n").is_some());
        assert!(after_gate("fn f() {}\n#[cfg(test)]\n").is_some());
    }

    /// A raw BYTE string must not put the scanner out of phase: its `"#`
    /// closer used to open a phantom string, after which a URL in a real
    /// string read as a comment and was blanked.
    #[test]
    fn code_only_keeps_raw_byte_strings_whole() {
        let src = "const H: &[u8] = br#\"{\"a\":\"b\"}\"#;\nlet u = \"http://x\"; // gone\n";
        let out = code_only(src);
        assert!(out.contains("br#\"{\"a\":\"b\"}\"#;"), "{out}");
        assert!(out.contains("\"http://x\";"), "{out}");
        assert!(!out.contains("gone"), "{out}");
        // An identifier ending in `br` is not a raw-string prefix.
        let ident = "let abr = 1; // c\n";
        assert!(!code_only(ident).contains("// c"));
    }

    /// A lifetime is not a char literal — mis-treating `'a` as one would eat
    /// the following bytes and could swallow a needle.
    #[test]
    fn code_only_leaves_lifetimes_alone() {
        let src = "fn g<'a>(x: &'a str) -> &'a str { x } // c\n";
        let out = code_only(src);
        assert!(
            out.contains("fn g<'a>(x: &'a str) -> &'a str { x }"),
            "{out}"
        );
        assert!(!out.contains("// c"), "{out}");
    }
}

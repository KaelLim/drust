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
        // Raw string `r"…"` / `r#"…"#` — checked before the bare-`"` arm so
        // the hashes are consumed with it.
        if b[i] == b'r'
            && !is_ident_byte(b, i.wrapping_sub(1))
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

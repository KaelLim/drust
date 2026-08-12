// Compile-time test-target coverage gate (#925, spec 2026-08-13).
//
// PURE functions only — no I/O, no `panic!`. `build.rs` does the file reading
// and turns violations into a build failure; the same file is mounted into the
// lib under `cfg(test)` (`src/lib.rs`) so the suite can exercise the logic.
// build.rs itself is never covered by `cargo test`, which is why the logic
// lives here instead of inline in build.rs — same arrangement as ui_gates.rs.
//
// WHY THIS GATE EXISTS: `[package] autotests = false` (the #925 consolidation)
// means cargo no longer auto-discovers `tests/*.rs`. A file nobody registered
// is then silently never compiled and never run — no error, no warning, no
// missing-suite line in the output. Before #925 that failure mode did not
// exist. This gate restores fail-loud: every `tests/*.rs` must be reachable
// from a `[[test]]` target, or be on the tiny allowlist.
//
// NOTE: plain `//` comments, NOT `//!` module docs. build.rs pulls this file
// in with `include!`, which splices it in *after* items — an inner doc comment
// there is a hard parse error (E0753).

/// `tests/*.rs` files that are deliberately neither a `[[test]]` target nor
/// reachable from one.
///
/// `helpers.rs` is the 42 KB shared harness every suite pulls in with
/// `#[path = "helpers.rs"] mod helpers;`. It declares zero `#[test]` fns, so
/// before #925 cargo compiled and linked it as a test binary of its own for
/// nothing. It stays off the target list on purpose.
///
/// Keep this list at the length it is. An allowlist is the failure mode this
/// gate exists to prevent — "just add it to the list" is how a suite goes dark.
pub const TEST_TARGET_ALLOWLIST: &[&str] = &["helpers.rs"];

/// One test-target coverage violation. `file` is the `tests/`-relative file
/// name (not a full path). Shape mirrors `ui_gates::Violation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestTargetViolation {
    pub file: String,
    pub rule: &'static str,
    pub message: String,
}

/// Every `path` value of a `[[test]]` table in the parsed Cargo manifest, as
/// written. An entry with no explicit `path` falls back to cargo's default
/// layout (`tests/<name>.rs`) so the gate does not depend on our generator's
/// style.
pub fn declared_test_paths(manifest: &toml::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(entries) = manifest.get("test").and_then(|v| v.as_array()) else {
        return out;
    };
    for entry in entries {
        if let Some(path) = entry.get("path").and_then(|v| v.as_str()) {
            out.push(path.to_string());
        } else if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
            out.push(format!("tests/{name}.rs"));
        }
    }
    out
}

/// Normalise a manifest `path` or a `#[path = "..."]` literal to a
/// `tests/`-relative file name (`"tests/g_mcp.rs"` → `"g_mcp.rs"`). Values
/// that name a subdirectory module (`"common/mod.rs"`) come back unchanged and
/// simply never match a top-level `tests/*.rs` file.
pub fn tests_relative(path: &str) -> String {
    let p = path.strip_prefix("./").unwrap_or(path);
    p.strip_prefix("tests/").unwrap_or(p).to_string()
}

/// Byte mask over a Rust source: `true` where the byte is live code, `false`
/// inside a comment (`//`, `/* */`, nesting) or inside a string / char literal
/// (including `b"…"`, `r"…"`, `br##"…"##`).
///
/// This exists because the gate is a TEXT scan, and a text scan that only
/// understands `//` is fail-OPEN in the one direction that matters: a `#[path]`
/// left inside a `/* … */` block is invisible to rustc but looked like a live
/// include, so commenting a harness member out that way dropped its tests while
/// the build stayed green — precisely the silent-dark suite the gate exists to
/// prevent.
///
/// String awareness is not optional either, and not theoretical: the real test
/// tree contains `/public/*` inside multi-line string literals
/// (`tests/upload_content_type_safety.rs`). A comment scanner blind to strings
/// would open a block comment there and swallow every include after it — the
/// opposite failure (a false red), but a broken build all the same.
///
/// `'` is a char literal only when it closes like one (`'x'`, `'\n'`,
/// `'\u{1F600}'`); anything else is a lifetime tick and stays code.
fn code_mask(source: &str) -> Vec<bool> {
    let b = source.as_bytes();
    let mut mask = vec![true; b.len()];
    let mut i = 0usize;

    // Blank `b[from..to)`, clamped to the source.
    let blank = |mask: &mut [bool], from: usize, to: usize| {
        for m in mask.iter_mut().take(to.min(b.len())).skip(from) {
            *m = false;
        }
    };

    while i < b.len() {
        // Raw / byte string prefixes must be tested before the bare `"` arm:
        // `r#"…"#` has no escapes and ends only on `"` + the same hash count.
        if (b[i] == b'r' || b[i] == b'b')
            && let Some((quote, hashes, raw)) = string_prefix_at(b, i)
        {
            let end = string_end(b, quote, hashes, raw);
            blank(&mut mask, i, end);
            i = end;
            continue;
        }
        match b[i] {
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                let mut j = i;
                while j < b.len() && b[j] != b'\n' {
                    j += 1;
                }
                blank(&mut mask, i, j);
                i = j;
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                let mut depth = 1usize;
                let mut j = i + 2;
                while j < b.len() && depth > 0 {
                    if j + 1 < b.len() && b[j] == b'/' && b[j + 1] == b'*' {
                        depth += 1;
                        j += 2;
                    } else if j + 1 < b.len() && b[j] == b'*' && b[j + 1] == b'/' {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                blank(&mut mask, i, j);
                i = j;
            }
            b'"' => {
                let end = string_end(b, i, 0, false);
                blank(&mut mask, i, end);
                i = end;
            }
            b'\'' => match char_literal_end(b, i) {
                Some(end) => {
                    blank(&mut mask, i, end + 1);
                    i = end + 1;
                }
                None => i += 1, // lifetime tick — live code
            },
            _ => i += 1,
        }
    }
    mask
}

/// If a string-literal prefix starts at `i` (`b"`, `r"`, `r#"`, `br##"`, …),
/// return `(index of the opening quote, hash count, is_raw)`. `None` when the
/// byte is just part of an identifier (`for`, `bytes`, a variable named `r`).
fn string_prefix_at(b: &[u8], i: usize) -> Option<(usize, usize, bool)> {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return None;
    }
    let mut j = i;
    if b[j] == b'b' {
        j += 1;
    }
    let mut raw = false;
    if j < b.len() && b[j] == b'r' {
        raw = true;
        j += 1;
    }
    if j == i {
        return None; // consumed neither `b` nor `r`
    }
    let mut hashes = 0usize;
    if raw {
        while j < b.len() && b[j] == b'#' {
            hashes += 1;
            j += 1;
        }
    }
    if j < b.len() && b[j] == b'"' {
        Some((j, hashes, raw))
    } else {
        None
    }
}

/// One past the closing quote of the string literal whose opening quote is at
/// `quote`. Unterminated literals end at EOF rather than panicking — this runs
/// in a build script over files that may be mid-edit.
fn string_end(b: &[u8], quote: usize, hashes: usize, raw: bool) -> usize {
    let mut j = quote + 1;
    while j < b.len() {
        if !raw && b[j] == b'\\' {
            j += 2;
            continue;
        }
        if b[j] == b'"' {
            let close = j + 1;
            if !raw
                || b[close..]
                    .iter()
                    .take(hashes)
                    .filter(|c| **c == b'#')
                    .count()
                    == hashes
            {
                return close + if raw { hashes } else { 0 };
            }
        }
        j += 1;
    }
    b.len()
}

/// Index of the closing `'` when a char literal starts at `i`, else `None`
/// (which means the tick opened a lifetime, not a literal).
fn char_literal_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if j >= b.len() {
        return None;
    }
    if b[j] == b'\\' {
        j += 1;
        if j >= b.len() {
            return None;
        }
        if b[j] == b'u' {
            // '\u{1F600}' — scan to the tick, bounded by the line.
            while j < b.len() && b[j] != b'\'' && b[j] != b'\n' {
                j += 1;
            }
            return (j < b.len() && b[j] == b'\'').then_some(j);
        }
        j += 1;
    } else {
        // One UTF-8 scalar; a `'` here is the empty-looking `'''` typo, not ours.
        j += match b[j] {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            _ => 4,
        };
    }
    (j < b.len() && b[j] == b'\'').then_some(j)
}

/// True when only whitespace separates `start` from the beginning of its line.
fn is_first_token_on_line(source: &str, start: usize) -> bool {
    source[..start]
        .rsplit('\n')
        .next()
        .is_none_or(|before| before.trim().is_empty())
}

/// Every `#[path = "..."]` literal in one test source that rustc would actually
/// act on, in file order.
///
/// Two conditions, both required, because the ONE thing this gate must never do
/// is count a `#[path]` the compiler ignores — that is how a commented-out
/// harness member goes dark with a green build:
///
/// 1. the attribute starts in live code (see `code_mask`): not inside `//`, not
///    inside `/* … */`, not inside a string literal;
/// 2. the attribute is the first non-whitespace token on its line, which is how
///    every real `#[path]` site in `tests/` is written. This is the belt to
///    `code_mask`'s braces: it independently rejects a `#[path = "…"]` that
///    appears mid-line inside prose or a literal, so forging a phantom include
///    edge takes two coincidences instead of one.
pub fn path_includes(source: &str) -> Vec<String> {
    let re = regex_lite::Regex::new(r#"#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]"#)
        .expect("compile #[path] scan regex");
    let mask = code_mask(source);
    let mut out = Vec::new();
    for cap in re.captures_iter(source) {
        let start = cap.get(0).expect("whole match").start();
        if !mask.get(start).copied().unwrap_or(false) {
            continue; // inside a comment or a literal — rustc never sees it
        }
        if !is_first_token_on_line(source, start) {
            continue;
        }
        out.push(cap.get(1).expect("capture group 1").as_str().to_string());
    }
    out
}

/// The gate. `test_sources` is `(file name relative to tests/, source text)`
/// for every top-level `tests/*.rs`; `manifest` is the parsed Cargo.toml.
///
/// Three rules:
///
/// - `unregistered-test-file` — the file compiles into no test binary at all:
///   it is not a `[[test]]` target and no reachable harness `#[path]`-includes
///   it. This is the silent-dark-suite case `autotests = false` introduced.
/// - `double-registered-test-file` — the file is BOTH its own `[[test]]` target
///   and a member of a harness, so every one of its tests compiles twice and
///   runs twice. Harmless-looking, but it inflates the suite total that the
///   #925 acceptance check ("same number of tests as before the merge") reads.
/// - `multi-harness-member` — the same file is a `#[path]` member of two
///   different harnesses. Identical consequence (tests run twice, suite total
///   inflated) reached by the other copy-paste slip: the 24 harnesses are
///   transcribed by hand from the plan's group table, and landing one file in
///   two groups compiles clean. Allowlisted shared modules (`helpers.rs`) are
///   exempt — being included by everything is their job.
///
/// Reachability is transitive: a harness that is itself unregistered does not
/// launder its members, because nothing compiles any of them.
pub fn check_test_targets(
    manifest: &toml::Value,
    test_sources: &[(String, String)],
) -> Vec<TestTargetViolation> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    let known: BTreeMap<&str, &str> = test_sources
        .iter()
        .map(|(name, src)| (name.as_str(), src.as_str()))
        .collect();

    let roots: BTreeSet<String> = declared_test_paths(manifest)
        .iter()
        .map(|p| tests_relative(p))
        .collect();

    // Walk the include graph from the declared targets.
    let mut reached: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = roots
        .iter()
        .filter(|r| known.contains_key(r.as_str()))
        .cloned()
        .collect();
    while let Some(file) = queue.pop_front() {
        if !reached.insert(file.clone()) {
            continue;
        }
        let Some(src) = known.get(file.as_str()) else {
            continue;
        };
        for inc in path_includes(src) {
            let inc = tests_relative(&inc);
            if known.contains_key(inc.as_str()) && !reached.contains(&inc) {
                queue.push_back(inc);
            }
        }
    }

    let mut out = Vec::new();

    for (name, _) in test_sources {
        if reached.contains(name) || TEST_TARGET_ALLOWLIST.contains(&name.as_str()) {
            continue;
        }
        let stem = name.strip_suffix(".rs").unwrap_or(name);
        out.push(TestTargetViolation {
            file: name.clone(),
            rule: "unregistered-test-file",
            message: format!(
                "tests/{name} compiles into no test binary: it is not a [[test]] target in \
                 Cargo.toml and no harness `#[path]`-includes it. Either add it to the \
                 matching tests/g_<group>.rs harness, or give it its own [[test]] entry \
                 (name = \"{stem}\", path = \"tests/{name}\")"
            ),
        });
    }

    // Which reachable file first `#[path]`-included each member. `test_sources`
    // is sorted by the caller, so "first" is deterministic and the second
    // inclusion is the one reported.
    let mut included_by: BTreeMap<String, String> = BTreeMap::new();

    for (name, src) in test_sources {
        if !reached.contains(name) {
            continue; // already reported as unregistered; its includes are dead too
        }
        for inc in path_includes(src) {
            let inc = tests_relative(&inc);
            if inc == *name || !known.contains_key(inc.as_str()) {
                continue;
            }
            if roots.contains(&inc) {
                out.push(TestTargetViolation {
                    file: inc.clone(),
                    rule: "double-registered-test-file",
                    message: format!(
                        "tests/{inc} is a [[test]] target AND a `#[path]` member of \
                         tests/{name} — every test in it compiles and runs twice. Drop one: \
                         a merged member keeps no [[test]] entry of its own"
                    ),
                });
            }
            if TEST_TARGET_ALLOWLIST.contains(&inc.as_str()) {
                continue; // shared module: included by everything, on purpose
            }
            match included_by.get(&inc) {
                None => {
                    included_by.insert(inc.clone(), name.clone());
                }
                Some(first) if first != name => {
                    out.push(TestTargetViolation {
                        file: inc.clone(),
                        rule: "multi-harness-member",
                        message: format!(
                            "tests/{inc} is a `#[path]` member of BOTH tests/{first} and \
                             tests/{name} — every test in it compiles and runs twice. A file \
                             belongs to exactly one group harness; check the #925 group table"
                        ),
                    });
                }
                Some(_) => {}
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(name: &str, body: &str) -> (String, String) {
        (name.to_string(), body.to_string())
    }

    fn manifest(toml_src: &str) -> toml::Value {
        toml::from_str(toml_src).expect("fixture manifest parses")
    }

    /// The shape of the real tree: one harness target plus its members, one
    /// standalone target, and the allowlisted shared helper.
    fn green_fixture() -> (toml::Value, Vec<(String, String)>) {
        let m = manifest(
            r#"
[[test]]
name = "g_mcp"
path = "tests/g_mcp.rs"
[[test]]
name = "base_path_root"
path = "tests/base_path_root.rs"
"#,
        );
        let sources = vec![
            src(
                "g_mcp.rs",
                "#[path = \"mcp_read.rs\"]\nmod mcp_read;\n#[path = \"mcp_write.rs\"]\nmod mcp_write;\n",
            ),
            src("mcp_read.rs", "#[path = \"helpers.rs\"]\nmod helpers;\n"),
            src("mcp_write.rs", "#[path = \"helpers.rs\"]\nmod helpers;\n"),
            src(
                "base_path_root.rs",
                "#[path = \"helpers.rs\"]\nmod helpers;\n",
            ),
            src("helpers.rs", "pub fn app() {}\n"),
        ];
        (m, sources)
    }

    #[test]
    fn green_when_every_file_is_a_target_a_member_or_allowlisted() {
        let (m, sources) = green_fixture();
        assert_eq!(
            check_test_targets(&m, &sources),
            vec![],
            "harness members, standalone targets and helpers.rs are all covered"
        );
    }

    /// The red half of the #925 Step-2 proof, as a fixture: drop one member
    /// from the harness and the gate must name exactly that file.
    #[test]
    fn red_when_a_harness_member_is_dropped() {
        let (m, mut sources) = green_fixture();
        sources[0] = src("g_mcp.rs", "#[path = \"mcp_write.rs\"]\nmod mcp_write;\n");
        let v = check_test_targets(&m, &sources);
        assert_eq!(v.len(), 1, "exactly the orphaned member is flagged: {v:?}");
        assert_eq!(v[0].file, "mcp_read.rs");
        assert_eq!(v[0].rule, "unregistered-test-file");
        assert!(
            v[0].message.contains("tests/mcp_read.rs"),
            "message names the file: {}",
            v[0].message
        );
    }

    /// Commenting the member out is the same failure — the scanner must not
    /// count a `#[path]` that only survives inside a `//` comment. This is the
    /// exact edit the live red/green proof makes to tests/g_mcp.rs.
    #[test]
    fn red_when_a_harness_member_is_commented_out() {
        let (m, mut sources) = green_fixture();
        sources[0] = src(
            "g_mcp.rs",
            "// #[path = \"mcp_read.rs\"]\n// mod mcp_read;\n#[path = \"mcp_write.rs\"]\nmod mcp_write;\n",
        );
        let v = check_test_targets(&m, &sources);
        assert_eq!(v.len(), 1, "commented-out include is not an include: {v:?}");
        assert_eq!(v[0].file, "mcp_read.rs");
    }

    /// Same edit, block-comment flavour. This one was live fail-OPEN: wrapping
    /// the include in `/* … */` left `cargo check` green while
    /// `cargo test --test g_mcp` silently dropped that member's tests, because
    /// the scanner only knew about `//`.
    #[test]
    fn red_when_a_harness_member_is_block_commented_out() {
        let (m, mut sources) = green_fixture();
        sources[0] = src(
            "g_mcp.rs",
            "/*\n#[path = \"mcp_read.rs\"]\nmod mcp_read;\n*/\n#[path = \"mcp_write.rs\"]\nmod mcp_write;\n",
        );
        let v = check_test_targets(&m, &sources);
        assert_eq!(
            v.len(),
            1,
            "block-commented include is not an include: {v:?}"
        );
        assert_eq!(v[0].file, "mcp_read.rs");
        assert_eq!(v[0].rule, "unregistered-test-file");
    }

    /// Rust block comments nest, so the closing `*/` of an inner block does not
    /// end the outer one. A depth-blind scanner would treat everything after it
    /// as live code again.
    #[test]
    fn red_when_a_harness_member_is_inside_a_nested_block_comment() {
        let (m, mut sources) = green_fixture();
        sources[0] = src(
            "g_mcp.rs",
            "/* outer /* inner */\n#[path = \"mcp_read.rs\"]\nmod mcp_read;\n*/\n#[path = \"mcp_write.rs\"]\nmod mcp_write;\n",
        );
        let v = check_test_targets(&m, &sources);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].file, "mcp_read.rs");
    }

    /// The other half of the same textual-scan class: a `#[path = "…"]` that
    /// only exists inside a string literal must not forge an include edge and
    /// launder an unregistered file into the reached set.
    #[test]
    fn a_path_attribute_inside_a_string_literal_does_not_register_a_file() {
        let (m, mut sources) = green_fixture();
        sources.push(src("orphan.rs", "#[test]\nfn t() {}\n"));
        // A reached member "mentions" orphan.rs in a doc line and in a literal.
        sources[1] = src(
            "mcp_read.rs",
            "#[path = \"helpers.rs\"]\nmod helpers;\n//! see #[path = \"orphan.rs\"]\nconst S: &str = r#\"\n#[path = \"orphan.rs\"]\n\"#;\n",
        );
        sources.sort();
        let v = check_test_targets(&m, &sources);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].file, "orphan.rs");
        assert_eq!(v[0].rule, "unregistered-test-file");
    }

    /// The false-RED direction, and not hypothetical: the real tree has
    /// `/public/*` inside multi-line string literals
    /// (tests/upload_content_type_safety.rs). A comment scanner blind to
    /// strings opens a block comment there and swallows every include that
    /// follows — turning a green tree into a build failure.
    #[test]
    fn a_slash_star_inside_a_string_does_not_swallow_later_includes() {
        let s = "const C: &str = \"the Caddy /public/* layer\";\n#[path = \"a.rs\"]\nmod a;\n";
        assert_eq!(path_includes(s), vec!["a.rs"]);

        let raw = "const C: &str = r#\"/admin/* and a \" quote\"#;\n#[path = \"b.rs\"]\nmod b;\n";
        assert_eq!(path_includes(raw), vec!["b.rs"]);

        // Char literals and lifetimes must not desync the scanner either:
        // `'"'` is a real occurrence in tests/batch_insert.rs.
        let quoted_char = "fn f<'a>(s: &'a str) -> String { s.replace('\"', \"\\\"\\\"\") }\n#[path = \"c.rs\"]\nmod c;\n";
        assert_eq!(path_includes(quoted_char), vec!["c.rs"]);
    }

    #[test]
    fn red_when_a_brand_new_test_file_is_never_registered() {
        let (m, mut sources) = green_fixture();
        sources.push(src("shiny_new_feature.rs", "#[test]\nfn t() {}\n"));
        let v = check_test_targets(&m, &sources);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].file, "shiny_new_feature.rs");
        assert!(
            v[0].message.contains("[[test]]"),
            "message tells you how to fix it: {}",
            v[0].message
        );
    }

    /// An unregistered harness does not launder its members: nothing compiles
    /// any of them, so all of them are reported.
    #[test]
    fn unregistered_harness_does_not_cover_its_members() {
        let m =
            manifest("[[test]]\nname = \"base_path_root\"\npath = \"tests/base_path_root.rs\"\n");
        let sources = vec![
            src(
                "g_new.rs",
                "#[path = \"new_one.rs\"]\nmod new_one;\n#[path = \"new_two.rs\"]\nmod new_two;\n",
            ),
            src("new_one.rs", ""),
            src("new_two.rs", ""),
            src("base_path_root.rs", ""),
        ];
        let mut files: Vec<String> = check_test_targets(&m, &sources)
            .into_iter()
            .map(|v| v.file)
            .collect();
        files.sort();
        assert_eq!(files, ["g_new.rs", "new_one.rs", "new_two.rs"]);
    }

    #[test]
    fn double_registration_is_flagged() {
        let (mut m, sources) = green_fixture();
        // mcp_read is a harness member AND kept its own [[test]] entry.
        let extra: toml::Value =
            manifest("[[test]]\nname = \"mcp_read\"\npath = \"tests/mcp_read.rs\"\n");
        let mut arr = m
            .get("test")
            .and_then(|v| v.as_array())
            .expect("fixture has [[test]]")
            .clone();
        arr.extend(
            extra
                .get("test")
                .and_then(|v| v.as_array())
                .expect("extra has [[test]]")
                .clone(),
        );
        m.as_table_mut()
            .expect("manifest is a table")
            .insert("test".to_string(), toml::Value::Array(arr));

        let v = check_test_targets(&m, &sources);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].rule, "double-registered-test-file");
        assert_eq!(v[0].file, "mcp_read.rs");
        assert!(v[0].message.contains("tests/g_mcp.rs"));
    }

    /// The T2–T4 copy-paste slip: 24 harnesses are transcribed by hand from the
    /// group table, and a file pasted into two of them compiles clean while its
    /// tests run twice.
    #[test]
    fn multi_harness_membership_is_flagged() {
        let (mut m, mut sources) = green_fixture();
        let extra: toml::Value =
            manifest("[[test]]\nname = \"g_two\"\npath = \"tests/g_two.rs\"\n");
        let mut arr = m
            .get("test")
            .and_then(|v| v.as_array())
            .expect("fixture has [[test]]")
            .clone();
        arr.extend(
            extra
                .get("test")
                .and_then(|v| v.as_array())
                .expect("extra has [[test]]")
                .clone(),
        );
        m.as_table_mut()
            .expect("manifest is a table")
            .insert("test".to_string(), toml::Value::Array(arr));
        // g_two claims mcp_read too — which g_mcp already owns.
        sources.push(src(
            "g_two.rs",
            "#[path = \"mcp_read.rs\"]\nmod mcp_read;\n",
        ));
        sources.sort();

        let v = check_test_targets(&m, &sources);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].rule, "multi-harness-member");
        assert_eq!(v[0].file, "mcp_read.rs");
        assert!(
            v[0].message.contains("tests/g_mcp.rs") && v[0].message.contains("tests/g_two.rs"),
            "message names both harnesses: {}",
            v[0].message
        );
    }

    /// The green half of the same rule: `helpers.rs` is `#[path]`-included by
    /// all 30-odd test files on purpose, so the allowlist must exempt it —
    /// otherwise the gate would fire on every harness in the tree.
    #[test]
    fn shared_helper_included_everywhere_is_not_multi_harness_membership() {
        let (m, sources) = green_fixture();
        let helper_includers = sources
            .iter()
            .filter(|(_, s)| s.contains("helpers.rs"))
            .count();
        assert!(helper_includers >= 3, "fixture must exercise the exemption");
        assert!(
            check_test_targets(&m, &sources)
                .iter()
                .all(|v| v.rule != "multi-harness-member"),
            "allowlisted shared modules are exempt from the one-harness rule"
        );
    }

    #[test]
    fn allowlist_covers_only_the_shared_helper() {
        assert_eq!(
            TEST_TARGET_ALLOWLIST,
            &["helpers.rs"],
            "growing this list is how a suite goes dark — see the gate's header comment"
        );
    }

    #[test]
    fn declared_test_paths_reads_explicit_and_default_layout() {
        let m = manifest(
            "[[test]]\nname = \"a\"\npath = \"tests/a.rs\"\n[[test]]\nname = \"b\"\n[[bin]]\nname = \"drust\"\npath = \"src/main.rs\"\n",
        );
        assert_eq!(declared_test_paths(&m), vec!["tests/a.rs", "tests/b.rs"]);
    }

    #[test]
    fn declared_test_paths_is_empty_without_a_test_array() {
        let m = manifest("[package]\nname = \"drust\"\n");
        assert!(declared_test_paths(&m).is_empty());
    }

    #[test]
    fn tests_relative_strips_the_prefix_but_keeps_subdir_modules() {
        assert_eq!(tests_relative("tests/g_mcp.rs"), "g_mcp.rs");
        assert_eq!(tests_relative("./tests/g_mcp.rs"), "g_mcp.rs");
        assert_eq!(tests_relative("mcp_read.rs"), "mcp_read.rs");
        assert_eq!(
            tests_relative("webhooks_common/mod.rs"),
            "webhooks_common/mod.rs"
        );
    }

    #[test]
    fn path_includes_tolerates_spacing_and_ignores_comments() {
        let s = "#[path=\"a.rs\"]\n#[ path = \"b.rs\" ]\n// #[path = \"c.rs\"]\nlet x = 1; // #[path = \"d.rs\"]\n";
        assert_eq!(path_includes(s), vec!["a.rs", "b.rs"]);
    }

    /// Every real `#[path]` site in `tests/` opens its line; a mid-line one is
    /// prose or a literal, never a module declaration rustc acts on.
    #[test]
    fn path_includes_requires_the_attribute_to_open_its_line() {
        assert_eq!(
            path_includes("  \t#[path = \"a.rs\"]\nmod a;\n"),
            vec!["a.rs"]
        );
        assert!(path_includes("let s = x; #[path = \"a.rs\"] mod a;\n").is_empty());
        assert!(path_includes("//! carries #[path = \"helpers.rs\"] itself\n").is_empty());
    }

    #[test]
    fn path_includes_ignores_block_comments_at_any_nesting_depth() {
        assert!(path_includes("/*\n#[path = \"a.rs\"]\n*/\n").is_empty());
        assert!(path_includes("/* /* x */\n#[path = \"a.rs\"]\n*/\n").is_empty());
        // …and the block must actually close before code resumes.
        assert_eq!(
            path_includes("/* off */\n#[path = \"a.rs\"]\nmod a;\n"),
            vec!["a.rs"]
        );
    }
}

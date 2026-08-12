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

/// Every `#[path = "..."]` literal in one test source, in file order.
///
/// Line comments are stripped first: commenting a harness member out MUST make
/// the gate go red, which is exactly how the red/green proof is run. A `#[path]`
/// that survives only inside a `//` comment is not a compiled include.
pub fn path_includes(source: &str) -> Vec<String> {
    let re = regex_lite::Regex::new(r#"#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]"#)
        .expect("compile #[path] scan regex");
    let mut out = Vec::new();
    for raw_line in source.lines() {
        let line = match raw_line.find("//") {
            Some(i) => &raw_line[..i],
            None => raw_line,
        };
        for cap in re.captures_iter(line) {
            out.push(cap.get(1).expect("capture group 1").as_str().to_string());
        }
    }
    out
}

/// The gate. `test_sources` is `(file name relative to tests/, source text)`
/// for every top-level `tests/*.rs`; `manifest` is the parsed Cargo.toml.
///
/// Two rules:
///
/// - `unregistered-test-file` — the file compiles into no test binary at all:
///   it is not a `[[test]]` target and no reachable harness `#[path]`-includes
///   it. This is the silent-dark-suite case `autotests = false` introduced.
/// - `double-registered-test-file` — the file is BOTH its own `[[test]]` target
///   and a member of a harness, so every one of its tests compiles twice and
///   runs twice. Harmless-looking, but it inflates the suite total that the
///   #925 acceptance check ("same number of tests as before the merge") reads.
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

    for (name, src) in test_sources {
        if !reached.contains(name) {
            continue; // already reported as unregistered; its includes are dead too
        }
        for inc in path_includes(src) {
            let inc = tests_relative(&inc);
            if inc != *name && roots.contains(&inc) && known.contains_key(inc.as_str()) {
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
}

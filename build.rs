//! Compile-time validator: every `t.s("...")` / `t.fmt("..."`) literal
//! in `src/mgmt/templates/**/*.html` MUST have a corresponding key in
//! `locales/en.toml`. Failure fails the build with file:line + a
//! Levenshtein-distance "did you mean" hint.
//!
//! Orphan detection also walks every `src/**/*.rs` (recursively) and
//! treats any double-quoted string literal whose shape matches a flat
//! TOML key (`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`, ≥2 segments) as a
//! reference. This covers Rust-side i18n injection paths the template
//! scanner can't see — e.g. `tenant_broadcast.rs` builds an `I18N`
//! object whose values are `t.s("broadcast_inspector.conn.state_*")`
//! and the template reads them as JS globals at runtime. Without this
//! pass, every such key shows up as a false-positive orphan warning.
//!
//! Soft warnings (do not fail build):
//!   - keys in `en.toml` not referenced by any template OR `.rs` file
//!     (orphans — safe to remove, but not a bug)
//!   - keys in any non-en bundle not in `en.toml` (dead — en is source of
//!     truth). Every `locales/<tag>.toml` is checked; adding a new locale
//!     file is enough, no edits to `build.rs` required.
//!
//! See spec docs/superpowers/specs/2026-05-22-drust-i18n-design.md §3.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

include!("build_support/ui_gates.rs");

fn main() {
    println!("cargo:rerun-if-changed=src/mgmt/templates");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=locales/en.toml");
    println!("cargo:rerun-if-changed=build.rs");

    // Discover every locale bundle in one dir-walk, emit rerun-if-changed
    // for each so adding `locales/<tag>.toml` automatically triggers a
    // rebuild and a dead-key check.
    let locales_dir = Path::new("locales");
    let mut non_en_locales: Vec<String> = Vec::new();
    for entry in fs::read_dir(locales_dir).expect("read locales dir") {
        let path = entry.expect("locale entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("locale file_stem utf-8")
            .to_string();
        if stem == "en" {
            continue;
        }
        println!("cargo:rerun-if-changed=locales/{stem}.toml");
        non_en_locales.push(stem);
    }
    non_en_locales.sort();

    let template_dir = Path::new("src/mgmt/templates");
    let mut used = scan_template_keys(template_dir);
    let en_keys = load_toml_keys("locales/en.toml");

    // Merge Rust-side references into `used` so orphan detection covers
    // keys whose only consumer is a `.rs` file (e.g. i18n injection into
    // JS globals via `tenant_broadcast.rs`'s I18N table, or sentinel
    // assertions inside `#[cfg(test)]` modules).
    scan_rs_key_refs(Path::new("src"), &en_keys, &mut used);

    // (a) missing in en — hard error
    let missing: Vec<_> = used
        .iter()
        .filter(|(k, _)| !en_keys.contains(k.as_str()))
        .collect();
    for (key, locs) in &missing {
        let hint = suggest_similar(key, &en_keys);
        for (file, line) in locs.iter() {
            eprintln!(
                "error: i18n key `{key}` missing from locales/en.toml \
                 (referenced at {file}:{line}){hint}"
            );
        }
    }
    if !missing.is_empty() {
        panic!(
            "i18n: {} missing key(s) — fix locales/en.toml before building",
            missing.len()
        );
    }

    // (b) orphans in en — soft warn
    let used_set: HashSet<&str> = used.keys().map(|s| s.as_str()).collect();
    for k in &en_keys {
        if !used_set.contains(k.as_str()) && !k.starts_with("_meta.") {
            println!(
                "cargo:warning=i18n: en.toml key `{k}` is not referenced \
                 by any template (orphan — safe to remove)"
            );
        }
    }

    // (c) dead keys in any non-en bundle — soft warn. en.toml is source of
    // truth, so any key present in another bundle but missing in en.toml is
    // either a typo or a stale translation that nothing renders.
    for stem in &non_en_locales {
        let keys = load_toml_keys(&format!("locales/{stem}.toml"));
        for k in &keys {
            if !en_keys.contains(k.as_str()) && !k.starts_with("_meta.") {
                println!(
                    "cargo:warning=i18n: {stem}.toml key `{k}` is not in en.toml \
                     (dead key — en.toml is source of truth)"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // (d) themes/*.toml validation
    // -----------------------------------------------------------------
    // Adding themes/<code>.toml is enough to trigger a rebuild + check.
    // Required key sets are hard-coded here — they're the implementation
    // contract for src/mgmt/theme.rs.

    println!("cargo:rerun-if-changed=themes");
    let themes_dir = Path::new("themes");
    let mut theme_codes: Vec<String> = Vec::new();
    for entry in fs::read_dir(themes_dir).expect("read themes dir") {
        let path = entry.expect("theme entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("theme file_stem utf-8")
            .to_string();
        println!("cargo:rerun-if-changed=themes/{stem}.toml");
        theme_codes.push(stem);
    }
    theme_codes.sort();

    const REQUIRED_UI_KEYS: &[&str] = &[
        "bg",
        "bg-deep",
        "surface",
        "surface-2",
        "surface-3",
        "border",
        "border-mid",
        "border-strong",
        "fg",
        "fg-2",
        "muted",
        "muted-2",
    ];
    const REQUIRED_ACCENT_KEYS: &[&str] = &[
        "accent",
        "accent-2",
        "accent-soft",
        "accent-border",
        "rust",
        "warn",
        "danger",
        "info",
        "mint",
        "lilac",
    ];
    const REQUIRED_MASCOT_KEYS: &[char] = &['B', 'E', 'P', 'Z', 'R', 'S', 'H'];

    for code in &theme_codes {
        let src = fs::read_to_string(format!("themes/{code}.toml"))
            .unwrap_or_else(|e| panic!("read themes/{code}.toml: {e}"));
        let val: toml::Value =
            toml::from_str(&src).unwrap_or_else(|e| panic!("parse themes/{code}.toml: {e}"));
        let has_system = val.get("system").is_some();
        let has_ui = val.get("ui").is_some();
        let has_accent = val.get("accent").is_some();
        let has_mascot = val.get("mascot").is_some();

        if has_system {
            if has_ui || has_accent || has_mascot {
                panic!(
                    "themes/{code}.toml: has [system] AND one of [ui]/[accent]/[mascot] — \
                     system themes reference others, they do not define palettes"
                );
            }
            let sys = val.get("system").unwrap();
            for partner in &["light", "dark"] {
                let target = sys
                    .get(partner)
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("themes/{code}.toml [system] missing '{partner}'"));
                if !theme_codes.iter().any(|c| c == target) {
                    panic!(
                        "themes/{code}.toml [system].{partner} = '{target}' but \
                         themes/{target}.toml does not exist"
                    );
                }
                if target == code {
                    panic!("themes/{code}.toml [system].{partner} cannot reference itself");
                }
            }
        } else {
            let ui = val
                .get("ui")
                .and_then(|v| v.as_table())
                .unwrap_or_else(|| panic!("themes/{code}.toml missing [ui]"));
            for k in REQUIRED_UI_KEYS {
                if !ui.contains_key(*k) {
                    panic!("themes/{code}.toml [ui] missing required key '{k}'");
                }
            }
            let accent = val
                .get("accent")
                .and_then(|v| v.as_table())
                .unwrap_or_else(|| panic!("themes/{code}.toml missing [accent]"));
            for k in REQUIRED_ACCENT_KEYS {
                if !accent.contains_key(*k) {
                    panic!("themes/{code}.toml [accent] missing required key '{k}'");
                }
            }
            let mascot = val
                .get("mascot")
                .and_then(|v| v.as_table())
                .unwrap_or_else(|| panic!("themes/{code}.toml missing [mascot]"));
            for k in REQUIRED_MASCOT_KEYS {
                let s = k.to_string();
                if !mascot.contains_key(&s) {
                    panic!("themes/{code}.toml [mascot] missing required key '{s}'");
                }
            }
        }
    }

    // v1.25 F7 — TOMLs in themes/ must match the Theme enum exactly.
    // If a new variant is added in src/mgmt/theme.rs, also add its code
    // here. If a TOML is added without an enum variant, palette_for()
    // panics at runtime on the first request — catch it at build time.
    const EXPECTED_THEMES: &[&str] = &["cozy-dark", "soft-light", "system"];

    let expected: std::collections::BTreeSet<&str> = EXPECTED_THEMES.iter().copied().collect();
    let actual: std::collections::BTreeSet<String> = fs::read_dir("themes")
        .expect("read themes dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e.file_name();
            let s = n.to_str()?.to_string();
            s.strip_suffix(".toml").map(String::from)
        })
        .collect();
    let actual_refs: std::collections::BTreeSet<&str> = actual.iter().map(|s| s.as_str()).collect();

    if actual_refs != expected {
        let missing: Vec<&&str> = expected.difference(&actual_refs).collect();
        let extra: Vec<&&str> = actual_refs.difference(&expected).collect();
        panic!(
            "themes/ ↔ EXPECTED_THEMES mismatch. Missing TOMLs: {:?}. Unexpected TOMLs: {:?}. \
             Edit build.rs EXPECTED_THEMES + Theme::ALL in src/mgmt/theme.rs together.",
            missing, extra,
        );
    }

    // ── Admin-UI consistency gates (spec 2026-07-20) ────────────────────
    // Pure scanners live in build_support/ui_gates.rs so the test suite can
    // cover them; this block does the I/O and turns violations into a build
    // failure. Fail-closed: any violation stops the build.
    run_ui_gates(template_dir);
}

/// Returns map: key → [(file, line), ...] for every literal `t.s("key")`
/// or `t.fmt("key", ...)` occurrence.
fn scan_template_keys(dir: &Path) -> BTreeMap<String, Vec<(String, usize)>> {
    let mut out: BTreeMap<String, Vec<(String, usize)>> = BTreeMap::new();
    // Translator surface: `t.s(...)`, `t.fmt(...)`, `t.fmt1(...)`,
    // `t.fmt2(...)`, `t.fmt3(...)`, and the HTML-escaping `t.fmt1_html(...)` /
    // `t.fmt3_html(...)` variants (feed `|safe` sinks). Earlier regex only
    // matched `s|fmt` and missed every numbered `fmtN` variant; the optional
    // `_html` suffix was then missed the same way — keys consumed only via an
    // `_html` variant surfaced as false-positive orphan warnings.
    let re =
        regex_lite::Regex::new(r#"t\s*\.\s*(?:s|fmt[0-9]*(?:_html)?)\s*\(\s*"([A-Za-z0-9_.]+)""#)
            .expect("compile i18n scan regex");

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => panic!("cannot read templates dir {}: {e}", dir.display()),
    };
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            panic!(
                "build.rs: subdirectory found in templates/ ({}). \
                 Recursive walk not implemented — either flatten or extend the scanner.",
                path.display()
            );
        }
        if path.extension().and_then(|s| s.to_str()) != Some("html") {
            continue;
        }
        let txt =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for (line_idx, line) in txt.lines().enumerate() {
            for cap in re.captures_iter(line) {
                let key = cap.get(1).unwrap().as_str().to_string();
                out.entry(key)
                    .or_default()
                    .push((path.display().to_string(), line_idx + 1));
            }
        }
    }
    out
}

/// Recursively walks `src/**/*.rs` and extracts every double-quoted
/// string literal whose value exists in `en_keys`. Matched keys are
/// merged into `used` with `(file, line)` for parity with the template
/// scanner's diagnostics. Skips strings inside line comments (`//`) to
/// avoid stray TODO references holding keys alive.
fn scan_rs_key_refs(
    dir: &Path,
    en_keys: &HashSet<String>,
    used: &mut BTreeMap<String, Vec<(String, usize)>>,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let lit_re =
        regex_lite::Regex::new(r#""([A-Za-z_][A-Za-z0-9_.]*)""#).expect("compile rs literal regex");
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            scan_rs_key_refs(&path, en_keys, used);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let txt = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for (line_idx, raw_line) in txt.lines().enumerate() {
            // Strip trailing line comment. Anything after `//` is not a
            // live reference — keeps stale `// TODO: rename foo.bar`
            // notes from holding keys alive.
            let line = match raw_line.find("//") {
                Some(i) => &raw_line[..i],
                None => raw_line,
            };
            for cap in lit_re.captures_iter(line) {
                let candidate = cap.get(1).unwrap().as_str();
                if !candidate.contains('.') {
                    continue;
                }
                if !en_keys.contains(candidate) {
                    continue;
                }
                used.entry(candidate.to_string())
                    .or_default()
                    .push((path.display().to_string(), line_idx + 1));
            }
        }
    }
}

fn load_toml_keys(path: &str) -> HashSet<String> {
    let src = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let val: toml::Value = toml::from_str(&src).unwrap_or_else(|e| panic!("parse {path}: {e}"));
    let mut out = HashSet::new();
    flatten_toml(&val, String::new(), &mut out);
    out
}

fn flatten_toml(v: &toml::Value, prefix: String, out: &mut HashSet<String>) {
    match v {
        toml::Value::Table(t) => {
            for (k, vv) in t {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_toml(vv, key, out);
            }
        }
        toml::Value::String(_) => {
            out.insert(prefix);
        }
        _ => {}
    }
}

fn suggest_similar(target: &str, set: &HashSet<String>) -> String {
    let mut best: (usize, &str) = (usize::MAX, "");
    for k in set {
        let d = levenshtein(target, k);
        if d < best.0 {
            best = (d, k.as_str());
        }
    }
    if best.0 <= 3 {
        format!(" — did you mean `{}`?", best.1)
    } else {
        String::new()
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Read every template + the CSS source, run all UI gates, and fail the build
/// on any violation with a file:line report.
fn run_ui_gates(template_dir: &Path) {
    let mut templates: Vec<(String, String)> = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(template_dir)
        .expect("read templates dir")
        .map(|e| e.expect("template entry").path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("html"))
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("template file_name utf-8")
            .to_string();
        let body =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        templates.push((name, body));
    }
    // The CSS gate compares against every style source, not just _styles.html:
    // page-scoped <style> blocks legitimately define page-local classes.
    //
    // Extract ONLY <style> block contents. Feeding whole templates in would
    // let JS property access masquerade as a class definition — `el.classList`
    // would register "classList" as defined — which weakens the gate and can
    // mask a real ghost class.
    let css: String = templates
        .iter()
        .map(|(_, body)| extract_style_blocks(body))
        .collect::<Vec<_>>()
        .join("\n");

    let violations = scan_all(&templates, &css);
    if !violations.is_empty() {
        let mut report = String::from("\n\nAdmin-UI consistency gate failed:\n\n");
        for v in &violations {
            report.push_str(&format!(
                "  {}:{}  [{}]\n      {}\n",
                v.file, v.line, v.rule, v.message
            ));
        }
        report
            .push_str("\nSee drust/CLAUDE.md \"Admin 頁面解剖學\" for the canonical page shape.\n");
        panic!("{report}");
    }
}

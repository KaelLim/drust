//! Compile-time validator: every `t.s("...")` / `t.fmt("..."`) literal
//! in `src/mgmt/templates/**/*.html` MUST have a corresponding key in
//! `locales/en.toml`. Failure fails the build with file:line + a
//! Levenshtein-distance "did you mean" hint.
//!
//! Soft warnings (do not fail build):
//!   - keys in `en.toml` not referenced by any template (orphans — safe
//!     to remove, but not a bug)
//!   - keys in `zh-TW.toml` not in `en.toml` (dead — en is source of truth)
//!
//! See spec docs/superpowers/specs/2026-05-22-drust-i18n-design.md §3.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/mgmt/templates");
    println!("cargo:rerun-if-changed=locales/en.toml");
    println!("cargo:rerun-if-changed=locales/zh-TW.toml");
    println!("cargo:rerun-if-changed=build.rs");

    let template_dir = Path::new("src/mgmt/templates");
    let used = scan_template_keys(template_dir);
    let en_keys = load_toml_keys("locales/en.toml");
    let zh_keys = load_toml_keys("locales/zh-TW.toml");

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

    // (c) keys in zh-TW.toml but NOT in en.toml — soft warn (dead in zh-TW)
    for k in &zh_keys {
        if !en_keys.contains(k.as_str()) && !k.starts_with("_meta.") {
            println!(
                "cargo:warning=i18n: zh-TW.toml key `{k}` is not in en.toml \
                 (dead key — en.toml is source of truth)"
            );
        }
    }
}

/// Returns map: key → [(file, line), ...] for every literal `t.s("key")`
/// or `t.fmt("key", ...)` occurrence.
fn scan_template_keys(dir: &Path) -> BTreeMap<String, Vec<(String, usize)>> {
    let mut out: BTreeMap<String, Vec<(String, usize)>> = BTreeMap::new();
    let re = regex_lite::Regex::new(r#"t\s*\.\s*(?:s|fmt)\s*\(\s*"([A-Za-z0-9_.]+)""#)
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
        let txt = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
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

fn load_toml_keys(path: &str) -> HashSet<String> {
    let src = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"));
    let val: toml::Value =
        toml::from_str(&src).unwrap_or_else(|e| panic!("parse {path}: {e}"));
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

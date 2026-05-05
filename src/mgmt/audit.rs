//! Admin-UI audit log viewer.
//!
//! Stateless read path on top of `$DRUST_LOG_DIR/audit-YYYY-MM-DD.jsonl{,.1,.N.gz}`.
//! No in-memory cache; every request rescans. See spec
//! `docs/superpowers/specs/2026-05-05-drust-audit-ui-design.md`.

use crate::safety::audit::AuditEntry;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    H1,
    H24,
    D7,
}

impl Window {
    pub fn from_str_or_default(s: &str) -> Self {
        match s {
            "1h" => Window::H1,
            "7d" => Window::D7,
            _ => Window::H24, // default + fallback for unrecognised input
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Window::H1 => "1h",
            Window::H24 => "24h",
            Window::D7 => "7d",
        }
    }

    /// Number of seconds in this window.
    pub fn seconds(self) -> i64 {
        match self {
            Window::H1 => 60 * 60,
            Window::H24 => 24 * 60 * 60,
            Window::D7 => 7 * 24 * 60 * 60,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AuditScope {
    Host,
    Tenant(String),
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub entries: Vec<AuditEntry>,
    pub parse_errors: usize,
    pub archive_errors: Vec<String>, // file names of skipped corrupt archives
    pub truncated_from: Option<usize>, // Some(N) iff entries was capped at MAX_ENTRIES
}

#[derive(Debug, Default, Clone)]
pub struct FilterSpec {
    pub tenant: Option<String>,
    pub op: Option<String>,
    pub status: Option<&'static str>, // "ok" | "error"
    pub before_ts: Option<String>,
}

#[derive(Debug, Default)]
pub struct Overview {
    pub total: u64,
    pub error_count: u64,
    pub error_pct: f64,
    pub p50_ms: u64,
    pub p99_ms: u64,
    pub qps_avg: f64,
    pub top_tenants: Vec<TopTenant>,  // len ≤ 5
    pub top_slow_ops: Vec<AuditEntry>, // len ≤ 5
}

#[derive(Debug, Clone)]
pub struct TopTenant {
    pub tenant: String,
    pub count: u64,
    pub error_pct: f64,
}

/// Hard cap on entries returned per scan_window call.
pub const MAX_ENTRIES: usize = 50_000;

/// Enumerate audit files under `dir` whose date falls inside `window` relative
/// to `now`. Match pattern is `audit-YYYY-MM-DD.jsonl(\.N(\.gz)?)?`. Files
/// outside the window or non-matching are skipped silently.
pub fn enumerate_audit_files(
    dir: &Path,
    window: Window,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let cutoff_date = (now - chrono::Duration::seconds(window.seconds()))
        .date_naive();

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        // Match audit-YYYY-MM-DD.jsonl(.N(.gz)?)?
        let stripped = match name_str.strip_prefix("audit-") {
            Some(s) => s,
            None => continue,
        };
        // first 10 bytes must be YYYY-MM-DD (ASCII). Use `str::get` so a
        // non-ASCII filename at byte offset 10 doesn't panic on slicing.
        let date_str = match stripped.get(..10) {
            Some(s) => s,
            None => continue,
        };
        let rest = &stripped[10..]; // safe: stripped.get(..10) succeeded
        let date = match chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            Ok(d) => d,
            Err(_) => continue,
        };
        // rest must be ".jsonl" optionally followed by ".N" and optionally ".gz"
        if !is_recognised_suffix(rest) {
            continue;
        }
        // window check: date >= cutoff_date (inclusive)
        if date < cutoff_date {
            continue;
        }
        out.push(entry.path());
    }
    // Sort newest-first by file name (lexical = chronological for our naming)
    out.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    out
}

fn is_recognised_suffix(rest: &str) -> bool {
    // first char must be ".", followed by "jsonl"
    let after_dot = match rest.strip_prefix('.') {
        Some(s) => s,
        None => return false,
    };
    let after_jsonl = match after_dot.strip_prefix("jsonl") {
        Some(s) => s,
        None => return false,
    };
    if after_jsonl.is_empty() {
        return true; // .jsonl
    }
    // .jsonl.N or .jsonl.N.gz — N is digits
    let after_dot2 = match after_jsonl.strip_prefix('.') {
        Some(s) => s,
        None => return false,
    };
    // Split off optional ".gz"
    let (numeric, after_num) = match after_dot2.find('.') {
        Some(i) => (&after_dot2[..i], &after_dot2[i..]),
        None => (after_dot2, ""),
    };
    if numeric.is_empty() || !numeric.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    matches!(after_num, "" | ".gz")
}

/// Parse a single JSONL line into an `AuditEntry`. Returns `None` for empty
/// lines, whitespace-only lines, or any parse failure (caller increments
/// `parse_errors` for non-empty failures).
pub fn parse_jsonl_line(line: &str) -> Option<AuditEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use chrono::{Duration, Utc};

    fn write(path: &PathBuf, content: &str) {
        fs::write(path, content).unwrap();
    }

    #[test]
    fn window_parses_known_values() {
        assert_eq!(Window::from_str_or_default("1h"), Window::H1);
        assert_eq!(Window::from_str_or_default("24h"), Window::H24);
        assert_eq!(Window::from_str_or_default("7d"), Window::D7);
    }

    #[test]
    fn window_falls_back_to_24h_on_unknown() {
        assert_eq!(Window::from_str_or_default(""), Window::H24);
        assert_eq!(Window::from_str_or_default("garbage"), Window::H24);
        assert_eq!(Window::from_str_or_default("30d"), Window::H24);
    }

    #[test]
    fn window_seconds() {
        assert_eq!(Window::H1.seconds(), 3600);
        assert_eq!(Window::H24.seconds(), 86_400);
        assert_eq!(Window::D7.seconds(), 604_800);
    }

    #[test]
    fn parse_valid_line() {
        let line = r#"{"ts":"2026-05-05T01:00:00.000Z","tenant":"acme","token_hint":"abcd1234","op":"GET /records","status":"ok","duration_ms":42}"#;
        let entry = parse_jsonl_line(line).expect("Some(_)");
        assert_eq!(entry.tenant, "acme");
        assert_eq!(entry.duration_ms, 42);
        assert_eq!(entry.status, "ok");
    }

    #[test]
    fn parse_malformed_line_returns_none() {
        assert!(parse_jsonl_line("not json").is_none());
        assert!(parse_jsonl_line(r#"{"ts":"x"}"#).is_none()); // missing required fields
    }

    #[test]
    fn parse_empty_line_returns_none() {
        assert!(parse_jsonl_line("").is_none());
        assert!(parse_jsonl_line("   \t").is_none());
    }

    #[test]
    fn enumerate_empty_dir_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let files = enumerate_audit_files(dir.path(), Window::H24, now);
        assert!(files.is_empty());
    }

    #[test]
    fn enumerate_picks_today_and_yesterday_for_24h() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let yesterday = (now - Duration::days(1)).format("%Y-%m-%d").to_string();
        let earlier = (now - Duration::days(5)).format("%Y-%m-%d").to_string();
        write(&dir.path().join(format!("audit-{today}.jsonl")), "");
        write(&dir.path().join(format!("audit-{yesterday}.jsonl")), "");
        write(&dir.path().join(format!("audit-{earlier}.jsonl.1.gz")), "");
        write(&dir.path().join("unrelated.txt"), "");

        let files = enumerate_audit_files(dir.path(), Window::H24, now);
        let names: Vec<String> = files.iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&format!("audit-{today}.jsonl")));
        assert!(names.contains(&format!("audit-{yesterday}.jsonl")));
        assert!(!names.contains(&format!("audit-{earlier}.jsonl.1.gz")));
        assert!(!names.iter().any(|n| n == "unrelated.txt"));
    }

    #[test]
    fn enumerate_picks_archives_for_7d() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let day3 = (now - Duration::days(3)).format("%Y-%m-%d").to_string();
        let day10 = (now - Duration::days(10)).format("%Y-%m-%d").to_string();
        write(&dir.path().join(format!("audit-{today}.jsonl")), "");
        write(&dir.path().join(format!("audit-{day3}.jsonl.1.gz")), "");
        write(&dir.path().join(format!("audit-{day10}.jsonl.5.gz")), "");

        let files = enumerate_audit_files(dir.path(), Window::D7, now);
        let names: Vec<String> = files.iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&format!("audit-{today}.jsonl")));
        assert!(names.contains(&format!("audit-{day3}.jsonl.1.gz")));
        assert!(!names.contains(&format!("audit-{day10}.jsonl.5.gz")));
    }

    #[test]
    fn enumerate_ignores_wrong_names() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        write(&dir.path().join("foo.jsonl"), "");
        write(&dir.path().join("audit-bad-date.jsonl"), "");
        write(&dir.path().join("audit-2026-13-99.jsonl"), ""); // bad month/day
        write(&dir.path().join("audit-2026-05-05.jsonl.bak"), ""); // unrecognised suffix
        let files = enumerate_audit_files(dir.path(), Window::H24, now);
        assert!(files.is_empty());
    }

    #[test]
    fn enumerate_skips_non_ascii_names_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        // Filename has the "audit-" prefix and is byte-len > 10, but byte 10
        // falls inside a multi-byte codepoint. Must be skipped, not panic.
        write(&dir.path().join("audit-abcdefghi😀.jsonl"), "");
        // Sanity: a valid file should still be picked.
        let today = now.format("%Y-%m-%d").to_string();
        write(&dir.path().join(format!("audit-{today}.jsonl")), "");

        let files = enumerate_audit_files(dir.path(), Window::H24, now);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![format!("audit-{today}.jsonl")]);
    }
}

//! Admin-UI audit log viewer.
//!
//! Stateless read path on top of `$DRUST_LOG_DIR/audit-YYYY-MM-DD.jsonl{,.1,.N.gz}`.
//! No in-memory cache; every request rescans. See spec
//! `docs/superpowers/specs/2026-05-05-drust-audit-ui-design.md`.

use crate::safety::audit::AuditEntry;

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
}

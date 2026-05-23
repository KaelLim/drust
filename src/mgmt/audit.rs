//! Admin-UI audit log viewer.
//!
//! Stateless read path on top of `$DRUST_LOG_DIR/audit-YYYY-MM-DD.jsonl{,.1,.N.gz}`.
//! No in-memory cache; every request rescans. See spec
//! `docs/superpowers/specs/2026-05-05-drust-audit-ui-design.md`.

use crate::safety::audit::AuditEntry;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Window {
    H1,
    H24,
    D7,
}

impl Window {
    pub fn from_str_or_default(s: &str) -> Self {
        match s {
            "24h" => Window::H24,
            "7d" => Window::D7,
            _ => Window::H1, // v1.24 — default + fallback for unrecognised input.
                             // Pre-v1.24 default was H24 but most pages render
                             // far faster on H1 and 24h/7d remain explicit picks.
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
    /// v1.24 — true entry count BEFORE the MAX_ENTRIES truncation. Same as
    /// `entries.len()` when not truncated; equals `truncated_from.unwrap()`
    /// when truncated. Used by aggregate() so the Overview total displays
    /// the real number instead of the 50K sample cap.
    pub total_raw: u64,
    /// v1.24 — true error count (entries with status == "error") computed
    /// before truncation.
    pub error_count_raw: u64,
    /// v1.24 — pre-truncation (total, errors) per tenant. Used when the
    /// Overview is tenant-scoped (either the per-tenant audit page, or
    /// the host page with a tenant filter applied) so the displayed total
    /// reflects all rows for that tenant, not just the ones that survived
    /// the 50K cap.
    pub tenant_counts_raw: std::collections::HashMap<String, (u64, u64)>,
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
    pub rps_avg: f64,
    pub top_tenants: Vec<TopTenant>,  // len ≤ 5
    pub top_slow_ops: Vec<AuditEntry>, // len ≤ 5
    /// v1.24 — true when latency/top tenants were computed over the 50K
    /// newest sample rather than the full window. UI surfaces a caveat
    /// in this case. `total` + `error_count` + `error_pct` + `rps_avg`
    /// are NOT sampled — they always reflect the real pre-truncation count.
    pub is_sampled: bool,
}

#[derive(Debug, Clone)]
pub struct TopTenant {
    pub tenant: String,
    /// Resolved display name. Empty when produced by `aggregate` alone;
    /// filled by `build_body_ctx` after a `tenants` meta lookup.
    pub tenant_name: String,
    pub count: u64,
    pub error_pct: f64,
}

/// v1.17.1 — wire-only projection of `AuditEntry` used by the audit
/// browse tab. Mirrors `AuditEntry` field-for-field, plus a derived
/// `tenant_name` (resolved from `meta.sqlite`) and a **non-flattened**
/// `extra` map so the page-side JS can read it as `e.extra`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntryView {
    pub ts: String,
    /// `ts` reformatted as `MM-DD HH:MM:SS` for compact display in the
    /// audit timeline. Falls back to the raw RFC3339 string if parsing
    /// fails (malformed audit row).
    pub ts_display: String,
    pub tenant: String,
    pub tenant_name: String,
    pub token_hint: String,
    pub op: String,
    pub status: String,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_error_code: Option<String>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl AuditEntryView {
    pub fn from_entry(e: &AuditEntry, tenant_name: &str) -> Self {
        Self {
            ts: e.ts.clone(),
            ts_display: format_ts_display(&e.ts),
            tenant: e.tenant.clone(),
            tenant_name: tenant_name.to_string(),
            token_hint: e.token_hint.clone(),
            op: e.op.clone(),
            status: e.status.clone(),
            duration_ms: e.duration_ms,
            collection: e.collection.clone(),
            sql_hash: e.sql_hash.clone(),
            record_id: e.record_id,
            error_code: e.error_code.clone(),
            error_message: e.error_message.clone(),
            auth_method: e.auth_method.clone(),
            oauth_email: e.oauth_email.clone(),
            oauth_error_code: e.oauth_error_code.clone(),
            extra: e.extra.clone(),
        }
    }
}

/// v1.17.2 — reformat an RFC3339 timestamp to `MM-DD HH:MM:SS` for
/// compact audit-row display. Falls back to the raw input on parse
/// failure so a malformed row still surfaces something useful.
pub fn format_ts_display(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| t.format("%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|_| ts.to_string())
}

/// v1.17.1 — resolve a raw audit tenant id to a display name. Handles
/// the `"-"` admin-plane sentinel and the missing-key case (tenant
/// soft-deleted after the row was written).
pub fn resolve_tenant_name(map: &std::collections::HashMap<String, String>, id: &str) -> String {
    if id == "-" {
        return "admin".to_string();
    }
    map.get(id).cloned().unwrap_or_else(|| id.to_string())
}

/// v1.17.1 — read the live tenants table into a `HashMap<id, name>`.
/// Soft-deleted rows are skipped. Returns an empty map on SQL error
/// so the audit page still renders (entries fall back to raw id).
pub fn build_tenant_name_map(conn: &rusqlite::Connection) -> std::collections::HashMap<String, String> {
    let mut stmt = match conn
        .prepare_cached("SELECT id, name FROM tenants WHERE deleted_at IS NULL")
    {
        Ok(s) => s,
        Err(_) => return std::collections::HashMap::new(),
    };
    let iter = match stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    }) {
        Ok(it) => it,
        Err(_) => return std::collections::HashMap::new(),
    };
    iter.filter_map(Result::ok).collect()
}

/// v1.17.1 — collect distinct `op` values from `entries`, sorted
/// ascending, capped at `limit`. Used to populate the toolbar's
/// `<datalist>` for the operation filter. Cap prevents HTML bloat
/// when an attacker injects wide op variation; beyond the cap, users
/// type free-form (the datalist is a hint, not a strict select).
pub fn distinct_ops_capped(entries: &[AuditEntry], limit: usize) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for e in entries {
        if set.len() >= limit {
            break;
        }
        set.insert(e.op.clone());
    }
    set.into_iter().collect()
}

/// v1.17.1 — `{id, name}` pair fed to the toolbar's tenant
/// `<datalist>`. Sorted by `name` so the dropdown is stable across
/// requests. Built once from `build_tenant_name_map`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TenantSummary {
    pub id: String,
    pub name: String,
}

pub fn tenant_summaries(map: &std::collections::HashMap<String, String>) -> Vec<TenantSummary> {
    let mut out: Vec<TenantSummary> = map
        .iter()
        .map(|(id, name)| TenantSummary {
            id: id.clone(),
            name: name.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
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

use std::io::{BufRead, BufReader};

/// Scan all audit files in `dir` whose date falls in `window`. Returns parsed
/// entries (sorted newest-ts first), parse_errors counter, and archive_errors
/// list. Caller is responsible for further in-memory filter/aggregate.
///
/// `now` is taken as a parameter so tests are deterministic.
pub fn scan_window(
    dir: &Path,
    window: Window,
    now: chrono::DateTime<chrono::Utc>,
) -> ScanResult {
    let mut result = ScanResult::default();
    let files = enumerate_audit_files(dir, window, now);
    let cutoff_ts = (now - chrono::Duration::seconds(window.seconds()))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    for path in files {
        let read = if path.extension().and_then(|s| s.to_str()) == Some("gz") {
            read_gz(&path)
        } else {
            read_plain(&path)
        };
        match read {
            Ok((entries, errs)) => {
                for e in entries {
                    if e.ts.as_str() >= cutoff_ts.as_str() {
                        result.entries.push(e);
                    }
                }
                result.parse_errors += errs;
            }
            Err(_) => {
                result
                    .archive_errors
                    .push(path.file_name().unwrap().to_string_lossy().into_owned());
            }
        }
    }

    // Sort newest-first by ts.
    result.entries.sort_by(|a, b| b.ts.cmp(&a.ts));

    // v1.24 — record TRUE pre-truncation totals so the Overview can show
    // honest counts even when the 50K cap is hit. Per-tenant breakdown
    // is built in the same pass so tenant-scoped Overview rows don't
    // fall back to sample-based numbers.
    result.total_raw = result.entries.len() as u64;
    for e in &result.entries {
        let is_err = e.status == "error";
        if is_err {
            result.error_count_raw += 1;
        }
        let slot = result
            .tenant_counts_raw
            .entry(e.tenant.clone())
            .or_insert((0, 0));
        slot.0 += 1;
        if is_err {
            slot.1 += 1;
        }
    }

    // Hard cap.
    if result.entries.len() > MAX_ENTRIES {
        result.truncated_from = Some(result.entries.len());
        result.entries.truncate(MAX_ENTRIES);
    }
    result
}

/// v1.24 — process-wide scan cache keyed by (log_dir, window). TTL is
/// short (10 s) so a busy admin flipping between Overview / Browse tabs
/// or refreshing the page doesn't re-parse hundreds of thousands of
/// JSONL lines on every click; an idle admin still sees fresh data
/// within seconds. Cache size is bounded to ≤ N windows × 1 entry each
/// — currently 3 entries max (H1/H24/D7), one per active window.
///
/// NOT shared with the host vs. per-tenant scopes: both share the same
/// (log_dir, window) key, because per-tenant filtering happens after the
/// scan via `tenant_counts_raw` and an in-memory `.retain()` pass.
const SCAN_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(10);

struct ScanCacheEntry {
    scan: std::sync::Arc<ScanResult>,
    expires_at: std::time::Instant,
}

static SCAN_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<(PathBuf, Window), ScanCacheEntry>>,
> = std::sync::OnceLock::new();

pub fn scan_window_cached(
    dir: &Path,
    window: Window,
    now: chrono::DateTime<chrono::Utc>,
) -> std::sync::Arc<ScanResult> {
    let cache = SCAN_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let key = (dir.to_path_buf(), window);
    let now_instant = std::time::Instant::now();

    // Fast path: live cache hit, clone the Arc and return.
    if let Ok(guard) = cache.lock() {
        if let Some(entry) = guard.get(&key) {
            if entry.expires_at > now_instant {
                return std::sync::Arc::clone(&entry.scan);
            }
        }
    }

    // Miss or expired — scan, store, evict any other expired entries.
    let result = std::sync::Arc::new(scan_window(dir, window, now));
    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            key,
            ScanCacheEntry {
                scan: std::sync::Arc::clone(&result),
                expires_at: now_instant + SCAN_CACHE_TTL,
            },
        );
        guard.retain(|_, e| e.expires_at > now_instant);
    }
    result
}

fn read_plain(path: &Path) -> std::io::Result<(Vec<AuditEntry>, usize)> {
    let f = std::fs::File::open(path)?;
    let reader = BufReader::new(f);
    parse_lines(reader)
}

fn read_gz(path: &Path) -> std::io::Result<(Vec<AuditEntry>, usize)> {
    let f = std::fs::File::open(path)?;
    let dec = flate2::read::GzDecoder::new(f);
    // BufReader::lines is lazy; the first read will surface a corrupt-gzip
    // header error which propagates via parse_lines's `?`.
    let reader = BufReader::new(dec);
    parse_lines(reader)
}

fn parse_lines<R: BufRead>(reader: R) -> std::io::Result<(Vec<AuditEntry>, usize)> {
    let mut entries = Vec::new();
    let mut errs = 0usize;
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match parse_jsonl_line(trimmed) {
            Some(e) => entries.push(e),
            None => errs += 1,
        }
    }
    Ok((entries, errs))
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

/// Compute summary stats over `entries`. `window` is used for RPS denom.
///
/// v1.24 — `total_raw` / `error_count_raw` come from `ScanResult` and
/// reflect the TRUE pre-truncation counts; `entries` is the (possibly
/// 50K-capped) sample used for latency percentiles and top-tenants. When
/// the sample is smaller than `total_raw`, `Overview.is_sampled` is set
/// to true so the UI can surface a caveat.
pub fn aggregate(
    entries: &[AuditEntry],
    window: Window,
    total_raw: u64,
    error_count_raw: u64,
) -> Overview {
    if total_raw == 0 {
        return Overview::default();
    }
    let total = total_raw;
    let error_count = error_count_raw;
    let error_pct = (error_count as f64) / (total as f64) * 100.0;

    let mut durations: Vec<u64> = entries.iter().map(|e| e.duration_ms).collect();
    durations.sort_unstable();
    let p50_ms = percentile(&durations, 50);
    let p99_ms = percentile(&durations, 99);

    let rps_avg = (total as f64) / (window.seconds() as f64);

    let top_tenants = compute_top_tenants(entries);
    let top_slow_ops = compute_top_slow_ops(entries);

    Overview {
        total,
        error_count,
        error_pct,
        p50_ms,
        p99_ms,
        rps_avg,
        top_tenants,
        top_slow_ops,
        is_sampled: (entries.len() as u64) < total_raw,
    }
}

fn percentile(sorted: &[u64], p: u8) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    // nearest-rank method: index = ceil(p/100 * N) - 1, clamped to [0, N-1]
    let n = sorted.len();
    let rank = ((p as f64) / 100.0 * (n as f64)).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted[idx]
}

fn compute_top_tenants(entries: &[AuditEntry]) -> Vec<TopTenant> {
    use std::collections::HashMap;
    let mut counts: HashMap<&str, (u64, u64)> = HashMap::new(); // (total, errors)
    for e in entries {
        let slot = counts.entry(e.tenant.as_str()).or_insert((0, 0));
        slot.0 += 1;
        if e.status == "error" {
            slot.1 += 1;
        }
    }
    let mut out: Vec<TopTenant> = counts
        .into_iter()
        .map(|(name, (total, errs))| TopTenant {
            tenant: name.to_string(),
            tenant_name: String::new(),
            count: total,
            error_pct: if total == 0 {
                0.0
            } else {
                (errs as f64) / (total as f64) * 100.0
            },
        })
        .collect();
    // Stable order: by count desc, then by tenant name asc for tie-break.
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.tenant.cmp(&b.tenant)));
    out.truncate(5);
    out
}

fn compute_top_slow_ops(entries: &[AuditEntry]) -> Vec<AuditEntry> {
    let mut sorted: Vec<AuditEntry> = entries.to_vec();
    sorted.sort_by(|a, b| b.duration_ms.cmp(&a.duration_ms));
    sorted.truncate(5);
    sorted
}

/// Apply filter spec. Result preserves input order (caller scan_window
/// already returns newest-first).
pub fn filter(entries: &[AuditEntry], spec: &FilterSpec) -> Vec<AuditEntry> {
    entries
        .iter()
        .filter(|e| {
            if let Some(t) = &spec.tenant {
                if &e.tenant != t {
                    return false;
                }
            }
            if let Some(o) = &spec.op {
                if &e.op != o {
                    return false;
                }
            }
            if let Some(s) = spec.status {
                if e.status != s {
                    return false;
                }
            }
            if let Some(cursor) = &spec.before_ts {
                // strict less-than: cursor itself excluded
                if e.ts.as_str() >= cursor.as_str() {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
}

use crate::mgmt::i18n::{LocaleHint, Translator};
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    pub tab: Option<String>,
    pub window: Option<String>,
    pub tenant: Option<String>,
    pub op: Option<String>,
    pub status: Option<String>,
    pub before_ts: Option<String>,
    pub auto: Option<String>,
}

const PAGE_SIZE: usize = 100;

#[derive(Debug)]
pub struct WindowChoice {
    pub label: &'static str,
    pub href: String,
    pub active: bool,
}

/// Precomputed view-model fed to the body partial. Both shell templates
/// (audit_host / audit_tenant) include `_audit_body.html` and pass these
/// fields by name.
pub struct BodyCtx {
    pub scope: AuditScope,
    pub is_host_scope: bool,
    pub tab: &'static str,
    pub window_str: &'static str,
    pub auto_refresh: bool,
    pub overview_link: String,
    pub browse_link: String,
    pub window_choices: Vec<WindowChoice>,
    pub refresh_link: String,
    pub auto_toggle_link: String,
    pub next_page_link: Option<String>,
    pub overview: Option<Overview>,
    pub entries: Vec<AuditEntry>,
    pub parse_errors: usize,
    pub archive_errors: Vec<String>,
    pub truncated_from: Option<usize>,
    pub tenant_filter: Option<String>,
    pub op_filter: Option<String>,
    pub status_filter: &'static str,
    pub tenants: Vec<TenantSummary>,
    pub distinct_ops: Vec<String>,
    pub entries_view: Vec<AuditEntryView>,
    pub entries_json: String,
    /// Overview-tab "Top slow ops" projected through `AuditEntryView`
    /// so the template can read `e.tenant_name`. Parallel to
    /// `overview.top_slow_ops`. Empty in the browse tab.
    pub top_slow_ops_view: Vec<AuditEntryView>,
}

#[derive(Template)]
#[template(path = "audit_host.html")]
struct AuditHostPage {
    version: &'static str,
    is_host_scope: bool,
    tab: &'static str,
    window_str: &'static str,
    auto_refresh: bool,
    overview_link: String,
    browse_link: String,
    window_choices: Vec<WindowChoice>,
    refresh_link: String,
    auto_toggle_link: String,
    next_page_link: Option<String>,
    overview: Option<Overview>,
    entries: Vec<AuditEntry>,
    parse_errors: usize,
    archive_errors: Vec<String>,
    truncated_from: Option<usize>,
    tenant_filter: Option<String>,
    op_filter: Option<String>,
    status_filter: &'static str,
    tenants: Vec<TenantSummary>,
    distinct_ops: Vec<String>,
    entries_view: Vec<AuditEntryView>,
    entries_json: String,
    top_slow_ops_view: Vec<AuditEntryView>,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

fn base_link(scope: &AuditScope) -> String {
    match scope {
        AuditScope::Host => "/drust/admin/audit".to_string(),
        AuditScope::Tenant(id) => format!("/drust/admin/tenants/{id}/_logs"),
    }
}

fn url_with(
    base: &str,
    tab: &str,
    window_str: &str,
    auto: bool,
    extra: &[(&str, &str)],
) -> String {
    use std::fmt::Write;
    let mut s = format!("{base}?tab={tab}&window={window_str}");
    for (k, v) in extra {
        if !v.is_empty() {
            write!(s, "&{k}={}", urlencoding::encode(v)).unwrap();
        }
    }
    if auto {
        s.push_str("&auto=1");
    }
    s
}

pub fn build_body_ctx(
    log_dir: &Path,
    meta: &rusqlite::Connection,
    scope: AuditScope,
    q: &AuditQuery,
) -> BodyCtx {
    let now = chrono::Utc::now();
    let tenant_name_map = build_tenant_name_map(meta);
    let tenants_for_dropdown = if matches!(&scope, AuditScope::Host) {
        tenant_summaries(&tenant_name_map)
    } else {
        Vec::new()
    };
    let window = Window::from_str_or_default(q.window.as_deref().unwrap_or(""));
    let tab: &'static str = match q.tab.as_deref() {
        Some("browse") => "browse",
        _ => "overview",
    };
    let status_filter: &'static str = match q.status.as_deref() {
        Some("ok") => "ok",
        Some("error") => "error",
        _ => "all",
    };
    let auto_refresh = matches!(q.auto.as_deref(), Some("1"));

    let scan = scan_window_cached(log_dir, window, now);

    let tenant_filter_effective: Option<String> = match &scope {
        AuditScope::Tenant(id) => Some(id.clone()),
        AuditScope::Host => q.tenant.as_ref().filter(|s| !s.is_empty()).cloned(),
    };
    let op_filter_effective: Option<String> = q.op.as_ref().filter(|s| !s.is_empty()).cloned();
    let status_for_filter = match status_filter {
        "ok" => Some("ok"),
        "error" => Some("error"),
        _ => None,
    };

    let (overview, entries, entries_view, distinct_ops, entries_json, next_cursor, top_slow_ops_view) = if tab == "overview" {
        // Clone so the optional tenant-filter `retain` doesn't mutate
        // the shared cached `scan.entries` (Arc); other concurrent
        // tenant scopes need to see the unfiltered sample.
        let mut for_overview = scan.entries.clone();
        if let Some(t) = &tenant_filter_effective {
            for_overview.retain(|e| &e.tenant == t);
        }
        // v1.24 — pre-truncation counts. When a tenant filter is in
        // effect, fall back to that tenant's pre-truncation row; otherwise
        // use the host-scope total. tenant_counts_raw is built in
        // scan_window before the 50K cap so the displayed total is honest
        // even on busy 7d windows.
        let (total_raw, error_raw) = if let Some(t) = &tenant_filter_effective {
            scan.tenant_counts_raw
                .get(t)
                .copied()
                .unwrap_or((0, 0))
        } else {
            (scan.total_raw, scan.error_count_raw)
        };
        let mut ov = aggregate(&for_overview, window, total_raw, error_raw);
        // Resolve tenant_name on TopTenant rows (compute_top_tenants
        // leaves them blank because `aggregate` doesn't carry the map).
        for t in &mut ov.top_tenants {
            t.tenant_name = resolve_tenant_name(&tenant_name_map, &t.tenant);
        }
        // Build the view-projection for Top slow ops so the template
        // can read `e.tenant_name` instead of the raw id.
        let slow_view: Vec<AuditEntryView> = ov
            .top_slow_ops
            .iter()
            .map(|e| AuditEntryView::from_entry(e, &resolve_tenant_name(&tenant_name_map, &e.tenant)))
            .collect();
        (
            Some(ov),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            String::from("[]"),
            None,
            slow_view,
        )
    } else {
        let spec = FilterSpec {
            tenant: tenant_filter_effective.clone(),
            op: op_filter_effective.clone(),
            status: status_for_filter,
            before_ts: q.before_ts.clone(),
        };
        let filtered = filter(&scan.entries, &spec);
        let page: Vec<AuditEntry> = filtered.iter().take(PAGE_SIZE).cloned().collect();
        let page_view: Vec<AuditEntryView> = page
            .iter()
            .map(|e| AuditEntryView::from_entry(e, &resolve_tenant_name(&tenant_name_map, &e.tenant)))
            .collect();
        let distinct_ops = distinct_ops_capped(&filtered, 200);
        // Inline-JSON-in-HTML safety: escape forward slashes preceded by `<` so
        // a literal `</script>` inside any string value (e.g. a hostile URI in
        // the `op` field) cannot prematurely close the surrounding
        // <script id="audit-entries"> element. The `\/` form is legal JSON per
        // RFC 8259 §7 and JSON.parse decodes it identically.
        let entries_json = serde_json::to_string(&page_view)
            .unwrap_or_else(|_| "[]".to_string())
            .replace("</", "<\\/");
        let next = if filtered.len() > PAGE_SIZE {
            page.last().map(|e| e.ts.clone())
        } else {
            None
        };
        (None, page, page_view, distinct_ops, entries_json, next, Vec::new())
    };

    let base = base_link(&scope);
    let window_str = window.as_str();

    let window_choices = ["1h", "24h", "7d"]
        .iter()
        .map(|w| WindowChoice {
            label: *w,
            href: url_with(&base, tab, w, false, &[]),
            active: *w == window_str,
        })
        .collect();

    let overview_link = url_with(&base, "overview", window_str, false, &[]);
    let browse_link = url_with(&base, "browse", window_str, false, &[]);

    let refresh_link = url_with(&base, tab, window_str, false, &[]);
    let auto_toggle_link = url_with(&base, tab, window_str, !auto_refresh, &[]);

    let next_page_link = next_cursor.map(|cursor| {
        let extras: Vec<(&str, &str)> = vec![
            ("tenant", tenant_filter_effective.as_deref().unwrap_or("")),
            ("op", op_filter_effective.as_deref().unwrap_or("")),
            ("status", status_filter),
            ("before_ts", &cursor),
        ];
        url_with(&base, "browse", window_str, auto_refresh, &extras)
    });

    let tenant_filter_for_render: Option<String> = match &scope {
        AuditScope::Host => tenant_filter_effective.clone(),
        AuditScope::Tenant(_) => None,
    };

    let is_host_scope = matches!(&scope, AuditScope::Host);
    BodyCtx {
        scope,
        is_host_scope,
        tab,
        window_str,
        auto_refresh,
        overview_link,
        browse_link,
        window_choices,
        refresh_link,
        auto_toggle_link,
        next_page_link,
        overview,
        entries,
        parse_errors: scan.parse_errors,
        archive_errors: scan.archive_errors.clone(),
        truncated_from: scan.truncated_from,
        tenant_filter: tenant_filter_for_render,
        op_filter: op_filter_effective,
        status_filter,
        tenants: tenants_for_dropdown,
        distinct_ops,
        entries_view,
        entries_json,
        top_slow_ops_view,
    }
}

pub async fn audit_host_page(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    Query(q): Query<AuditQuery>,
) -> Response {
    let meta = state.session.meta.lock().await;
    let body = build_body_ctx(&state.log_dir, &meta, AuditScope::Host, &q);
    drop(meta);
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    let page = AuditHostPage {
        version: env!("CARGO_PKG_VERSION"),
        is_host_scope: body.is_host_scope,
        tab: body.tab,
        window_str: body.window_str,
        auto_refresh: body.auto_refresh,
        overview_link: body.overview_link,
        browse_link: body.browse_link,
        window_choices: body.window_choices,
        refresh_link: body.refresh_link,
        auto_toggle_link: body.auto_toggle_link,
        next_page_link: body.next_page_link,
        overview: body.overview,
        entries: body.entries,
        parse_errors: body.parse_errors,
        archive_errors: body.archive_errors,
        truncated_from: body.truncated_from,
        tenant_filter: body.tenant_filter,
        op_filter: body.op_filter,
        status_filter: body.status_filter,
        tenants: body.tenants,
        distinct_ops: body.distinct_ops,
        entries_view: body.entries_view,
        entries_json: body.entries_json,
        top_slow_ops_view: body.top_slow_ops_view,
        t: Translator::new(locale),
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
    };
    Html(page.render().unwrap()).into_response()
}

#[derive(Template)]
#[template(path = "audit_tenant.html")]
struct AuditTenantPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    collections: Vec<crate::storage::schema::Collection>,
    active_coll: String,
    is_host_scope: bool,
    tab: &'static str,
    window_str: &'static str,
    auto_refresh: bool,
    overview_link: String,
    browse_link: String,
    window_choices: Vec<WindowChoice>,
    refresh_link: String,
    auto_toggle_link: String,
    next_page_link: Option<String>,
    overview: Option<Overview>,
    entries: Vec<AuditEntry>,
    parse_errors: usize,
    archive_errors: Vec<String>,
    truncated_from: Option<usize>,
    tenant_filter: Option<String>,
    op_filter: Option<String>,
    status_filter: &'static str,
    tenants: Vec<TenantSummary>,
    distinct_ops: Vec<String>,
    entries_view: Vec<AuditEntryView>,
    entries_json: String,
    top_slow_ops_view: Vec<AuditEntryView>,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

pub async fn audit_tenant_page(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
    Query(q): Query<AuditQuery>,
) -> Response {
    // Tenant existence check (mirrors src/mgmt/tokens.rs:api_keys_page).
    let conn = state.session.meta.lock().await;
    let tenant_name: Option<String> = conn
        .query_row(
            "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
        .ok();
    let tenant_name = match tenant_name {
        Some(n) => n,
        None => return (axum::http::StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };

    // Load collections for the sidebar (failure non-fatal — sidebar still
    // renders virtual rows like `_api_keys`).
    let collections = crate::storage::tenant_db::open_read(&state.data_dir, &tenant_id)
        .ok()
        .and_then(|c| crate::storage::schema::list_collections(&c).ok())
        .unwrap_or_default();

    let body = build_body_ctx(
        &state.log_dir,
        &conn,
        AuditScope::Tenant(tenant_id.clone()),
        &q,
    );
    drop(conn);
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    let tpl = AuditTenantPage {
        version: env!("CARGO_PKG_VERSION"),
        tenant_id,
        tenant_name,
        collections,
        active_coll: "_logs".to_string(),
        is_host_scope: body.is_host_scope,
        tab: body.tab,
        window_str: body.window_str,
        auto_refresh: body.auto_refresh,
        overview_link: body.overview_link,
        browse_link: body.browse_link,
        window_choices: body.window_choices,
        refresh_link: body.refresh_link,
        auto_toggle_link: body.auto_toggle_link,
        next_page_link: body.next_page_link,
        overview: body.overview,
        entries: body.entries,
        parse_errors: body.parse_errors,
        archive_errors: body.archive_errors,
        truncated_from: body.truncated_from,
        tenant_filter: body.tenant_filter,
        op_filter: body.op_filter,
        status_filter: body.status_filter,
        tenants: body.tenants,
        distinct_ops: body.distinct_ops,
        entries_view: body.entries_view,
        entries_json: body.entries_json,
        top_slow_ops_view: body.top_slow_ops_view,
        t: Translator::new(locale),
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
    };
    Html(tpl.render().unwrap()).into_response()
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

    use std::io::Write;

    fn write_gz(path: &PathBuf, content: &str) {
        let f = std::fs::File::create(path).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        enc.write_all(content.as_bytes()).unwrap();
        enc.finish().unwrap();
    }

    fn entry_line(ts: &str, tenant: &str, op: &str, status: &str, ms: u64) -> String {
        format!(
            r#"{{"ts":"{ts}","tenant":"{tenant}","token_hint":"hash0001","op":"{op}","status":"{status}","duration_ms":{ms}}}"#
        )
    }

    fn mk_entry(ts: &str, tenant: &str, op: &str, status: &str, ms: u64) -> AuditEntry {
        let line = entry_line(ts, tenant, op, status, ms);
        parse_jsonl_line(&line).unwrap()
    }

    #[test]
    fn window_parses_known_values() {
        assert_eq!(Window::from_str_or_default("1h"), Window::H1);
        assert_eq!(Window::from_str_or_default("24h"), Window::H24);
        assert_eq!(Window::from_str_or_default("7d"), Window::D7);
    }

    #[test]
    fn window_falls_back_to_1h_on_unknown() {
        // v1.24: default changed from H24 to H1 — most loads are sub-second.
        assert_eq!(Window::from_str_or_default(""), Window::H1);
        assert_eq!(Window::from_str_or_default("garbage"), Window::H1);
        assert_eq!(Window::from_str_or_default("30d"), Window::H1);
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

    #[test]
    fn scan_window_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let res = scan_window(dir.path(), Window::H24, now);
        assert!(res.entries.is_empty());
        assert_eq!(res.parse_errors, 0);
        assert!(res.archive_errors.is_empty());
        assert!(res.truncated_from.is_none());
    }

    #[test]
    fn scan_window_reads_plain_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let lines = format!(
            "{}\n{}\n{}\n",
            entry_line(&format!("{today}T00:01:00.000Z"), "acme", "GET", "ok", 10),
            entry_line(&format!("{today}T00:02:00.000Z"), "beta", "POST", "error", 20),
            entry_line(&format!("{today}T00:03:00.000Z"), "acme", "DELETE", "ok", 5),
        );
        write(&dir.path().join(format!("audit-{today}.jsonl")), &lines);

        let res = scan_window(dir.path(), Window::H24, now);
        assert_eq!(res.entries.len(), 3);
        assert_eq!(res.parse_errors, 0);
    }

    #[test]
    fn scan_window_skips_malformed_lines_with_counter() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let lines = format!(
            "{}\nnot json\n\n{}\n",
            entry_line(&format!("{today}T00:01:00.000Z"), "acme", "GET", "ok", 10),
            entry_line(&format!("{today}T00:02:00.000Z"), "beta", "POST", "error", 20),
        );
        write(&dir.path().join(format!("audit-{today}.jsonl")), &lines);

        let res = scan_window(dir.path(), Window::H24, now);
        assert_eq!(res.entries.len(), 2);
        assert_eq!(res.parse_errors, 1); // empty line not counted, "not json" counted
    }

    #[test]
    fn scan_window_reads_gz_archives_for_7d() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let day3 = (now - Duration::days(3)).format("%Y-%m-%d").to_string();
        write(
            &dir.path().join(format!("audit-{today}.jsonl")),
            &format!("{}\n", entry_line(&format!("{today}T00:01:00.000Z"), "acme", "GET", "ok", 10)),
        );
        write_gz(
            &dir.path().join(format!("audit-{day3}.jsonl.1.gz")),
            &format!(
                "{}\n{}\n",
                entry_line(&format!("{day3}T12:00:00.000Z"), "beta", "POST", "ok", 50),
                entry_line(&format!("{day3}T12:01:00.000Z"), "beta", "GET", "ok", 7),
            ),
        );

        let res = scan_window(dir.path(), Window::D7, now);
        assert_eq!(res.entries.len(), 3);
        assert!(res.archive_errors.is_empty());
    }

    #[test]
    fn scan_window_corrupt_gz_records_archive_error() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let day3 = (now - Duration::days(3)).format("%Y-%m-%d").to_string();
        // Not a valid gzip stream:
        write(&dir.path().join(format!("audit-{day3}.jsonl.1.gz")), "this is not gzip");

        let res = scan_window(dir.path(), Window::D7, now);
        assert!(res.entries.is_empty());
        assert_eq!(res.archive_errors.len(), 1);
        assert!(res.archive_errors[0].contains("audit-"));
    }

    #[test]
    fn scan_window_caps_at_max_entries() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        // Synthesize MAX_ENTRIES + 100 lines with monotonic ts so all fall in window.
        let mut buf = String::new();
        for i in 0..(MAX_ENTRIES + 100) {
            // milliseconds of the minute drift so ts strings are unique
            let ts = format!("{today}T00:{:02}:{:02}.{:03}Z", (i / 60) % 60, i % 60, i % 1000);
            buf.push_str(&entry_line(&ts, "acme", "GET", "ok", 1));
            buf.push('\n');
        }
        write(&dir.path().join(format!("audit-{today}.jsonl")), &buf);

        let res = scan_window(dir.path(), Window::H24, now);
        assert_eq!(res.entries.len(), MAX_ENTRIES);
        assert_eq!(res.truncated_from, Some(MAX_ENTRIES + 100));
    }

    /// Helper for tests: counts entries to derive total_raw + error_count_raw
    /// the way scan_window does for the non-truncated case. Lets the existing
    /// test assertions ride on (Window, &entries) without needing every test
    /// to spell out the raw numbers explicitly.
    fn agg_full(entries: &[AuditEntry], window: Window) -> Overview {
        let total_raw = entries.len() as u64;
        let error_raw = entries.iter().filter(|e| e.status == "error").count() as u64;
        aggregate(entries, window, total_raw, error_raw)
    }

    #[test]
    fn aggregate_empty_input() {
        let ov = agg_full(&[], Window::H24);
        assert_eq!(ov.total, 0);
        assert_eq!(ov.error_count, 0);
        assert_eq!(ov.error_pct, 0.0);
        assert_eq!(ov.p50_ms, 0);
        assert_eq!(ov.p99_ms, 0);
        assert_eq!(ov.rps_avg, 0.0);
        assert!(ov.top_tenants.is_empty());
        assert!(ov.top_slow_ops.is_empty());
        assert!(!ov.is_sampled);
    }

    #[test]
    fn aggregate_totals_and_errors() {
        let entries = vec![
            mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "ok", 10),
            mk_entry("2026-05-05T01:00:01.000Z", "acme", "GET", "error", 12),
            mk_entry("2026-05-05T01:00:02.000Z", "beta", "POST", "ok", 5),
        ];
        let ov = agg_full(&entries, Window::H1);
        assert_eq!(ov.total, 3);
        assert_eq!(ov.error_count, 1);
        // 33.333...%
        assert!((ov.error_pct - 33.333).abs() < 0.01, "got {}", ov.error_pct);
    }

    #[test]
    fn aggregate_p50_p99_known_dataset() {
        // 100 entries, durations 1..=100 ms. p50 should be 50, p99 should be 99.
        let entries: Vec<AuditEntry> = (1..=100)
            .map(|i| mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "ok", i))
            .collect();
        let ov = agg_full(&entries, Window::H1);
        assert_eq!(ov.p50_ms, 50);
        assert_eq!(ov.p99_ms, 99);
    }

    #[test]
    fn aggregate_top_tenants_ordered_by_count_capped_at_5() {
        let mut entries = Vec::new();
        for (tenant, n) in [("a", 10), ("b", 8), ("c", 6), ("d", 4), ("e", 2), ("f", 1), ("g", 1)] {
            for _ in 0..n {
                entries.push(mk_entry("2026-05-05T01:00:00.000Z", tenant, "GET", "ok", 1));
            }
        }
        let ov = agg_full(&entries, Window::H1);
        let names: Vec<&str> = ov.top_tenants.iter().map(|t| t.tenant.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d", "e"]); // top 5, in count-desc order
        assert_eq!(ov.top_tenants.len(), 5);
    }

    #[test]
    fn aggregate_top_tenants_error_pct() {
        let entries = vec![
            mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "ok", 1),
            mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "error", 1),
            mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "error", 1),
            mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "error", 1),
        ];
        let ov = agg_full(&entries, Window::H1);
        assert_eq!(ov.top_tenants.len(), 1);
        assert_eq!(ov.top_tenants[0].tenant, "acme");
        assert_eq!(ov.top_tenants[0].count, 4);
        assert!((ov.top_tenants[0].error_pct - 75.0).abs() < 0.01);
    }

    #[test]
    fn aggregate_top_slow_ops_capped_at_5_desc() {
        let entries: Vec<AuditEntry> = [10, 50, 200, 30, 5, 1000, 7, 800]
            .iter()
            .enumerate()
            .map(|(i, ms)| {
                mk_entry(
                    &format!("2026-05-05T01:00:{:02}.000Z", i),
                    "acme",
                    "GET",
                    "ok",
                    *ms,
                )
            })
            .collect();
        let ov = agg_full(&entries, Window::H1);
        assert_eq!(ov.top_slow_ops.len(), 5);
        let durations: Vec<u64> = ov.top_slow_ops.iter().map(|e| e.duration_ms).collect();
        assert_eq!(durations, vec![1000, 800, 200, 50, 30]);
    }

    #[test]
    fn aggregate_marks_sampled_when_total_raw_exceeds_entries_len() {
        // 3 entries kept, but pre-truncation count was 150K — i.e. the 50K
        // cap fired. Overview.total reports the honest 150_000, and
        // is_sampled flags that latency / top stats came from the sample.
        let entries = vec![
            mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "ok", 10),
            mk_entry("2026-05-05T01:00:01.000Z", "acme", "GET", "ok", 12),
            mk_entry("2026-05-05T01:00:02.000Z", "beta", "POST", "ok", 5),
        ];
        let ov = aggregate(&entries, Window::H1, 150_000, 4_500);
        assert_eq!(ov.total, 150_000);
        assert_eq!(ov.error_count, 4_500);
        assert!((ov.error_pct - 3.0).abs() < 0.01);
        assert!(ov.is_sampled, "is_sampled should be true when entries.len() < total_raw");
    }

    fn fixture() -> Vec<AuditEntry> {
        // Sorted newest-first (matches what scan_window returns).
        vec![
            mk_entry("2026-05-05T01:00:03.000Z", "beta", "DELETE", "error", 4),
            mk_entry("2026-05-05T01:00:02.000Z", "beta", "GET", "ok", 3),
            mk_entry("2026-05-05T01:00:01.000Z", "acme", "POST", "error", 2),
            mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "ok", 1),
        ]
    }

    #[test]
    fn filter_by_tenant() {
        let f = FilterSpec { tenant: Some("acme".into()), ..Default::default() };
        let r = filter(&fixture(), &f);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|e| e.tenant == "acme"));
    }

    #[test]
    fn filter_by_op() {
        let f = FilterSpec { op: Some("GET".into()), ..Default::default() };
        let r = filter(&fixture(), &f);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|e| e.op == "GET"));
    }

    #[test]
    fn filter_by_status_error() {
        let f = FilterSpec { status: Some("error"), ..Default::default() };
        let r = filter(&fixture(), &f);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|e| e.status == "error"));
    }

    #[test]
    fn filter_by_status_ok() {
        let f = FilterSpec { status: Some("ok"), ..Default::default() };
        let r = filter(&fixture(), &f);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|e| e.status == "ok"));
    }

    #[test]
    fn filter_combined_and() {
        let f = FilterSpec {
            tenant: Some("acme".into()),
            status: Some("error"),
            ..Default::default()
        };
        let r = filter(&fixture(), &f);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].op, "POST");
    }

    #[test]
    fn filter_before_ts_excludes_cursor_entry() {
        // before_ts is exclusive: entries with ts < cursor pass; ts == cursor excluded.
        let f = FilterSpec {
            before_ts: Some("2026-05-05T01:00:02.000Z".into()),
            ..Default::default()
        };
        let r = filter(&fixture(), &f);
        let timestamps: Vec<&str> = r.iter().map(|e| e.ts.as_str()).collect();
        assert_eq!(
            timestamps,
            vec!["2026-05-05T01:00:01.000Z", "2026-05-05T01:00:00.000Z"]
        );
    }


    #[test]
    fn audit_entry_view_serializes_extra_as_nested_object() {
        // AuditEntry uses #[serde(flatten)] on `extra`; the view must NOT.
        let mut e = mk_entry("2026-05-20T12:00:00.000Z", "acme", "GET /x", "ok", 5);
        e.extra.insert("auth_kind".to_string(), serde_json::json!("user"));
        e.extra.insert("auth_user_id".to_string(), serde_json::json!("u-abc"));
        let view = AuditEntryView::from_entry(&e, "Acme Inc");
        let json = serde_json::to_string(&view).unwrap();
        // The extra fields must NOT appear at the top level.
        assert!(
            !json.contains(r#""auth_kind":"user","tenant"#) && !json.contains(r#""tenant":"acme","auth_kind"#),
            "extra keys must not flatten to top level: {json}"
        );
        // They must appear nested under `extra`.
        assert!(
            json.contains(r#""extra":{"#),
            "extra block missing: {json}"
        );
        assert!(json.contains(r#""auth_kind":"user""#));
        assert!(json.contains(r#""auth_user_id":"u-abc""#));
        assert!(json.contains(r#""tenant_name":"Acme Inc""#));
    }

    #[test]
    fn resolve_tenant_name_handles_sentinels() {
        let mut map = std::collections::HashMap::new();
        map.insert("a".to_string(), "Alpha".to_string());
        map.insert("b".to_string(), "Beta".to_string());

        assert_eq!(resolve_tenant_name(&map, "a"), "Alpha");
        assert_eq!(resolve_tenant_name(&map, "b"), "Beta");
        // "-" sentinel → "admin"
        assert_eq!(resolve_tenant_name(&map, "-"), "admin");
        // Missing id (e.g. tenant soft-deleted after audit row written) → fallback to id itself.
        assert_eq!(resolve_tenant_name(&map, "ghost-id"), "ghost-id");
    }

    #[test]
    fn distinct_ops_capped_returns_sorted_and_caps() {
        // Mixed input with duplicates: result must be unique + sorted ascending.
        let entries = vec![
            mk_entry("2026-05-20T12:00:00.000Z", "t", "POST /records", "ok", 1),
            mk_entry("2026-05-20T12:00:01.000Z", "t", "GET /records", "ok", 1),
            mk_entry("2026-05-20T12:00:02.000Z", "t", "GET /records", "ok", 1),
            mk_entry("2026-05-20T12:00:03.000Z", "t", "DELETE /records", "ok", 1),
        ];
        let ops = distinct_ops_capped(&entries, 200);
        assert_eq!(ops, vec!["DELETE /records", "GET /records", "POST /records"]);
    }

    #[test]
    fn distinct_ops_capped_truncates_at_limit() {
        let entries: Vec<AuditEntry> = (0..500)
            .map(|i| mk_entry("2026-05-20T12:00:00.000Z", "t", &format!("op-{i:04}"), "ok", 1))
            .collect();
        let ops = distinct_ops_capped(&entries, 200);
        assert_eq!(ops.len(), 200);
    }

    #[test]
    fn tenant_summaries_sorted_by_name() {
        let mut map = std::collections::HashMap::new();
        map.insert("z-id".to_string(), "Alpha".to_string());
        map.insert("a-id".to_string(), "Charlie".to_string());
        map.insert("m-id".to_string(), "Bravo".to_string());
        let v = tenant_summaries(&map);
        let names: Vec<&str> = v.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "Bravo", "Charlie"]);
    }

    #[test]
    fn entries_json_escapes_script_closer_in_op() {
        // Hostile op containing `</script>` must not break out of the inline
        // <script type="application/json"> blob when embedded into HTML.
        let mut e = mk_entry(
            "2026-05-20T12:00:00.000Z",
            "acme",
            "GET /records/</script><script>x</script>",
            "ok",
            5,
        );
        e.extra.insert("k".into(), serde_json::json!("v"));
        let view = AuditEntryView::from_entry(&e, "Acme Inc");
        let raw = serde_json::to_string(&[view]).unwrap();
        // Direct serde output contains the literal `</`.
        assert!(raw.contains("</script>"), "baseline assumption: serde does not escape `</`");
        // Apply the same .replace the production code applies.
        let safe = raw.replace("</", "<\\/");
        assert!(!safe.contains("</script>"), "after escape, `</script>` must be gone");
        assert!(safe.contains("<\\/script>"), "the slash escape must be visible");
        // And the result must still round-trip back to the same logical content via JSON.parse-equivalent.
        let parsed: serde_json::Value = serde_json::from_str(&safe).unwrap();
        assert_eq!(parsed[0]["op"], "GET /records/</script><script>x</script>");
    }
}

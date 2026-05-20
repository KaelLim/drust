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

/// v1.17 — pick a time-series bucket size so each chart has 60–200
/// buckets regardless of window. Returns bucket size in seconds.
///
/// | window | seconds | buckets |
/// |--------|---------|---------|
/// | 1h     | 60      | 60      |
/// | 24h    | 600     | 144     |
/// | 7d     | 3600    | 168     |
pub fn adaptive_bucket_seconds(window: Window) -> i64 {
    match window {
        Window::H1 => 60,
        Window::H24 => 600,
        Window::D7 => 3600,
    }
}

/// v1.17 — derive HTTP status class from an AuditEntry. The audit
/// pipeline stores `status: String` as "ok"/"error" (text, NOT an HTTP
/// code) and `error_code: Option<String>` carrying either `HTTP_<code>`
/// for transport-level failures or a typed code (`WRITE_DENIED`,
/// `COLLECTION_NOT_FOUND`, ...) for application-level denials.
///
/// Returns one of `2xx | 4xx | 5xx` for the stacking chart. Typed
/// codes that aren't `HTTP_<n>` default to `4xx`, because in drust
/// they're virtually all 4xx denials.
fn status_class(entry: &AuditEntry) -> StatusClass {
    match entry.error_code.as_deref() {
        None => StatusClass::Ok,
        Some(c) if c.starts_with("HTTP_5") => StatusClass::Server,
        Some(c) if c.starts_with("HTTP_4") => StatusClass::Client,
        Some(_) => StatusClass::Client, // typed denial → 4xx
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusClass {
    Ok,
    Client,
    Server,
}

/// v1.17 — bucket entries by `adaptive_bucket_seconds(window)`-wide
/// time windows, counting by HTTP status class. Returns buckets in
/// chronological order from `now - window` to `now`, zero-filled
/// across gaps so the SVG chart x-axis is contiguous.
///
/// `now` is parameterised (not `Utc::now()`) so tests can inject
/// deterministic time.
pub fn time_series_buckets(
    entries: &[AuditEntry],
    window: Window,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<TimeBucket> {
    let bucket_secs = adaptive_bucket_seconds(window);
    let window_secs = window.seconds();
    let bucket_count: usize = (window_secs / bucket_secs) as usize;
    let window_start = now.timestamp() - window_secs;
    // Align window_start down to its bucket boundary so bucket[0]
    // begins at a stable edge.
    let aligned_start = (window_start / bucket_secs) * bucket_secs;

    let mut buckets: Vec<TimeBucket> = (0..bucket_count)
        .map(|i| TimeBucket {
            ts_unix: aligned_start + (i as i64) * bucket_secs,
            ..Default::default()
        })
        .collect();

    for e in entries {
        let ts = match chrono::DateTime::parse_from_rfc3339(&e.ts) {
            Ok(t) => t.with_timezone(&chrono::Utc),
            Err(_) => continue, // malformed timestamp — skip silently
        };
        let secs = ts.timestamp();
        if secs < aligned_start || secs >= aligned_start + (bucket_count as i64) * bucket_secs {
            continue;
        }
        let idx = ((secs - aligned_start) / bucket_secs) as usize;
        // Defensive clamp: floating off-by-one near the right edge.
        let idx = idx.min(bucket_count - 1);
        let b = &mut buckets[idx];
        match status_class(e) {
            StatusClass::Ok => b.count_2xx += 1,
            StatusClass::Client => b.count_4xx += 1,
            StatusClass::Server => b.count_5xx += 1,
        }
    }
    buckets
}

/// v1.17 — group entries by `error_code`, sort by count desc with
/// lexicographic tie-break, return top `n`. Entries with `error_code
/// = None` are skipped (they're successes, not errors).
pub fn top_error_codes(entries: &[AuditEntry], n: usize) -> Vec<ErrorCodeCount> {
    let mut counts: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for e in entries {
        if let Some(code) = e.error_code.as_deref() {
            *counts.entry(code).or_insert(0) += 1;
        }
    }
    let mut pairs: Vec<ErrorCodeCount> = counts
        .into_iter()
        .map(|(code, count)| ErrorCodeCount {
            code: code.to_string(),
            count,
        })
        .collect();
    // Sort by count desc, then code asc (lexicographic tie-break).
    pairs.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.code.cmp(&b.code)));
    pairs.truncate(n);
    pairs
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
    pub rps_avg: f64,
    pub top_tenants: Vec<TopTenant>,  // len ≤ 5
    pub top_slow_ops: Vec<AuditEntry>, // len ≤ 5
}

#[derive(Debug, Clone)]
pub struct TopTenant {
    pub tenant: String,
    pub count: u64,
    pub error_pct: f64,
}

/// v1.17 — one bucket of the requests-over-time chart.
/// `ts_unix` is the bucket's left edge in seconds since UNIX epoch.
/// Counts are by HTTP status class.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimeBucket {
    pub ts_unix: i64,
    pub count_2xx: u32,
    pub count_4xx: u32,
    pub count_5xx: u32,
}

/// v1.17 — one row of the top-error-codes chart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCodeCount {
    pub code: String,
    pub count: u32,
}

/// v1.17 — log-scale duration histogram with the three percentile cuts
/// pre-computed. Fixed-shape buckets at indices:
/// 0: 0–10ms, 1: 10–50, 2: 50–200, 3: 200–1000, 4: 1000–5000, 5: 5000+ ms.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LatencyHistogram {
    pub buckets: [u32; 6],
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
}

/// v1.17 — one bar of the top-tenants-by-request-count chart
/// (host scope only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantBar {
    pub tenant: String,
    pub count: u32,
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

    // Hard cap.
    if result.entries.len() > MAX_ENTRIES {
        result.truncated_from = Some(result.entries.len());
        result.entries.truncate(MAX_ENTRIES);
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

/// Compute summary stats over `entries`. `window` is used only for RPS denom
/// (each audit row corresponds to one HTTP request — not one SQL query).
pub fn aggregate(entries: &[AuditEntry], window: Window) -> Overview {
    let total = entries.len() as u64;
    if total == 0 {
        return Overview::default();
    }
    let error_count = entries.iter().filter(|e| e.status == "error").count() as u64;
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
    scope: AuditScope,
    q: &AuditQuery,
) -> BodyCtx {
    let now = chrono::Utc::now();
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

    let scan = scan_window(log_dir, window, now);

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

    let (overview, entries, next_cursor) = if tab == "overview" {
        let mut for_overview = scan.entries.clone();
        if let Some(t) = &tenant_filter_effective {
            for_overview.retain(|e| &e.tenant == t);
        }
        (Some(aggregate(&for_overview, window)), Vec::new(), None)
    } else {
        let spec = FilterSpec {
            tenant: tenant_filter_effective.clone(),
            op: op_filter_effective.clone(),
            status: status_for_filter,
            before_ts: q.before_ts.clone(),
        };
        let filtered = filter(&scan.entries, &spec);
        let page: Vec<AuditEntry> = filtered.iter().take(PAGE_SIZE).cloned().collect();
        let next = if filtered.len() > PAGE_SIZE {
            page.last().map(|e| e.ts.clone())
        } else {
            None
        };
        (None, page, next)
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
        archive_errors: scan.archive_errors,
        truncated_from: scan.truncated_from,
        tenant_filter: tenant_filter_for_render,
        op_filter: op_filter_effective,
        status_filter,
    }
}

pub async fn audit_host_page(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let body = build_body_ctx(&state.log_dir, AuditScope::Host, &q);
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
}

pub async fn audit_tenant_page(
    State(state): State<crate::mgmt::tenants::TenantsState>,
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
    drop(conn);
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

    let body = build_body_ctx(&state.log_dir, AuditScope::Tenant(tenant_id.clone()), &q);
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

    #[test]
    fn aggregate_empty_input() {
        let ov = aggregate(&[], Window::H24);
        assert_eq!(ov.total, 0);
        assert_eq!(ov.error_count, 0);
        assert_eq!(ov.error_pct, 0.0);
        assert_eq!(ov.p50_ms, 0);
        assert_eq!(ov.p99_ms, 0);
        assert_eq!(ov.rps_avg, 0.0);
        assert!(ov.top_tenants.is_empty());
        assert!(ov.top_slow_ops.is_empty());
    }

    #[test]
    fn aggregate_totals_and_errors() {
        let entries = vec![
            mk_entry("2026-05-05T01:00:00.000Z", "acme", "GET", "ok", 10),
            mk_entry("2026-05-05T01:00:01.000Z", "acme", "GET", "error", 12),
            mk_entry("2026-05-05T01:00:02.000Z", "beta", "POST", "ok", 5),
        ];
        let ov = aggregate(&entries, Window::H1);
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
        let ov = aggregate(&entries, Window::H1);
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
        let ov = aggregate(&entries, Window::H1);
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
        let ov = aggregate(&entries, Window::H1);
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
        let ov = aggregate(&entries, Window::H1);
        assert_eq!(ov.top_slow_ops.len(), 5);
        let durations: Vec<u64> = ov.top_slow_ops.iter().map(|e| e.duration_ms).collect();
        assert_eq!(durations, vec![1000, 800, 200, 50, 30]);
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
    fn adaptive_bucket_seconds_matches_table() {
        assert_eq!(adaptive_bucket_seconds(Window::H1), 60);
        assert_eq!(adaptive_bucket_seconds(Window::H24), 600);
        assert_eq!(adaptive_bucket_seconds(Window::D7), 3600);
    }

    fn mk_entry_with_code(
        ts: &str,
        tenant: &str,
        op: &str,
        status_text: &str,
        error_code: Option<&str>,
        ms: u64,
    ) -> AuditEntry {
        let err_part = match error_code {
            Some(c) => format!(r#","error_code":"{c}""#),
            None => String::new(),
        };
        let line = format!(
            r#"{{"ts":"{ts}","tenant":"{tenant}","token_hint":"hash0001","op":"{op}","status":"{status_text}","duration_ms":{ms}{err_part}}}"#
        );
        parse_jsonl_line(&line).unwrap()
    }

    #[test]
    fn time_series_buckets_zero_fills_empty_intervals() {
        // 24h window → 600s bucket → 144 buckets total. Insert entries at
        // bucket 0 and bucket 5 only; everything else must be zeroed.
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-20T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let bucket_0_ts = "2026-05-19T12:00:00.000Z";
        let bucket_5_ts = "2026-05-19T12:50:00.000Z"; // 5 * 600s = 3000s later
        let entries = vec![
            mk_entry_with_code(bucket_0_ts, "t", "GET /x", "ok", None, 10),
            mk_entry_with_code(bucket_5_ts, "t", "GET /x", "ok", None, 10),
        ];
        let buckets = time_series_buckets(&entries, Window::H24, now);
        assert_eq!(buckets.len(), 144, "24h / 600s = 144 buckets");
        assert_eq!(buckets[0].count_2xx, 1);
        for b in &buckets[1..5] {
            assert_eq!(b.count_2xx + b.count_4xx + b.count_5xx, 0);
        }
        assert_eq!(buckets[5].count_2xx, 1);
    }

    #[test]
    fn time_series_buckets_status_class_correctness() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-20T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ts = "2026-05-20T11:59:30.000Z"; // bucket 0 of 1h window
        let entries = vec![
            mk_entry_with_code(ts, "t", "op", "ok", None, 1),
            mk_entry_with_code(ts, "t", "op", "error", Some("HTTP_404"), 1),
            mk_entry_with_code(ts, "t", "op", "error", Some("HTTP_500"), 1),
            // Typed denial code: maps to 4xx (default for non-HTTP_5xx error codes).
            mk_entry_with_code(ts, "t", "op", "error", Some("WRITE_DENIED"), 1),
        ];
        let buckets = time_series_buckets(&entries, Window::H1, now);
        // Last bucket = "now" bucket. Look for our entries there.
        let last = buckets.last().unwrap();
        assert_eq!(last.count_2xx, 1);
        assert_eq!(last.count_4xx, 2); // HTTP_404 + WRITE_DENIED
        assert_eq!(last.count_5xx, 1);
    }

    #[test]
    fn time_series_buckets_deterministic_with_injected_now() {
        let now1 = chrono::DateTime::parse_from_rfc3339("2026-05-20T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let now2 = now1;
        let entries = vec![mk_entry_with_code(
            "2026-05-20T11:30:00.000Z",
            "t",
            "op",
            "ok",
            None,
            1,
        )];
        let b1 = time_series_buckets(&entries, Window::H1, now1);
        let b2 = time_series_buckets(&entries, Window::H1, now2);
        assert_eq!(b1, b2);
    }

    #[test]
    fn time_series_buckets_drops_entries_outside_window() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-20T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let entries = vec![
            // Way outside the 1h window
            mk_entry_with_code("2026-05-19T12:00:00.000Z", "t", "op", "ok", None, 1),
            // Inside
            mk_entry_with_code("2026-05-20T11:45:00.000Z", "t", "op", "ok", None, 1),
        ];
        let buckets = time_series_buckets(&entries, Window::H1, now);
        let total: u32 = buckets.iter().map(|b| b.count_2xx).sum();
        assert_eq!(total, 1, "only the in-window entry should appear");
    }

    #[test]
    fn top_error_codes_descending_with_n_cap() {
        let mut entries = Vec::new();
        // 15 distinct codes with counts 1, 2, 3, ... 15
        for (i, name) in [
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
        ]
        .iter()
        .enumerate()
        {
            let count = i as u64 + 1;
            for _ in 0..count {
                entries.push(mk_entry_with_code(
                    "2026-05-20T12:00:00.000Z",
                    "t",
                    "op",
                    "error",
                    Some(name),
                    1,
                ));
            }
        }
        let top = top_error_codes(&entries, 10);
        assert_eq!(top.len(), 10);
        // Highest first: O (15), N (14), M (13), ...
        assert_eq!(top[0].code, "O");
        assert_eq!(top[0].count, 15);
        assert_eq!(top[9].code, "F");
        assert_eq!(top[9].count, 6);
    }

    #[test]
    fn top_error_codes_skips_entries_without_code() {
        // `error_code = None` means "no error" and must not appear.
        let entries = vec![
            mk_entry_with_code("2026-05-20T12:00:00.000Z", "t", "op", "ok", None, 1),
            mk_entry_with_code(
                "2026-05-20T12:00:00.000Z",
                "t",
                "op",
                "error",
                Some("REAL_ERR"),
                1,
            ),
        ];
        let top = top_error_codes(&entries, 10);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].code, "REAL_ERR");
    }

    #[test]
    fn top_error_codes_ties_break_lexicographically() {
        let entries = vec![
            mk_entry_with_code("2026-05-20T12:00:00.000Z", "t", "op", "error", Some("ZZZ"), 1),
            mk_entry_with_code("2026-05-20T12:00:00.000Z", "t", "op", "error", Some("AAA"), 1),
            mk_entry_with_code("2026-05-20T12:00:00.000Z", "t", "op", "error", Some("MMM"), 1),
        ];
        let top = top_error_codes(&entries, 10);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].code, "AAA");
        assert_eq!(top[1].code, "MMM");
        assert_eq!(top[2].code, "ZZZ");
    }
}

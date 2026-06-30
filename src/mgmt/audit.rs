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
}

#[derive(Debug, Default)]
pub struct Overview {
    pub total: u64,
    pub error_count: u64,
    pub error_pct: f64,
    pub p50_ms: u64,
    pub p99_ms: u64,
    pub rps_avg: f64,
    pub top_tenants: Vec<TopTenant>,   // len ≤ 5
    pub top_slow_ops: Vec<AuditEntry>, // len ≤ 5
    /// Process-lifetime count of audit entries dropped due to writer
    /// channel-full. Populated from `audit_db::dropped_total()` in
    /// `aggregate_via_sql`. Resets on drust restart. v1.24.2 F3.
    pub dropped_total: u64,
}

#[derive(Debug, Clone)]
pub struct TopTenant {
    pub tenant: String,
    /// Resolved display name. Empty when produced by `aggregate_via_sql`
    /// alone; filled by `build_body_ctx` after a `tenants` meta lookup.
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
pub fn build_tenant_name_map(
    conn: &rusqlite::Connection,
) -> std::collections::HashMap<String, String> {
    let mut stmt =
        match conn.prepare_cached("SELECT id, name FROM tenants WHERE deleted_at IS NULL") {
            Ok(s) => s,
            Err(_) => return std::collections::HashMap::new(),
        };
    let iter = match stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
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

    let cutoff_date = (now - chrono::Duration::seconds(window.seconds())).date_naive();

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
pub fn scan_window(dir: &Path, window: Window, now: chrono::DateTime<chrono::Utc>) -> ScanResult {
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
    result
}

pub(crate) fn read_plain(path: &Path) -> std::io::Result<(Vec<AuditEntry>, usize)> {
    let f = std::fs::File::open(path)?;
    let reader = BufReader::new(f);
    parse_lines(reader)
}

pub(crate) fn read_gz(path: &Path) -> std::io::Result<(Vec<AuditEntry>, usize)> {
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
    tenant_filter: Option<String>,
    op_filter: Option<String>,
    status_filter: &'static str,
    tenants: Vec<TenantSummary>,
    distinct_ops: Vec<String>,
    entries_view: Vec<AuditEntryView>,
    entries_json: String,
    top_slow_ops_view: Vec<AuditEntryView>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

fn base_link(scope: &AuditScope) -> String {
    match scope {
        AuditScope::Host => crate::base_path::base("/admin/audit"),
        AuditScope::Tenant(id) => crate::base_path::base(&format!("/admin/tenants/{id}/_logs")),
    }
}

fn url_with(base: &str, tab: &str, window_str: &str, auto: bool, extra: &[(&str, &str)]) -> String {
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

/// v1.24 — SQL-backed body builder. Replaces the JSONL scan + in-memory
/// aggregate path. Issues at most 4 SELECTs against `meta_logs.sqlite`
/// (one for Overview total/errors, one for latency durations, one for
/// top tenants, one for top slow ops; browse-tab issues one paginated
/// SELECT). Returns the same `BodyCtx` shape the templates already
/// consume, minus the deleted `truncated_from` field.
pub async fn build_body_ctx(
    audit_conn: &std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    tenant_name_map: std::collections::HashMap<String, String>,
    scope: AuditScope,
    q: &AuditQuery,
) -> BodyCtx {
    let now = chrono::Utc::now();
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

    let cutoff_ts = (now - chrono::Duration::seconds(window.seconds()))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let tenant_filter_effective: Option<String> = match &scope {
        AuditScope::Tenant(id) => Some(id.clone()),
        AuditScope::Host => q.tenant.as_ref().filter(|s| !s.is_empty()).cloned(),
    };
    let op_filter_effective: Option<String> = q.op.as_ref().filter(|s| !s.is_empty()).cloned();
    let status_for_filter: Option<&str> = match status_filter {
        "ok" => Some("ok"),
        "error" => Some("error"),
        _ => None,
    };

    let conn_guard = audit_conn.lock().await;
    let conn: &rusqlite::Connection = &conn_guard;

    let (
        overview,
        entries,
        entries_view,
        distinct_ops,
        entries_json,
        next_cursor,
        top_slow_ops_view,
    ) = if tab == "overview" {
        let mut ov =
            aggregate_via_sql(conn, &cutoff_ts, tenant_filter_effective.as_deref(), window);
        // Resolve tenant_name on TopTenant rows (aggregate_via_sql
        // leaves them blank because it doesn't carry the meta map).
        for t in &mut ov.top_tenants {
            t.tenant_name = resolve_tenant_name(&tenant_name_map, &t.tenant);
        }
        // Build the view-projection for Top slow ops so the template
        // can read `e.tenant_name` instead of the raw id.
        let slow_view: Vec<AuditEntryView> = ov
            .top_slow_ops
            .iter()
            .map(|e| {
                AuditEntryView::from_entry(e, &resolve_tenant_name(&tenant_name_map, &e.tenant))
            })
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
        // Browse tab. PAGE_SIZE+1 fetches one extra row so we can detect
        // a next page without a second COUNT query.
        let mut page: Vec<AuditEntry> = query_browse(
            conn,
            &cutoff_ts,
            tenant_filter_effective.as_deref(),
            op_filter_effective.as_deref(),
            status_for_filter,
            q.before_ts.as_deref(),
            PAGE_SIZE + 1,
        );
        let has_more = page.len() > PAGE_SIZE;
        if has_more {
            page.truncate(PAGE_SIZE);
        }
        let page_view: Vec<AuditEntryView> = page
            .iter()
            .map(|e| {
                AuditEntryView::from_entry(e, &resolve_tenant_name(&tenant_name_map, &e.tenant))
            })
            .collect();
        let distinct_ops = distinct_ops_capped(&page, 200);
        // Inline-JSON-in-HTML safety: escape forward slashes preceded by `<` so
        // a literal `</script>` inside any string value (e.g. a hostile URI in
        // the `op` field) cannot prematurely close the surrounding
        // <script id="audit-entries"> element. The `\/` form is legal JSON per
        // RFC 8259 §7 and JSON.parse decodes it identically.
        let entries_json = crate::mgmt::script_json::escape_json_for_script(
            &serde_json::to_string(&page_view).unwrap_or_else(|_| "[]".to_string()),
        );
        let next = if has_more {
            page.last().map(|e| e.ts.clone())
        } else {
            None
        };
        (
            None,
            page,
            page_view,
            distinct_ops,
            entries_json,
            next,
            Vec::new(),
        )
    };

    drop(conn_guard);

    let base = base_link(&scope);
    let window_str = window.as_str();

    let window_choices = ["1h", "24h", "7d"]
        .iter()
        .map(|w| WindowChoice {
            label: w,
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
        parse_errors: 0,
        archive_errors: Vec::new(),
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
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let tenant_name_map = {
        let meta = state.session.meta.lock().await;
        build_tenant_name_map(&meta)
    };
    let body = build_body_ctx(
        &state.audit_meta_read,
        tenant_name_map,
        AuditScope::Host,
        &q,
    )
    .await;
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
        tenant_filter: body.tenant_filter,
        op_filter: body.op_filter,
        status_filter: body.status_filter,
        tenants: body.tenants,
        distinct_ops: body.distinct_ops,
        entries_view: body.entries_view,
        entries_json: body.entries_json,
        top_slow_ops_view: body.top_slow_ops_view,
        t: Translator::new(locale),
        admin,
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
    tenant_filter: Option<String>,
    op_filter: Option<String>,
    status_filter: &'static str,
    tenants: Vec<TenantSummary>,
    distinct_ops: Vec<String>,
    entries_view: Vec<AuditEntryView>,
    entries_json: String,
    top_slow_ops_view: Vec<AuditEntryView>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

pub async fn audit_tenant_page(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
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

    let tenant_name_map = build_tenant_name_map(&conn);
    drop(conn);
    let body = build_body_ctx(
        &state.audit_meta_read,
        tenant_name_map,
        AuditScope::Tenant(tenant_id.clone()),
        &q,
    )
    .await;
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
        tenant_filter: body.tenant_filter,
        op_filter: body.op_filter,
        status_filter: body.status_filter,
        tenants: body.tenants,
        distinct_ops: body.distinct_ops,
        entries_view: body.entries_view,
        entries_json: body.entries_json,
        top_slow_ops_view: body.top_slow_ops_view,
        t: Translator::new(locale),
        admin,
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
    };
    Html(tpl.render().unwrap()).into_response()
}

/// v1.24 — SQL-backed Overview computation. Reads from the audit DB
/// via the supplied read connection. Replaces the JSONL-scan +
/// in-memory aggregate path. Returns Overview with REAL counts (no
/// 50K-sample caveat).
pub fn aggregate_via_sql(
    conn: &rusqlite::Connection,
    cutoff_ts: &str,
    tenant_filter: Option<&str>,
    window: Window,
) -> Overview {
    // Total + error count in one query.
    let (total, error_count): (u64, u64) = conn
        .query_row(
            "SELECT
               COUNT(*),
               SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END)
             FROM audit
             WHERE ts >= ?1
               AND (?2 IS NULL OR tenant = ?2)",
            rusqlite::params![cutoff_ts, tenant_filter],
            |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
                ))
            },
        )
        .unwrap_or((0, 0));

    if total == 0 {
        return Overview::default();
    }

    let error_pct = (error_count as f64) / (total as f64) * 100.0;
    let rps_avg = (total as f64) / (window.seconds() as f64);

    // Pull duration_ms column only for in-memory percentile (SQLite has
    // no built-in percentile fn; window functions exist but add complexity).
    let mut durations: Vec<u64> = {
        let mut stmt = match conn.prepare(
            "SELECT duration_ms FROM audit
             WHERE ts >= ?1
               AND (?2 IS NULL OR tenant = ?2)",
        ) {
            Ok(s) => s,
            Err(_) => return Overview::default(),
        };
        let rows: rusqlite::Result<Vec<u64>> = stmt
            .query_map(rusqlite::params![cutoff_ts, tenant_filter], |r| {
                r.get::<_, i64>(0).map(|n| n as u64)
            })
            .and_then(|rows| rows.collect());
        rows.unwrap_or_default()
    };
    durations.sort_unstable();
    let p50_ms = percentile(&durations, 50);
    let p99_ms = percentile(&durations, 99);

    // Top tenants — only relevant when no tenant filter is applied.
    let top_tenants: Vec<TopTenant> = if tenant_filter.is_some() {
        Vec::new()
    } else {
        let mut stmt = match conn.prepare(
            "SELECT tenant,
                    COUNT(*) AS n,
                    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errs
             FROM audit
             WHERE ts >= ?1
             GROUP BY tenant
             ORDER BY n DESC
             LIMIT 5",
        ) {
            Ok(s) => s,
            Err(_) => {
                return Overview {
                    total,
                    error_count,
                    error_pct,
                    p50_ms,
                    p99_ms,
                    rps_avg,
                    top_tenants: Vec::new(),
                    top_slow_ops: Vec::new(),
                    dropped_total: crate::safety::audit_db::dropped_total(),
                };
            }
        };
        let rows: rusqlite::Result<Vec<TopTenant>> = stmt
            .query_map(rusqlite::params![cutoff_ts], |r| {
                let tenant: String = r.get(0)?;
                let n: i64 = r.get(1)?;
                let errs: i64 = r.get::<_, Option<i64>>(2)?.unwrap_or(0);
                Ok(TopTenant {
                    tenant,
                    tenant_name: String::new(),
                    count: n as u64,
                    error_pct: if n == 0 {
                        0.0
                    } else {
                        (errs as f64) / (n as f64) * 100.0
                    },
                })
            })
            .and_then(|rows| rows.collect());
        rows.unwrap_or_default()
    };

    // Top slow ops — same window + filter; SELECT * row-by-row, full AuditEntry hydrate.
    let top_slow_ops: Vec<AuditEntry> = {
        let mut stmt = match conn.prepare(
            "SELECT ts, tenant, token_hint, op, status, duration_ms,
                    error_code, auth_method, oauth_email, oauth_error_code,
                    caller_ip, user_agent, extra,
                    actor_admin_id, actor_email_snapshot
             FROM audit
             WHERE ts >= ?1
               AND (?2 IS NULL OR tenant = ?2)
             ORDER BY duration_ms DESC
             LIMIT 5",
        ) {
            Ok(s) => s,
            Err(_) => {
                return Overview {
                    total,
                    error_count,
                    error_pct,
                    p50_ms,
                    p99_ms,
                    rps_avg,
                    top_tenants,
                    top_slow_ops: Vec::new(),
                    dropped_total: crate::safety::audit_db::dropped_total(),
                };
            }
        };
        let rows: rusqlite::Result<Vec<AuditEntry>> = stmt
            .query_map(rusqlite::params![cutoff_ts, tenant_filter], row_to_entry)
            .and_then(|rows| rows.collect());
        rows.unwrap_or_default()
    };

    Overview {
        total,
        error_count,
        error_pct,
        p50_ms,
        p99_ms,
        rps_avg,
        top_tenants,
        top_slow_ops,
        dropped_total: crate::safety::audit_db::dropped_total(),
    }
}

/// v1.24 — paginated browse rows via SQL. `before_ts` is the cursor
/// (returned in the previous page's response). Returns up to `limit`
/// rows ordered by `(ts DESC, id DESC)`.
pub fn query_browse(
    conn: &rusqlite::Connection,
    cutoff_ts: &str,
    tenant_filter: Option<&str>,
    op_filter: Option<&str>,
    status_filter: Option<&str>,
    before_ts: Option<&str>,
    limit: usize,
) -> Vec<AuditEntry> {
    let sql = "SELECT ts, tenant, token_hint, op, status, duration_ms,
                      error_code, auth_method, oauth_email, oauth_error_code,
                      caller_ip, user_agent, extra,
                      actor_admin_id, actor_email_snapshot
               FROM audit
               WHERE ts >= ?1
                 AND (?2 IS NULL OR tenant = ?2)
                 AND (?3 IS NULL OR op = ?3)
                 AND (?4 IS NULL OR status = ?4)
                 AND (?5 IS NULL OR ts < ?5)
               ORDER BY ts DESC, id DESC
               LIMIT ?6";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows: rusqlite::Result<Vec<AuditEntry>> = stmt
        .query_map(
            rusqlite::params![
                cutoff_ts,
                tenant_filter,
                op_filter,
                status_filter,
                before_ts,
                limit as i64,
            ],
            row_to_entry,
        )
        .and_then(|rows| rows.collect());
    rows.unwrap_or_default()
}

/// Convert a single SQL row back into an AuditEntry. Re-hoists
/// caller_ip + user_agent BACK into extra so the existing template JS
/// (which reads e.extra.caller_ip) keeps working unchanged. v1.25
/// templates can read the dedicated columns via a wider AuditEntryView,
/// but v1.24 stays backward-compatible.
fn row_to_entry(r: &rusqlite::Row) -> rusqlite::Result<AuditEntry> {
    let extra_str: Option<String> = r.get(12)?;
    let mut extra: serde_json::Map<String, serde_json::Value> = extra_str
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();

    let caller_ip: Option<String> = r.get(10)?;
    let user_agent: Option<String> = r.get(11)?;
    if let Some(ip) = caller_ip {
        extra.insert("caller_ip".into(), serde_json::Value::String(ip));
    }
    if let Some(ua) = user_agent {
        extra.insert("user_agent".into(), serde_json::Value::String(ua));
    }

    Ok(AuditEntry {
        ts: r.get(0)?,
        tenant: r.get(1)?,
        token_hint: r.get(2)?,
        op: r.get(3)?,
        status: r.get(4)?,
        duration_ms: r.get::<_, i64>(5)? as u64,
        collection: None,
        sql_hash: None,
        record_id: None,
        error_code: r.get(6)?,
        error_message: None,
        auth_method: r.get(7)?,
        oauth_email: r.get(8)?,
        oauth_error_code: r.get(9)?,
        actor_admin_id: r.get(13).unwrap_or(None),
        actor_email_snapshot: r.get(14).unwrap_or(None),
        extra,
    })
}

// ===== Admin-plane audit JSON twins (v1.44, CLI Phase 2 T8) =====

#[derive(serde::Serialize)]
pub struct TopTenantJson {
    pub tenant: String,
    pub tenant_name: String,
    pub count: u64,
    pub error_pct: f64,
}
#[derive(serde::Serialize)]
pub struct OverviewJson {
    pub total: u64,
    pub error_count: u64,
    pub error_pct: f64,
    pub p50_ms: u64,
    pub p99_ms: u64,
    pub rps_avg: f64,
    pub dropped_total: u64,
    pub top_tenants: Vec<TopTenantJson>,
    pub top_slow_ops: Vec<AuditEntryView>,
}
#[derive(serde::Serialize)]
pub struct AuditJson {
    pub tab: &'static str,
    pub window: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overview: Option<OverviewJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<AuditEntryView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_ts: Option<String>,
}

async fn audit_json_inner(
    audit_conn: &std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    tenant_name_map: std::collections::HashMap<String, String>,
    scope: AuditScope,
    q: &AuditQuery,
) -> AuditJson {
    let now = chrono::Utc::now();
    let window = Window::from_str_or_default(q.window.as_deref().unwrap_or(""));
    let tab: &'static str = match q.tab.as_deref() {
        Some("browse") => "browse",
        _ => "overview",
    };
    let status_filter: Option<&str> = match q.status.as_deref() {
        Some("ok") => Some("ok"),
        Some("error") => Some("error"),
        _ => None,
    };
    let cutoff_ts = (now - chrono::Duration::seconds(window.seconds()))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let tenant_filter: Option<String> = match &scope {
        AuditScope::Tenant(id) => Some(id.clone()),
        AuditScope::Host => q.tenant.as_ref().filter(|s| !s.is_empty()).cloned(),
    };
    let op_filter: Option<String> = q.op.as_ref().filter(|s| !s.is_empty()).cloned();
    let guard = audit_conn.lock().await;
    let conn: &rusqlite::Connection = &guard;
    if tab == "overview" {
        let ov = aggregate_via_sql(conn, &cutoff_ts, tenant_filter.as_deref(), window);
        let top_tenants = ov
            .top_tenants
            .iter()
            .map(|t| TopTenantJson {
                tenant: t.tenant.clone(),
                tenant_name: resolve_tenant_name(&tenant_name_map, &t.tenant),
                count: t.count,
                error_pct: t.error_pct,
            })
            .collect();
        let top_slow_ops = ov
            .top_slow_ops
            .iter()
            .map(|e| {
                AuditEntryView::from_entry(e, &resolve_tenant_name(&tenant_name_map, &e.tenant))
            })
            .collect();
        drop(guard);
        AuditJson {
            tab,
            window: window.as_str(),
            tenant: tenant_filter,
            overview: Some(OverviewJson {
                total: ov.total,
                error_count: ov.error_count,
                error_pct: ov.error_pct,
                p50_ms: ov.p50_ms,
                p99_ms: ov.p99_ms,
                rps_avg: ov.rps_avg,
                dropped_total: ov.dropped_total,
                top_tenants,
                top_slow_ops,
            }),
            entries: None,
            next_before_ts: None,
        }
    } else {
        let mut page = query_browse(
            conn,
            &cutoff_ts,
            tenant_filter.as_deref(),
            op_filter.as_deref(),
            status_filter,
            q.before_ts.as_deref(),
            PAGE_SIZE + 1,
        );
        drop(guard);
        let has_more = page.len() > PAGE_SIZE;
        if has_more {
            page.truncate(PAGE_SIZE);
        }
        let next = if has_more {
            page.last().map(|e| e.ts.clone())
        } else {
            None
        };
        let entries = page
            .iter()
            .map(|e| {
                AuditEntryView::from_entry(e, &resolve_tenant_name(&tenant_name_map, &e.tenant))
            })
            .collect();
        AuditJson {
            tab,
            window: window.as_str(),
            tenant: tenant_filter,
            overview: None,
            entries: Some(entries),
            next_before_ts: next,
        }
    }
}

pub async fn audit_host_json(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let map = {
        let meta = state.session.meta.lock().await;
        build_tenant_name_map(&meta)
    };
    axum::Json(audit_json_inner(&state.audit_meta_read, map, AuditScope::Host, &q).await)
        .into_response()
}

pub async fn audit_tenant_json(
    State(state): State<crate::mgmt::tenants::TenantsState>,
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let (map, exists) = {
        let meta = state.session.meta.lock().await;
        let exists = meta
            .query_row(
                "SELECT 1 FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
                rusqlite::params![tenant_id],
                |_| Ok(()),
            )
            .is_ok();
        (build_tenant_name_map(&meta), exists)
    };
    if !exists {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error_code":"TENANT_NOT_FOUND","message":"no such tenant"})),
        )
            .into_response();
    }
    axum::Json(
        audit_json_inner(
            &state.audit_meta_read,
            map,
            AuditScope::Tenant(tenant_id),
            &q,
        )
        .await,
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::fs;
    use std::path::PathBuf;

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
        let names: Vec<String> = files
            .iter()
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
        let names: Vec<String> = files
            .iter()
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
    }

    #[test]
    fn scan_window_reads_plain_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let today = now.format("%Y-%m-%d").to_string();
        let lines = format!(
            "{}\n{}\n{}\n",
            entry_line(&format!("{today}T00:01:00.000Z"), "acme", "GET", "ok", 10),
            entry_line(
                &format!("{today}T00:02:00.000Z"),
                "beta",
                "POST",
                "error",
                20
            ),
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
            entry_line(
                &format!("{today}T00:02:00.000Z"),
                "beta",
                "POST",
                "error",
                20
            ),
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
            &format!(
                "{}\n",
                entry_line(&format!("{today}T00:01:00.000Z"), "acme", "GET", "ok", 10)
            ),
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
        write(
            &dir.path().join(format!("audit-{day3}.jsonl.1.gz")),
            "this is not gzip",
        );

        let res = scan_window(dir.path(), Window::D7, now);
        assert!(res.entries.is_empty());
        assert_eq!(res.archive_errors.len(), 1);
        assert!(res.archive_errors[0].contains("audit-"));
    }

    #[test]
    fn audit_entry_view_serializes_extra_as_nested_object() {
        // AuditEntry uses #[serde(flatten)] on `extra`; the view must NOT.
        let mut e = mk_entry("2026-05-20T12:00:00.000Z", "acme", "GET /x", "ok", 5);
        e.extra
            .insert("auth_kind".to_string(), serde_json::json!("user"));
        e.extra
            .insert("auth_user_id".to_string(), serde_json::json!("u-abc"));
        let view = AuditEntryView::from_entry(&e, "Acme Inc");
        let json = serde_json::to_string(&view).unwrap();
        // The extra fields must NOT appear at the top level.
        assert!(
            !json.contains(r#""auth_kind":"user","tenant"#)
                && !json.contains(r#""tenant":"acme","auth_kind"#),
            "extra keys must not flatten to top level: {json}"
        );
        // They must appear nested under `extra`.
        assert!(json.contains(r#""extra":{"#), "extra block missing: {json}");
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
        assert_eq!(
            ops,
            vec!["DELETE /records", "GET /records", "POST /records"]
        );
    }

    #[test]
    fn distinct_ops_capped_truncates_at_limit() {
        let entries: Vec<AuditEntry> = (0..500)
            .map(|i| {
                mk_entry(
                    "2026-05-20T12:00:00.000Z",
                    "t",
                    &format!("op-{i:04}"),
                    "ok",
                    1,
                )
            })
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
        assert!(
            raw.contains("</script>"),
            "baseline assumption: serde does not escape `</`"
        );
        // Exercise the shared canonical escaper (same one production now uses).
        let safe = crate::mgmt::script_json::escape_json_for_script(&raw);
        assert!(
            !safe.contains("</script>"),
            "after escape, `</script>` must be gone"
        );
        assert!(
            safe.contains("<\\/script>"),
            "the slash escape must be visible"
        );
        // And the result must still round-trip back to the same logical content via JSON.parse-equivalent.
        let parsed: serde_json::Value = serde_json::from_str(&safe).unwrap();
        assert_eq!(parsed[0]["op"], "GET /records/</script><script>x</script>");
    }
}

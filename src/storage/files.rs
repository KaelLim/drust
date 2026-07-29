//! Shared file-storage helpers used by both admin and tenant upload flows.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum Owner {
    Admin,
    Tenant(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Inline,
    Attachment,
}

/// Bucket for the given visibility. Only two buckets exist host-wide:
/// `public` (website=on, anonymous read via Caddy) and `private` (drust-
/// proxied). Tenant vs admin ownership is encoded in the key prefix,
/// not the bucket.
pub fn bucket_for(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
    }
}

/// Build the object key for a new upload. Admin uploads land at the
/// bucket root (`<file-id>`); tenant uploads are prefixed with the
/// tenant id so one bucket can host every tenant safely.
pub fn compose_key(owner: &Owner, file_id: &str) -> String {
    match owner {
        Owner::Admin => file_id.to_string(),
        Owner::Tenant(id) => format!("{id}/{file_id}"),
    }
}

/// Backward-compat shim: some call sites ask for just the bucket based
/// on (owner, vis); admin and tenant now share buckets so we ignore
/// `owner` and route by visibility alone.
pub fn bucket_for_upload(_owner: &Owner, visibility: Visibility) -> String {
    bucket_for(visibility).to_string()
}

pub fn build_public_url(
    base_url: &str,
    owner: &Owner,
    visibility: Visibility,
    key: &str,
) -> String {
    let base = base_url.trim_end_matches('/');
    // DB stores the bare object id (`<uuid>.<ext>`). Tenant objects live
    // under `<tenant>/<uuid>` inside the shared bucket, so public URLs
    // interleave the tenant id. Private URLs go through drust's own
    // bytes/signed endpoints and keep the bare key for the /{key} route.
    match (owner, visibility) {
        (Owner::Admin, Visibility::Public) => format!("{base}/public/{key}"),
        (Owner::Tenant(id), Visibility::Public) => format!("{base}/public/{id}/{key}"),
        (Owner::Admin, Visibility::Private) => {
            format!(
                "{base}{}",
                crate::base_path::base(&format!("/admin/files/{key}/bytes"))
            )
        }
        (Owner::Tenant(id), Visibility::Private) => {
            format!(
                "{base}{}",
                crate::base_path::base(&format!("/t/{id}/files/{key}/bytes"))
            )
        }
    }
}

pub fn default_cache_control(visibility: Visibility, _disposition: Disposition) -> &'static str {
    match visibility {
        Visibility::Public => "public, max-age=86400",
        Visibility::Private => "private, no-store",
    }
}

/// Binding to a row of _system_files. Shared between admin (meta.sqlite)
/// and tenant (data.sqlite) — same shape in both.
#[derive(Debug, Clone, Serialize)]
pub struct FileRow {
    pub id: i64,
    pub key: String,
    pub original_name: String,
    pub content_type: Option<String>,
    pub size_bytes: i64,
    pub content_disposition: Option<String>, // mode: "inline" | "attachment"
    pub visibility: String,                  // "public" | "private"
    pub cache_control: Option<String>,
    pub meta_json: Option<String>,
    pub uploaded_at: String,
    pub uploader: String,
}

pub fn map_file_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileRow> {
    Ok(FileRow {
        id: row.get("id")?,
        key: row.get("key")?,
        original_name: row.get("original_name")?,
        content_type: row.get("content_type")?,
        size_bytes: row.get("size_bytes")?,
        content_disposition: row.get("content_disposition")?,
        visibility: row.get("visibility")?,
        cache_control: row.get("cache_control")?,
        meta_json: row.get("meta_json")?,
        uploaded_at: row.get("uploaded_at")?,
        uploader: row.get("uploader")?,
    })
}

// ───────────────────────────────────────────────────────────────────────────
// Stored-XSS neutralization (2026-07-29 audit, finding P0-1)
// ───────────────────────────────────────────────────────────────────────────
//
// Tenant-uploaded objects are served from the SAME ORIGIN as the admin UI:
// Caddy serves `/public/*` (Garage web) and `/drust/*` (this service) out of
// one site block, and drust itself streams private bytes back at
// `/drust/t/{id}/files/{key}/bytes` (also under `/drust/admin/...`). A file
// stored with a caller-supplied `text/html` (or SVG, or XML) content type and
// rendered `inline` therefore executes script in the admin plane's origin —
// escalating a tenant service key to host-admin via the admin session cookie.
//
// The fix is to never let those types reach a browser as a renderable
// document. `neutralize_content_type` is applied TWICE (defence in depth, per
// CLAUDE.md's DiD >= 2 rule):
//   * layer 1 — at every ingest path, so the bytes are never STORED with a
//     dangerous type (Mode-A admin + tenant multipart, tus finalize, the edge
//     function `put-file` host op, and the visibility bucket move);
//   * layer 2 — at every drust-owned byte responder, so rows uploaded BEFORE
//     this fix are served safely too.
// The Caddy `/public/*` block additionally carries `X-Content-Type-Options:
// nosniff` (operator-owned, outside this repo); every drust responder sets it
// too.
//
// Why the pair (structural type rule + `nosniff`) is COMPLETE, and why there
// is no blanket `Content-Security-Policy: sandbox` on file responses:
//   * a type that DECLARES itself a scriptable document is caught by
//     `is_unsafe_inline_type` — the `+xml` suffix rule makes that structural,
//     not an enumeration that the next vendor type escapes;
//   * a type the browser does NOT recognise cannot be sniffed back into HTML,
//     because `nosniff` makes the declared type authoritative — it is
//     downloaded, not rendered;
//   * PDF is the remaining scriptable format, and PDF JS runs in the viewer's
//     own context: it cannot read the admin DOM or issue credentialed
//     same-origin requests.
// A blanket `sandbox` CSP would add nothing against these and WOULD risk
// breaking legitimate inline rendering (images, PDF viewer), so it is
// deliberately not set. Revisit if a new scriptable, browser-recognised
// document format appears.

/// Content types a browser renders as a scriptable document when served
/// `inline`. Serving any of these from the admin origin is stored XSS.
///
/// This list is the EXACT-MATCH tail of the rule — the structural `+xml`
/// suffix in [`is_unsafe_inline_type`] already covers `application/xhtml+xml`,
/// `image/svg+xml` and every vendor XML type, so only the essences that do not
/// end in `+xml` need enumerating.
///
/// `application/javascript` is deliberately ABSENT: navigating to a `.js` URL
/// downloads/renders it as text, it does not execute in the page's origin, and
/// neutering it would break legitimate static-asset hosting.
pub const UNSAFE_INLINE_CONTENT_TYPES: &[&str] = &[
    "text/html",
    "text/xml",
    "application/xml",
    // XSLT: a stylesheet can carry an XHTML-namespaced <script>.
    "text/xsl",
];

/// True when `ct` is a script-executing document type. Case-insensitive and
/// parameter-insensitive: `"text/html"`, `"TEXT/HTML"`, `" text/html "` and
/// `"text/html; charset=utf-8"` all match.
///
/// The rule is deliberately STRUCTURAL, not a blocklist of known names: every
/// `<type>/<subtype>+xml` essence is an XML document type to Blink
/// (`MIMETypeRegistry::IsXMLMIMEType`) and Gecko, and an XML document
/// containing an XHTML-namespaced `<script>` executes in the response's
/// origin. An enumerated list is always a strict subset of that — the
/// 2026-07-29 adversarial review broke the first version of this function with
/// `application/rss+xml`, which no reasonable enumeration would have listed.
pub fn is_unsafe_inline_type(ct: &str) -> bool {
    let essence = ct.split(';').next().unwrap_or("").trim();
    if essence.is_empty() {
        return false;
    }
    let lower = essence.to_ascii_lowercase();
    lower.ends_with("+xml")
        || UNSAFE_INLINE_CONTENT_TYPES
            .iter()
            .any(|u| lower.as_str() == *u)
}

/// Turn a STORED string into a response header value, falling back when the
/// stored bytes are not header-legal.
///
/// Every value these responders echo (`content_type`, `content_disposition`,
/// `cache_control`) originates as unvalidated caller input — the tus ingest
/// path takes `Upload-Metadata: filetype` as base64 free text with no MIME
/// validation at all, and the multipart path takes `cache_control` verbatim.
/// A stored `"text/plain\r\nX: y"` therefore reaches `HeaderValue::from_str`,
/// which rejects CR/LF/NUL — and the previous `.parse().unwrap()` turned that
/// into a panic on the SERVE path, i.e. a stored denial-of-service against
/// every later reader of that row. (2026-07-29 audit, adversarial review.)
pub fn safe_header_value(value: &str, fallback: &'static str) -> axum::http::header::HeaderValue {
    axum::http::header::HeaderValue::from_str(value)
        .unwrap_or_else(|_| axum::http::header::HeaderValue::from_static(fallback))
}

/// Map a caller-supplied / stored content type onto the (content type,
/// disposition mode) pair that is safe to store AND to serve.
///
/// * a script-executing type -> `("application/octet-stream", "attachment")`
/// * anything else -> unchanged, `"inline"`
/// * `None` / blank -> `("application/octet-stream", "inline")`
pub fn neutralize_content_type(ct: Option<&str>) -> (String, &'static str) {
    match ct.map(str::trim).filter(|s| !s.is_empty()) {
        Some(c) if is_unsafe_inline_type(c) => {
            ("application/octet-stream".to_string(), "attachment")
        }
        Some(c) => (c.to_string(), "inline"),
        None => ("application/octet-stream".to_string(), "inline"),
    }
}

#[cfg(test)]
mod content_type_safety_tests {
    use super::*;

    #[test]
    fn neutralize_flags_html_and_variants() {
        for ct in [
            "text/html",
            "text/html;charset=utf-8",
            "text/html; charset=UTF-8",
            "TEXT/HTML",
            " text/html ",
            "image/svg+xml",
            "IMAGE/SVG+XML; charset=utf-8",
            "application/xhtml+xml",
            "text/xml",
            "application/xml",
        ] {
            assert!(is_unsafe_inline_type(ct), "{ct} must be flagged unsafe");
            let (out_ct, disp) = neutralize_content_type(Some(ct));
            assert_eq!(out_ct, "application/octet-stream", "ct for {ct}");
            assert_eq!(disp, "attachment", "disposition for {ct}");
        }
    }

    #[test]
    fn neutralize_passes_through_safe_types() {
        for ct in [
            "image/png",
            "application/pdf",
            "text/plain",
            "application/javascript",
            "text/javascript",
            "application/json",
            "text/html-ish",
            "text/htmlx",
        ] {
            assert!(!is_unsafe_inline_type(ct), "{ct} must NOT be flagged");
            let (out_ct, disp) = neutralize_content_type(Some(ct));
            assert_eq!(out_ct, ct, "ct for {ct}");
            assert_eq!(disp, "inline", "disposition for {ct}");
        }
    }

    #[test]
    fn neutralize_handles_missing_and_blank() {
        assert_eq!(
            neutralize_content_type(None),
            ("application/octet-stream".to_string(), "inline")
        );
        assert_eq!(
            neutralize_content_type(Some("")),
            ("application/octet-stream".to_string(), "inline")
        );
        assert_eq!(
            neutralize_content_type(Some("   ")),
            ("application/octet-stream".to_string(), "inline")
        );
        assert!(!is_unsafe_inline_type(""));
        assert!(!is_unsafe_inline_type("   "));
        assert!(!is_unsafe_inline_type(";charset=utf-8"));
    }

    /// 2026-07-29 audit, adversarial review finding 3A: an exact-match list is
    /// the wrong shape. Blink's `MIMETypeRegistry::IsXMLMIMEType` (and Gecko's
    /// equivalent) treat EVERY `<type>/<subtype>+xml` essence as an XML
    /// document, plus `text/xsl` — and an XML document carrying an
    /// XHTML-namespaced `<script>` executes in the response's origin. So the
    /// five enumerated types were a strict subset of the real vector:
    /// `application/rss+xml` sailed through and re-opened P0-1.
    #[test]
    fn neutralize_flags_every_xml_document_type() {
        for ct in [
            "application/rss+xml",
            "application/atom+xml",
            "application/mathml+xml",
            "application/x+xml",
            "APPLICATION/RSS+XML; charset=utf-8",
            "text/xsl",
            "TEXT/XSL",
            " text/xsl ",
        ] {
            assert!(is_unsafe_inline_type(ct), "{ct} must be flagged unsafe");
            let (out_ct, disp) = neutralize_content_type(Some(ct));
            assert_eq!(out_ct, "application/octet-stream", "ct for {ct}");
            assert_eq!(disp, "attachment", "disposition for {ct}");
        }
    }

    /// A stored value that is not header-legal must degrade to the fallback,
    /// never panic the responder. `Upload-Metadata: filetype` (tus) is base64
    /// free text with no MIME validation, so CR/LF/NUL are all reachable.
    #[test]
    fn safe_header_value_degrades_instead_of_panicking() {
        for bad in [
            "text/plain\r\nX-Injected: y",
            "text/plain\n",
            "text/plain\r",
            "text/plain\0",
            "\u{7f}",
        ] {
            assert_eq!(
                safe_header_value(bad, "application/octet-stream"),
                "application/octet-stream",
                "{bad:?} must fall back"
            );
        }
        // A legal value is passed through untouched.
        assert_eq!(
            safe_header_value("image/png", "application/octet-stream"),
            "image/png"
        );
    }

    /// The `+xml` rule is a SUFFIX on the essence, not a substring: a type that
    /// merely mentions xml stays inline.
    #[test]
    fn xml_suffix_rule_does_not_over_match() {
        for ct in [
            "application/xml-dtd",
            "text/xmlish",
            "application/vnd.foo+xmlx",
            "application/json",
        ] {
            assert!(!is_unsafe_inline_type(ct), "{ct} must NOT be flagged");
        }
    }
}

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

/// Error code for a non-service caller whose `visibility=public` is not
/// covered by a `public_upload_roles` grant on the governing prefix (v1.64,
/// #974). 403 on REST, a host-op `Err` on the edge station.
pub const FILE_PUBLIC_UPLOAD_DENIED: &str = "FILE_PUBLIC_UPLOAD_DENIED";

/// Which identity an upload station is deciding for.
///
/// Deliberately its own three-state enum rather than `bool is_service`: the
/// grant names ROLES, so the decision needs to tell `user` from `anon`, and a
/// boolean would have collapsed exactly the distinction the registry draws.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UploadCaller {
    /// `AuthCtx::Service` — or the host-admin management plane, which is a
    /// different plane with the same publish authority.
    Service,
    /// An end-user session token.
    User,
    /// An anonymous tenant token.
    Anon,
}

impl UploadCaller {
    /// The name this caller must find inside `public_upload_roles`.
    ///
    /// `Service` has none, and that is the point: a service caller never
    /// consults the registry at all, so no grant can widen or narrow it.
    pub fn grant_role(self) -> Option<&'static str> {
        match self {
            UploadCaller::Service => None,
            UploadCaller::User => Some("user"),
            UploadCaller::Anon => Some("anon"),
        }
    }

    /// The data-plane classification. The admin plane has no `AuthCtx` and
    /// passes [`UploadCaller::Service`] explicitly instead.
    pub fn from_auth(auth: &crate::auth::middleware::AuthCtx) -> Self {
        match auth {
            crate::auth::middleware::AuthCtx::Service { .. } => UploadCaller::Service,
            crate::auth::middleware::AuthCtx::User { .. } => UploadCaller::User,
            crate::auth::middleware::AuthCtx::Anon => UploadCaller::Anon,
        }
    }
}

/// A publish refused for want of a grant. The station maps it to its own
/// transport (HTTP 403 / host-op `Err`) with [`FILE_PUBLIC_UPLOAD_DENIED`].
///
/// `detail` is for the SERVER LOG only. The registry is service-only readable
/// on every face precisely because it is the tenant's access map, so the
/// caller-facing [`message`](Self::message) must not say which prefix governs
/// the upload or whether a rule exists there at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibilityRefused {
    pub detail: String,
}

impl VisibilityRefused {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        FILE_PUBLIC_UPLOAD_DENIED
    }

    /// The stable, non-revealing caller-facing message.
    pub const fn message(&self) -> &'static str {
        "publishing an upload requires a public_upload_roles grant on the \
         governing file-policy prefix; ask the tenant's service owner to grant \
         it (PUT /file-policies), or upload with visibility=private"
    }
}

impl std::fmt::Display for VisibilityRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for VisibilityRefused {}

/// v1.64 (#974) — the ONE publish decision, shared by every upload station that
/// has a caller identity (Mode-A multipart, tus create, edge `put-file`).
///
/// |             | asks for `public`                          | asks for `private` / says nothing |
/// |-------------|--------------------------------------------|-----------------------------------|
/// | service     | always granted                             | `service_default` / `Private`     |
/// | user / anon | only with a grant on the governing prefix  | `Private`, always                 |
///
/// The grant is `_system_file_policy.public_upload_roles` on the LONGEST prefix
/// matching this upload's declared `path` — the same `longest_match` the read
/// side uses, so "which rule governs this file" has one answer across the whole
/// feature. This REPLACES two earlier shapes: v1.63.0's blanket
/// `FILE_VISIBILITY_SERVICE_ONLY` refusal (publishing reachable only with a
/// god-mode key, so tenants embedded one in their frontends) and v1.63.1's
/// "explicit is always honored" interim (no lever at all between "may upload"
/// and "may publish"). Neither shipped.
///
/// * `caller` — see [`UploadCaller`]; `Service` short-circuits before the
///   registry is read, exactly as service bypasses every other RLS gate.
/// * `requested` — what the caller asked for; `None` = the field was absent.
/// * `service_default` — what a SERVICE caller gets when it asks for nothing.
///   **This differs per station on purpose**: Mode-A multipart has always
///   defaulted to `Public` and tus has always defaulted to `Private`. Do not
///   "unify" them — flipping tus to public would publish every existing
///   service upload that omits the field.
/// * `path` — the caller-declared logical path of THIS upload, `None` when it
///   declared none. An unfiled upload can only ever match the root rule `''`,
///   the same rule `longest_match` gives a `path IS NULL` row on the read side.
/// * `load_policies` — the registry, read LAZILY on the connection the station
///   already holds. Lazy for two reasons: a service upload must not pay for a
///   read it ignores, and a broken registry must not break service uploads,
///   which are the recovery path. A load failure on the arm that DOES need it
///   is a refusal (fail-closed: an unreadable rule cannot be shown to grant).
///
/// Deny-by-default is deliberate and is why the release ships a one-time
/// grandfather grant for existing tenants
/// (`db::migrations::seed_public_upload_grant`): the un-granted state has to
/// mean "no", or `public_upload_roles` would be a suggestion. Silence from a
/// non-service caller is `Private` on every station — pre-v1.63 Mode-A
/// published every field-less upload, anonymous ones included, and that footgun
/// must not come back.
///
/// Publishing remains a one-way escape from the per-file gate: a `public`
/// object is served by Caddy straight out of Garage and never reaches drust
/// again. That is why the grant is checked at MINT time here, and why `sign`
/// and the set-visibility `PATCH` stay service-only (CLAUDE.md invariant 19).
pub fn enforce_upload_visibility(
    caller: UploadCaller,
    requested: Option<Visibility>,
    service_default: Visibility,
    path: Option<&str>,
    load_policies: impl FnOnce() -> Result<Vec<crate::storage::file_policy::FilePolicyRow>, String>,
) -> Result<Visibility, VisibilityRefused> {
    if matches!(caller, UploadCaller::Service) {
        return Ok(requested.unwrap_or(service_default));
    }
    // Silence, and an explicit `private`, need no grant and no registry read.
    if !matches!(requested, Some(Visibility::Public)) {
        return Ok(Visibility::Private);
    }
    let Some(role) = caller.grant_role() else {
        // Unreachable — `Service` returned above — but a future variant that
        // forgets its role name must land on the closed side of the gate.
        return Err(VisibilityRefused::new(
            "caller kind has no publish-grant role name",
        ));
    };
    let policies = load_policies()
        .map_err(|e| VisibilityRefused::new(format!("file policy registry unreadable: {e}")))?;
    let Some(rule) = crate::storage::file_policy::longest_match(&policies, path) else {
        return Err(VisibilityRefused::new(format!(
            "no file policy rule governs path {path:?} (role {role})"
        )));
    };
    match rule.public_upload_roles.as_deref() {
        Some(roles) if roles.iter().any(|r| r == role) => Ok(Visibility::Public),
        _ => Err(VisibilityRefused::new(format!(
            "prefix {:?} does not grant public upload to {role}",
            rule.prefix
        ))),
    }
}

/// **TEMPORARY (#974 T1 → deleted by T2).** The v1.63.1 decision, unchanged,
/// kept alive only so the four upload stations keep compiling and behaving
/// EXACTLY as they do on this branch while T2 wires them to the grant-aware
/// [`enforce_upload_visibility`] above one station at a time.
///
/// It is a copy of the old body rather than a delegation on purpose: routing it
/// through the new function with an empty rule set would silently flip every
/// station to deny, and routing it with a grant-ignoring shortcut would put a
/// second publish rule in the codebase. Nothing new may call this.
pub fn enforce_upload_visibility_v1631(
    is_service: bool,
    requested: Option<Visibility>,
    service_default: Visibility,
) -> Visibility {
    if is_service {
        return requested.unwrap_or(service_default);
    }
    requested.unwrap_or(Visibility::Private)
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
    /// v1.63 (#950-B) — caller-declared logical path; NULL = unfiled. Metadata
    /// only: never an address (the physical key is `key`).
    pub path: Option<String>,
    /// v1.63 (#950-B) — carried so the row map handed to the policy evaluator
    /// contains the SYSTEM columns. `validate_field` waves `id`/`created_at`/
    /// `updated_at` through unconditionally, and `eval_policy` reads the map
    /// by key: a MISSING key is not an error there, it reads as Null, so a
    /// `created_at` comparison would over-deny (Unknown) and an
    /// `updated_at is_null` test would silently be TRUE — fail-OPEN over every
    /// file in the tenant. Keeping both columns on `FileRow` is what keeps the
    /// SQL and in-memory evaluators in lockstep.
    pub created_at: String,
    pub updated_at: String,
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
        // By NAME, like every field above — all six call sites are
        // `SELECT * FROM _system_files` on a plain (never `prepare_cached`)
        // statement, so a column added to either `_system_files` copy is
        // picked up without touching the SQL. See CLAUDE.md invariant 11 for
        // why the "plain prepare" half of that sentence matters.
        path: row.get("path")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

// ───────────────────────────────────────────────────────────────────────────
// Stored-XSS mitigation (2026-07-29 audit, finding P0-1; redesigned 2026-07-30)
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
// v1.56.2 closed this by downgrading the type to `application/octet-stream` +
// `attachment` at ingest AND at serve, so the browser never renders it. That
// broke every legitimate use of the same feature (a Google-Docs-export-to-HTML
// pipeline, SVG logos) — HTML/SVG could no longer be VIEWED, only downloaded.
//
// The v1.56.3 redesign keeps the content type as declared/stored (so it
// renders) and instead sandboxes the RENDERING: every response whose type is
// `is_unsafe_inline_type` carries `Content-Security-Policy: sandbox
// allow-top-navigation-by-user-activation` ([`SANDBOX_CSP`]). Bare `sandbox`
// gives the document a unique opaque origin and disables scripts, forms, and
// popups; `allow-top-navigation-by-user-activation` restores plain hyperlink
// navigation (a genuine user click can still leave the page) without
// re-enabling anything script-driven. This is the same technique GitHub uses
// to serve arbitrary user HTML from `raw.githubusercontent.com` directly, and
// CSP3 explicitly extends `sandbox` to top-level (not just framed) documents
// — Chrome, Firefox, and Safari all enforce it there.
//
// **`allow-same-origin` and `allow-scripts` must NEVER be added to
// [`SANDBOX_CSP`].** Either one alone is close to harmless; together they
// reopen exactly the escalation this exists to close (a script that can also
// read the admin origin's cookies and issue credentialed same-origin
// requests). A `<meta http-equiv="Content-Security-Policy">` inside the
// document cannot relax this — CSP enforcement is the INTERSECTION of every
// applicable policy, header and meta alike, never the union.
//
// Applied at:
//   * every drust-owned byte responder — `tenant_files::stream_bytes`,
//     `signed_bytes::respond`, the admin `/admin/files/{key}/bytes` handler —
//     via [`content_security_policy_for`], keyed off the STORED type, so a row
//     from any point in time (before or after this file existed) is covered;
//   * the Caddy `/public/*` block (`handle_response` matcher on the upstream's
//     OWN `Content-Type`, not on the request path's file extension — a caller
//     controls the object's key/extension and its declared Content-Type
//     independently, so an extension-based matcher is bypassable and a
//     response-header-based one is not). The Caddy regex mirrors
//     `is_unsafe_inline_type` exactly and the two MUST be kept in lockstep.
// Ingest no longer downgrades anything — `is_unsafe_inline_type` now drives a
// CSP decision at serve time only, never a stored-value rewrite.
//
// `X-Content-Type-Options: nosniff` remains unconditional on every responder
// and on the Caddy block regardless of declared type — it is the ONLY defense
// against a DIFFERENT attack (a file declared as a safe type, e.g.
// `image/png`, whose bytes a browser could still sniff back into HTML without
// it). CSP sandbox and nosniff are orthogonal and both stay on.

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

/// Lowercase the type/subtype ("essence") portion of a content type,
/// leaving any `;params` suffix byte-for-byte untouched.
///
/// MIME essence matching is case-insensitive (RFC 2045 §5.1), so this
/// changes nothing about how any client interprets or renders the type — it
/// exists purely so the Caddy `/public/*` `handle_response` matcher (see
/// `is_unsafe_inline_type`'s doc comment) can rely on ONE canonical casing.
/// Caddy 2.6.2's response-matcher allowlist has no case-insensitive or regex
/// option (only a plain, case-SENSITIVE glob on `header`), so without this
/// normalization an upload declaring `Content-Type: TeXt/HtMl` would sail
/// past a lowercase-only Caddy pattern while a browser still renders it as
/// HTML — MIME type matching is case-insensitive independent of `nosniff`,
/// which guards a different class of attack (an UNRECOGNIZED type being
/// sniffed into something else, not an unambiguous-but-oddly-cased one).
pub fn normalize_content_type_case(ct: &str) -> String {
    let ct = ct.trim();
    match ct.find(';') {
        Some(idx) => {
            let (essence, rest) = ct.split_at(idx);
            format!("{}{rest}", essence.trim().to_ascii_lowercase())
        }
        None => ct.to_ascii_lowercase(),
    }
}

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
    lower.ends_with("+xml") || UNSAFE_INLINE_CONTENT_TYPES.contains(&lower.as_str())
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

/// The `Content-Security-Policy` value applied when serving a script-executing
/// type. See the module doc comment above for the full threat model and the
/// hard invariant: `allow-same-origin` and `allow-scripts` must NEVER be
/// added — either one defeats this protection.
pub const SANDBOX_CSP: &str = "sandbox allow-top-navigation-by-user-activation";

/// `Content-Security-Policy` header value to send when serving `ct`, if any.
/// `None` means "declared type is not a scriptable document — no CSP needed
/// for this purpose" (the response still gets `nosniff` unconditionally,
/// applied separately by each responder).
pub fn content_security_policy_for(ct: &str) -> Option<&'static str> {
    is_unsafe_inline_type(ct).then_some(SANDBOX_CSP)
}

/// Insert the three headers that decide whether `ct` renders safely:
/// `Content-Type` (via [`safe_header_value`] — `ct` is unvalidated caller
/// input), `X-Content-Type-Options: nosniff` (unconditional — the defense
/// against a browser sniffing a DIFFERENT declared type back into HTML), and
/// `Content-Security-Policy` (only when [`content_security_policy_for`]
/// returns `Some`).
///
/// This is the ONE place all three drust byte responders
/// (`tenant_files::stream_bytes`, `signed_bytes::respond`, the admin
/// `/admin/files/{key}/bytes` handler) build these three headers, so the
/// CSP-sandbox decision cannot drift between them — a responder that inserted
/// its own copy of this logic could silently skip the CSP branch and reopen
/// P0-1 for that one route without anyone noticing.
pub fn insert_content_type_headers(headers: &mut axum::http::HeaderMap, ct: &str) {
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        safe_header_value(ct, "application/octet-stream"),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::header::HeaderValue::from_static("nosniff"),
    );
    if let Some(csp) = content_security_policy_for(ct) {
        headers.insert(
            axum::http::header::CONTENT_SECURITY_POLICY,
            axum::http::header::HeaderValue::from_static(csp),
        );
    }
}

#[cfg(test)]
mod content_type_safety_tests {
    use super::*;

    #[test]
    fn flags_html_and_variants_as_unsafe() {
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
            assert_eq!(
                content_security_policy_for(ct),
                Some(SANDBOX_CSP),
                "csp for {ct}"
            );
        }
    }

    #[test]
    fn safe_types_get_no_csp() {
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
            assert_eq!(content_security_policy_for(ct), None, "csp for {ct}");
        }
    }

    #[test]
    fn empty_and_blank_are_not_flagged() {
        assert!(!is_unsafe_inline_type(""));
        assert!(!is_unsafe_inline_type("   "));
        assert!(!is_unsafe_inline_type(";charset=utf-8"));
        assert_eq!(content_security_policy_for(""), None);
    }

    /// (kept from the 2026-07-29 adversarial review) an exact-match list is
    /// the wrong shape — `application/rss+xml` sailed through the first
    /// version of `is_unsafe_inline_type`.
    #[test]
    fn flags_every_xml_document_type_as_unsafe() {
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
            assert_eq!(
                content_security_policy_for(ct),
                Some(SANDBOX_CSP),
                "csp for {ct}"
            );
        }
    }

    /// Codified guardrail: whoever edits SANDBOX_CSP next cannot silently
    /// weaken it. This only checks the string — it is a tripwire, not a
    /// substitute for the review this file's history demands.
    #[test]
    fn sandbox_csp_never_grants_same_origin_or_scripts() {
        // Exact-literal pin (codex review, 2026-07-30): substring checks alone
        // would wave through a widened value that still avoids the two named
        // tokens (e.g. adding `allow-forms` or `allow-popups`) — no such
        // widening should land without deliberately touching this assertion.
        assert_eq!(
            SANDBOX_CSP,
            "sandbox allow-top-navigation-by-user-activation"
        );
        assert!(!SANDBOX_CSP.contains("allow-same-origin"));
        assert!(!SANDBOX_CSP.contains("allow-scripts"));
        assert!(SANDBOX_CSP.starts_with("sandbox"));
    }

    /// Exercises the ONE function all three drust byte responders call — this
    /// is the shared-logic coverage the 2026-07-30 adversarial review asked
    /// for: `tenant_files::stream_bytes` is covered end-to-end by
    /// `tests/upload_content_type_safety.rs`, but `signed_bytes::respond` and
    /// the admin `/admin/files/{key}/bytes` handler have no router harness.
    /// Since all three now call this one function for these three headers,
    /// testing it once here covers all three call sites structurally — a
    /// responder that stopped calling it (or reimplemented it) would be the
    /// only way to regress, and that's a one-line diff to catch on review.
    #[test]
    fn insert_content_type_headers_sets_csp_only_for_unsafe_types() {
        let mut h = axum::http::HeaderMap::new();
        insert_content_type_headers(&mut h, "text/html");
        assert_eq!(h.get("content-type").unwrap(), "text/html");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("content-security-policy").unwrap(), SANDBOX_CSP);

        let mut h = axum::http::HeaderMap::new();
        insert_content_type_headers(&mut h, "image/png");
        assert_eq!(h.get("content-type").unwrap(), "image/png");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert!(
            h.get("content-security-policy").is_none(),
            "a safe type must not get a CSP header"
        );

        // A caller-controlled value that isn't header-legal degrades via
        // safe_header_value instead of panicking, and — being a fallback of
        // "application/octet-stream" — correctly gets NO csp header either.
        let mut h = axum::http::HeaderMap::new();
        insert_content_type_headers(&mut h, "text/plain\r\nX-Injected: y");
        assert_eq!(h.get("content-type").unwrap(), "application/octet-stream");
        assert!(h.get("content-security-policy").is_none());
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

    /// The Caddy `/public/*` `handle_response` matcher can only do a plain,
    /// CASE-SENSITIVE glob on the upstream's `Content-Type` (Caddy 2.6.2's
    /// response-matcher allowlist has no `header_regexp`/`expression`, so
    /// there is no case-insensitive option there) — so an ingest-time upload
    /// declaring `Content-Type: TeXt/HtMl` would sail past a lowercase-only
    /// Caddy pattern while a browser still renders it as HTML (MIME essence
    /// matching is case-insensitive per RFC 2045 §5.1, independent of
    /// `nosniff`, which only guards a DIFFERENT class of attack). Every
    /// ingest site therefore normalizes the essence to lowercase before
    /// storing, so the Caddy glob only ever needs to match ONE casing.
    #[test]
    fn normalize_content_type_case_lowercases_essence_only() {
        assert_eq!(normalize_content_type_case("TEXT/HTML"), "text/html");
        assert_eq!(normalize_content_type_case("Text/Html"), "text/html");
        assert_eq!(
            normalize_content_type_case("Text/Html; charset=UTF-8"),
            "text/html; charset=UTF-8",
            "params after the first ';' are left byte-for-byte untouched"
        );
        assert_eq!(
            normalize_content_type_case(" TEXT/HTML "),
            "text/html",
            "outer whitespace is trimmed"
        );
        assert_eq!(normalize_content_type_case("image/PNG"), "image/png");
        assert_eq!(normalize_content_type_case(""), "");
        assert_eq!(
            normalize_content_type_case("APPLICATION/RSS+XML"),
            "application/rss+xml"
        );
    }

    /// **TEMPORARY (#974 T1 → deleted with the shim in T2).** The four upload
    /// stations still call `enforce_upload_visibility_v1631`, so its truth
    /// table is still live behaviour and stays pinned until they move.
    #[test]
    fn the_v1631_shim_is_unchanged_until_the_stations_move() {
        use Visibility::{Private, Public};
        assert_eq!(enforce_upload_visibility_v1631(true, None, Public), Public);
        assert_eq!(
            enforce_upload_visibility_v1631(true, None, Private),
            Private
        );
        for station_default in [Public, Private] {
            assert_eq!(
                enforce_upload_visibility_v1631(false, None, station_default),
                Private
            );
            assert_eq!(
                enforce_upload_visibility_v1631(false, Some(Public), station_default),
                Public,
                "the interim 'explicit is always honored' rule, which the grant \
                 matrix below REPLACES once the stations are wired"
            );
        }
    }
}

#[cfg(test)]
mod publish_grant_tests {
    use super::*;
    use crate::storage::file_policy::FilePolicyRow;
    use Visibility::{Private, Public};

    /// A rule granting `roles` the publish right on `prefix`. `owner_scoped` is
    /// set so the row is a shape the write face would accept.
    fn granting(prefix: &str, roles: &[&str]) -> FilePolicyRow {
        FilePolicyRow {
            prefix: prefix.to_string(),
            owner_scoped: true,
            public_read: false,
            select_policy: None,
            delete_policy: None,
            public_upload_roles: Some(roles.iter().map(|r| r.to_string()).collect()),
        }
    }

    /// The same rule with no grant at all — the state every prefix is in until
    /// someone writes one.
    fn ungranted(prefix: &str) -> FilePolicyRow {
        FilePolicyRow {
            public_upload_roles: None,
            ..granting(prefix, &[])
        }
    }

    /// The registry as a station would supply it.
    fn registry(rows: Vec<FilePolicyRow>) -> impl FnOnce() -> Result<Vec<FilePolicyRow>, String> {
        move || Ok(rows)
    }

    /// A registry read that fails, as an unreadable or corrupt one does.
    fn broken() -> impl FnOnce() -> Result<Vec<FilePolicyRow>, String> {
        || Err("no such table: _system_file_policy".to_string())
    }

    /// Service is decided before the registry is consulted at all — pinned by
    /// handing it a registry that would PANIC if it were read. Both station
    /// defaults are deliberately different and both are pinned here: a
    /// "harmonising" edit that flips tus to public fails this test.
    #[test]
    fn service_is_unchanged_and_never_reads_the_registry() {
        let unreadable = || -> Result<Vec<FilePolicyRow>, String> {
            panic!("a service upload must not pay for, or depend on, a registry read")
        };
        assert_eq!(
            enforce_upload_visibility(UploadCaller::Service, None, Public, None, unreadable),
            Ok(Public),
            "Mode-A service default"
        );
        assert_eq!(
            enforce_upload_visibility(
                UploadCaller::Service,
                None,
                Private,
                Some("a/x.bin"),
                registry(vec![])
            ),
            Ok(Private),
            "tus service default — must NOT become public"
        );
        assert_eq!(
            enforce_upload_visibility(
                UploadCaller::Service,
                Some(Public),
                Private,
                None,
                registry(vec![])
            ),
            Ok(Public)
        );
        assert_eq!(
            enforce_upload_visibility(
                UploadCaller::Service,
                Some(Private),
                Public,
                None,
                registry(vec![])
            ),
            Ok(Private)
        );
    }

    #[test]
    fn a_granted_role_may_publish_into_the_granted_prefix() {
        for (caller, role) in [(UploadCaller::User, "user"), (UploadCaller::Anon, "anon")] {
            assert_eq!(
                enforce_upload_visibility(
                    caller,
                    Some(Public),
                    Private,
                    Some("avatars/me.png"),
                    registry(vec![granting("avatars/", &[role])])
                ),
                Ok(Public),
                "{role} is granted on avatars/"
            );
            // …and the grant is per-ROLE: the other role is still refused by
            // the very same rule.
            let other = match caller {
                UploadCaller::User => UploadCaller::Anon,
                _ => UploadCaller::User,
            };
            assert!(
                enforce_upload_visibility(
                    other,
                    Some(Public),
                    Private,
                    Some("avatars/me.png"),
                    registry(vec![granting("avatars/", &[role])])
                )
                .is_err(),
                "a grant naming only {role} must not cover the other role"
            );
        }
    }

    #[test]
    fn an_ungranted_prefix_refuses_and_the_refusal_names_the_public_code() {
        let refusal = enforce_upload_visibility(
            UploadCaller::User,
            Some(Public),
            Public,
            Some("docs/a.pdf"),
            registry(vec![ungranted("docs/"), granting("", &["user"])]),
        )
        .unwrap_err();
        assert_eq!(refusal.code(), FILE_PUBLIC_UPLOAD_DENIED);
        assert!(
            !refusal.message().contains("docs/"),
            "the caller-facing message must not disclose the registry's shape: \
             {}",
            refusal.message()
        );
        assert!(
            refusal.detail.contains("docs/"),
            "…while the server-side detail must, or an operator cannot debug it"
        );
    }

    #[test]
    fn the_longest_matching_prefix_decides_in_both_directions() {
        // A deeper GRANT overrides an ungranted parent…
        assert_eq!(
            enforce_upload_visibility(
                UploadCaller::User,
                Some(Public),
                Private,
                Some("shared/pics/a.png"),
                registry(vec![ungranted(""), granting("shared/pics/", &["user"])])
            ),
            Ok(Public)
        );
        // …and a deeper UNGRANTED rule overrides a granted root, which is the
        // direction that would be a hole if longest-match were reversed.
        assert!(
            enforce_upload_visibility(
                UploadCaller::User,
                Some(Public),
                Private,
                Some("shared/hr/pay.csv"),
                registry(vec![
                    granting("", &["anon", "user"]),
                    ungranted("shared/hr/")
                ])
            )
            .is_err(),
            "a deeper rule that grants nobody must close a prefix its parent opened"
        );
    }

    #[test]
    fn an_unfiled_upload_is_decided_by_the_root_rule_alone() {
        // `path = None` can only ever match `''` — the same rule the read side
        // applies to a `path IS NULL` row.
        assert_eq!(
            enforce_upload_visibility(
                UploadCaller::Anon,
                Some(Public),
                Public,
                None,
                registry(vec![granting("", &["anon"])])
            ),
            Ok(Public),
            "the grandfather grant lands on the root, and this is the upload it \
             has to keep working"
        );
        assert!(
            enforce_upload_visibility(
                UploadCaller::Anon,
                Some(Public),
                Public,
                None,
                registry(vec![granting("uploads/", &["anon"])])
            )
            .is_err(),
            "a deeper grant can never cover an unfiled upload"
        );
    }

    #[test]
    fn every_fail_closed_direction_refuses() {
        // (a) empty registry — a tenant that cleared its root.
        assert!(
            enforce_upload_visibility(
                UploadCaller::User,
                Some(Public),
                Public,
                Some("x/y.bin"),
                registry(vec![])
            )
            .is_err()
        );
        // (b) a matching rule with no grant column set.
        assert!(
            enforce_upload_visibility(
                UploadCaller::User,
                Some(Public),
                Public,
                Some("x/y.bin"),
                registry(vec![ungranted("x/")])
            )
            .is_err()
        );
        // (c) an unreadable / corrupt registry. Deny, never "no rules ⇒ open",
        // and never a silent downgrade to private: the caller is TOLD.
        let refusal = enforce_upload_visibility(
            UploadCaller::Anon,
            Some(Public),
            Public,
            Some("x/y.bin"),
            broken(),
        )
        .unwrap_err();
        assert!(
            refusal.detail.contains("unreadable"),
            "got {}",
            refusal.detail
        );
    }

    /// The half of v1.63 that survives every revision: a non-service caller
    /// that says NOTHING gets `Private`, on both stations, with or without a
    /// grant. Pre-v1.63 Mode-A published every field-less upload.
    #[test]
    fn silence_is_private_for_a_caller_even_where_a_grant_exists() {
        for station_default in [Public, Private] {
            for caller in [UploadCaller::User, UploadCaller::Anon] {
                assert_eq!(
                    enforce_upload_visibility(
                        caller,
                        None,
                        station_default,
                        Some("open/a.bin"),
                        registry(vec![granting("open/", &["anon", "user"])])
                    ),
                    Ok(Private),
                    "silence must never inherit the station default, and a grant \
                     is permission to publish — not an instruction to"
                );
                assert_eq!(
                    enforce_upload_visibility(
                        caller,
                        Some(Private),
                        station_default,
                        Some("open/a.bin"),
                        registry(vec![granting("open/", &["anon", "user"])])
                    ),
                    Ok(Private)
                );
            }
        }
    }

    #[test]
    fn caller_classification_maps_auth_to_the_grant_role_names() {
        use crate::auth::middleware::AuthCtx;
        assert_eq!(
            UploadCaller::from_auth(&AuthCtx::Service { admin_id: None }),
            UploadCaller::Service
        );
        assert_eq!(
            UploadCaller::from_auth(&AuthCtx::User {
                user_id: "u-1".into(),
                token_hash: String::new()
            }),
            UploadCaller::User
        );
        assert_eq!(UploadCaller::from_auth(&AuthCtx::Anon), UploadCaller::Anon);
        assert_eq!(UploadCaller::Service.grant_role(), None);
        assert_eq!(UploadCaller::User.grant_role(), Some("user"));
        assert_eq!(UploadCaller::Anon.grant_role(), Some("anon"));
    }
}

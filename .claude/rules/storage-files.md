---
paths:
  - "src/storage/files.rs"
  - "src/storage/visibility.rs"
  - "src/storage/garage.rs"
  - "src/tenant/uploads/**"
  - "src/tenant/mod.rs"
  - "src/tenant/file_caps.rs"
  - "src/mgmt/public_files.rs"
  - "src/mgmt/tenant_files.rs"
---

# Object storage, uploads, and the same-origin XSS defense

Fires when you touch the Garage S3 client, per-tenant files, the tus upload server, the file-caps gate, or any byte-responder.

## Garage integration

Optional; activated by `GARAGE_S3_ENDPOINT` + friends in `.env`.

- **Garage is an independent service** (see `tool/garage/CLAUDE.md`). drust speaks plain S3 via `object_store::aws::AmazonS3`. drust boots with Garage unreachable — storage tab shows "not configured" / admin ops return 503; rest of drust unaffected.
- **Reads bypass drust.** Anonymous GETs hit Caddy `/public/*`, which reverse-proxies to Garage `s3_web` (`127.0.0.1:47831`) with `Host: public.web.local`. drust is only in the *write* path.
- **SQLite-first upload / S3-first delete.** Upload inserts metadata row, puts to Garage, compensates by deleting row on S3 failure. Delete calls Garage first (idempotent on NotFound), then clears row. Orphans surfaced by `reconcile` page.
- **`_system_*` drop-protected.** `storage::schema::is_protected_collection()` is consulted by `drop_collection`, for both admin-level `_system_files` and per-tenant `_system_files`.
- **Disk guard**: uploads return 507 when `/var/lib/garage` has less than `DRUST_DISK_MIN_FREE_PCT` (default 20) percent free.

## Per-tenant files

Tenant files live in two **host-wide** buckets — `public` (website-enabled, served via Caddy `/public/*`) and `private` (drust-proxied) — namespaced by a `<tenant-id>/` key prefix. Per-tenant buckets were retired; `_trash_pending_revokes` / `_orphan_buckets` + the `reconcile` page only clean up legacy per-tenant buckets left from before that change.

- **Cap-gated.** `src/tenant/file_caps.rs::file_caps_layer` (inner to `bearer_auth_layer` on `files_router`, replacing the older blanket `require_service_layer`) gates each route per-verb from a pure `classify_file_route` matrix: **service unrestricted; anon/user checked against the tenant's `file_anon_caps_json` / `file_user_caps_json`** (subset of `{read,list,upload,delete}`, default `'[]'` = service-only, so every existing tenant is unchanged). **make-public (`PATCH` set-visibility) + `sign` stay service-only** (not cap verbs). Shared-pool model — NOT per-file owner-scoped. Config service-only via MCP `set_file_caps` (auth-cache hook 12).
- **The Mode-A handlers are also mounted under `/admin` (no `TenantRef`), so the gate MUST stay a layer, never a required handler extractor.**
- The tus handlers keep an inline `require_file_cap` as DiD layer 2 **and bind each session to its creating bearer** (the `_system_upload_sessions.uploader` column records service/anon/`<user_id>`; a non-service `HEAD`/`PATCH`/`DELETE` whose identity ≠ `uploader` gets 404).
- **Visibility toggle** (`src/storage/visibility.rs::change_visibility`): public ⇄ private is a bucket move (copy → UPDATE row → delete-old), not a flag flip — the bytes physically move between the two buckets. Ordering keeps the live row always pointing at an existing object; a crash leaves a space-only reconcile orphan, retries are idempotent. The only UPDATE path on `_system_files`.

## Mode B large-file upload / tus 1.0 (`src/tenant/uploads/`)

Resumable-upload server at `/t/<id>/uploads/*`: five tus methods plus a service-only `GET` (list sessions), all cap-gated per verb like Mode A. Each `PATCH` chunk is bounded by `DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES` (default 64 MiB) via a per-route `DefaultBodyLimit`; chunks append to a durable spool file (`tenants/<id>/_uploads/<token>.part`) so the filesystem byte-count is the offset source of truth and resume survives client disconnect and server restart. On completion: `INSERT OR IGNORE` a `_system_files` row (SQLite-first, idempotent), stream the spool to Garage via `put_file_in`, then delete the spool and session row. Hourly in-process janitor reclaims abandoned sessions; never touches `_system_files` or Garage.

> [!WARNING]
> **Mode B keeps every HTTP request small by design (chunks ≤ `DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES`, default 64 MiB) so it stays under the 200 MB Caddy/.221 ingress limit.** Never raise a body-limit to accommodate large uploads — the tus chunking protocol exists precisely so each individual request stays small.

## Stored-XSS mitigation (`src/storage/files.rs`)

Tenant bytes are served from the **same origin as the admin UI** (Caddy serves `/public/*` and `/drust/*` from one site block), so a caller-supplied `text/html`/XML content type rendered `inline` executes script in the admin plane's origin — escalating a tenant service key to host-admin.

The fix sandboxes the *rendering*; the declared type is kept as-is. Ingest only lowercases the essence via `normalize_content_type_case` — MIME matching is case-insensitive so this changes nothing about how any client renders the file; it exists solely so the case-sensitive Caddy layer below only needs to match one canonical casing. `storage::files::insert_content_type_headers` — the ONE function all three drust byte responders (`tenant_files::stream_bytes`, admin `/admin/files/{key}/bytes`, `signed_bytes::respond`) call — sends `Content-Security-Policy: sandbox allow-top-navigation-by-user-activation` (`SANDBOX_CSP`) whenever `is_unsafe_inline_type` flags the stored type. Bare `sandbox` gives the document a unique opaque origin and disables scripts/forms/popups; `allow-top-navigation-by-user-activation` restores plain hyperlink clicks without re-enabling anything script-driven — the same technique GitHub uses for `raw.githubusercontent.com`.

> [!CAUTION]
> **`allow-same-origin` and `allow-scripts` must NEVER be added to `SANDBOX_CSP`** — either one defeats the protection; a codified test pins the exact string. The classifier stays **structural, not an enumeration** — every `<type>/<subtype>+xml` essence is an XML document type to Blink/Gecko (the first version of this fix was broken by `application/rss+xml`). `nosniff` remains unconditional on every responder — the orthogonal defense against a browser sniffing a *different* declared-safe type back into HTML. **ANY new byte-responder path MUST call `insert_content_type_headers`.**

The Caddy `/public/*` block (which bypasses drust entirely, reverse-proxying straight to Garage) carries a matching `handle_response` matcher keyed off the upstream's own served `Content-Type` — never the request path's extension, which a caller sets independently of the declared type. Caddy 2.6.2's response-matcher allowlist has **no regex or case-insensitive option**, only a plain glob on `header`, so the matcher is a boundary-aware exact + prefix-with-`;` pair per essence (never a loose `text/html*`, which would also flag `text/html-ish`) and depends on drust's lowercase normalization above.

> [!WARNING]
> **Changing `is_unsafe_inline_type` obliges you to change the Caddy `@markup` matcher in the same breath**, and to verify it live rather than trusting `caddy adapt`. The matcher lives in `../garage/deploy/Caddyfile`; the `copy_response` rule that governs any edit to that block is in `.claude/rules/build-deploy.md`, which has the full outage story.

**Stored strings never reach a header via `.parse().unwrap()`** — tus takes `Upload-Metadata: filetype` as unvalidated free text, so `safe_header_value` degrades instead of panicking the responder.

## Provenance

Extracted from CLAUDE.md "Storage integration", "Per-tenant files", and the Mode B upload bullet during the 2026-08-02 restructure.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — CORS support on tenant routes (browser-direct fetch finally works)

- **Symptom prior to this fix**: a static frontend at e.g.
  `https://app.example.com` could not call `https://drust/t/<id>/records/...`
  via `fetch()`. The browser-issued `OPTIONS` preflight (which by spec
  omits `Authorization`) was rejected with `401 UNAUTHENTICATED` because
  `bearer_auth_layer` checks the bearer token unconditionally. With no
  preflight success the browser never sent the real request, forcing
  consumers to deploy a backend proxy (Cloudflare Functions, etc.) that
  just relays the call — defeating the BaaS value proposition.
- **Fix in `src/tenant/mod.rs`**:
  - New `DRUST_CORS_ORIGINS` env var (parsed in `src/config.rs`) — a
    comma-separated allow-list of full origins. Empty/unset = layer is
    not wired (status quo).
  - `build_cors_layer()` constructs a `tower_http::cors::CorsLayer` with
    `AllowOrigin::list(<parsed>)`, methods `GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD`,
    headers `Authorization, Content-Type, Accept`, max-age 600 s.
  - The layer is applied **outside** `bearer_auth_layer` (i.e. as the
    last `.layer(...)` call) so preflight is intercepted by tower_http
    before reaching auth. Real cross-origin GET/POST/etc. still flow
    through `bearer_auth_layer` unchanged; the response just gains the
    `Access-Control-Allow-Origin` header on the way out.
- **Why this is safe**: preflight returns no body and runs no business
  logic — even with auth skipped, attackers learn only "origin X is
  whitelisted." Disallowed origins still get a 200 but **without** the
  `Access-Control-Allow-Origin` header, so the browser blocks the real
  request client-side. The bearer token is never observed by the CORS
  layer because preflight never carries one.
- **Subdomain wildcard support** (added in same release): allow-list
  entries may now include a single `*` standing in for one variable
  segment — `https://*.tzuchi.org` matches every subdomain but rejects
  the bare apex (`https://tzuchi.org`); `http://localhost:*` matches
  any dev port. Multi-`*` patterns are rejected. Wildcard logic lives
  in `tenant::origin_matches` with unit tests covering suffix-injection
  attacks (`https://tzuchi.org.attacker.com`), hyphen-confusion
  (`https://attacker-tzuchi.org`), and scheme mismatch
  (`http://` vs pattern requiring `https://`).
- **Verified end-to-end** with curl against
  `OPTIONS /t/abc/records/posts`, 11 cases — all pass:
  - allow: `*.tzuchi.org`, `*.tzuchi.org.tw`, `*.tzuchi-org.tw`,
    multi-level subdomains, `localhost:*`
  - deny: `evil.com`, bare apex, suffix injection, hyphen confusion,
    scheme mismatch
  - `GET` without token → still 401 (auth boundary untouched) AND
    carries ACAO so client-side error handling works
- **Scope**: tenant routes only (`/t/<id>/...`). Admin UI routes
  (`/admin/*`) have no CORS layer because they're cookie-authenticated
  server-rendered HTML; cross-origin browser fetch makes no sense there.

### Changed — Admin UI collapsed from 3 pages to 2 (`_api_keys` virtual collection)

- **Before**: `/admin/tenants` (list) → `/admin/tenants/{id}` (detail with anon · service
  · MCP) → `/admin/tenants/{id}/collections/{name}` (data, 2-pane shell with
  collection sidebar). The detail page lived outside the shell, so once you
  drilled into data you couldn't get back to the keys without navigating away.
- **After**: `/admin/tenants` (list) → `/admin/tenants/{id}/<entry>` (2-pane
  shell). The old detail page is gone; `GET /admin/tenants/{id}` 302-redirects
  to `/admin/tenants/{id}/_api_keys`. Three sidebar entries are always present:
  - `🔑 _api_keys` — virtual, renders the anon + service key cards and the
    MCP setup card (formerly the standalone detail page). Driven by the new
    `tokens::api_keys_page` handler and `tenant_api_keys.html` template.
  - `🔒 _system_files` — was already a sidebar link, but the destination page
    (`tenant_files_admin.html`) used to be single-column. It now also uses
    `<div class="shell">{% include "_collection_sidebar.html" %}…</div>`, so
    you can switch back to `_api_keys` or another collection without losing
    the sidebar context.
  - Real collections from `sqlite_master`, ordered after the virtual rows.
- `tenant_detail.html` deleted. The MCP `claude mcp remove` line was also
  folded into a `<details>` so the register command is the visible default.
- Reroll-token handlers redirect to `/_api_keys` instead of the now-defunct
  detail URL.

### Added — Tenants index search box

- `tenants_list.html`: client-side filter (`<input type="search">`) on tenant
  name + id-prefix, with `/` to focus and `Esc` to clear. Live row counter
  updates inline (`12 / 100 rows`); a no-match row appears when the filter
  zeroes the table. Removed the misleading static `sort: id ↑` label.
- 100% template-side: no new SQL, no new endpoint. Designed for the 100+
  tenant scale we want to support without paginating.

### Fixed — Cards overflowing the right `.shell` track (clipped by `.macwin overflow:hidden`)

- Root cause: `.shell` used `grid-template-columns: var(--sidebar-w) 1fr`.
  A `1fr` track has `min-width: auto` (= min-content), so internal min-content
  (long bearer URLs, the schema-grid's 200 px columns, the 4-track toolbar
  `1fr 260px 200px auto`) widened the right track until cards visually
  protruded past the sidebar — and got clipped by `.macwin { overflow: hidden }`.
- Fix in `_styles.html`:
  - Track is now `minmax(0, 1fr)` so it can shrink below content
  - `.shell > .main { min-width: 0 }` propagates the shrink policy
  - `.shell .page { max-width: 100%; padding: 28px 28px 100px }` (drops the
    dead-code `.page-wide` 1400 px and tightens horizontal padding from 48 to 28)
  - `.shell .page > .card { max-width: 100%; min-width: 0 }`
  - `.shell .page .toolbar` rebuilt with `minmax(0, …)` tracks; reflows to a
    2-column grid below 1100 px viewport.

### Removed — Breadcrumbs across all admin pages; topbar path is now clickable

- The topbar `path` (`~/tenants/{id}/_api_keys`) already shows the same
  breadcrumb trail. Having both was redundant; the breadcrumbs took ~24 px
  of vertical real-estate per page for no signal.
- Stripped `<nav class="crumbs">` from `tenants_list.html`,
  `collections.html`, `collection_rows.html`, `files.html`,
  `tenant_files_admin.html`, `files_reconcile.html`.
- `_styles.html` adds `.prompt .path a` styling so the navigable segments in
  the topbar (e.g. `tenants` → `/admin/tenants`, `{id}` → `/_api_keys`) are
  visually link-like (dotted underline on hover) without losing the green
  accent colour of the path.

### Fixed — Claude Code rejected `tools/list` silently (16 tools never loaded)

- **Symptom**: `claude mcp list` showed `drust-<tenant>: ✓ Connected`,
  the MCP `initialize` handshake succeeded, the server's
  `serverInfo.instructions` block was injected into the system prompt
  (so the LLM "knew about" drust), but the 16 tool schemas never
  appeared in the tool registry. Neither mid-session nor fresh-session
  startup populated the tools — calling any drust tool failed with
  `InputValidationError`.
- **Root cause found in CC's own MCP log** at
  `~/.cache/claude-cli-nodejs/<project>/mcp-logs-drust-<tenant>/<ts>.jsonl`:
  ```json
  {"error": "Failed to fetch tools: [
    {\"path\": [\"tools\", 10, \"inputSchema\", \"properties\", \"data\"],
     \"message\": \"Invalid input\"},
    {\"path\": [\"tools\", 15, \"inputSchema\", \"properties\", \"data\"],
     \"message\": \"Invalid input\"}]"}
  ```
  Claude Code's zod validator rejected the entire 16-tool list because
  two tools (`insert_record` and `update_record`, alphabetical positions
  10 and 15) had a top-level `data: serde_json::Value` field. `schemars`
  emits that as the opaque schema `{"default": null}` with no `type`,
  which zod treats as invalid. The underlying JSON-RPC wire format is
  perfectly valid — this is a client-side strictness divergence.
- **Fix** in `src/mcp/handler.rs`:
  ```rust
  // Was: pub data: serde_json::Value
  pub data: std::collections::HashMap<String, serde_json::Value>,
  ```
  `schemars` now emits
  `{"type": "object", "additionalProperties": true}`, which zod accepts.
  The handler re-wraps into `Value::Object` before delegating to the
  existing `write_tools::{insert_record, update_record}` — no change in
  wire shape, no change in behaviour.
- **Scope note**: the same opaque-schema problem existed on
  `FieldSpec.default_value` (nested inside `create_collection`'s
  `fields`), but zod tolerates it at that deeper path. If future zod
  versions tighten, move `default_value` to a tagged enum
  (`{"literal": …}` / `{"sql": …}`) or override via
  `#[schemars(schema_with = …)]`.
- **Verified**: Claude Code picked up all 16 `mcp__drust-<tenant>__*`
  tools immediately after `systemctl restart drust`, **even mid-session**.
  The earlier assumption that mid-session `claude mcp add-json` never
  loads was wrong — it was always schema rejection masquerading as
  silent no-op.

### Changed — MCP tool parameter names unified to `collection`

- Collection-scoped tools previously split between `name: String`
  (`count_rows`, `describe_collection`, `drop_collection`, `sample_rows`)
  and `collection: String` (`add_field`, `delete_record`, `drop_field`,
  `insert_record`, `update_record`). An LLM with no cross-call memory
  would guess wrong roughly half the time and bounce off
  `missing field 'name'` / `missing field 'collection'`.
- All collection-scoped tools now take `collection`. `create_collection`
  keeps `name` — semantically correct (you are naming the new thing).
- `sample_rows.n` renamed to `limit` for consistency with
  `list_files.limit`. Default is still 20, clamp still 500.

### Fixed — `query` tool error messages (was "Query is not read-only")

- `src/mcp/tools/read.rs` collapsed every `ExecError` variant back into
  `rusqlite::Error::InvalidQuery` with `.map_err(|_| …)`. Its Display is
  hard-coded to `"Query is not read-only"` — which is semi-accurate for
  write attempts but **flatly wrong** for `SELECT FROM sqlite_master`
  (that IS read-only, just blocked by the authorizer for tenant
  isolation).
- Now each `ExecError` variant surfaces a specific message:
  - Authorizer-blocked write → `` `query` is read-only — use `insert_record` / `update_record` / `delete_record` for row writes, or `create_collection` / `drop_collection` / `add_field` / `drop_field` for schema changes (underlying: not authorized) ``
  - sqlite_master access → `` access to SQLite metadata tables is denied — use `list_collections` or `describe_collection` to inspect schema (underlying: …) ``
  - Other SQL / timeout / oversize errors preserve the underlying
    detail verbatim.
- `src/query/executor.rs::classify()` extended: drust's own authorizer
  surfaces its rejections with the word "prohibited" (not "authoriz"),
  and mentions `sqlite_master` / `sqlite_temp_master` / `sqlite_schema`
  by name. All of those now route to `ExecError::Forbidden`.

### Changed — MCP protocol upgrade (rmcp 0.4.1 → 1.5.0)

- **MCP protocol version**: advertises **2025-11-25** (was 2025-03-26).
  Claude Code 2.1.119's `/mcp` panel crashed against the old protocol
  because it parses responses with the newer schema shape; after the
  upgrade handshake negotiates cleanly.
- **Breaking changes absorbed** in `src/mcp/handler.rs`:
  - `Parameters` moved from `rmcp::handler::server::tool::Parameters`
    to `rmcp::handler::server::wrapper::Parameters`.
  - `ServerInfo` / `Implementation` are now `#[non_exhaustive]` — direct
    struct construction is rejected. Switched to builder form:
    `ServerInfo::new(caps).with_server_info(Implementation::new(name, ver)).with_instructions(...)`.
  - Do **not** use `Implementation::from_build_env()` — it reads rmcp's
    own `CARGO_PKG_NAME` ("rmcp"), not the calling crate's. Use
    `Implementation::new("drust", env!("CARGO_PKG_VERSION"))` explicitly.
  - `#[tool_handler]` no longer reads a `tool_router` field from the
    service struct — macro now calls `Self::tool_router()` directly.
    Removed the now-unused field + its initializer in `new()`.
- **Server-side verified end-to-end**: initialize / notifications/initialized
  / tools/list / tools/call all round-trip for protocol 2025-11-25.
  Session flow visible in `rmcp::transport::streamable_http_server::session::local`
  journal events.

### Changed — OAuth 2.0 Protected Resource Metadata reverted

- Briefly added an RFC 9728 metadata endpoint + `WWW-Authenticate`
  challenge header in an attempt to quiet Claude Code CLI's
  "SDK auth failed: HTTP 404" warning. Reverted after spec audit:
  - MCP 2025-06-18 §Authorization Server Discovery mandates
    `authorization_servers` contain **at least one** AS — an empty
    array (our bearer-only model) is non-compliant. The spec is
    explicitly "all OAuth 2.1 or nothing" — no Bearer-only path.
  - RFC 9728 §3 also requires the metadata URL to be formed by
    inserting `/.well-known/oauth-protected-resource` **between
    host and path**, which would have needed a Caddy rewrite since
    the drust mount is under `/drust/*`.
- Posture: drust does not implement MCP authorization per spec; it
  uses static Bearer tokens minted in the admin UI, passed via
  `headers` in the client's MCP config. The SDK's 404 warning on the
  well-known path is cosmetic and does not affect tool invocation.

### Fixed — `insert_record` / `update_record` error messages

- Unknown field or unknown collection returned
  `rusqlite::Error::InvalidQuery`, whose Display is hard-coded to
  the string **"Query is not read-only"** (it's the variant rusqlite
  uses for authorizer write-rejection). That bubbled up verbatim as
  the tool error, confusing LLM callers into thinking they'd hit the
  read-only authorizer instead of a schema mismatch.
- New `invalid_input(msg)` helper in `src/mcp/tools/write.rs` returns
  `rusqlite::Error::SqliteFailure(ffi::Error::new(1), Some(msg))` —
  its Display uses the custom message. Messages now read:
  - `unknown collection: 'foo'`
  - `unknown field 'tumor' for collection 'notes' (allowed: body, created_at, id, title, updated_at)`
- Same fix applied to `update_record`.

### Fixed — `sql_type` discoverability

- `type_to_sqlite` error message was `unsupported type: TEXT` — no
  hint about what was supported. Now:
  `unsupported sql_type: 'TEXT' (allowed: text, integer, real, boolean, datetime, json — all lowercase)`.
- `create_collection` and `add_field` tool descriptions now enumerate
  the allowed `sql_type` values, so MCP clients / LLMs learn the
  constraint from the schema up front instead of via trial-and-error.

### Changed — storage architecture reworked

- **Two buckets, host-wide**: `public` (website=on) and `private`. The old
  per-tenant bucket model (`tenant-<id>-pub` / `-prv`) and the Y-scope
  `admin-private` bucket are gone. Tenant ownership is encoded as a
  path prefix inside the shared bucket:
  - admin uploads live at bucket root: `<uuid>.<ext>` (unchanged — no
    migration of existing admin files needed).
  - tenant T uploads live under `<T-uuid>/<uuid>.<ext>`.
- **Caddy `/t-public/{tenant}/*` removed** — tenant public URLs are now
  `/public/<tenant>/<file>`, served by the existing `/public/*` proxy.
- **Tenant id is UUID v4** — the create form dropped the slug input.
  Display name is the only user-visible field; id is auto-generated.
- **Signed URLs are drust-minted** — admin / tenant `POST .../sign`
  endpoints return a drust-served URL (`/drust/s/admin/<key>?e=&t=&d=`
  or `/drust/s/t/<tenant>/<key>?…`) backed by an HMAC-SHA256 token over
  `(owner|key|expires|download)`. Secret is 32 random bytes generated
  at startup (in-memory; restart invalidates live URLs, acceptable
  because the default TTL is 1 hour). Replaces the previous
  S3-presigned URL that pointed at `127.0.0.1:47830` (LAN-only).
- **Caddy reverse-proxy reload** — `/etc/caddy/Caddyfile` lost the
  `/t-public/` block.
- **Admin UI modal replaces native alert/confirm/prompt** — new
  `_modal.html` partial + `drustUI.{alert,confirm,prompt}` globals,
  used by tenants list delete, admin + tenant files delete / sign URL,
  and the signed-URL result (with inline copy-to-clipboard icon).
- **Upload form UX** — `<fieldset>` + radio inputs replaced with
  pill-toggle segmented control (`.pill-toggle`). Cache-Control and
  custom metadata are REST/MCP-only now — hidden from the form;
  server defaults to `public, max-age=86400` (1 day) for public files,
  `private, no-store` for private, when the upload form doesn't specify.
- **Tenant detail page** — pagehead shows display name (no "Tenant:"
  prefix); breadcrumb home link reads "← home"; copy-id button exposes
  the full UUID. Collection pages follow the same pattern
  (`← back` + mono UUID in crumbs, pagehead shows collection name).
- **Tenant create recycles soft-deleted ids** — if the requested id
  collides with a soft-deleted tenant, drust hard-purges the old row +
  trash dir + tokens before INSERT.
- **Garage admin API `set_website` endpoint corrected** — old code tried
  `POST /v1/bucket/<id>/website` (404); new code uses
  `PUT /v1/bucket/<id>` with a `websiteAccess` sub-object. (Only
  relevant to bootstrap now.)
- **Bootstrap script**: creates `private` bucket (idempotent). Loads
  `garage/.env` then passes `GARAGE_RPC_SECRET` / `GARAGE_ADMIN_TOKEN`
  into the `sudo -u garage` invocation so it works without the caller
  sourcing .env manually. Guards `garage key create drust-client` so
  subsequent runs don't mint duplicate keys.

### Removed

- `src/mgmt/tenants::provision_storage_for_tenant` and matching
  compensating-rollback helpers (`rollback_local_tenant`,
  `soft_delete_storage_for_tenant`, `restore_storage_for_tenant`,
  `hard_delete_storage_for_tenant`).
- `storage::files::bucket_for_upload` now a thin compat shim — new
  code uses `bucket_for(vis)` + `compose_key(owner, id)`.
- Caddy `/t-public/{tenant}/*` block.
- UI chips: `ID is auto-generated (UUID v4)` hint, `2 fixed slots per tenant`,
  `service-key-only · streamable http · claude code` (shortened to
  just "claude code"), tenant-detail `#<short-id>` badge.

### Fixed

- Tenant UNIQUE constraint on soft-deleted id reuse.
- Admin sign URL previously leaked `http://127.0.0.1:47830/admin-private/...`
  — now returns `https://tool.tzuchi-org.tw/drust/s/admin/<key>?…`.
- "copy URL" action on private rows (both admin and tenant files pages)
  — hidden now, since the underlying URL required session / bearer
  auth. Private files only show "Sign URL" → issues a public, time-
  limited, drust-served URL via the HMAC route.

## [1.5.0] - 2026-04-23

### Added

- **Per-tenant Garage buckets** — creating a tenant now auto-provisions
  `tenant-<id>-pub` (website enabled) and `tenant-<id>-prv` (private)
  buckets, granted to `drust-client`. Rollback on failure is compensating.
- **New system table `_system_files`** in every tenant's `data.sqlite`
  (same shape as the admin-level `_system_files` in `meta.sqlite`). Drop-
  protected via `is_protected_collection()`.
- **Per-tenant file REST** at `/drust/t/<id>/files` — POST multipart
  upload / GET list / GET one / DELETE one / POST `<key>/sign` /
  GET `<key>/bytes`. All service-key-only.
- **Three new MCP tools**: `list_files` (pagination + visibility filter),
  `delete_file`, `get_file_url` (stable URL for public, pre-signed URL
  with TTL for private, optional `download=true` forces attachment).
  MCP deliberately has NO upload tool — instructions field directs the
  LLM to the REST endpoint.
- **Admin tenant-files UI** at `/drust/admin/tenants/<id>/files` — upload,
  delete, sign-URL parity with `/drust/admin/files`; files land in the
  tenant's own buckets.
- **Admin UI upload form simplified** — Cache-Control and custom metadata
  JSON moved to REST/MCP only. Server defaults cache-control to
  `public, max-age=86400` (1 day) for public, `private, no-store` for
  private, when the form doesn't specify.
- **Disk-usage banner** on `/admin/files`, `/admin/tenants`, and
  `/admin/tenants/<id>/files`. Uploads refuse with 507 when free disk
  drops below `DRUST_DISK_MIN_FREE_PCT` (default 20).
- **Reconcile page extensions** — `_trash_pending_revokes` and
  `_orphan_buckets` tables surface compensating failures from Garage
  access revokes (soft-delete) and bucket deletes (hard-delete).
- **Tenant ID validation tightened** — 1..=52 chars, `[a-z0-9-]+`, no
  reserved names (S3 bucket naming).
- **Garage bootstrap extension** — `admin-private` bucket created +
  granted to drust-client, idempotent. Needed for admin
  `visibility=private` uploads to the host-level files page.
- **Caddy `/t-public/<tenant>/*`** reverse-proxy — makes public files
  uploaded to `tenant-<id>-pub` reachable via stable URLs.
- **Copy MCP config** now emits both the `claude mcp add-json` command
  AND an `export DRUST_TOKEN=...` line + a curl example for shell-based
  file uploads.
- **New env var**: `DRUST_DISK_MIN_FREE_PCT` (default 20).

### Changed

- `_system_public_files` (admin-level metadata table) renamed to
  `_system_files` with new columns `visibility` (default `public`),
  `cache_control`, `meta_json`. Migration is idempotent on boot.
- `/drust/admin/public-files` → `/drust/admin/files` (308 redirect).
- MCP `instructions` field is now dynamic per-tenant and documents the
  REST upload endpoint + all 16 tools.
- Public-file default cache: `max-age=3600` → `max-age=86400`.
- MCP tool count: **13 → 16**.

### Fixed

- Clippy `-D warnings` clean across the crate (6 pre-existing issues
  from earlier phases + 3 new-code smells).

### Notes

- Phase 9 test helpers (`boot_with_mock_garage`) are not yet built;
  the plan's `tenant_files_mcp` integration tests are deferred —
  in-process unit coverage + live smoke-test is the current stand-in.

## [1.4.0] - 2026-04-21

### Added

- **Garage (S3-compatible) integration** (X+ scope per
  `docs/superpowers/specs/2026-04-21-garage-object-store-integration.md`).
  Optional, activated by setting `GARAGE_S3_ENDPOINT` in `.env`; drust
  without those env vars behaves exactly as before.
- **Admin UI at `/drust/admin/public-files`** — list + upload +
  delete + reconcile for the host-level public bucket. Anonymous reads
  are served by Caddy reverse-proxying `/public/*` straight to Garage's
  `s3_web` endpoint; drust is not in the read path.
- **System collection `_system_public_files`** in `meta.sqlite`
  (metadata for public bucket objects: key, original name, MIME, size,
  uploader, timestamps). Created idempotently on every boot.
- **`_system_*` prefix drop-protection** — a generic
  `is_protected_collection()` helper enforced by the `drop_collection`
  MCP tool. System collections cannot be dropped via the API.
- **Tenant list nav link** — the tenants page now has a `system /
  public files →` link for discoverability.
- **New env vars**: `GARAGE_S3_ENDPOINT`, `GARAGE_ADMIN_ENDPOINT`,
  `GARAGE_S3_ACCESS_KEY`, `GARAGE_S3_SECRET_KEY`, `GARAGE_ADMIN_TOKEN`,
  `GARAGE_PUBLIC_BUCKET` (default `public`), `GARAGE_MAX_UPLOAD_SIZE`
  (default 52428800 = 50 MB), `DRUST_PUBLIC_BASE_URL` (default
  `http://localhost:8793`).
- **New crate deps**: `object_store = "0.11"` (aws feature),
  `mime_guess = "2"`, `bytes = "1"`; `axum` gains the `multipart`
  feature.

### Architecture

- Garage and drust are two **independent** services communicating via
  the S3 protocol. drust is a Garage client; neither depends on the
  other for basic functionality. If Garage is unreachable, drust
  gracefully degrades (upload/delete return 503; the list page still
  renders from SQLite metadata). All other drust features —
  tenants, MCP, REST, auth — are unaffected.

### Notes

- Per-tenant bucket support is explicitly deferred to a future Y spec.
  This release only manages a single `public` bucket.
- The Garage service itself lives at `tool/garage/` (not versioned in
  this repo — see its `CLAUDE.md` for the service-level invariants).

## [1.3.1] - 2026-04-21

### Added
- **Favicon** — 16×16 LiveChonk (happy pose) as inline SVG, served via
  `data:image/svg+xml` URI from the new `_favicon.html` partial. Same
  pixel geometry as the canvas mascot elsewhere in the UI — black
  silhouette, green `^^` eyes, pink nose. Crisp at any size thanks to
  `shape-rendering="crispEdges"`.
- **Per-page `<meta name="description">`** on all five admin templates
  (login, tenants list, tenant detail, collections empty, collection
  rows). Descriptions are short (≤160 chars) and include dynamic
  fields where relevant (tenant id, collection name, row/field counts).
- **`<meta name="theme-color" content="#1a2327">`** on every page, so
  mobile browsers colour their chrome to match the terminal pane.

### Changed
- Each template's `<head>` now `{% include %}`s `_favicon.html` in
  addition to `_styles.html`; it's the canonical place for browser
  metadata that's independent of the visible body.

## [1.3.0] - 2026-04-21

### Added
- **Two new schema MCP tools — `drop_field` and `drop_collection`** —
  rounding out the schema-mutation surface (previous tools only grew
  schemas). Both are service-key-only (MCP is service-only by design)
  and both are irreversible.
  - `drop_field(collection, field)` → `ALTER TABLE … DROP COLUMN`.
    Rejects the three drust-maintained system columns (`id`,
    `created_at`, `updated_at`) up-front; SQLite itself rejects drops
    that would break a UNIQUE, index, FK, CHECK, trigger, or view.
  - `drop_collection(name)` → `DROP TABLE` plus the matching
    `_updated_at` trigger. Rejects the drop when any **other**
    collection still has a `foreign_key` column pointing at this one
    (caller must `drop_field` those columns first) — stops the
    destructive op from silently orphaning references.
  - Tool count on the per-tenant MCP server: **11 → 13**.
- `storage::schema::find_fk_referrers` helper that scans every user
  table's `PRAGMA foreign_key_list` for columns referencing a given
  target; used by `drop_collection` and available for future reuse.

### Changed
- Admin UI MCP card caption + `tenant_detail.html` now say "all 13
  drust tools" to match the new count.

## [1.2.2] - 2026-04-21

### Changed
- **Tenant detail: MCP setup now lives in its own card**, separate from
  the API keys card. The old `{ }` button + caption on the service-key
  row are gone; in their place, a new **"MCP server"** card directly
  below the keys shows:
  - The full `claude mcp add-json drust-<tenant> '{…}'` command, with
    the bearer token masked (first 16 chars shown) for visual confirmation.
  - A copy button that writes the unmasked command to the clipboard.
  - A footer hint mentioning the `drust-<tenant>` server name and the
    matching `claude mcp remove` teardown command.
- Legacy tenants (service key created before v1.1c, plaintext not stored)
  see a dedicated "reroll to enable" hint in the MCP card instead of a
  broken copy button.

## [1.2.1] - 2026-04-21

### Changed
- **Copy MCP config button now emits a `claude mcp add-json` command**
  instead of a `mcpServers` JSON block. The previous format required
  the admin to hand-edit a config file; the CLI form is one paste into
  a terminal. Shape:
  ```
  claude mcp add-json drust-<tenant-id> '{"type":"http","url":"https://<host>/drust/t/<tenant-id>/mcp","headers":{"Authorization":"Bearer drust_..."}}'
  ```
  Caption under the service-key card updated to match.

## [1.2.0] - 2026-04-21

### Added
- **LiveChonk pixel-cat mascot** — vanilla-JS port of the design-bundle
  `mascot.jsx`. 16×16 pixel silhouette with mouse-tracking eyes, natural
  blinking, and occasional ear twitch. Shipped as `_mascot.html` partial;
  auto-wires any `<canvas class="pix" data-chonk=... data-size=...>`.
  Present at 18 px in the topbar of every admin page, 48 px on the login
  card, 96 px on empty states (tenants / collections / 0-records),
  and 56 px on the filter-parse-error alert.
- **Left-side collection sidebar** on the collection-detail page
  (`_collection_sidebar.html`). Lists every collection for the active
  tenant; current one highlighted with a 2 px accent border. Sidebar
  scroll is independent of main-content scroll.

### Changed
- All admin pages now render inside a viewport-fixed `.macwin` shell;
  internal scroll is container-scoped (the `body` no longer scrolls).
- `/admin/tenants/{id}/collections` 302-redirects to the first
  collection when the tenant has any; empty tenants land on a dedicated
  empty-state page. The old "here's a table of all collections" view
  is gone.
- Collection-detail breadcrumb simplified from
  `drust / {tenant} / collections / {coll}` to `drust / {tenant}` —
  the collection name lives in the page title and sidebar active state.
- Login page now renders inside the `.macwin` frame (previously used
  a bare `.auth-wrap`), matching every other admin page.

## [1.1.1] - 2026-04-21

### Added
- **"Copy MCP config" button on the tenant-detail page.** Next to the
  service-key card (anon cards don't get the button — MCP is
  service-only anyway), a `{ }` icon emits a ready-to-paste
  `mcpServers` JSON snippet into the clipboard. The URL uses
  `window.location.origin`, so the copied config matches whatever
  public hostname the admin reached the page on — no backend-side
  URL template is needed. Shape:
  ```json
  { "mcpServers": { "drust-<tenant-id>": {
    "type": "http",
    "url": "https://<host>/drust/t/<tenant-id>/mcp",
    "headers": { "Authorization": "Bearer drust_..." }
  } } }
  ```
- A short explanatory line under the service key card points AI-client
  users at this flow. `_icons.html` gains `#i-braces` (Lucide "braces").
- **rmcp Streamable HTTP transport wired up at `/t/:tenant/mcp`.** Each
  tenant is now a self-contained MCP server exposing all 11 drust
  tools (list_collections / describe_collection / sample_rows /
  count_rows / query / explain / insert_record / update_record /
  delete_record / create_collection / add_field). Closes the v0.1.0
  Known issue "rmcp HTTP endpoint at `/t/:tenant/mcp` is deferred".
  MCP sessions are bound to one tenant via a per-tenant
  `StreamableHttpService` in `src/mcp/http_registry.rs`
  (`DashMap<TenantId, Arc<StreamableHttpService<DrustMcpService>>>`);
  the factory closure captures the tenant's `DrustMcp` state per
  session. `rmcp::transport::streamable_http_server::LocalSessionManager`
  handles session IDs in-memory.
- **MCP is service-key-only.** Anon keys calling `/t/:tenant/mcp`
  get `403 WRITE_DENIED`. Rationale: MCP clients are AI agents
  needing full CRUD; anon keys are for read-only REST consumers,
  and a per-tool role gate inside the rmcp handler would be brittle.
  Read-only MCP can be added later if demand materialises.
- `src/mcp/handler.rs` — `DrustMcpService` with `#[tool_router]` +
  11 `#[tool]` methods that thin-wrap the existing
  `src/mcp/tools/*` async functions, adapting
  `anyhow::Result<Value>` into `Result<CallToolResult, McpError>`.
- `src/tenant/mcp_dispatch.rs` — axum handler that runs after
  `bearer_auth_layer` (so auth + rate-limit + audit automatically
  cover `/mcp` traffic), extracts the tenant, looks up the service,
  and delegates via `tower::ServiceExt::oneshot`.
- Four integration tests in `tests/mcp_protocol.rs`: full
  initialize → tools/list handshake asserting all 11 tool names are
  registered; `tools/call list_collections` roundtrip verifying the
  real underlying function is invoked; anon-bearer rejection;
  missing-bearer rejection.
- `FieldSpec` gained a `schemars::JsonSchema` derive so it can appear
  in MCP tool input schemas (`create_collection.fields`, `add_field.field`).

### Changed
- `Cargo.toml`: add `schemars = "1"` and `tower = { version = "0.5",
  features = ["util"] }` (the latter for `ServiceExt::oneshot` in
  the dispatch handler). rmcp features unchanged — `transport-worker`
  is still required (rmcp's server streamable-HTTP module depends
  on it internally despite the name).
- `TenantStack` gains an `mcp: Arc<McpHttpRegistry>` field; four test
  helpers updated to construct one via `helpers::test_mcp_http`.

- **Schema fields may now declare a foreign key to another collection.**
  `FieldSpec` gains an optional `foreign_key: String` naming the target
  collection; all collections' `id` is the implicit referenced column.
  Emits inline `REFERENCES "<target>"("id") ON DELETE RESTRICT`. The
  target must already exist at DDL time (pre-checked with a clear error
  rather than SQLite's cryptic "no such table"); self-references inside
  a `create_collection` call are permitted because the table exists by
  the time the FK is resolved. Closes the v1 limitation "`foreign_key`
  also deferred to v1.1" from the design spec's schema section.
- `describe_collection` now reports each field's `foreign_key` target
  (sourced from `PRAGMA foreign_key_list`), exposed in MCP and REST
  schema responses. Omitted when null so existing consumers do not
  see a new key on non-FK fields.
- Four new integration tests in `tests/mcp_write_schema.rs`: describe
  surfaces FK target, missing target rejected pre-DDL, FK enforced
  on insert of orphan child, `ON DELETE RESTRICT` blocks parent
  delete while children reference it.
- **Field `default_value` may now be an allowlisted SQL expression.**
  Previously `default_value` was restricted to JSON scalars (null, bool,
  number, string — rendered as a quoted literal). It now also accepts
  `{"sql": "<expression>"}` where `<expression>` is exact-matched
  against `SQL_DEFAULT_ALLOWLIST` in `src/mcp/tools/schema.rs`. The
  initial allowlist: `datetime('now')`, `date('now')`, `time('now')`,
  `CURRENT_TIMESTAMP`, `CURRENT_DATE`, `CURRENT_TIME`. Non-allowlisted
  SQL is rejected with a clear error. Closes the v1 limitation spec
  §schema noted as "deferred to v1.1 because they require
  authorizer-aware validation" — in practice a tight allowlist is both
  safer and simpler than parsing.
- **Audit log is now written on every tenant-data-plane request.**
  Each request produces one JSONL entry in
  `/var/log/drust/audit-YYYY-MM-DD.jsonl` (path from `DRUST_LOG_DIR`)
  with: `ts`, `tenant`, `token_hint`, `op` (e.g. `"GET /records/posts"`
  with the `/t/{tenant}` prefix stripped), `duration_ms`, `status`
  (`ok` / `error`), and on error an `error_code` of the form
  `HTTP_{status}`. The append is dispatched via `tokio::spawn` so it
  does not block the response. Was flagged as a Known issue in the
  v0.1.0 CHANGELOG.
- `tests/audit_middleware.rs` — three integration tests: success
  entries, error entries for missing bearer, and `/t/{tenant}` prefix
  stripping in `op`.
- **Per-token rate limit is now enforced on the tenant data plane.**
  The `RateLimiter` in `src/safety/rate_limit.rs` previously had passing
  unit tests but was never wired into the HTTP stack; it is now checked
  inline at the top of `bearer_auth_layer`, keyed on the bearer's
  SHA-256 hash. Exceeded requests respond `429 Too Many Requests` with
  `error_code: "RATE_LIMITED"` and a `Retry-After` header. The check
  runs *before* the meta.sqlite token lookup, so an attacker hammering
  with invalid bearers is also bounded.
- `tests/rate_limit_middleware.rs` — three integration tests:
  budgeted burst denial, independent buckets per token, bounding
  unauthenticated request floods.

### Changed
- `TenantAuthState` gains a `limiter: Arc<RateLimiter>` field and an
  `audit: Arc<AuditLog>` field. All construction sites (main.rs +
  four test setups) updated. Runtime rate-limit budget / window read
  from `DRUST_RATE_LIMIT_PER_TOKEN` (default 60) /
  `DRUST_RATE_LIMIT_WINDOW_SECS` (default 10s); audit log directory
  from `DRUST_LOG_DIR` — both were already being parsed by `Config`
  but had no effect.

- **`set_admin_password` CLI** (`src/bin/set_admin_password.rs`) —
  rotates an admin's `password_hash` in `meta.sqlite` via drust's own
  argon2id hasher. Username from argv, password from stdin (so it does
  not appear in `ps`/argv). Fills a gap: `bootstrap_admin` only seeds
  when `admins` is empty, and there was no other change-password path.
  Run as the `drust` user:
  ```bash
  sudo -u drust bash -c \
    'read -s P && DRUST_DATA_DIR=/var/lib/drust \
      ./target/release/set_admin_password admin <<< "$P"'
  ```

## [1.1.0] - 2026-04-21

### Added
- **Reveal / copy / reroll API keys inline on the tenant detail page**
  (v1.1c). Tokens are now stored both as a SHA-256 hash (auth path —
  unchanged) and as plaintext (display path — admin UI only). Each key
  card shows the masked key with an eye toggle, a copy-to-clipboard
  button, and a reroll button. Replaces the prior post-reroll
  query-string banner.
- **`tokens.plaintext TEXT` column** (idempotent migration at startup).
  Tokens created before v1.1c have `NULL` here; their card shows
  `key not stored — created before v1.1c` and offers reroll to
  regenerate a stored key.
- **`api_key_card` askama macro** in `tenant_detail.html` —
  `{% macro api_key_card(role, chip_class, scopes, info, tenant_id) %}`,
  called once per role. Replaces ~90 lines of near-duplicate anon /
  service markup with a single component used twice.
- **`anon` / `service` role split on bearer tokens** (Supabase-style).
  `service` is the full-power credential (current behaviour, unchanged).
  `anon` is read-only: list / get / filter / subscribe / `POST /query` work,
  but `POST/PATCH/DELETE` on records return `403 WRITE_DENIED`. No RLS —
  per-row policy is deliberately out of scope for v1.1a.
- **2-slot fixed-key model with reroll** (v1.1b). Each tenant has exactly
  one anon slot and one service slot. Tokens cannot be issued ad-hoc; they
  can only be **rerolled**, which atomically revokes the current active
  token(s) of that role and issues a new one. Old plaintext stops working
  immediately.
- `POST /drust/admin/api/tenants/{id}/tokens/{role}/reroll` — new endpoint.
  `{role}` is `anon` or `service`. On success: 201 with
  `{role, token, id, created_at, revoked_legacy_count}`. Token shown once.
- `POST /drust/admin/api/tenants` still returns an `initial_tokens` object
  with both an `anon` and a `service` key on creation. The legacy
  `initial_token` field is preserved and continues to be the `service` key.
- `CHANGELOG.md` (this file)
- `_icons.html` template partial with reusable SVG sprite block
- Integration tests: `tests/token_roles.rs` (7 tests),
  rewritten `tests/tokens_api.rs` (4 reroll tests)

### Changed
- Tenant detail page redesigned around a **2-card API-keys layout** — one
  card per role (anon / service), each with last-rotated timestamp +
  `↻ Reroll` action. Replaces the prior N-row tokens table + issue form +
  per-token revoke buttons.
- If a tenant has more than one active token of a given role (possible
  only for tenants created before v1.1a), the card shows a
  `{n} legacy key(s) still active` warning and a reroll cleans them all.

### Removed
- `POST /drust/admin/api/tenants/{id}/tokens` (arbitrary issuance) — the
  2-slot model forbids extra tokens; use reroll instead.
- `DELETE /drust/admin/api/tenants/{id}/tokens/{token_id}` (individual
  revoke) — reroll supersedes this for normal ops.
- `POST /drust/admin/tenants/{id}/tokens/new` form route and
  `.../tokens/{id}/revoke` form route and their HTML form markup.

### Changed
- Admin UI minimum text size raised to 18px for readability; layout
  reflowed proportionally
- Removed remaining Chinese strings — UI is now English-only
- Replaced emoji glyphs (📊, ⚠) with inline SVG icons (Lucide), bundled
  offline
- Topbar/auth-foot version string now sourced from `Cargo.toml` at compile
  time
- `meta.sqlite` migration: `tokens.role TEXT NOT NULL DEFAULT 'service'`
  column added idempotently at startup. Existing tokens gain the default
  `'service'` role — no manual migration required.
- New `ErrorCode::WriteDenied` variant (serialises as `WRITE_DENIED`)

## [0.1.0] - 2026-04-20

Initial production release.

### Added
- Multi-tenant management plane: session-authenticated admin UI, tenant CRUD,
  bearer-token issuance / revocation
- Per-tenant data plane:
  - REST CRUD with PocketBase-style URLs (`/t/{tenant}/records/{coll}/...`)
  - `POST /query` with `sqlite3_set_authorizer` whitelist for read-only SQL
  - `?filter=` URL parameter mapped through the same authorizer pipeline
  - SSE subscribe per `(tenant, collection)` for live record events
- 11 MCP tool functions: `list_collections`, `describe_collection`,
  `sample_rows`, `count_rows`, `query`, `explain`, `insert_record`,
  `update_record`, `delete_record`, `create_collection`, `add_field`
- Read-only data browser in admin UI with filter / sort / pagination /
  graceful error rendering
- Authentication primitives:
  - Argon2id admin password hashing
  - Bearer tokens stored as SHA-256 hex, constant-time compared with `subtle`
  - 7-day session cookies (`HttpOnly; Secure; SameSite=Strict; Path=/drust`)
- Storage layer:
  - One isolated `data.sqlite` file per tenant under `/var/lib/drust/tenants/`
  - WAL + memory-mapped I/O + 64 MB cache PRAGMAs applied per connection
  - Per-tenant connection pool: serialized writer + N-reader pool
  - Schema introspection via `sqlite_master` + `PRAGMA table_info`
  - Per-tenant quota checks (file size + row count)
- Operations:
  - Daily `drust-backup.timer` runs `VACUUM INTO` snapshots → tarball,
    30-day retention
  - Daily `drust-janitor.timer` prunes soft-deleted tenants from `_trash/`
    after 7 days
  - logrotate config for `/var/log/drust/*.jsonl`
- Deployment artefacts:
  - `deploy/drust.service` (sandboxed systemd unit)
  - `deploy/Caddyfile` snippet (with `header_up Host` for rmcp DNS-rebinding
    guard)
- Dark macOS Terminal aesthetic admin UI (Claude Design handoff):
  traffic-light window chrome, terminal-prompt topbar, monospace typography,
  terminal-green accent

### Known issues
- Per-token rate-limit middleware exists in `src/safety/rate_limit.rs` and
  passes its unit tests, but is not wired into the HTTP middleware stack
- Audit-log middleware likewise exists in `src/safety/audit.rs` but is not
  wired; no requests are currently being recorded to
  `/var/log/drust/audit-*.jsonl`
- rmcp HTTP endpoint at `/t/{tenant}/mcp` is deferred; the 11 MCP tool
  functions are exercised in-process by integration tests but are not yet
  reachable over HTTP

[Unreleased]: https://example.invalid/drust/compare/v1.5.0...HEAD
[1.5.0]: https://example.invalid/drust/compare/v1.4.0...v1.5.0
[1.4.0]: https://example.invalid/drust/compare/v1.3.1...v1.4.0
[1.3.1]: https://example.invalid/drust/compare/v1.3.0...v1.3.1
[1.3.0]: https://example.invalid/drust/compare/v1.2.2...v1.3.0
[1.2.2]: https://example.invalid/drust/compare/v1.2.1...v1.2.2
[1.2.1]: https://example.invalid/drust/compare/v1.2.0...v1.2.1
[1.2.0]: https://example.invalid/drust/compare/v1.1.1...v1.2.0
[1.1.1]: https://example.invalid/drust/compare/v1.1.0...v1.1.1
[1.1.0]: https://example.invalid/drust/compare/v0.1.0...v1.1.0
[0.1.0]: https://example.invalid/drust/releases/tag/v0.1.0

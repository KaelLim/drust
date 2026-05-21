# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Gap note (2026-05-21):** entries for v1.14 / v1.15 / v1.16 / v1.17.0 were not landed in this file at release time. The features are documented in [`drust/CLAUDE.md`](CLAUDE.md) and their respective spec/plan docs under `docs/superpowers/`. Backfill is open work.

## [1.19.2] — 2026-05-21

### Security
- **/records/* SQL injection bypass on owner_field**: a user-token holder on a collection with `owner_field` + `read_scope=own` could send `?filter=1=1) -- ` to comment out the auto-appended `AND "owner_field" = '<user_id>'` clause and read other users' rows. Reject with 400 `USER_FILTER_DENIED_ON_OWNER_SCOPED` when user + owner-scoped + filter|sort. Service/anon paths and non-owner-scoped user calls unchanged.
- **Admin login + admin OAuth callback now rate-limited per-IP** (5/min, LRU 4096-bucket) via `IpRateLimit`. Closes parallel-thread argon2 grind window — admin password is no longer susceptible to brute-force from a single IP.
- **Webhook SSRF defense**: reqwest client now refuses to follow redirects (`Policy::none()`); `check_url` resolves the registered host to all IPs and rejects if any falls in private/loopback/link-local ranges (RFC1918, 127/8, 169.254/16, IPv6 ::1 / fc00::/7 / fe80::/10). Dev-mode `http://localhost` carve-out preserved. Residual DNS-rebinding window (host resolves public at register, changes to private later) queued for v1.21.

### Plan
- [`docs/superpowers/plans/2026-05-21-drust-v1192-v120-patch.md`](docs/superpowers/plans/2026-05-21-drust-v1192-v120-patch.md) (combined v1.19.2 + v1.20 plan)

## [1.19.1] — 2026-05-21

### Fixed
- **Admin UI schema-row visual** — the schema tab head + body rendered 8 cells but the CSS grid only declared 7 tracks, causing header / body columns to desynchronize. Added the 8th track.
- **Schema cache invalidation** on every description write (MCP `set_*_description` + REST PUT description handlers) — was a latent gap; cache consumers don't read `.description` today but would silently see stale data once they did.
- **Admin UI description handlers** now block `_system_*` collections (403), check collection / field / index existence (404) before write, and route the JSON-blob read-modify-write through the per-tenant writer mutex so concurrent admin + MCP/REST writes can't lose updates.
- **`add_field`** now persists `FieldSpec.description` — was silently dropped (same shape as the bug `6132a89` closed for `create_collection`).
- **`drop_index`** runs `DROP INDEX` + `index_descriptions_json` cleanup in a single `with_writer` closure so a mid-cleanup failure can't orphan a JSON-blob key.
- **`create_collection_with_desc`** pre-validates every description (collection-level + per-field) before `CREATE TABLE`, eliminating the half-described-collection failure mode.
- **`read_field_descriptions` / `read_index_descriptions`** now parse JSON per-key — one bad value no longer wipes the whole map.
- **`get_schema_overview_handler`** now returns typed `json_error` on 500 instead of plain-string bodies, matching the rest of the file.

### Added
- **Internal `debug_assert!`** in `write_collection_description` / `write_field_description` / `write_index_description` so a future caller forgetting `check_description` surfaces immediately in dev/test.
- **Admin UI live UTF-8 byte counter** beside the description textarea (Blob().size); save button disables when over 2048 bytes.
- **Admin UI inline error banner** when a server-side validator failure redirects back with `?desc_error=<code>`.

### Tests
- `rest_set_description_user_denied` / `rest_set_field_description_user_denied`
- `rest_set_description_nul_returns_422`
- `rest_set_field_description_on_protected_returns_403` / `rest_set_index_description_on_protected_returns_403`
- `add_field_persists_field_description`
- `description_read_tests` (3 tests for partial-malformed JSON)
- New `tests/admin_description_write.rs` for the 3 admin POST routes

### Plan
- [`docs/superpowers/plans/2026-05-21-drust-v1191-patch.md`](docs/superpowers/plans/2026-05-21-drust-v1191-patch.md)

## [1.19.0] — 2026-05-21

### Added
- **Schema descriptions** for collections, fields, indexes, and RPCs (RPC was already there since v1.6; now surfaced uniformly).
- MCP tools `set_collection_description`, `set_field_description`, `set_index_description`, `get_schema_overview`.
- REST routes `PUT /t/<id>/collections/<c>/description`, `PUT /t/<id>/collections/<c>/fields/<f>/description`, `PUT /t/<id>/collections/<c>/indexes/<i>/description`, `GET /t/<id>/schema/overview`.
- `FieldSpec.description`, `CreateCollectionArgs.description`, `CreateIndexArgs.description` accepted at create time.
- Admin UI per-collection page: inline-editable description tile + Description column on fields + indexes tables.

### Changed
- `Collection`, `Field`, `IndexInfo`, `CollectionSchema` gain optional `description: Option<String>` with `skip_serializing_if = "Option::is_none"` — existing response payloads remain byte-identical when no description is set.

### Internal
- `_system_collection_meta` gains 3 columns via idempotent `add_column_if_missing` migration: `description`, `field_descriptions_json`, `index_descriptions_json`.
- New shared validator `check_description` (≤2048 bytes, no NUL, trim).
- `drop_index` now cleans the matching key from `index_descriptions_json`.

### Spec / Plan
- Spec: `docs/superpowers/specs/2026-05-21-drust-schema-description-design.md`
- Plan: `docs/superpowers/plans/2026-05-21-drust-schema-description.md`

## 1.17.2 - 2026-05-21

Patch release: admin UI polish round 2 — chart removal, tenant name everywhere, audit row format.

### Removed

- **Audit overview SVG chart grid** (v1.17.0 feature). The four server-side inline-SVG charts (requests-over-time / top error codes / latency distribution / top tenants) and their supporting CSS used the wrong design tokens (`--card-bg` / `--sans` / `--radius` / `--ok` / `--warn` / `--err` instead of drust's real `--surface` / `--font-sans` / `--mint` / `--danger`), falling back to GitHub-style cold-blue colors that clashed with drust's warm palette. User-decided removal. Deleted:
  - `src/mgmt/svg_charts.rs` (390 LOC SVG renderer)
  - `src/mgmt/templates/_audit_charts.html` (chart layout partial)
  - `tests/audit_chart_render.rs` (3 integration tests)
  - Chart compute helpers in `src/mgmt/audit.rs`: `adaptive_bucket_seconds`, `status_class`/`StatusClass`, `time_series_buckets`, `top_error_codes`, `latency_histogram`, `tenant_request_bars`, and the 13 lib tests covering them.
  - Chart-related view-model structs: `TimeBucket`, `ErrorCodeCount`, `LatencyHistogram`, `TenantBar`, `ChartCtx`.
  - 4 SVG-string fields on `BodyCtx` / `AuditHostPage` / `AuditTenantPage`.
  - Chart-grid / chart-card / chart-legend / legend-swatch CSS in `_styles.html`.

### Changed

- **Tenant name resolution on overview-tab tables.** `/admin/audit?tab=overview` Top tenants and Top slow ops tables now show the resolved `tenant_name` instead of the raw UUID. UUID surfaced via `title=` hover. Implementation: `TopTenant` gains a `tenant_name` field (populated by `build_body_ctx` after a `tenants` meta lookup; `aggregate()` itself leaves it blank because it doesn't carry the map); Top slow ops is rendered from a new parallel `top_slow_ops_view: Vec<AuditEntryView>` field on `BodyCtx`.
- **Tenant name in 4 other surfaces:**
  - `backup_inspect.html` post-restore flash now shows tenant name (lookup from the snapshot's own tenant list). `RestoreFlash` gains a `tenant_name` field.
  - `collections.html` (empty-tenant page) title + meta + breadcrumb now show name. `CollectionsPage` gains `tenant_name`; handler calls `tenant_name_lookup`.
  - `files_reconcile.html` pending-revokes row now shows tenant name. `PendingRevokeRow` gains `tenant_name`; the underlying SQL does a `LEFT JOIN tenants` so soft-deleted rows still surface (name comes back NULL → falls back to id in the row builder).
  - `tenant_api_keys.html` sub-header changes "Tenant <code>id</code>" to "Tenant <b>name</b> <code>id</code>" (name primary, id secondary).
- **Audit timeline timestamp format.** Browse-tab row + Top slow ops cell now show `MM-DD HH:MM:SS` (15 chars) instead of the full RFC3339 string (24 chars). Implemented as a new `ts_display: String` field on `AuditEntryView` populated by `format_ts_display()`. Raw RFC3339 still surfaces on hover via `title=`.
- **Audit timeline grid + body wrapping.** `.tl-row` time column widened 78px → 104px to fit the new format with margin. `align-items: center` → `align-items: baseline` so wrapped body content (pill + op + error_code) lines up cleanly on its first row instead of vertically centering the variable-height block. `.tl-row .tl-body` switched from `display:inline-flex` to `display:flex` with explicit `line-height: 1.6` for predictable multi-line spacing.

### Internal

- `format_ts_display(ts: &str) -> String` helper in `src/mgmt/audit.rs` (chrono parse + format, falls back to raw on parse error).
- Kept `mk_entry_with_code` test helper (marked `#[allow(dead_code)]` for now — its callers were the deleted chart tests; reused only if a future test needs the `error_code` injection shape).

### Out of scope (deferred)

- Other admin pages where tenant id is shown but intentionally labeled as identifier (`tenant_overview.html` "Tenant id <code>...</code>", `_collection_sidebar.html` plane pill id-under-name, code-style URL examples) — kept as id since the operational context makes id the right choice.
- CHANGELOG backfill for v1.14 / v1.15 / v1.16 / v1.17.0 — see gap note above.

## 1.17.1 - 2026-05-21

Patch release: admin UI refresh + `X-Drust-Version` response header. No schema or public API change.

### Added

- **`X-Drust-Version` response header** on every reply (`tower_http::set_header::SetResponseHeaderLayer::if_not_present`). drust-js SDK reads this on first request to detect server version + warn on mismatch.
- **Audit log row → modal detail**: `/admin/audit` (host) and `/admin/tenants/<id>/_logs` (per-tenant) browse-tab rows are now click-to-open. Replaces the inline `<details>` expansion with `drustUI.detail({title, fields, actions?})` reading from an embedded `<script id="audit-entries" type="application/json">` blob. Keyboard parity: row carries `tabindex="0"` + `role="button"`; Enter/Space opens the modal.
- **Audit toolbar `<datalist>` dropdowns**: tenant filter (host scope only) reads from `meta.sqlite.tenants WHERE deleted_at IS NULL`; op filter reads from the window's distinct `op` values (capped at 200 via `BTreeSet`). Replaces opaque text inputs. Native HTML5 — zero JS framework dependency.
- **Audit row tenant pill** shows resolved `tenant_name` instead of UUID. Full UUID still surfaced via `title=` hover and inside the modal detail view. Pill carries `onclick="event.stopPropagation()"` so clicking it navigates without also opening the modal.
- **6 new lucide-style icon symbols** in `_icons.html` (`#i-download` / `#i-trash` / `#i-search` / `#i-external-link` / `#i-info` / `#i-x`).
- **`drustUI.detail({title, fields, actions?})` API** in `_modal.html`. Reuses the existing modal overlay. Renders `<dl class="modal-detail-grid">` from `fields[]`. Uses `textContent` everywhere — XSS-safe by construction.
- **`/admin/tenants` search input** wrapped in `.input-with-icon` with a leading `#i-search` SVG. Placeholder simplified to `"search…"`; full hint moved to `title=`.
- **`/admin/tenants` row actions** (`copy id` + `Delete`) get leading `#i-copy` + `#i-trash` icons. `copy id` click-feedback now swaps the SVG `<use href>` from `#i-copy` → `#i-check` and updates only the `.label` span, instead of nuking the whole button via `textContent`.
- **`/admin/backups` row actions** (`Inspect` + `Download`) get leading `#i-eye` + `#i-download` icons.

### Fixed

- **`/admin/backups` DB glyph rendered solid black** because the inline `<svg>` was missing `fill="none" stroke="currentColor"`. Switched to `<use href="#i-db"/>` (the existing symbol has correct attrs); the existing `.bk-glyph { color: var(--accent) }` rule now paints it.
- **XSS via `</script>` in audit op string**: the embedded JSON blob in `/admin/audit?tab=browse` is wrapped in `<script type="application/json">`. HTML5 §8.2.6.4 terminates the `<script>` element at any literal `</script>` token regardless of `type=`. `serde_json` does not escape `</` by default. Applied the canonical `</` → `<\/` swap on the serialized payload (RFC 8259 §7 legal; `JSON.parse` round-trips identically). Caught by code-quality review on the v1.17.1 admin-UI commit series.

### Internal

- `AuditEntryView` view-model in `src/mgmt/audit.rs` — wire-only projection of `AuditEntry` with non-flattened `extra` (so page-side JS sees `e.extra` as a nested object) and a derived `tenant_name`. The underlying `AuditEntry` retains `#[serde(flatten)]` on `extra` for the JSONL persistence shape.
- `build_tenant_name_map` / `resolve_tenant_name` / `distinct_ops_capped` / `tenant_summaries` helpers added to `src/mgmt/audit.rs`. `build_body_ctx` now takes a `&rusqlite::Connection` so the helpers can run against the same meta connection.
- Stale assertion in `tests/audit_ui_routes.rs::browse_admin_plane_row_shows_admin_text_not_broken_link` updated (the old inline `<details>` markup it asserted against was removed). +6 new integration tests covering datalist presence/absence, `data-idx` attribute, JSON blob, and the tenant-name pill.

### Out of scope (deferred)

- Action-button icons on other admin pages (`_api_keys` / `_system_files` / collection studio / `_oauth_providers` / `_webhooks`) — kept text-only this round; future polish pass.
- Audit overview tab unchanged — the four server-side SVG charts (v1.17.0) stay as-is.
- Backups row `Restore` / `Delete` actions — not surfaced in the current template (restore is reached via the inspect page; delete is automatic 30-day retention). Out of UI-refresh scope.

Spec: [`../docs/superpowers/specs/2026-05-20-drust-admin-ui-refresh-design.md`](../docs/superpowers/specs/2026-05-20-drust-admin-ui-refresh-design.md). Plan: [`../docs/superpowers/plans/2026-05-20-drust-admin-ui-refresh.md`](../docs/superpowers/plans/2026-05-20-drust-admin-ui-refresh.md).

## 1.13.0 - 2026-05-16

Minor release: outbound webhooks for record CRUD events.

### Added

- New per-tenant `_system_webhooks` table (idempotent migration; fresh tenants get it via `SCHEMA_SQL`): `collection`, `events` (JSON subset of `["created","updated","deleted"]`), `url` (`https://` only, with `http://localhost` dev exception), `secret` (drust-generated 32-byte hex), `active`, `last_failure_at`, `last_failure_reason`.
- `WebhookDispatcher` in `src/tenant/webhook_dispatcher.rs`: hooks every record-CRUD `EventBus::publish` call site (3 in `records.rs`, 3 in `mcp/tools/write.rs`); fans out one `tokio::spawn` per matching subscription; delivery does 4 inline attempts at +0s/+1s/+5s/+30s with 10s per-attempt timeout; classifies 5xx/network/timeout as retryable and 4xx as terminal; on full failure updates the webhook row's `last_failure_at` / `last_failure_reason`.
- HMAC-SHA256 body signing — `X-Drust-Signature: sha256=<hex>` header (GitHub convention). `X-Drust-Delivery-Id` (uuid v4) + `X-Drust-Timestamp` (RFC3339) headers also repeat in the JSON body so recipients can dedupe across retries.
- Service-only REST: `POST/GET/PATCH/DELETE /t/<id>/admin/webhooks[/<wid>]`. `POST` returns the plaintext secret exactly once; all other reads redact as `●●●●`. `PATCH` cannot rotate the secret (rotate = delete + create).
- Service-only MCP tools: `create_webhook` / `list_webhooks` / `update_webhook` / `delete_webhook`. Same redaction rule.
- Admin UI virtual sidebar entry `🔔 _webhooks` (7th virtual entry, after `_oauth_providers`). Page lists subscriptions with `last_failure_at` tooltip, inline create form, per-row delete button. Raw secret surfaced once via short-lived HttpOnly cookie + `Referrer-Policy: no-referrer` redirect (no query-param leak).

### Out of scope (deferred to v1.14+)

- Durable outbox + dedicated worker process (events fired while drust is crashed mid-POST are lost).
- Per-delivery audit-log rows (`webhook.delivered` / `webhook.failed`). Failure state is captured only in `_system_webhooks.last_failure_at` / `last_failure_reason`; the existing `tracing::warn!` on dispatch errors provides operational visibility.
- Wildcard collection / event subscription (`collection = "*"`).
- Non-CRUD event types (user-auth, DDL, file).
- `previous` (before) state on UPDATE / DELETE payloads.
- Auto-disable on consecutive failures + tenant-admin notification.
- Webhook replay UI (manual re-fire from audit row).

Spec: [`../docs/superpowers/specs/2026-05-15-drust-outbound-webhook-design.md`](../docs/superpowers/specs/2026-05-15-drust-outbound-webhook-design.md). Plan: [`../docs/superpowers/plans/2026-05-15-drust-outbound-webhook.md`](../docs/superpowers/plans/2026-05-15-drust-outbound-webhook.md).

## 1.12.3 - 2026-05-15

Patch release: fix MCP HTTP idle-timeout that forced Claude Code clients to manually `/mcp` reconnect every few minutes.

### Fixed

- `src/mcp/http_registry.rs` now sets `LocalSessionManager::session_config.keep_alive = 24h` (was rmcp default 5 min). Interactive MCP clients (Claude Code) idle for >5 min would otherwise hit `HTTP 404 Session not found` on the next tool call and have no auto-recovery; a 24h window covers a typical workday while still letting CC's daily restart cycle GC zombie sessions naturally.

## 1.12.2 - 2026-05-15

Patch release: auth-surface forensic hardening + doc drift fixes from the v1.9–v1.12 cross-version horizontal review. No schema or API changes.

### Fixed

- `POST /drust/login` now equalises argon2 timing on the unknown-username branch via `dummy_hash()`, mirroring the v1.9 tenant `/auth/login` invariant (S1). Closes the wall-clock admin-username-existence oracle.
- Admin audit UI no longer renders a broken `/admin/tenants/-/_logs` link for admin-plane rows (admin OAuth + admin password login). `tenant="-"` now displays as `"admin"` plain text.
- `drust/CLAUDE.md` virtual sidebar entry count corrected from three to six (`_api_keys`, `_rpc`, `_system_files`, `_system_users`, `_oauth_providers`, `_logs`).
- `docs/oauth-setup.md` per-tenant error table now lists `oauth_session_error` (5xx-class user-create / session-insert failure).
- `CHANGELOG.md` spec-link paths fixed to `../docs/superpowers/...` so they resolve from inside `drust/`.
- `src/auth/user.rs` timing-test docstring no longer says "Run with `cargo test --release`" — that's actively forbidden in this repo (LTO + 1 codegen-unit → 40+ min).

### Changed

- `register` / `login` / `oauth_callback` (tenant + admin) audit rows now carry `auth_kind` (`"user"` or `"admin"`) — the field was previously only injected by `bearer_auth_layer`, which these handlers run outside of. Failure rows carry the attempted kind so probing attempts surface in the same query.
- Password authentication flows now set the typed `auth_method = "password"` audit field, matching the OAuth flows' `auth_method = "oauth_google"` / `"oauth_github"`.
- Admin audit UI template now renders the typed `auth_method`, `oauth_email`, `oauth_error_code` fields plus the `extra` flatten map (`auth_user_id`, `index_name`, `redirect_uris_count`, etc.) — previously shipped to JSONL but invisible in the UI. Neutral metadata uses a new `audit-extras` CSS class so it doesn't inherit the error-red color of `audit-err`.

### Tests

- Admin login timing-spread test (`tests/admin_login_timing.rs`, `--ignored`).
- `extra.auth_kind` assertions on register / login / OAuth callback rows (tenant + admin).
- `entry.auth_method == "password"` assertions on password flows.
- Audit UI HTML-shape assertions for typed OAuth fields + extra map + admin tenant-link guard.

## 1.12.1 - 2026-05-15

Patch release: review-deferred follow-ups for v1.12 per-tenant OAuth. No schema or API changes.

### Fixed

- Admin DELETE / upsert on `_oauth_providers` against a nonexistent tenant_id no longer materialises an empty `tenants/<bogus>/data.sqlite`. New `ensure_tenant_exists` helper guards both paths before any `get_or_open` call.
- `_system_users.profile` for OAuth-auto-created rows now carries `picture` per spec §3.3 (extracted from Google `id_token.picture` and GitHub `/user.avatar_url`). v1.12.0 silently dropped this field.

### Changed

- Admin REST `PUT` / `DELETE` `/admin/oauth-providers` now attach `AuditExtra` (`{provider, redirect_uris_count}` on PUT, `{provider}` on DELETE) so the daily audit JSONL captures the mutation shape, matching the v1.9 admin-user-route precedent.
- `_oauth_providers` upsert validation failures now return specific `error_code`s (`INVALID_PROVIDER`, `INVALID_REDIRECT_URI`, `EMPTY_REDIRECT_URIS`, `INVALID_CLIENT_ID`, `INVALID_CLIENT_SECRET`) instead of the umbrella `INVALID_OAUTH_CONFIG`. Mirrored in the `set_oauth_provider` MCP tool.

### Tests

- `/me/password` rejects OAuth-only sentinel users with `409 OAUTH_ONLY_NO_PASSWORD` — symmetric to the existing login-rejection test.
- `/callback` rate-limit returns `429 rate_limited` after 5 requests in 60 s from the same `X-Forwarded-For[-2]` IP.
- Two concurrent OAuth callbacks for the same fresh email both succeed with distinct session tokens; exactly one `_system_users` row created (regression guard for the v1.12 T7-T9 fix-up).

## 1.12.0 - 2026-05-15

### Added — Per-tenant OAuth for end users (Google + GitHub)

- `/drust/t/<tid>/oauth/<provider>/{start,callback}` — end users sign in
  with a tenant's Google/GitHub app and receive a `drust_user_*` bearer
  token via URL fragment (Supabase / Auth0 pattern). The 10-step
  callback chain: provider config / state CSRF / PKCE / redirect_uri
  allowlist with TOCTOU re-check / token exchange / email_verified /
  `allow_self_register` gate / auto-link by email / auto-create with
  `password_hash="$oauth-only$"` sentinel / user-session create / audit /
  302 to frontend `<cb>#access_token=...&token_type=Bearer&expires_in=2592000`
  or `<cb>#error=<code>`.
- `_system_oauth_providers` per-tenant table (idempotent migration in
  `src/storage/sqlite.rs`; fresh-tenant schema in `SCHEMA_SQL` includes
  it from the start). Columns: `provider`, `client_id`, `client_secret`
  (plaintext at rest, mode-600 SQLite file), `allowed_redirect_uris`
  (comma-separated, exact-match validation), `created_at`, `updated_at`.
- Admin REST `GET/PUT/DELETE /drust/t/<tid>/admin/oauth-providers[/{provider}]`
  (service-key only; `client_secret` always redacted as `"***"` on GET;
  PUT validates provider name in `{google, github}`, URL scheme, length,
  allowlist non-empty + each entry parses as `https?://`).
- 3 MCP tools (service-key): `set_oauth_provider`, `list_oauth_providers`,
  `delete_oauth_provider` — mirror the REST shape 1:1.
- Admin UI virtual sidebar entry `🔐 _oauth_providers` per tenant at
  `/drust/admin/tenants/<id>/_oauth_providers` (Askama template, two-pane
  shell, secrets masked in the listing, single shared form for upsert).
- Sentinel `password_hash="$oauth-only$"` for OAuth-only users:
  `login_handler` returns `401 INVALID_CREDENTIALS` (same-timing dummy
  verify against `DUMMY_HASH`); `set_self_password` returns
  `409 OAUTH_ONLY_NO_PASSWORD`.
- Audit rows on every OAuth callback enriched with
  `auth_method=oauth_<provider>`, `oauth_email`, `oauth_error_code`,
  `auth_user_id` (on success). Failure rows carry the same fields with
  the corresponding error_code value.
- Per-IP rate-limit on `/callback` (5 events / 60 s, XFF[-2] resolution,
  reuses v1.9 `IpRateLimit`). `/start` is cheap, not throttled.
- `tests/tenant_oauth.rs` — 17 integration tests: happy paths (Google +
  GitHub), state/PKCE, invalid_redirect (at-start + TOCTOU at callback),
  provider error, email_unverified, not_allowed / auto_create / auto_link,
  sentinel-blocks-password, cross-tenant isolation (config + users),
  audit enrichment.
- `src/oauth/` library (v1.11 admin OAuth) reused unchanged.
  `TenantAuthState` gained
  `oauth_adapter_override: Arc<HashMap<String, Arc<dyn OauthProvider>>>`
  for test-only injection (empty `HashMap` in production).

### Compatibility

- Zero breaking changes; tenants without `_system_oauth_providers` rows
  behave exactly as v1.11. The migration runs once per tenant on first
  v1.12 boot.
- Existing password login + v1.9 user-auth flows unchanged.
- v1.11 admin OAuth unchanged.
- 230 tests passing (201 lib + 12 admin OAuth + 17 tenant OAuth).

### Manual smoke (release gate)

- Configure Google in tenant T1 admin UI → end user runs OAuth from a
  test frontend → token fragment lands at frontend → API call with
  `Authorization: Bearer drust_user_*` succeeds against `/me`.
- Same with GitHub.
- Audit row carries `tenant=<tid>`, `auth_method=oauth_google`,
  `oauth_email=<the_email>`, `auth_user_id=<uuid>`.
- Cross-tenant: T2's service key against `/t/<T1_id>/admin/oauth-providers`
  → 403.

## 1.11.1 - 2026-05-15

### Fixed — Production-only OAuth bugs caught in T29 manual smoke

- **Cookie `Path` matches Caddy prefix.** OAuth state + PKCE cookies were
  emitted with `Path=/admin`, but the browser sees the callback URL as
  `/drust/admin/oauth/<p>/callback` (Caddy `handle_path /drust/*` strips
  the prefix before forwarding to axum). Result: the browser refused to
  send the cookie on the callback → every login failed with
  `oauth_state_mismatch`. Fix: `Path=/drust/admin` in `src/oauth/state.rs`,
  with a unit-test regression guard
  (`oauth::state::tests::cookie_paths_match_caddy_prefix`).
- **Admin session cookie `SameSite=Lax`.** Was `Strict`, which breaks the
  OAuth callback redirect chain — browsers consider the whole
  `Google → drust callback → 302 to /drust/admin/tenants` chain
  cross-site-initiated, so the freshly-set Strict cookie isn't sent on
  the followup GET. Users bounced back to `/drust/login` despite the
  session being created in DB (3 audit rows confirmed). Lax is the
  industry-standard stance for session cookies; CSRF protection should
  come from CSRF tokens, not from `SameSite=Strict`. Fix in
  `src/auth/middleware.rs`, regression test
  `auth::middleware::ctx_tests::session_cookie_is_samesite_lax`.

### Why integration tests didn't catch these

`tests/admin_oauth.rs` uses `tower::ServiceExt::oneshot()` to drive the
axum Router directly, bypassing Caddy entirely. Cookie `Path` and
SameSite are browser-side enforcement; the test harness doesn't model
a browser. The two unit-test regression guards above pin the literal
attribute strings as the durable fix.

## 1.11.0 - 2026-05-15

### Added — Admin OAuth login (Google + GitHub)

- `/drust/login` accepts Google and GitHub OAuth in addition to
  username + password. Both providers gated by env config; buttons
  render only when both `CLIENT_ID` and `CLIENT_SECRET` of a provider
  are set (partial config logs `warn` and skips that provider).
- `admins.email` nullable column added (idempotent migration; partial
  unique index `idx_admins_email` enforces uniqueness when present).
  Use `set_admin_password --username <u> --email <addr>` to populate.
- Email allowlist enforced via `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS`
  (comma-separated, lowercased on parse). Email-verified flag from the
  provider is required; unverified emails return
  `oauth_email_unverified`.
- PKCE (RFC 7636 S256) + CSRF state cookie (constant-time compare via
  `subtle::ct_eq`); conformant to RFC 9700 (OAuth 2.0 Security BCP).
- New `src/oauth/` actor-agnostic library: `OauthProvider` trait +
  Google OIDC adapter + GitHub OAuth 2.0 adapter + `ProviderRegistry`
  driven from env. v1.12 per-tenant OAuth will plug into the same
  trait.
- Audit log gains `auth_method`, `oauth_email`, `oauth_error_code`
  fields on admin-login rows; `tenant` / `token_hint` are `"-"` for
  admin-plane rows.
- New `.env.example` annotated reference and `docs/oauth-setup.md`
  provider-registration walkthrough for self-hosters.
- 12 integration tests in `tests/admin_oauth.rs` cover the foundation
  (fake provider HTTP server) + 2 happy paths + 9 negative paths.

### Compatibility

- **Zero breaking changes.** Self-hosters not setting OAuth env vars
  see no UI or behavior change.
- Existing password login flow unchanged.
- No tenant-side impact.
- 186 lib tests + all integration tests pass.

### Manual smoke (release gate, T29 — owner sign-off)

- Google login → /drust/admin/tenants
- GitHub login → /drust/admin/tenants
- Password login still works on /drust/login
- `audit-*.jsonl` rows carry `auth_method = "oauth_<provider>"`

## 1.10.1 - 2026-05-14

### Fixed — Code-review follow-ups for v1.10 vector search

- **FilterAst depth cap** — `/search`'s `where` AST now refuses bool
  trees nested deeper than 32 levels. Returns
  `400 FILTER_TOO_DEEP`. Prevents stack exhaustion on a maliciously
  deep `{"and":[{"and":[…]}]}` payload that fits inside axum's
  default 2 MB body cap. `MAX_FILTER_DEPTH` lives in
  `src/query/vector_filter.rs`.
- **MCP integration tests for vector storage & search** — new
  `tests/mcp_vector.rs` (10 tests) pins the MCP-side codepath that
  v1.10.0 nearly shipped broken: insert/update vector encoding,
  default-hide vector column on response, dim mismatch typed error
  (`VECTOR_DIM_MISMATCH`), search top-k ordering, k/metric/filter
  guards, `FILTER_TOO_DEEP` rejection.

## 1.10.0 - 2026-05-13

### Added — Vector storage & similarity search (sqlite-vec)

Per-tenant vector storage as a first-class field type plus a
similarity-search endpoint, both REST and MCP. Built on `sqlite-vec`
statically linked alongside `rusqlite::bundled`. Brute-force scan
v1 — vec0 paired index deferred to vNext (non-breaking upgrade).

- **New `FieldSpec` type `vector(dim)`** — lowers to a SQLite BLOB
  column. Dim bounded 1..=4096. Declared on `create_collection` /
  `add_field` like any other field; persisted in
  `_system_collection_meta.vector_fields_json`.
- **Records CRUD encodes JSON arrays as packed-f32 BLOBs** —
  `[0.12, -0.04, …]` on the wire, exactly `dim * 4` byte BLOB at
  rest. Dim mismatch / NaN / Inf rejected at 422 with
  `VECTOR_DIM_MISMATCH` / `VECTOR_NON_FINITE` / `VECTOR_TYPE_ERROR`.
- **Vector fields default-hidden on read** — list / get / insert /
  update responses exclude vector columns. v1 has no opt-in
  mechanism (`fields=` deferred); vectors are retrieved via
  `/search`. Avoids ballooning list responses by ~1.5 KB per row
  × 384-dim.
- **New `POST /t/{tenant}/collections/{coll}/search`** — body:
  ```json
  { "field": "embedding", "vector": [...], "k": 10,
    "metric": "cosine|l2|l1",
    "where": <FilterAst>, "select": ["id", "title"] }
  ```
  Returns rows ordered by `_distance`. drust constructs all SQL
  from the structured Filter AST — no raw SQL accepted.
- **Filter AST** (`src/query/vector_filter.rs`) — tree of
  `and / or / not` over leaves `{field: scalar}` (eq shorthand) or
  `{field: {op: operand}}` with ops `eq|ne|gt|gte|lt|lte|like|in|nin`.
  Every operand binds as `?`. Vector fields cannot appear.
- **Auth**: anon needs `select` cap; user token with read_scope=own
  gets auto-appended `<owner_field> = :user_id` clause; service
  bypasses. **User tokens CAN call `/search`** even though they
  cannot call `/query` — drust constructs the SQL itself.
- **MCP `search_collection` tool** — same body shape, same compile
  + execute path. Service-only by transport.
- **Extension load**: `sqlite-vec` registered as a SQLite
  auto-extension (OnceLock-gated) before any tenant connection
  opens. Side benefit: stored RPCs and `/query` can call
  `vec_distance_*` with a service token.
- **Schema migration**: `migrate_tenant_db` adds
  `vector_fields_json TEXT NOT NULL DEFAULT '[]'` to
  `_system_collection_meta`. Idempotent.

Non-goals / deferred to vNext: vec0 paired indexes (ANN), embedding
generation, hybrid (FTS5 + vector) ranking, `hamming` metric (needs
bit-packed vectors), opt-in `fields=` to surface vectors on read,
per-user-token owner-scoped search integration tests.

Spec: `../docs/superpowers/specs/2026-05-13-drust-vector-search-design.md`.

## 1.9.0 - 2026-05-12

### Added — Per-tenant end-user authentication (registered users, sessions, owner-scoped rows)

Drust gains a real notion of "end user" on top of the existing anon /
service tokens. Tenants can register users, issue session-backed bearer
tokens, and scope rows per-user via a declarative `owner_field` —
without giving up the BaaS-shaped REST/MCP surface. Spec:
[`../docs/superpowers/specs/2026-05-09-drust-user-auth-design.md`](../docs/superpowers/specs/2026-05-09-drust-user-auth-design.md).

- **New per-tenant tables** (auto-migrated on startup, soft-delete safe):
  - `_system_users` — `(id, email UNIQUE NOCASE, password_hash, verified,
    profile JSON, created_at, updated_at)`. Password hashed with
    argon2id. Profile column stores arbitrary JSON; encoded
    idempotently so a client that stringifies the object on the wire
    still round-trips as a JSON object on read (legacy double-encoded
    rows are healed on the read path).
  - `_system_sessions` — `(token_hash, user_id, ip_at_login,
    user_agent, created_at, expires_at)`. Plaintext tokens prefixed
    `drust_user_`, SHA-256-hashed at rest; sliding 30-day expiry
    refreshed on each authenticated request.

- **Three-kind bearer resolution** in `bearer_auth_layer` — checks
  user-session table first (per-tenant), then falls through to the
  existing service / anon meta lookup. Result is exposed downstream as
  the new `AuthCtx` enum `{ Anon, Service, User { user_id,
  token_hash } }`, which DML/RPC/admin handlers branch on.

- **REST surface** (per tenant, mounted under `/drust/t/<id>/`):
  - `POST /auth/register` — gated by `tenants.allow_self_register` flag
    (default `0`); per-IP rate-limit 3/min on registration attempts.
  - `POST /auth/login` — uses argon2id + a fixed `DUMMY_HASH` to
    equalize timing across known/unknown email paths (S1). Per-IP
    rate-limit 5/min. Returns the plaintext session token once.
  - `POST /auth/logout` / `POST /auth/logout-all` — revoke the current
    token or all of the user's tokens.
  - `GET /me` / `PATCH /me` — read or update the caller's profile.
  - `POST /me/password` — rotate password; revokes all existing
    sessions and mints a fresh one.
  - `POST/DELETE /admin/users` + `GET/PATCH/DELETE /admin/users/<uid>`
    — service-only CRUD with cascade delete (drops owner-scoped rows
    from every collection that declares an `owner_field`, plus
    revokes the user's sessions) and an explicit revoke-sessions
    endpoint.

- **Per-collection row-level filter** (`owner_field` + `read_scope`):
  - `POST/DELETE /collections/<coll>/owner-field` — admin tool to bind
    a collection's row-ownership column. The setter validates the
    target field is `TEXT NOT NULL` and references `_system_users(id)`
    via FK before accepting; safe to set on populated tables only when
    every existing row already satisfies the FK.
  - `read_scope` per collection: `own` (default — user sees only rows
    where `owner_field = user_id`) or `all` (user sees everything,
    INSERT still overwrites `owner_field` with caller's `user_id`).
  - `UPDATE` / `DELETE` of a foreign row returns 404 (not 403), to
    avoid enumeration.
  - **Anon is denied** on owner-scoped collections regardless of
    `anon_caps`. Service tokens bypass the filter on read but must
    populate `owner_field` on INSERT (`409 OWNER_FIELD_REQUIRED`
    otherwise).
  - User tokens **fall through** to `anon_caps` on non-owner-scoped
    collections — they never escalate above what anon could do there.

- **User tokens denied on `/query`, `/query/explain`, `/mcp`** — drust
  doesn't rewrite user-supplied SQL, so the `owner_field` filter can't
  be enforced on those surfaces. Returns `403 QUERY_USER_DENIED` /
  `403 MCP_USER_DENIED`. For per-user SELECTs on owner-scoped data,
  use a stored RPC with `:user_id` (auto-bound from `AuthCtx`).

- **Stored RPCs accept user tokens** when `anon_callable = true`. When
  the RPC declares a `:user_id` parameter and the body omits it, drust
  auto-binds the calling user's id from `AuthCtx`. The RPC body itself
  is **not** subject to `owner_field` filtering — RPC author owns the
  filter (S4).

- **MCP tools** (9 new, MCP remains service-only):
  - `create_user`, `list_users`, `get_user`, `update_user`,
    `delete_user`, `revoke_user_sessions`
  - `set_owner_field`, `unset_owner_field`
  - `set_self_register`

- **Admin UI**:
  - Virtual sidebar entry `👤 _system_users` (slotted after `_rpc`,
    before real collections). `password_hash` column masked as `●●●●`
    in the rendered table.
  - `Allow self-register` checkbox on the `_api_keys` page toggles
    `tenants.allow_self_register`.

- **Audit-log enrichment** — every authenticated request now records
  `auth_kind` (`anon`/`service`/`user`) and, for user tokens,
  `auth_user_id`. Auth-endpoint rows additionally carry `email` and
  `ip_at_login` on login/register; admin user-delete rows carry
  `deleted_records` (per-collection cascade counts) and
  `revoked_sessions`. **Auth bodies are NEVER persisted** (S6 — the
  path-aware sanitizer strips `password`, `current_password`,
  `new_password` from request/response payloads on every auth route).

- **New janitor binary `drust_session_janitor`** — daily systemd timer
  sweeps expired `_system_sessions` rows with a 1-day grace window,
  per-tenant, soft-delete-aware. Replaces the would-be `_system_sessions`
  bloat without touching live writers.

### Security

- Bearer-token surface widens from `{anon, service}` to
  `{anon, service, user}`. User tokens are strictly weaker than anon
  on non-owner-scoped collections (they fall through to `anon_caps`)
  and strictly weaker than service on the management surface
  (`/admin/*`, `/query*`, `/mcp` all reject).
- `_system_users` and `_system_sessions` are drop-protected (same
  `is_protected_collection()` rule as `_system_files` etc.) and hidden
  at the SQL authorizer layer.
- argon2id at default OWASP-2023 parameters; rate-limit is global
  per-IP, computed from `XFF[-2]` to match the `.221 → :8793 → 127.0.0.1`
  two-hop chain (S3). Trusting just the right hop matters: trusting
  `XFF[-1]` would let any unauthenticated caller forge an IP by
  setting the header themselves.

### Fixed

- **Profile column asymmetry** (post-ship): MCP `create_user` with a
  JSON-object `profile` round-tripped fine, but a client that
  stringified the object on the wire ended up reading back a JSON
  string instead of an object. New `src/auth/profile.rs` encode/decode
  helpers normalize on write and unwrap one layer on read — idempotent
  on both shapes, heals legacy double-encoded rows.

## 1.8.0 - 2026-05-08

### Added — Per-collection indexes (MCP + REST + admin UI)

Tenants can now create and drop SQLite indexes on their collections —
single-field or composite, optional `UNIQUE`, with a large-table guard
to keep accidental DDL from stalling the writer mutex on big tables.

- **MCP tools** `create_index` + `drop_index`. Auto-names composite
  indexes as `idx_<coll>_<f1>_<f2>_...`; rejects unknown fields,
  duplicate field lists, and `_system_*` tables outright.
- **REST surface** `POST/DELETE /drust/t/<id>/collections/<coll>/indexes`
  (service-only) — same validation, same naming rules.
- **Admin UI** — Indexes section on every collection page, lists
  existing indexes + a create form (composite supported, unique
  checkbox). Uses the same admin-session token under the hood; no
  separate auth boundary.
- **`POST /drust/t/<id>/query/explain`** — anon-allowed (same SQL
  authorizer as `/query`), returns the `EXPLAIN QUERY PLAN` rows for
  a given SELECT. Surfaced as a textarea on the admin collection page
  so you can verify an index is actually picked up before relying on
  it.

### Added — Large-table guard for CREATE INDEX

- New env var `DRUST_INDEX_LARGE_TABLE_ROWS` (default `1_000_000`).
  `create_index` queries `count(*)` on the target collection first; if
  it exceeds the threshold and the caller didn't pass `force: true`,
  returns `409 LARGE_TABLE` with the row count in the error body.
  Plumbed end-to-end to all three surfaces (MCP / REST / admin UI).
- Audit-log entries for index DDL include `index_name`,
  `index_fields`, `row_count`, and `force_used` so you can later tell
  which big-table indexes were intentional.

### Added — Audit log extensibility

- `AuditEntry::with_extra` — op-specific keys flatten into the JSONL
  row instead of nesting under a generic `meta` field, so log readers
  (the on-disk renderer at `/admin/audit`, the per-tenant `_logs`
  page, downstream tooling) can grep by exact key without a JSON
  path.

### Changed

- **Authorizer** for `/records/<coll>` get-by-id path now consults
  `anon_caps` (was: missed; only the list / write paths did).
  `/records/_system_*` is blocked for both anon and service
  regardless of caps (404, not 403 — same shape as `/query`'s
  `_system_*` denial). The Schema-tab UI's anon_caps editor notes
  inline that the cap governs `/records/*` only, **not** `/query`.
- **MCP tool count: 21 → 23** (`create_index` + `drop_index`).

### Fixed

- **Soft-delete cache eviction** — `delete_tenant` now evicts the
  per-tenant pool, MCP service instance, and SSE broadcast bus
  before moving the directory to `_trash/`. Previously a quick
  re-create on the same tenant id would still see stale opened
  handles, including a writer connection holding a `wal` lock on
  the now-moved file.
- **Rate-limit bucket map** — bounded with a hard cap +
  background-task cleanup, so a long-running drust serving many
  distinct client IPs no longer grows the bucket map unboundedly.
- **Graceful shutdown** — main loop now waits for the audit-writer
  mpsc channel to drain on SIGTERM. Previously a fast restart could
  truncate the in-flight `audit-YYYY-MM-DD.jsonl` line.

## 1.7.3 - 2026-05-08

### Added

- **MCP tool `set_anon_caps`** — replaces the per-collection anon DML
  capability set (`["select","insert","update","delete"]` subset).
  Closes the gap where this was reachable only from the admin UI's
  Schema-tab editor; service tokens calling MCP can now toggle anon
  read/write per collection without the round-trip through a browser
  cookie session. Refuses `_system_*` collections (matches the
  protection on `drop_collection`), verifies the collection exists
  before writing, and invalidates the in-process schema cache so the
  next REST/MCP request through the tenant router sees the new gate
  immediately. Tests: round-trip with `describe_collection`, empty
  caps lock anon out, `_system_*` rejection, unknown-collection
  rejection.
- **MCP tool `whoami`** — returns the calling tenant's identity, both
  bearer tokens (anon + service) in **plaintext**, the relative
  REST/MCP/files/rpc endpoint paths, and the configured
  `max_upload_bytes`. Designed for the file-upload flow specifically:
  `POST /drust/t/<id>/files` (multipart) deliberately has no MCP tool
  because MCP can't carry binary payloads, so a model wired only to
  MCP previously had no way to construct the curl/HTTP call. `whoami`
  surfaces everything that call needs in one shot. MCP is service-only
  at the auth layer, so the caller already holds the service token —
  re-emitting it here doesn't widen the threat model.
- **Plumbing**: `DrustMcpInner` gains `meta: Option<Arc<Mutex<Connection>>>`
  + `max_upload_bytes: usize`. `McpRegistry::with_bus_and_storage`
  now takes both. The `McpRegistry::new` / `with_bus` test
  constructors leave `meta = None`; tools that require it (`whoami`)
  bail with `META_UNAVAILABLE` instead of panicking.

### Changed

- `storage::schema::DmlVerb` now derives `schemars::JsonSchema` so it
  can appear in MCP tool argument schemas directly (used by
  `set_anon_caps`).
- `tests/helpers.rs`: added missing `cors_origins: Vec::new()` to the
  `TenantStack` literal — pre-existing breakage from the v1.5.1 CORS
  field addition that only surfaced now because tests outside the
  `helpers.rs` mod weren't recompiling against it.

### Notes

Tokens minted before v1.1c stored only the hash, not the plaintext.
For those, `whoami.tokens.<role>.plaintext` is `null`; admin UI reroll
is the recovery path. Fresh tenants on v1.1c+ always have plaintext
populated.

## 1.7.2 - 2026-05-05

### Added

- **RPC test playground** at `/admin/tenants/{id}/_rpc/{name}/test`. The
  link from `tenant_rpc.html` was previously dead — this lights it up.
  Renders one input per declared param with type-aware coercion
  (`text` / `integer` / `real` / `boolean`), submits via POST to a
  `/test/run` route, and re-renders with: result table (column names +
  rows, with NULL formatting), execution `duration_ms`, the bound JSON
  body for confirmation, and `EXPLAIN QUERY PLAN <sql>` rows. Empty
  inputs surface as `null` so missing-required errors come from
  `validate_and_bind`, matching the live REST endpoint's behaviour.
  Implementation reuses `crate::query::executor::execute_read_query_with_named`
  and `crate::rpc::params::{validate_and_bind, BoundValue}` directly —
  no duplication of the gating logic. EXPLAIN is best-effort; failures
  there don't block the real run.
- **Backup snapshot inspection** at `/admin/backups/{filename}/inspect`.
  Streams the `.tar.zst` through `zstd::Decoder` → `tar::Archive` on a
  blocking thread (`tokio::task::spawn_blocking`), extracts only
  `meta.sqlite` to a `tempfile::NamedTempFile`, opens it read-only,
  and lists active tenants with each tenant's `data.sqlite` size in
  the archive. Tenants with no `data.sqlite` in the snapshot (created
  after the backup ran) render with an em dash and no restore button.
- **Backup tenant restore** at `POST /admin/backups/{filename}/restore`.
  Extracts `tenants/<id>/data.sqlite` (and `meta.json` if present) to
  `<data_dir>/_trash/<tid>-restored-<ts>/`. **Does NOT overwrite the
  live tenant directory** — admin must `mv` the file back manually
  after inspection. This protects against accidental clobber of work
  that post-dates the snapshot. Tenant id validated with a strict
  uuid-v4-shaped regex (36 chars, hex with hyphens at the canonical
  positions); anything else returns 400 before any FS access. PRG
  redirect carries a success flash to the inspect page on completion;
  partial extracts are cleaned up on failure.
- New deps: `tar = "0.4"`, `zstd = "0.13"`, `tempfile = "3"` (was
  dev-only). Three new unit tests for `parse_tenant_db_path`,
  `is_uuid_like`, and a full `extract_meta_and_sizes` round-trip
  building a synthetic `.tar.zst` in memory and asserting size
  recovery + `meta.sqlite` byte-for-byte.

## 1.7.1 - 2026-05-05

### Added

- **Backup snapshot UI** at `/admin/backups` — read-only list + per-file
  download (`Content-Type: application/zstd`, streamed via `tokio_util::io::ReaderStream`,
  no buffering). Enumerates `<data_dir>/backups/drust-*.tar.zst` (the
  output of `drust-backup.timer`), shows size + ISO mtime + relative age,
  newest first. Filename pattern is whitelisted (`drust-…tar.zst`,
  no path separators) so traversal attempts return 400 before any FS
  access. Topbar `backups` link added to `tenants_list.html`. Restore /
  inspect remain manual (`tar --zstd -xf …`) — guarded UI flow can land
  later. New dependency: `tokio-util = "0.7"` (io feature only).
- **Audit drill-down links** — in `_audit_body.html`, the `tenant`
  cell (Top tenants / Top slowest ops / Browse) and the `coll` cell now
  resolve to in-context destinations: tenant → `/admin/tenants/{id}/_logs`,
  collection → `/admin/tenants/{id}/collections/{coll}`. Drilling from
  host audit into a single tenant's audit is one click.
- **Per-row audit detail panel** — `<details>` expansion replaces the
  one-line `token_hint · duration_ms` summary with a full key/value
  block (every populated `AuditEntry` field, optional ones gated by
  `if let Some`). `error_message` renders in a red-tinted `<pre>` with
  wrap so multi-line stack traces stay readable. Styling lives in new
  `dl.audit-detail` rule in `_styles.html` — adding a new entry field
  is one `<dt>/<dd>` pair, no CSS changes.
- **Per-tenant disk breakdown** on tenants list — three numeric columns
  (`db` / `files` / **total**) replacing the old `db_size_kb` (`KB`-only)
  cell. All three pass through the new `humanize_bytes` helper (B / KB
  / MB / GB autoscale). Sorting still by name; future column-sort can
  build on the same struct fields.
- **`GarageClient::bucket_usage(name)`** — admin API wrapper returning
  `Option<BucketUsage { objects, bytes, multipart_orphan_objects,
  multipart_orphan_bytes }>` from `GET /v1/bucket?globalAlias=...`.
  Returns `Ok(None)` for 404 (matches `lookup_bucket` shape). No UI
  consumer yet — the per-tenant `tenant-<id>-{pub,prv}` buckets aren't
  provisioned on existing deployments. Hooking the host `/admin/files`
  card or the per-tenant `tenant_files_admin` page once buckets exist
  is one struct field + one template tweak.

### Changed

- **`tenant_name` in topbar paths**: `tenant_files_admin.html`,
  `tenant_rpc.html`, `tenant_rpc_form.html`, and `collection_rows.html`
  now show the tenant's display name in the macOS title bar and prompt
  path; URLs still carry the uuid. `RpcPage` / `RpcForm` / `RowsPage`
  gain a `tenant_name` field, and `rpc_admin.rs` / `browse.rs` look it
  up via meta.sqlite (failure → 404 with the same shape as the
  existence check). Reduces "which tenant am I in?" cognitive load
  noticeably on the per-tenant pages.
- **Audit table styling** — `top_tenants`, `top_slow_ops`, and Browse
  switched from `class="tbl"` (undefined, fell back to browser
  default) to the standard `class="data"` admin grid. Stat cards
  (Total / Errors / p50/p99 / Avg QPS) now share the new
  `.audit-stats` grid: equal-height by default, body fills card via
  `flex:1`, content vertically centered — eliminates the ragged
  bottoms when one card's content wraps.
- **Audit Browse pager** — replaced the one-off "next page →" link
  with the standard `.pager` / `.page-of` / `.pager-group` layout used
  by collection rows + admin files. Cursor pagination semantics
  unchanged (`before_ts` query param); only visual aligned.
- **`_rpc` list pagination** — `page` / `per_page` query params
  (default 20, options 20/50/100/200), `.pager` footer + per-page
  selector. Slices in Rust on top of `registry::list` so the SQL
  layer stays simple; large lists pay the full-list cost once per
  page hit, but `_system_rpc` per tenant is bounded so this is fine.
- **`_system_files` (tenant page) pagination** — proper `LIMIT/OFFSET`
  against `_system_files` plus a `COUNT(*) + COALESCE(SUM(size_bytes), 0)`
  for the header. Default 25/page, options 10/25/50/100. The previous
  unpaginated `ORDER BY uploaded_at DESC` is gone.
- **`.main` no longer sets `display: flex; flex-direction: column;`**
  — single `.page` child means normal block flow is equivalent. Drops
  one source of layout confusion across every admin page.

### Fixed

- The `_logs` page (tenant scope) used to render a `tenant` column that
  was redundant — every row had the same value. Hidden in tenant scope
  via `is_host_scope` gating on both Top slowest ops and the Browse
  table; colspan on the expand row drops to 6 in tenant scope.

## 1.7.0 - 2026-05-05

### Added

- **Admin audit log UI** — two new admin-session-protected GET routes
  surface the existing `audit-YYYY-MM-DD.jsonl` files via a stateless file
  scan:
  - `/admin/audit` — host-level overview across all tenants. Topbar
    `Audit` link added to existing host pages
    (`tenants_list.html`, `files.html`, `files_reconcile.html`,
    `tenant_docs.html`).
  - `/admin/tenants/{id}/_logs` — per-tenant scope, sidebar virtual entry
    `📋 _logs` alongside `_api_keys` / `_rpc` / `_system_files`.
  Both share `src/mgmt/audit.rs` (scan + parse + filter + aggregate).
  Page modes: Overview (totals, error rate, p50/p99, avg QPS, top
  tenants on host scope only, top slow ops) and Browse (paginated table
  with `<details>` row expansion, server-side filter by tenant/op/status,
  `before_ts` cursor pagination). Window is enum `1h | 24h | 7d`.
  `flate2` is the new dependency for reading rotated `*.jsonl.*.gz`
  archives.

### Changed

- `AuditEntry.status` changed from `&'static str` to `String` so the type
  derives `Deserialize` for the audit JSONL parser. Constructors
  (`success()` / `failure()`) updated accordingly; existing call sites
  in `src/tenant/router.rs` and `tests/audit_log.rs` go through the
  constructors and need no changes.
- `MgmtState` and `TenantsState` carry a new `log_dir: PathBuf` field
  (sourced from `cfg.log_dir` / `$DRUST_LOG_DIR`).

### Fixed

- `tests/mgmt_login.rs` and `tests/admin_files_routes.rs` were drifting
  fixtures missing `url_sign_secret` and `tenants` fields introduced in
  v1.5+ / v1.6+. Now compile and pass alongside the new audit suite.

### Notes

- No migration. Audit JSONL files are already produced by all prior
  releases; the new UI only adds a read path.
- `tests/tenant_files_rest.rs` remains broken pre-existing (separate
  fixture for `TenantFilesState`, missing `url_sign_secret`). Out of
  scope for this release; recommended as a separate housekeeping commit.

## 1.6.0 - 2026-04-30

### Added

- **Per-collection DML capability allowlist** — every collection's
  schema metadata gains an `anon_caps` field, a subset of
  `{select, insert, update, delete}`. Default `["select"]` (preserves
  the v1.5.x "anon = read-only" status quo); opt-in widening per
  collection lets anon callers run INSERT / UPDATE / DELETE without a
  backend wrapper. Service is unrestricted regardless. Persisted in a
  new per-tenant `_system_collection_meta` table (one row per
  collection); per-tenant `SchemaCache` (`src/storage/schema_cache.rs`)
  keeps the hot-path lookup hash-map fast. DDL paths
  (`create_collection` / `drop_collection` / `add_field` /
  `drop_field`) invalidate the cache and manage the meta row.
- **Stored RPCs (Supabase-style named SQL functions)** — new
  `_system_rpc` table per tenant + `src/rpc/` module
  (`params.rs` / `registry.rs` / `prepare.rs` / `handler.rs`).
  REST `POST /drust/t/<id>/rpc/<name>` (anon allowed per-RPC via the
  `anon_callable` flag); MCP tools `create_rpc`, `update_rpc`,
  `delete_rpc`, `list_rpc`, `call_rpc` (service-only at the
  MCP-dispatch layer regardless of `anon_callable` — that flag
  governs only the REST path). Counters (`anon_calls` /
  `service_calls` / `last_called_at`) bumped through the writer
  mutex regardless of caller role. SQL bodies validated at create /
  update time via `prepare()` under the read-only authorizer
  (rejects non-SELECT actions, `ATTACH`, `sqlite_master`, unknown
  tables).
- **Admin UI `_rpc` virtual sidebar entry** (⚡ icon, slotted between
  `_api_keys` and `_system_files`) — list / create / edit / delete
  workflow with prepare-time SQL validation. "Allow anon callers"
  checkbox carries a confirm modal.
- **Admin UI anon_caps editor on the Schema tab** — four checkboxes
  (select / insert / update / delete) POSTing to
  `/admin/tenants/<id>/collections/<coll>/anon-caps`; explicit empty
  array locks the collection privately.
- **`execute_read_query_with_named`** in `src/query/executor.rs` —
  query executor variant that binds rusqlite `:name` placeholders
  from a `BTreeMap<String, BoundValue>`, used by the RPC handler.

### Changed

- **Authorizer `Read` arm extended to deny any `_system_*` table**
  (was: only `sqlite_*`). Closes the SQL-layer hide for
  `_system_rpc` and `_system_collection_meta`. Both anon and service
  affected — these tables only ever yield to structured handlers.
- **REST DML write handlers** (`POST` / `PATCH` / `DELETE` on
  `/records/<coll>`) — role gate switched from `require_service`
  (always 403 anon, code `WRITE_DENIED`) to `require_dml_cap`
  (consults per-collection `anon_caps`). For legacy collections
  with no meta row, `default_anon_caps() = ["select"]` preserves the
  old behaviour — anon writes still 403 — but the error code is now
  `ANON_DENIED` with a per-verb / per-collection message.
- **MCP tool count: 16 → 21**. `instructions` field bumped
  accordingly.

### Security

- The "anon = read-only" guarantee is replaced with "anon = subset of
  DML defined per-collection in `anon_caps`, default `["select"]`".
  The default preserves existing-tenant behaviour. Application-layer
  identity / one-vote-per-user enforcement remains the consumer's
  responsibility — drust deliberately does not implement RLS.
- `_system_rpc` and `_system_collection_meta` are drop-protected via
  the existing `is_protected_collection()` `_system_` prefix rule and
  authorizer-hidden at the SQL layer for both anon and service. Access
  is only via structured REST/MCP handlers.

### Fixed

- **anon_caps editor form deserialization** — the Schema-tab form
  POSTs `caps=select&caps=insert&...` (one repeated key per checked
  checkbox), but `update_anon_caps` was wired to `axum::Form` which
  uses `serde_urlencoded` and cannot collect repeated keys into
  `Vec<String>` (returns `422 Unprocessable Entity: invalid type:
  string "select", expected a sequence`). Switched to
  `axum_extra::extract::Form` (backed by `serde_html_form`) — same
  pattern already used in `mgmt::public_files`. Caught by the
  T26 live integration smoke test.

## 1.5.1 - 2026-04-29

> Note: these changes also rode in the v1.6-pre commit on 2026-04-30 but
> are scoped separately here because they're orthogonal to the v1.6.0
> anon_caps / RPC feature set.

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

## 1.5.0 - 2026-04-23

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

## 1.4.0 - 2026-04-21

### Added

- **Garage (S3-compatible) integration** (X+ scope per
  `../docs/superpowers/specs/2026-04-21-garage-object-store-integration.md`).
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

## 1.3.1 - 2026-04-21

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

## 1.3.0 - 2026-04-21

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

## 1.2.2 - 2026-04-21

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

## 1.2.1 - 2026-04-21

### Changed
- **Copy MCP config button now emits a `claude mcp add-json` command**
  instead of a `mcpServers` JSON block. The previous format required
  the admin to hand-edit a config file; the CLI form is one paste into
  a terminal. Shape:
  ```
  claude mcp add-json drust-<tenant-id> '{"type":"http","url":"https://<host>/drust/t/<tenant-id>/mcp","headers":{"Authorization":"Bearer drust_..."}}'
  ```
  Caption under the service-key card updated to match.

## 1.2.0 - 2026-04-21

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

## 1.1.1 - 2026-04-21

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

## 1.1.0 - 2026-04-21

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

## 0.1.0 - 2026-04-20

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

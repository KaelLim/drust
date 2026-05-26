## [1.28.12] - 2026-05-26

### Changed
- Collection page footer is now a thin status bar pinned to the browser viewport bottom (was `position:sticky` inside the page scroll, which left the bar floating mid-air right below the table on short pages). New shape: 36px tall, `var(--bg-deep)` tint, single `var(--border-mid)` hairline on top, muted 12px sans typography — Excel / Supabase status-bar aesthetic. Left edge anchored at `248px` (matches `.app-shell` grid's sidebar column), right edge at viewport edge.
- `[Table]` / `[Definition]` tabs (`.view-tabs`) removed from the footer markup. Definition view is still reachable via the `?view=definition` URL param (the JS init reads from `searchParams`, and the `.view-tabs button` querySelectorAll gracefully no-ops with the markup gone). A later release will decide whether to surface Definition view elsewhere or retire it entirely.

### Internal
- `.coll-sticky-bottom` swapped `var(--line-2)` (ghost var since v1.23) for `var(--border-mid)` on the top border.

## [1.28.11] - 2026-05-26

### Fixed
- Collection page filter popover (chip [+ Filter] and [Sort]) form controls had no background or text color set. The `.filter-popover select, .filter-popover input` rule only declared padding + border + radius + font, and the border itself referenced `var(--line)` (no theme definition — same ghost-var class as v1.28.10's checkbox fix). Browsers fell back to UA defaults: white background + black text. Against the popover's dark `var(--bg)` shell this looked unstyled. Selects and inputs now mirror the canonical `.input` / `.select` token shape — `var(--bg-deep)` background, `var(--fg)` text, `var(--border-mid)` border, with an `--accent-border` focus ring matching the rest of the admin forms. The popover container border also swapped from `var(--line)` to `var(--border-mid)`, and the box shadow opacity went from 0.12 to 0.35 (the v1.28.x dark themes need a punchier shadow to read as a layered surface).

## [1.28.10] - 2026-05-26

### Fixed
- Checkbox border was effectively invisible after v1.28.9. The new custom skin referenced `var(--bg-soft)` for the unchecked background and `var(--line)` for the border, but those CSS custom properties have had no definition in any theme since the v1.23 palette refactor (`09af66a` removed the legacy `--line: oklch(…)` declarations without sweeping the 19 remaining references across `_styles.html`). With both vars undefined, the background fell back to `transparent` and the border to `currentColor`, which in most contexts rendered as a barely-visible hairline against the page bg. Checkbox now uses real theme tokens: `var(--bg-deep)` for the unchecked fill and `var(--border-strong)` for the border, with `var(--accent-border)` on hover — clearly visible in cozy-dark, soft-light, and system tracking either. The other ~14 ghost-variable references elsewhere in `_styles.html` (chips, popovers, view-tabs) are unaffected by this commit and remain a separate cleanup target.

## [1.28.9] - 2026-05-26

### Added
- Admin sidebar now renders the real Google/GitHub profile (display name + avatar URL) instead of the hardcoded `AK` placeholder. Both OAuth callbacks (`oauth_login.rs`) persist `name` + `picture` claims onto two new `admins` columns (`display_name`, `picture_url`) on every sign-in; sidebar resolves to an `<img referrerpolicy="no-referrer">` when `picture_url` is set, else a `<div>{{ initials }}</div>` derived from name (`Kael Lim` → `KL`) or email local-part (`kael1996@…` → `KA`). New `AdminProfileExt` extension + `admin_profile_layer` middleware inside the protected scope.

### Changed
- Collection page settings popover (gear button) is now a right-side drawer: `min(420px, 33vw)`, no backdrop dim, 220ms slide-in via transform, independent scroll. The page behind stays interactive (`aria-modal="false"`). Close via `[×]`, ESC, or click outside.
- All admin checkboxes now have a custom CSS-only skin (`appearance: none`). Unchecked = `--bg-soft` + line border (no more stark-white square against dark themes); checked = `--accent` fill + white check mark drawn as a rotated rectangle via `::after`. `:focus-visible` and `:disabled` states included.

### Internal
- Two new nullable columns on `admins` (`display_name`, `picture_url`) via the existing `add_column_if_missing` migration helper.
- New `src/mgmt/admin_profile.rs` — `AdminProfileExt` struct + `compute_initials` + `load_admin_profile` + `admin_profile_layer`. 8 unit tests cover the initials algorithm.
- Every askama admin page struct gains a sibling `pub admin: AdminProfileExt` field next to `pub t: Translator`. Handlers extract `Extension<AdminProfileExt>` and pass it through.
- Four orphan i18n keys retired: `admin_sidebar.foot.username`, `admin_sidebar.foot.scope`, `collection_sidebar.foot.admin`, `collection_sidebar.foot.scope`. Values are now derived from the admin profile, not translated strings.
- `design.html`'s sample `<div class="who-av">AK</div>` at line 451 is kept as a literal — it's the design-system reference, not tied to a live session. (`design.html`'s role-badge showcase at line 249 was migrated to `common.role.admin` since `admin_sidebar.foot.username` no longer exists.)

## [1.28.8] - 2026-05-26

### Fixed
- `/admin/settings` Save was still a no-op for admins who only ever signed in via OAuth (Google / GitHub). v1.28.1 added a `Max-Age=0` cleanup of legacy `Path=/` cookies inside the password-login handler (`routes.rs:411-416`), but the OAuth callback handler (`oauth_login.rs`) was not touched — so OAuth-only admins who logged in between `61fd078` (first `drust_theme` on callback) and `622b44f` (2026-05-24 migration to the canonical `Path=/drust` builders) still had the stale `Path=/` cookies in their jar after every OAuth sign-in. The fresh `Path=/drust` cookies coexisted with them, and `CookieJar::get` returned the stale value on some browsers, masking the Save. OAuth callback now mirrors the v1.28.1 cleanup: two extra `Set-Cookie` headers expire `drust_locale` / `drust_theme` at `Path=/`. Affected users see the bug clear after one fresh OAuth sign-in.

## [1.28.7] - 2026-05-26

### Changed
- `/list` denial code for anon callers on owner-scoped collections is now `ANON_FORBIDDEN_OWNER_SCOPED`, matching `/records/*` and `/search`. The previous code `OWNER_SCOPED_ANON_DENIED` is removed. The HTTP status and the error message are unchanged. External clients pattern-matching the old string need to update.

### Fixed
- Webhook `x-drust-delivery-id` and `x-drust-timestamp` headers now match the corresponding fields in the HMAC-signed body for the same delivery. Previously `dispatch()` generated one UUID/timestamp pair for the body and `deliver_for_test()` generated a second pair for the headers, silently breaking log correlation between a subscriber's request log and drust's `last_failure_reason`. Both values are now generated once in `dispatch()` and threaded through.

### Internal
- `webhook_dispatcher::deliver_for_test` accepts an optional `PreCheckResolveFn` (`Arc<dyn Fn(String, u16) -> BoxFuture<Result<(), String>> + Send + Sync>`) for tests to fake the wrap-first DNS check. Production callers pass `None` — the path is bit-for-bit unchanged. Three previously-`#[ignore]`d integration tests in `tests/webhook_dns_rebind.rs` (`mixed_resolve_dials_only_public`, `ipv6_private_literal_terminal`, `dns_failure_terminal`) are now active.

## [1.28.6] - 2026-05-26

### Fixed
- Collection editor + end-users pages had content sitting at 50px from the page edge while every other admin page (overview, api_keys, rpc, files, oauth providers, webhooks, logs, audit) sits at 32px — the canonical `.page` horizontal padding. Caused by `.coll-sticky-top` / `.coll-toolbar` / `.coll-table-wrap` / `.coll-sticky-bottom` each adding their own 18px on top of `.page`'s 32px. UX felt off when navigating between sidebar entries (content jumped further in).
- Fix: negative-margin on the sticky chrome cancels `.page`'s horizontal padding so background + border render full-bleed; internal 32px padding restores content alignment. Middle sections drop horizontal padding and inherit `.page`'s 32px. Net result: all admin pages share one content-edge position.

### Changed
- `.coll-sticky-bottom` background changes from `var(--bg)` to `var(--bg-deep)` for stronger visual separation from the scrolling content above.

## [1.28.5] - 2026-05-25

### Changed
- Collection page Table rows truncate each cell to a single line with `…` ellipsis instead of wrapping long content. Hover the cell to read the full value (already exposed via `title=…` from the JS renderer). Uses `table-layout:fixed` + `max-width:280px` per td. Matches the pre-v1.28 `.trunc`-cell look.

## [1.28.4] - 2026-05-25

### Added
- Collection page sticky-top now shows the eyebrow `Tenant · <tenant_name>` above the collection title, matching the pre-v1.28 `.view-head` chrome. Uses the existing `.eyebrow` style + `common.label.tenant` i18n key (no new keys).

## [1.28.3] - 2026-05-25

### Changed
- Collection page sticky-top `<h1>` font reverts to the pre-v1.28 `.view-title` look (34px `var(--font-display)`, 500 weight, -0.6px letter-spacing, 1.08 line-height) instead of the 18px sans the v1.28 redesign shipped with. Per user preference — keeps the page title visually anchored consistent with the rest of the admin UI.

## [1.28.2] - 2026-05-25

### Fixed
- v1.28 explain modal popped open on page load and refused to close. Root cause: the modal `<div>` carried both `hidden` attribute AND inline `style="...display:flex..."`; the inline `display:` value beats the UA stylesheet's `[hidden] { display:none }`, so the modal was always visible. Moved the modal styling into a new `.coll-modal` / `.coll-modal-body` class pair in `_styles.html` (no `display:` collision on the host element) so `hidden` is once again the single source of truth for visibility.

## [1.28.1] - 2026-05-25

### Fixed
- `/admin/settings` Save was a no-op for any admin who had logged in via the password flow. The login handler wrote `drust_locale` / `drust_theme` cookies with `Path=/` and no `Secure` flag, while `/admin/settings` writes them with `Path=/drust; Secure` (the canonical attributes). After Save, the browser kept both cookies; `axum_extra::CookieJar::get` then returned the stale `Path=/` value, masking the new one and making the page appear unchanged. Login now routes through `build_locale_cookie` / `build_theme_cookie` so attributes match, and proactively expires any pre-v1.28.1 `Path=/` cookies still in the browser jar via `Max-Age=0`.

## [1.28.0] - 2026-05-25

### Added
- `POST /admin/tenants/<id>/collections/<coll>/_list` — admin-session-protected JSON endpoint that backs the redesigned collection editor's chip filter. Accepts `{filters:[{field,op,value}], sort, page, per_page}`; bridges UI ops (`contains`, `starts_with`, `ends_with`, `between`, `is_true`, `is_false`, `is_null`, `is_not_null`) onto FilterAst and compiles to SQL with `?` binds. Returns `{columns, rows, total, page, per_page, total_pages}`.
- `is_null` and `is_not_null` operators on `FilterAst` leaves (`src/query/vector_filter.rs`).

### Changed
- **Admin collection editor (`/drust/admin/tenants/<id>/collections/<coll>`) — Supabase-style redesign.** Six tabs collapse to two view modes (Table, Definition). Per-collection settings (anon caps, realtime toggle, SSE quickstart docs, EXPLAIN tool) move into a `[⚙]` popover anchored to the sticky header. Description renders inline in the header (no tile, no label). Pagination + view switcher move into the sticky footer; the duplicated meta-row is gone. Filter UI is a structured chip row (column × operator × value), backed by the new `_list` endpoint — no more raw SQL `WHERE` input.
- Layout: single viewport scroll (removed `.records-scroll{max-height:600px}`); full-content-width (no central column cap).
- URL params: `?tab=schema|indexes` → 302 to `?view=definition`; `?tab=anon|realtime|explain` → 302 to `?view=table`. `?filter=<raw SQL>` is dropped (no safe translation); a `tracing::info!` records each hit on the legacy URL.

### Removed
- Server-side rendering of rows from `collection_rows_page` — the template ships a shell and the browser fetches via `_list` (~170 LOC cleanup in `src/mgmt/browse.rs`).
- 33 orphan i18n keys (deleted tab blocks).

## [1.27.0] - 2026-05-25

### Added
- Per-tenant schema codegen endpoints: `GET /t/<id>/openapi.json` (OpenAPI 3.1), `GET /t/<id>/types.ts` (TypeScript types), `GET /t/<id>/zod.ts` (Zod schemas). All three are generated live from `_system_collection_meta` + PRAGMA. Auth follows `/records/*` — anon and service both read schema shape; description text is only included for service bearers. Response header `X-Drust-Schema-Source: anon|service` declares the mode.
- OpenAPI paths auto-emit `POST /records/<c>`, `POST /collections/<c>/list`, `GET/PUT/DELETE /records/<c>/{id}`, plus `POST /collections/<c>/search` for vector collections and `GET /records/<c>/subscribe` for realtime collections. FilterAst is a shared `$ref`.

### Notes
- RPC codegen deliberately out of scope for v1.27 — output column inference for arbitrary stored SELECTs is brittle (aggregates, JSON funcs, computed exprs). Will revisit when there's demand signal.
- Schema codegen is read-only metadata: no writes, no audit emission, no webhook fires.

## [1.26.0] - 2026-05-25

### Added
- `suggested_fix` field on every REST error response and MCP `ErrorData.data`. Static catalog (~25 entries, one per error code) plus four context-aware sites (`FIELD_NOT_FOUND`, `COLLECTION_NOT_FOUND`, `VECTOR_DIM_MISMATCH`, `OWNER_FIELD_REQUIRED`) that substitute actual variable values into the hint.
- `dry_run: true` parameter on `delete_record` / `drop_collection` / `drop_index` (MCP); query string `?dry_run=true` on the matching REST routes (`DELETE /records/<c>/<id>` and `DELETE /collections/<c>/indexes/<n>`). Returns a blast-radius preview (FK blockers, dependent indexes, RPCs that reference the collection, reverse FKs) without mutating storage, writing audit, or firing webhooks.
- `recent_writes` MCP tool. Service-key only. Returns the latest write events (ts/op/collection/status/error_code) for the calling tenant from `meta_logs.sqlite`. Params: `limit` (1..=200, default 50), `collection`, `since_ts`.

### Notes
- All additions are byte-compatible with v1.25.2: `suggested_fix` is optional (omitted when no catalog entry), `dry_run` defaults to `false`, `recent_writes` is a new tool that did not exist.

## [1.25.2] - 2026-05-24

### Removed
- JSONL dual-write path and the `AUDIT_DUAL_WRITE` env var. SQLite is the only audit storage now; a startup WARN is logged if the env is still set.
- Historical `/var/log/drust/audit-*.jsonl*` archives (~520M; all data already in `meta_logs.sqlite`).

### Notes
- Same-day retirement overrode the original 30-day SQLite validation window: v1.24.x ran clean for ~24h on the canonical path, marginal value of dual-write fell below operational cost. Pre-retirement implementation remains at git tag `v1.24.2`.

## [1.25.1] - 2026-05-24

### Removed
- v1.24.2 one-time migration block that promoted the legacy `audit-backfill.done` filesystem marker to the in-DB sentinel — already fired exactly once per install.
- `/var/lib/drust/audit-backfill.done` filesystem marker on the live host.
- `deploy/logrotate-drust` + `/etc/logrotate.d/drust` — no-op for date-named files, deprecated since v1.24.0.

## [1.25.0] - 2026-05-24

### Fixed
- Theme persistence when cookies are cleared but admin session remains. Split the theme middleware: cookie-only outer (covers `/login` + OAuth callback) + DB-aware inner (after admin-session layer).
- `drust_theme` and `drust_locale` cookies now use `Path=/drust + Secure`, matching `drust_session`. Dev override: `DRUST_DEV_NO_SECURE_COOKIES=1`.
- Build now panics on theme TOML ↔ enum drift instead of failing at runtime.

## [1.24.2] - 2026-05-24

### Changed
- Audit backfill is now atomic — synchronous before the writer task spawns, wrapped in a single transaction including the sentinel row. No partial-state on mid-drain kill.
- Retention anchored to wall-clock 03:00 UTC instead of uptime-relative interval. VACUUM no longer skips a month if drust restarts on day 1.

### Added
- `_meta` key/value table inside `meta_logs.sqlite` holds `backfill_done` and `last_vacuum_ts`.
- Channel-full WARN sampled to 1st + every 10,000th to bound journal spam; 60s drop-summary task with non-zero delta logging; "Audit drops" chip on the admin overview (only renders when non-zero).

## [1.24.1] - 2026-05-24

### Fixed
- Backup script now snapshots `meta_logs.sqlite` alongside `meta.sqlite`. Without this, a disk failure would have lost the entire 90-day audit trail introduced in v1.24.0.

## [1.24.0] - 2026-05-24

### Added
- Audit log SQLite storage at `meta_logs.sqlite` (batched writer; channel-full drops counted + warned). JSONL writes ran in parallel during a 30-day validation window via `AUDIT_DUAL_WRITE` (default `true`); retired in v1.25.2.
- One-shot JSONL backfill on first start, idempotent. v1.24 launch backfilled ~2.58M rows in ~9s.
- In-process retention: daily DELETE rows older than 90d, monthly VACUUM on the 1st (UTC).
- Audit row `caller_ip` and `user_agent` promoted out of `extra` into dedicated indexed columns.

### Changed
- Audit Overview totals are SQL aggregates. `MAX_ENTRIES=50_000` cap and 10s `SCAN_CACHE` removed — counts are honest by construction.
- Browse pagination uses `(ts DESC, id DESC)` cursor for stable ordering across timestamp ties.

### Deprecated
- `/etc/logrotate.d/drust` (no-op for date-named files). Removed in v1.25.1.

## [1.23.0] - 2026-05-23

### Added
- Server-side theming for the admin UI: three themes (`system` / `cozy-dark` / `soft-light`). `system` auto-switches via `prefers-color-scheme`. Persisted via `drust_theme` cookie + `admins.theme` column.
- Palettes shipped as `themes/<code>.toml` embedded via `include_str!`. `build.rs` enforces structural validity at compile time.

## [1.22.0] - 2026-05-22

### Added
- Server-side i18n for the admin UI: English (default) and 繁體中文. Resolved from `drust_locale` cookie → `Accept-Language` → `en`. Topbar language switcher. Missing keys fall back to `en` with a dev-only warn.
- Translation bundles compiled into the binary; `build.rs` panics on missing keys at compile time. 705+ keys across 25 templates.

## [1.20.0] - 2026-05-21

### Changed
- Admin REST writers in `mgmt/{browse,rpc_admin,tenant_files}.rs` migrated from raw `open_write` to `pool.with_writer`, unifying admin writes with the data-plane concurrency model.
- `drust_session_janitor` is now async; per-tenant DELETEs go through `pool.with_writer` and inherit `busy_timeout=5000`, closing a deadlock window when drust is actively writing.

### Fixed
- MCP `insert_record` / `update_record` / `delete_record` now block writes against `_system_*` tables (`PROTECTED_COLLECTION`), symmetric with the existing REST block.
- MCP `delete_record` returns `RECORD_NOT_FOUND` instead of `COLLECTION_NOT_FOUND` when the table exists but the id is absent.
- TOCTOU race closed in 6 schema helpers (`set_anon_caps`, `set_realtime`, `set_owner_field`, `set_collection_description`, `set_field_description`, `set_index_description`): existence check now runs inside the same writer closure as the write. Distinct `COLLECTION_NOT_FOUND` / `FIELD_NOT_FOUND` / `INDEX_NOT_FOUND` sentinels preserved.

## [1.19.2] - 2026-05-21

### Security
- Closed `?filter` / `?sort` SQL-injection bypass on `owner_field` for user tokens on owner-scoped collections. Returns `400 USER_FILTER_DENIED_ON_OWNER_SCOPED`.
- Per-IP rate limit (5/min) added to admin login + admin OAuth callback. Closes the parallel-thread argon2 grind window.
- Webhook SSRF defense: redirect-following disabled; `check_url` resolves the registered host and rejects any private/loopback/link-local IP. Residual DNS-rebinding window queued for v1.21.

## [1.19.1] - 2026-05-21

### Fixed
- Admin UI schema-row column-count mismatch (8 cells against 7 grid tracks).
- Schema cache invalidation now fires on every description write.
- Admin description handlers block `_system_*`, check existence before write, and route JSON-blob read-modify-write through the writer mutex.
- `add_field` now persists `FieldSpec.description` (silently dropped before).
- `drop_index` runs `DROP INDEX` + JSON cleanup in a single writer closure.
- `create_collection_with_desc` validates every description before `CREATE TABLE`, eliminating the half-described-collection failure mode.
- Description readers parse JSON per-key — one bad value no longer wipes the whole map.

### Added
- Live UTF-8 byte counter beside the description textarea; save button disables when over 2048 bytes.
- Inline error banner on validator-failure redirect (`?desc_error=<code>`).

## [1.19.0] - 2026-05-21

### Added
- Schema descriptions for collections, fields, indexes, and RPCs (RPC was already supported since v1.6 — now surfaced uniformly across the API).
- MCP tools `set_collection_description`, `set_field_description`, `set_index_description`, `get_schema_overview`.
- REST: PUT routes for description + `GET /t/<id>/schema/overview`.
- Admin UI: inline-editable description tile + Description column on fields and indexes tables.

### Changed
- `Collection`, `Field`, `IndexInfo`, `CollectionSchema` gain optional `description` with `skip_serializing_if = "Option::is_none"` — payloads byte-identical when no description set.

## [1.17.2] - 2026-05-21

### Removed
- Audit overview SVG chart grid (v1.17.0 feature). Used wrong design tokens that fell back to GitHub-cold-blue, clashing with drust's warm palette. User-decided removal rather than refactor.

### Changed
- Tenant name shown everywhere (audit overview tables, backup restore flash, empty-tenant page, reconcile pending revokes, API keys sub-header). UUID still on hover.
- Audit timeline timestamp format: `MM-DD HH:MM:SS` (15 chars) instead of full RFC3339 (24 chars). Raw still on hover.
- Audit timeline grid widened to fit the new format; wrapping cleaned up.

## [1.17.1] - 2026-05-21

### Added
- `X-Drust-Version` response header on every reply.
- Audit log row → modal detail: click-to-open via `drustUI.detail()` reading from an embedded JSON blob. Keyboard parity (Enter/Space).
- Audit toolbar `<datalist>` dropdowns: tenant filter (host scope), op filter from window's distinct ops (capped at 200).
- Audit row tenant pill shows resolved name instead of UUID.
- 6 new icon symbols; leading icons on `/admin/tenants` search input and `/admin/backups` row actions.

### Fixed
- `/admin/backups` DB glyph rendered solid black (missing fill/stroke on inline SVG).
- XSS via literal `</script>` inside the audit `op` string in the embedded JSON blob. Now `</` → `<\/` swapped before serialization.

## [1.13.0] - 2026-05-16

### Added
- Outbound webhooks on record CRUD events. Per-tenant `_system_webhooks` table; HMAC-SHA256 signed POSTs; 4 inline attempts (+0/+1/+5/+30s, 10s each); 5xx/network/timeout retryable, 4xx terminal.
- Service-only REST: `POST/GET/PATCH/DELETE /t/<id>/admin/webhooks[/<wid>]`. Secret returned plaintext exactly once; redacted as `●●●●` everywhere else. PATCH cannot rotate (rotate = delete + create).
- MCP tools: `create_webhook` / `list_webhooks` / `update_webhook` / `delete_webhook`.
- Admin UI virtual sidebar entry `🔔 _webhooks`; raw secret surfaced once via short-lived HttpOnly cookie + `Referrer-Policy: no-referrer`.

## [1.12.3] - 2026-05-15

### Fixed
- MCP HTTP idle-timeout extended from rmcp default 5 min to 24 h. Interactive MCP clients (Claude Code) idling >5 min would otherwise hit `404 Session not found` on the next tool call with no auto-recovery.

## [1.12.2] - 2026-05-15

### Fixed
- `POST /drust/login` equalises argon2 timing on unknown-username via a fixed dummy hash. Closes admin-username-existence wall-clock oracle.
- Admin audit UI no longer renders a broken `/admin/tenants/-/_logs` link for admin-plane rows.

### Changed
- Tenant + admin `register` / `login` / `oauth_callback` audit rows now carry `auth_kind`. Failure rows carry the attempted kind so probing surfaces in the same query.
- Password auth flows now set `auth_method = "password"`, matching OAuth's typed value.
- Admin audit UI renders the typed `auth_method` / `oauth_email` / `oauth_error_code` + the `extra` flatten map.

## [1.12.1] - 2026-05-15

### Fixed
- Admin DELETE / upsert on `_oauth_providers` against a nonexistent tenant_id no longer materialises an empty `tenants/<bogus>/data.sqlite`.
- `_system_users.profile` for OAuth-auto-created rows now carries `picture` (Google `id_token.picture` / GitHub `avatar_url`) — silently dropped in v1.12.0.

### Changed
- Admin REST PUT/DELETE `/admin/oauth-providers` attach typed `AuditExtra`.
- `_oauth_providers` validation failures return specific codes (`INVALID_PROVIDER`, `INVALID_REDIRECT_URI`, `EMPTY_REDIRECT_URIS`, `INVALID_CLIENT_ID`, `INVALID_CLIENT_SECRET`) instead of umbrella `INVALID_OAUTH_CONFIG`.

## [1.12.0] - 2026-05-15

### Added
- Per-tenant OAuth (Google + GitHub) for end users. End-user flow returns to frontend with `<cb>#access_token=drust_user_xxx` (Supabase / Auth0 URL-fragment pattern).
- Per-tenant `_system_oauth_providers` table. Admin REST `GET/PUT/DELETE /admin/oauth-providers[/{provider}]` (service-key only; `client_secret` redacted on GET).
- 3 MCP tools: `set_oauth_provider`, `list_oauth_providers`, `delete_oauth_provider`.
- Admin UI virtual sidebar entry `🔐 _oauth_providers`.
- Sentinel `password_hash="$oauth-only$"` for OAuth-only users. Password login returns `401 INVALID_CREDENTIALS`; `/me/password` returns `409 OAUTH_ONLY_NO_PASSWORD`.
- Per-IP rate-limit (5/min) on `/callback`.
- Audit rows enriched with `auth_method=oauth_<provider>`, `oauth_email`, `oauth_error_code`, `auth_user_id`.

## [1.11.1] - 2026-05-15

### Fixed
- OAuth state + PKCE cookies now use `Path=/drust/admin` (was `/admin`, didn't match Caddy `handle_path /drust/*` strip behavior). Every callback was failing `oauth_state_mismatch` because the browser refused to send the cookie.
- Admin session cookie `SameSite=Strict` → `Lax`. Strict broke the OAuth callback redirect chain.

## [1.11.0] - 2026-05-15

### Added
- Admin OAuth login (Google + GitHub) alongside username + password. Buttons render only when both client id and secret are env-set.
- `admins.email` nullable column (idempotent migration; partial unique index when present). Populate via `set_admin_password --email <addr>`.
- Email allowlist via `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS`; provider `email_verified` flag required.
- PKCE (RFC 7636 S256) + CSRF state cookie (constant-time compare); conformant to RFC 9700 OAuth 2.0 Security BCP.
- New actor-agnostic OAuth library: `OauthProvider` trait + Google OIDC + GitHub OAuth 2.0 adapters. Reused by v1.12 per-tenant OAuth.

## [1.10.1] - 2026-05-14

### Fixed
- `/search`'s `where` AST refuses bool trees nested deeper than 32 levels (`400 FILTER_TOO_DEEP`). Prevents stack exhaustion from a deeply-nested payload that fits inside axum's 2MB body cap.

## [1.10.0] - 2026-05-13

### Added
- Vector storage as a first-class field type: `vector(dim)`, dim 1..=4096. Lowers to a SQLite BLOB of packed little-endian f32. Dim mismatch / NaN / Inf rejected at 422 (`VECTOR_DIM_MISMATCH` / `VECTOR_NON_FINITE` / `VECTOR_TYPE_ERROR`).
- `POST /t/<id>/collections/<c>/search` with structured `{field, vector, k, metric, where, select}`. Metric: `cosine` / `l2` / `l1`. drust constructs SQL from a Filter AST — no raw SQL accepted.
- MCP `search_collection` tool (mirrors REST shape).
- User tokens can call `/search` even though they cannot call `/query` — drust builds the SQL, so `owner_field` enforcement is by construction.
- Vector fields excluded from GET/list responses by default (v1 has no opt-in mechanism).
- sqlite-vec registered as a SQLite auto-extension at process start. Side benefit: `vec_distance_*` is callable from `/query` (service token) and stored RPCs.

## [1.9.0] - 2026-05-12

### Added
- Per-tenant end-user authentication: `_system_users` + `_system_sessions` tables. Tokens `drust_user_*`, SHA-256-hashed at rest, sliding 30d expiry. argon2id verify with fixed dummy-hash timing equalization. Self-register opt-in via `tenants.allow_self_register`.
- Three-kind bearer resolution: `Anon` / `Service` / `User { user_id }` exposed as `AuthCtx`.
- REST: `POST /auth/{register,login,logout,logout-all}`; `GET/PATCH /me`; `POST /me/password`. Service-only admin user CRUD with cascade delete.
- Per-collection `owner_field` + `read_scope` (`own` / `all`): user tokens see only their rows; foreign UPDATE/DELETE returns 404 (no enumeration); anon denied on owner-scoped collections; service must populate `owner_field` on INSERT (`409 OWNER_FIELD_REQUIRED`).
- Stored RPCs accept user tokens when `anon_callable=true`; auto-bind `:user_id` from `AuthCtx` if declared.
- 9 MCP tools mirroring the REST surface; admin UI virtual entry `👤 _system_users`.
- Daily `drust_session_janitor` binary sweeps expired sessions with 1d grace.
- Audit rows enriched: `auth_kind`, `auth_user_id`, `email` / `ip_at_login` on auth endpoints, `deleted_records` / `revoked_sessions` on admin user delete. Auth bodies are never persisted.

### Security
- User tokens denied on `/query`, `/query/explain`, `/mcp` (`403 QUERY_USER_DENIED` / `MCP_USER_DENIED`) — drust does not rewrite user-supplied SQL, so `owner_field` cannot be enforced on those surfaces.
- Per-IP rate-limit: login 5/min, register 3/min. IP from `XFF[-2]` per the `.221 → :8793 → 127.0.0.1` hop chain.

## [1.8.0] - 2026-05-08

### Added
- Per-collection indexes: MCP `create_index` / `drop_index`, REST `POST/DELETE /t/<id>/collections/<coll>/indexes`. Composite + unique supported, auto-named `idx_<coll>_<f1>_<f2>...`.
- Large-table guard: `DRUST_INDEX_LARGE_TABLE_ROWS` (default 1M); `create_index` returns `409 LARGE_TABLE` over threshold unless `force: true`.
- `POST /t/<id>/query/explain` returns EXPLAIN QUERY PLAN rows. Anon-allowed.
- Admin UI Indexes section + EXPLAIN textarea on each collection page.
- `AuditEntry::with_extra` — op-specific keys flatten into the audit row.

### Changed
- `/records/<coll>` get-by-id now consults `anon_caps` (was missed). `/records/_system_*` blocked for both anon and service regardless of caps (404).
- MCP tool count: 21 → 23.

### Fixed
- Soft-delete now evicts the per-tenant pool, MCP service, and SSE bus before moving the directory — quick re-create on the same tenant id no longer hits stale handles.
- Rate-limit bucket map is now bounded with background cleanup.
- Graceful shutdown waits for audit-writer mpsc to drain on SIGTERM.

## [1.7.3] - 2026-05-08

### Added
- MCP tool `set_anon_caps` — toggle per-collection anon DML caps without going through the admin UI cookie session.
- MCP tool `whoami` — returns tenant identity, both bearer tokens in plaintext, REST/MCP/files/rpc paths, and `max_upload_bytes`. Bootstraps the multipart file-upload flow that has no MCP tool by design.

### Notes
- Tokens minted before v1.1c stored only the hash; for those, `whoami.tokens.<role>.plaintext` is `null`. Admin UI reroll is the recovery path.

## [1.7.2] - 2026-05-05

### Added
- RPC test playground at `/admin/tenants/{id}/_rpc/{name}/test` — type-aware param inputs, runs against a read connection, returns result rows + `duration_ms` + `EXPLAIN QUERY PLAN`.
- Backup snapshot inspect at `/admin/backups/{filename}/inspect` — streams the `.tar.zst` on `spawn_blocking`, extracts `meta.sqlite` to a tempfile, lists tenants with each tenant's `data.sqlite` size in the archive.
- Backup tenant restore: `POST /admin/backups/{filename}/restore` extracts a tenant's `data.sqlite` to `_trash/<tid>-restored-<ts>/`. **Does not overwrite live data** — admin `mv`s back manually. Filename strictly whitelisted; tenant id validated as uuid-v4-shaped.

## [1.7.1] - 2026-05-05

### Added
- Backup snapshot UI: `/admin/backups` (read-only list) + per-file download (streamed `.tar.zst`, no buffering). Filename pattern whitelisted; traversal returns 400 before any FS access.
- Audit drill-down links: tenant cell → `/admin/tenants/{id}/_logs`, collection cell → `/admin/tenants/{id}/collections/{coll}`.
- Per-row audit detail panel via `<details>` (full key/value block; `error_message` in red-tinted wrapping `<pre>`).
- Per-tenant disk breakdown: `db` / `files` / **total** columns on the tenants list (auto-scaled B/KB/MB/GB).
- `GarageClient::bucket_usage(name)` admin API wrapper.

### Changed
- `tenant_name` now shown in topbar paths on per-tenant pages (URLs still carry the UUID).
- Audit table styling unified to `.data` admin grid; stat cards equal-height.
- `_rpc` and `_system_files` pages gain pagination.

### Fixed
- Tenant-scope `_logs` page hides the redundant tenant column.

## [1.7.0] - 2026-05-05

### Added
- Admin audit log UI: `/admin/audit` (host) + `/admin/tenants/{id}/_logs` (per-tenant). Stateless file scan over `audit-YYYY-MM-DD.jsonl{,.N,.gz}`. Modes: Overview (totals, error rate, p50/p99, avg QPS, top tenants on host scope, top slow ops) + Browse (paginated `<details>` rows). Window: `1h | 24h | 7d`.

### Changed
- `AuditEntry.status` from `&'static str` to `String` so the type derives `Deserialize` for the audit JSONL parser.
- `MgmtState` + `TenantsState` carry `log_dir: PathBuf`.

### Notes
- No migration. Audit JSONL files were already produced by all prior releases; this only adds a read path.

## [1.6.0] - 2026-04-30

### Added
- Per-collection DML capability allowlist (`anon_caps`): subset of `{select, insert, update, delete}`, default `[select]`. Persisted in per-tenant `_system_collection_meta`. Service is unrestricted.
- Stored RPCs (Supabase-style named SQL functions): per-tenant `_system_rpc` table; REST `POST /drust/t/<id>/rpc/<name>` (anon allowed per-RPC via `anon_callable`); MCP tools `create_rpc` / `update_rpc` / `delete_rpc` / `list_rpc` / `call_rpc` (service-only on the MCP transport regardless of `anon_callable`).
- Admin UI: `_rpc` virtual sidebar entry (list / create / edit / delete with SQL prepare-time validation) + anon_caps editor on the Schema tab.

### Changed
- SQL authorizer Read arm extended to deny any `_system_*` table (was: only `sqlite_*`). Both anon and service affected.
- REST DML write handlers now consult per-collection `anon_caps` (was: always `require_service`). Legacy collections preserve "anon = read-only" via the `[select]` default.
- MCP tool count: 16 → 21.

### Security
- The "anon = read-only" guarantee becomes "anon = subset of DML defined per-collection in `anon_caps`, default `[select]`". RLS deliberately out of scope.

## [1.5.1] - 2026-04-29

### Added
- CORS support on tenant routes. New `DRUST_CORS_ORIGINS` (comma-separated allow-list, empty = layer disabled). Applied OUTSIDE `bearer_auth_layer` so OPTIONS preflight is intercepted before auth. Subdomain wildcards (single `*`) supported — `https://*.tzuchi.org`, `http://localhost:*`; multi-`*` rejected at parse.
- Tenants index search box (client-side filter on name + id-prefix; `/` to focus, `Esc` to clear).

### Changed
- Admin UI collapsed from 3 pages to 2. Old `/admin/tenants/{id}` detail page is gone; `GET /admin/tenants/{id}` 302s to `/admin/tenants/{id}/_api_keys`. New virtual sidebar entries `🔑 _api_keys` and `🔒 _system_files`.
- MCP protocol upgrade: rmcp 0.4.1 → 1.5.0; protocol version 2025-03-26 → 2025-11-25. Fixes Claude Code 2.1.119 `/mcp` panel crash.
- MCP tool parameter names unified to `collection` (was: split between `name` and `collection`). `create_collection` keeps `name`.
- `sample_rows.n` renamed to `limit`.

### Removed
- Breadcrumbs across all admin pages; the topbar path is now the clickable navigation.

### Fixed
- Claude Code zod-validator silently rejected the entire MCP tool list because `insert_record` / `update_record` had top-level `data: serde_json::Value` (schemars emits no `type`). Switched to `HashMap<String, Value>`.
- `query` tool error messages: collapsed `ExecError → InvalidQuery` produced "Query is not read-only", wrong for sqlite_master and other authorizer denials. Each variant now surfaces a specific message.
- `insert_record` / `update_record` error messages: unknown collection / unknown field no longer say "Query is not read-only".
- `sql_type` discoverability: error message and tool descriptions now enumerate allowed types.
- `.shell` grid track set to `minmax(0, 1fr)` so cards no longer overflow the `.macwin` boundary on long content.

## [1.5.0] - 2026-04-23

### Added
- Per-tenant Garage buckets: auto-provision `tenant-<id>-pub` (website on) and `tenant-<id>-prv` (private) on tenant create. Rollback on failure is compensating.
- Per-tenant `_system_files` system table.
- Per-tenant file REST at `/drust/t/<id>/files`: multipart upload / list / get / delete / `/sign` (pre-signed URL) / `/bytes` (private proxy). Service-key-only.
- 3 new MCP tools: `list_files` (pagination + visibility filter), `delete_file`, `get_file_url`. **No upload tool by design** — MCP can't carry binary; instructions point the LLM at the REST endpoint.
- Admin tenant-files UI at `/drust/admin/tenants/<id>/files` (parity with `/drust/admin/files`).
- Disk-usage guard: uploads return 507 when free disk drops below `DRUST_DISK_MIN_FREE_PCT` (default 20).
- Reconcile-page extensions: `_trash_pending_revokes` and `_orphan_buckets` surface compensating failures.

### Changed
- `_system_public_files` (admin-level) → `_system_files` with new columns `visibility` / `cache_control` / `meta_json`. Idempotent on boot.
- `/drust/admin/public-files` → `/drust/admin/files` (308 redirect).
- MCP `instructions` field is now dynamic per-tenant.
- MCP tool count: 13 → 16.

## [1.4.0] - 2026-04-21

### Added
- Garage (S3-compatible) integration. Optional, activated by `GARAGE_S3_ENDPOINT` in `.env`; without env vars, drust behaves exactly as before.
- Admin UI at `/drust/admin/public-files` (list / upload / delete / reconcile for the host-level public bucket).
- System collection `_system_public_files` in `meta.sqlite`.
- `_system_*` prefix drop-protection via `is_protected_collection()` enforced by `drop_collection`.
- New env: `GARAGE_S3_ENDPOINT`, `GARAGE_ADMIN_ENDPOINT`, `GARAGE_S3_ACCESS_KEY`, `GARAGE_S3_SECRET_KEY`, `GARAGE_ADMIN_TOKEN`, `GARAGE_PUBLIC_BUCKET` (default `public`), `GARAGE_MAX_UPLOAD_SIZE` (default 50MB), `DRUST_PUBLIC_BASE_URL`.

### Notes
- Reads bypass drust: anonymous GETs hit Caddy `/public/*`, reverse-proxied to Garage `s3_web`. drust is only in the write path.
- Garage gracefully unavailable: upload/delete return 503; list page renders from SQLite metadata. Tenants, MCP, REST, and auth unaffected.

## [1.3.1] - 2026-04-21

### Added
- Favicon — 16×16 LiveChonk (happy pose) as inline SVG via `data:image/svg+xml`.
- Per-page `<meta name="description">` on all five admin templates (≤160 chars).
- `<meta name="theme-color" content="#1a2327">` matches the terminal pane on mobile browsers.

## [1.3.0] - 2026-04-21

### Added
- MCP `drop_field(collection, field)` — `ALTER TABLE ... DROP COLUMN`. Rejects the three system columns (`id`, `created_at`, `updated_at`); SQLite rejects drops that would break a UNIQUE / index / FK / CHECK / trigger / view.
- MCP `drop_collection(name)` — `DROP TABLE` + matching `_updated_at` trigger. Rejects the drop when another collection still has a foreign-key column pointing at this one.
- MCP tool count: 11 → 13.

## [1.2.2] - 2026-04-21

### Changed
- Tenant detail: MCP setup now lives in its own card, separate from the API keys card.

## [1.2.1] - 2026-04-21

### Changed
- "Copy MCP config" emits a `claude mcp add-json` command instead of a `mcpServers` JSON block (one paste into a terminal vs hand-edit a config file).

## [1.2.0] - 2026-04-21

### Added
- LiveChonk pixel-cat mascot — 16×16 silhouette with mouse-tracking eyes, blinking, occasional ear twitch. Wires any `<canvas class="pix" data-chonk=... data-size=...>` automatically.
- Left-side collection sidebar on the collection-detail page. Sidebar scroll independent of main-content scroll.

### Changed
- All admin pages render inside a viewport-fixed `.macwin` shell; internal scroll is container-scoped.
- `/admin/tenants/{id}/collections` 302s to the first collection; empty tenants land on a dedicated empty-state page.
- Login page now renders inside the `.macwin` frame.

## [1.1.1] - 2026-04-21

### Added
- rmcp Streamable HTTP transport wired at `/t/:tenant/mcp`. Each tenant is a self-contained MCP server. Closes the v0.1.0 Known issue.
- MCP is service-key-only — anon keys get `403 WRITE_DENIED`.
- "Copy MCP config" button on the tenant detail page.
- Schema fields may declare `foreign_key: String` naming the target collection. Emits `REFERENCES "<target>"("id") ON DELETE RESTRICT`. Target must already exist at DDL time.
- Field `default_value` accepts `{"sql": "<expression>"}` against an allowlist (`datetime('now')`, `date('now')`, `time('now')`, `CURRENT_TIMESTAMP`, `CURRENT_DATE`, `CURRENT_TIME`).
- Audit log now written on every tenant-data-plane request — closes the v0.1.0 Known issue.
- Per-token rate limit now enforced — closes the v0.1.0 Known issue.
- `set_admin_password` CLI to rotate an admin's `password_hash` (reads from stdin so it doesn't appear in `ps`).

### Changed
- `describe_collection` reports each field's `foreign_key` target (omitted when null; existing consumers unaffected).
- Rate-limit budget / window from `DRUST_RATE_LIMIT_PER_TOKEN` (default 60) / `DRUST_RATE_LIMIT_WINDOW_SECS` (default 10). Audit log dir from `DRUST_LOG_DIR`.

## [1.1.0] - 2026-04-21

### Added
- `anon` / `service` role split on bearer tokens (Supabase-style). `service` is full-power; `anon` is read-only — list / get / filter / subscribe / `POST /query` work, but write methods return `403 WRITE_DENIED`. No RLS — per-row policy deliberately out of scope.
- 2-slot fixed-key model with reroll. Each tenant has exactly one anon and one service slot. Tokens cannot be issued ad-hoc — only rerolled, which atomically revokes the current active token of that role.
- `POST /drust/admin/api/tenants/{id}/tokens/{role}/reroll`.
- Reveal / copy / reroll API keys inline on the tenant detail page. Tokens stored both as SHA-256 hash (auth) and plaintext (display, admin UI only). Pre-v1.1c tokens have `NULL` plaintext and show a "reroll to enable" hint.
- `tokens.plaintext TEXT` column (idempotent migration).
- `_icons.html` partial with reusable SVG sprite block.

### Changed
- Tenant detail page redesigned around a 2-card API-keys layout (one card per role with last-rotated timestamp + reroll button).
- Admin UI minimum text size raised to 18px for readability.
- Removed remaining Chinese strings — UI is English-only.
- Replaced emoji glyphs with inline SVG icons (Lucide), bundled offline.
- Version string now sourced from `Cargo.toml` at compile time.
- `meta.sqlite` migration: `tokens.role TEXT NOT NULL DEFAULT 'service'` column added idempotently.

### Removed
- Arbitrary token issuance endpoint and per-token revoke endpoint — supplanted by reroll.

## [0.1.0] - 2026-04-20

Initial production release.

### Added
- Multi-tenant management plane: session-authenticated admin UI, tenant CRUD, bearer-token issuance / revocation.
- Per-tenant data plane: REST CRUD with PocketBase-style URLs; `POST /query` with `sqlite3_set_authorizer` whitelist for read-only SQL; `?filter=` URL parameter through the same authorizer pipeline; SSE subscribe per `(tenant, collection)`.
- 11 MCP tool functions: `list_collections`, `describe_collection`, `sample_rows`, `count_rows`, `query`, `explain`, `insert_record`, `update_record`, `delete_record`, `create_collection`, `add_field`.
- Read-only data browser in admin UI with filter / sort / pagination.
- Authentication primitives: Argon2id admin password hashing; bearer tokens stored as SHA-256, constant-time compared; 7-day session cookies (`HttpOnly; Secure; SameSite=Strict; Path=/drust`).
- Storage layer: one isolated `data.sqlite` per tenant; WAL + memory-mapped I/O + 64MB cache PRAGMAs; per-tenant connection pool (serialized writer + N-reader); per-tenant quota checks.
- Operations: daily `drust-backup.timer` (`VACUUM INTO` snapshots → tarball, 30-day retention); daily `drust-janitor.timer` (prunes soft-deleted tenants after 7d); logrotate for `/var/log/drust/*.jsonl`.
- Deployment artefacts: `deploy/drust.service` (sandboxed systemd unit); `deploy/Caddyfile` snippet (with `header_up Host` for rmcp DNS-rebinding guard).
- Dark macOS Terminal aesthetic admin UI: traffic-light window chrome, terminal-prompt topbar, monospace typography, terminal-green accent.

### Known issues
- Per-token rate-limit middleware exists but is not wired into the HTTP stack (fixed in v1.1.1).
- Audit-log middleware exists but is not wired (fixed in v1.1.1).
- rmcp HTTP endpoint at `/t/{tenant}/mcp` is deferred (shipped in v1.1.1).

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://example.invalid/drust/compare/v1.1.0...HEAD
[1.1.0]: https://example.invalid/drust/compare/v0.1.0...v1.1.0
[0.1.0]: https://example.invalid/drust/releases/tag/v0.1.0

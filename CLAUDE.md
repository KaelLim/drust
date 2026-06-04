---
type: service
kind: http
name: drust
port: 47826
path: /drust
status: production
updated: 2026-06-04
version: 1.33.2
---

# drust — Rust multi-tenant SQLite BaaS

Self-hosted service providing a management UI (PocketHost-like) and per-tenant REST + MCP endpoints backed by isolated SQLite files. Design: [`docs/superpowers/specs/2026-04-20-drust-design.md`](../docs/superpowers/specs/2026-04-20-drust-design.md). Per-release changes live in [`CHANGELOG.md`](CHANGELOG.md); this file documents how the system is currently shaped, not the path it took to get here. For a per-file orientation index (what each `.rs` declares, imports, is imported by), see [`docs/architecture.md`](docs/architecture.md) — auto-generated, rebuild with `bash docs/gen-architecture.sh`.

## Build & restart

```bash
cd /home/kaelsohappy1/tool/drust
cargo build --release
sudo systemctl restart drust
curl -s http://127.0.0.1:47826/health   # → ok
```

## Tests

```bash
cargo test                                # all integration tests under tests/
cargo test --test mcp_write_schema        # one test file
cargo test set_anon_caps -- --nocapture   # one test, with stdout
```

The `tests/` directory holds 100+ integration test files covering MCP, REST, auth, audit, backups, storage, the SQL authorizer, schema codegen, and the admin `_list` endpoint. Each module's `#[cfg(test)]` blocks compile as part of the lib — no separate unit-test layout. Test factories `TenantAuthState::test_default` / `TenantsState::test_default` / `TenantFilesState::test_default` (gated on `cfg(any(test, debug_assertions))`) keep inline struct literals out of test files; prefer them when adding new tests.

## Architecture at a glance

### Data plane

- **`meta.sqlite`** (management): admins, sessions, tenants, hashed bearer tokens. Admin password rotation: `src/bin/set_admin_password.rs` reads stdin, hashes via argon2id; `--email` populates `admins.email` for OAuth login.
- **`tenants/<id>/data.sqlite`** (one per tenant). Reads go through `SQLITE_OPEN_READONLY` connections with `sqlite3_set_authorizer` whitelist in `src/query/authorizer.rs`; cross-tenant `ATTACH` denied. Writes go through structured REST/MCP tools against a per-tenant serialized writer mutex (`pool.with_writer`); schema enforcement at tool layer. `FieldSpec` supports allowlisted SQL defaults (`{"sql": "datetime('now')"}`) and foreign keys (`foreign_key: "<target>"` → `ON DELETE RESTRICT`). Admin REST writes (`src/mgmt/{browse,rpc_admin,tenant_files}.rs`) also route through `pool.with_writer` — same concurrency model as data-plane writes.
- **`meta_logs.sqlite`** (v1.24+): audit rows via `AuditWriter` (`OnceLock` in `src/safety/audit_db.rs`). Writer task drains a `mpsc::channel(1000)`, batches INSERTs every 100ms or 100 rows. Channel-full drops + counter + sampled `tracing::warn!`. Reader side uses SQL aggregates (`src/mgmt/audit.rs::aggregate_via_sql`). Retention runs in-process: daily 90-day DELETE + monthly VACUUM anchored to 03:00 UTC via `sleep_until`. JSONL dual-write retired in v1.25.2.

### Per-collection schema metadata

Stored in per-tenant `_system_collection_meta` (one row per collection). Surfaced uniformly via MCP tools + REST PUT routes + admin UI. Cache invalidation through `pool.schema_cache` (`src/storage/schema_cache.rs`). Existence checks are done INSIDE the same `pool.with_writer` closure as the write to close TOCTOU vs `drop_collection`; sentinels `COLLECTION_NOT_FOUND` / `FIELD_NOT_FOUND` / `INDEX_NOT_FOUND` are distinct.

- **`anon_caps`** (v1.6+): subset of `{select, insert, update, delete}`, default `[select]`. Service is unrestricted. **Governs `/records/*` ONLY, NOT `/query`** — the free-form SELECT endpoint accepts anon for any non-system table; revoke the anon token to fully restrict read. `_system_*` tables are blocked from `/records/*` AND from MCP write tools (`insert_record` / `update_record` / `delete_record` return `PROTECTED_COLLECTION`) for both anon and service (404 / 403); independent of cap setting.
- **`realtime_enabled`** (v1.16+, default `0` for new collections, backfilled `1` for existing): gates SSE `/t/<id>/records/<coll>/subscribe`. Disable order matters — see invariants.
- **`owner_field` + `read_scope`** (v1.9+): row-level filter for user tokens. INSERT auto-populates owner_field; UPDATE/DELETE foreign rows → 404; anon → 403 on owner-scoped collections; service bypasses but must populate owner_field on INSERT (409 OWNER_FIELD_REQUIRED).
- **Vector fields** (v1.10+): `FieldSpec.type = "vector"` + required `dim` (1..=4096), lowered to BLOB of packed little-endian f32. Excluded from GET/list responses by default. sqlite-vec registered as auto-extension at process start.
- **`description`** (v1.19+): per-collection / field / index / RPC plain-text (≤2048 bytes, no NUL). Stored in `description`, `field_descriptions_json`, `index_descriptions_json` columns. `get_schema_overview` MCP tool + `GET /t/<id>/schema/overview` REST return everything in one call for LLM bootstrap.

### Tools & endpoints

- **Stored RPCs** (v1.6+, `_system_rpc`): named SELECT functions via REST `POST /drust/t/<id>/rpc/<name>` + MCP `call_rpc`. SQL validated at create time under the read-only authorizer. Per-RPC `anon_callable` flag gates the anon REST path (MCP is service-only unconditionally). User tokens accepted when `anon_callable=true` and auto-bind `:user_id` if declared. Test playground at `/admin/tenants/{id}/_rpc/{name}/test`.
- **Per-collection indexes** (v1.8+): MCP `create_index`/`drop_index`, REST `POST/DELETE /t/<id>/collections/<coll>/indexes`. Composite + unique supported, auto-named `idx_<coll>_<f1>_...`. `DRUST_INDEX_LARGE_TABLE_ROWS` guard (default 1M, 409 LARGE_TABLE unless `force: true`). `POST /t/<id>/query/explain` exposes EXPLAIN QUERY PLAN.
- **Structured `/records/*` list** (v1.21+): `POST /t/<id>/collections/<c>/list` + MCP `list_records`. Body `{filter, sort, page, per_page, select}` with `filter` as `vector_filter::FilterAst`; SQL built in `src/query/list_builder.rs` with `?` placeholders so `owner_field` enforcement is by construction. Service-only `/list/explain`.
- **Vector similarity search** (v1.10+): `POST /t/<id>/collections/<c>/search` body `{field, vector, k, metric, where, select}`. drust builds SQL; `owner_field` auto-applied. MCP `search_collection` mirrors 1:1. v1 is brute-force scan; ~10⁵ rows is the practical ceiling.
- **Per-tenant MCP** at `/t/<tenant>/mcp` — Streamable HTTP via `rmcp`, one `StreamableHttpService<DrustMcpService>` per tenant cached in `src/mcp/http_registry.rs`. Tool list in `src/mcp/handler.rs` (`#[tool]` annotations). **Service-key-only** — anon → `403 WRITE_DENIED`, user tokens → `403 MCP_USER_DENIED`. `whoami` returns tenant identity + both bearer tokens plaintext + REST/upload paths so models can hit the multipart upload route (which has no MCP tool by design).
- **AI introspection helpers** (v1.26+): every REST error JSON includes a `suggested_fix` field with a context-aware remediation hint; same applied to MCP `ErrorData.data`. Destructive ops `delete_record` / `drop_collection` / `drop_index` accept `dry_run: true` and return `would_*` counts + blast radius without mutating. New `recent_writes` MCP tool (service-only) reads the last 100 mutation rows from `meta_logs.sqlite` filtered to the calling tenant — lets a retrying model recover what its previous attempt already did. Catalog of fixes in `src/safety/error_fixes.rs`; blast-radius probes in `src/storage/blast_radius.rs`.
- **Per-tenant schema codegen** (v1.27+, `src/codegen/`): `GET /t/<id>/openapi.json` (OpenAPI 3.1, all CRUD + `/search` + `/subscribe` + FilterAst `$ref`), `GET /t/<id>/types.ts` (TypeScript Row / Insert / Update interfaces with FK JSDoc), `GET /t/<id>/zod.ts` (RowSchema / InsertSchema / UpdateSchema runtime validators; vector → `z.array(z.number()).length(N)`). Bearer-gated; anon vs service shapes differ — service surface includes per-collection / field / index descriptions, anon strips them. `X-Drust-Schema-Source: anon|service` response header records which view was rendered. Golden-file tests under `tests/codegen/golden/` regenerate with `DRUST_CODEGEN_REGENERATE=1`.
- **Admin `_list` endpoint** (v1.28+, `src/mgmt/collection_list.rs`): `POST /admin/tenants/<id>/collections/<coll>/_list` body `{filters:[{field,op,value}], sort, page, per_page}` returns `{columns, rows, total, page, per_page, total_pages}`. Bridges UI ops (`contains` / `between` / `is_true` / `is_null` / etc.) onto `FilterAst` then compiles with `?` binds. Bypasses the read-only authorizer for `_system_*` tables (admin path; connection still `SQLITE_OPEN_READONLY`). Masks sensitive columns (`_system_users.password_hash`). Emits one audit row per call (op `admin.collection.list`). Backs the chip filter on the redesigned collection editor (see Admin UI section).
- **Mode B large-file upload / tus 1.0** (v1.33+, `src/uploads/`): resumable-upload server at `/t/<id>/uploads/*`. Five tus methods — `OPTIONS` (capability), `POST` (create session), `HEAD` (offset probe), `PATCH` (append chunk), `DELETE` (abort) — plus service-only `GET` (list sessions). Each `PATCH` chunk is bounded by `DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES` (default 64 MiB) via a per-route `DefaultBodyLimit`; chunks append to a durable spool file (`tenants/<id>/_uploads/<token>.part`) so the filesystem byte-count is the offset source of truth and resume survives client disconnect and server restart. On completion: `INSERT OR IGNORE` a `_system_files` row (SQLite-first, idempotent), stream the spool to Garage via `put_file_in`, then delete the spool and session row. Service-key-only (`403 WRITE_DENIED` for anon/user). New per-tenant `_system_upload_sessions` table. Four env knobs: `DRUST_LARGE_UPLOAD_MAX_BYTES` (2 GiB), `DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES` (64 MiB), `DRUST_LARGE_UPLOAD_MAX_SESSIONS_PER_TENANT` (5), `DRUST_LARGE_UPLOAD_SESSION_TTL_SECS` (86400). Hourly in-process janitor reclaims abandoned sessions; never touches `_system_files` or Garage. Mode A (`POST /t/<id>/files`) unchanged.

### Auth

- **Bearer tokens** (`meta.sqlite`): per-tenant anon + service. Resolved in `bearer_auth_layer`, which also wires rate-limit + audit; denials get `error_code: HTTP_<status>`.
- **End-user auth** (v1.9+): per-tenant `_system_users` + `_system_sessions`. Tokens `drust_user_*`, SHA-256-hashed, sliding 30d. argon2id verify with fixed `DUMMY_HASH` for timing equalization. Brute-force defenses: per-IP rate-limit on login (5/min) + register (3/min), IP = XFF[-2]. Self-register opt-in via `tenants.allow_self_register`. Admin REST `/t/<id>/admin/users` + 9 MCP tools + admin UI virtual entry. Daily janitor binary `drust_session_janitor` (async, per-tenant DELETEs via `pool.with_writer`) sweeps expired sessions with 1d grace.
- **Admin OAuth** (v1.11+): Google + GitHub buttons on `/drust/login`. Env-driven (`DRUST_OAUTH_*` + `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS` + `DRUST_PUBLIC_URL`). `src/mgmt/oauth_login.rs::oauth_callback` runs a 9-step chain. Google id_token base64-decoded WITHOUT sig verification (confidential client, TLS-trusted token endpoint, per OIDC Core §3.1.3.7). Per-IP 5/min on callback. See [`docs/oauth-setup.md`](docs/oauth-setup.md).
- **Per-tenant OAuth** (v1.12+): each tenant configures Google/GitHub for its own end users. Config in per-tenant `_system_oauth_providers`. End-user flow returns to frontend with `<cb>#access_token=drust_user_xxx` (Supabase/Auth0 URL-fragment pattern). Allowlisted redirect URIs exact-match, re-checked TOCTOU-safe at callback. Sentinel `password_hash="$oauth-only$"` blocks password login + `/me/password` (`409 OAUTH_ONLY_NO_PASSWORD`). Per-IP 5/min on callback.
- **OAuth library** (`src/oauth/`): `OauthProvider` trait + Google + GitHub adapters + state/PKCE helpers, shared by admin and per-tenant flows. `TenantAuthState.oauth_adapter_override` injects mocks in tests.

### Background work

- **Stats sampler** (v1.15+, `src/mgmt/stats.rs::run_stats_sampler`): `tokio::spawn` refresh of `meta.sqlite.tenants.{db_bytes, files_bytes, stats_updated_at}` at `DRUST_STATS_SAMPLE_INTERVAL_SECS` (default 300s; 0 disables). `/admin/tenants` reads only meta — TTFB drops from ~1–2s to <50ms at N=15 tenants. Fresh tenants get one immediate `sample_one()` after create so the row renders with real numbers on next load.
- **Outbound webhooks** (v1.13+, `_system_webhooks`): CRUD events publish to matching subscriptions via `WebhookDispatcher` — `tokio::spawn` per delivery, HMAC-SHA256-signed POST, 4 attempts (+0/+1/+5/+30s, 10s each). 4xx terminal, 5xx/network retryable. No outbox; events lost on mid-POST crash (accepted). Three config surfaces (admin sidebar `🔔 _webhooks`, service-only REST, MCP). Secret 32-byte hex returned plaintext exactly once; PATCH cannot rotate (rotate = delete + create). **DNS-rebind close** (v1.21+, `src/tenant/webhook_resolver.rs`): `PinnedPublicResolver` filters RFC1918 / loopback / link-local at every dispatch attempt; `check_url` register-time gate retained (defense in depth — drop either and pre-patch rows re-open the hole). Dev `http://localhost` bypass.
- **SSE broadcast** per `(tenant, collection)` from record CRUD. Gated by composed `realtime_enabled AND anon_caps[select]` — see invariants.
- **WS rooms broadcast** (v1.31+, `src/tenant/rooms/`): multiplex `GET /t/<id>/realtime` (one conn → N rooms via `op:subscribe`/`op:publish` frames) + REST `POST /t/<id>/rooms/<room>` + MCP `broadcast` tool. Subscribe is open to anon / user / service. Publish was service-only until **v1.32.5**, which introduced two opt-in tenant flags `allow_user_publish` / `allow_anon_publish` (default off) read by `bearer_auth_layer` and gated through the shared `check_publish_allowed` helper (`src/tenant/rooms/policy.rs`). MCP `broadcast` stays service-only by MCP dispatch regardless of these flags — defense in depth ≥ 2. Admin surface: `PATCH /admin/tenants/<id>/publish-policy`, two checkboxes on `_api_keys`, and MCP `set_publish_policy`. Deny codes: REST `PUBLISH_USER_DENIED` / `PUBLISH_ANON_DENIED` (legacy `WRITE_DENIED` retained in `error_aliases`); WS `WS_PUBLISH_USER_DENIED` / `WS_PUBLISH_ANON_DENIED`.
- **Soft-delete** moves `tenants/<id>/` into `_trash/<id>-<ts>/`; `drust-janitor.timer` deletes after 7d.
- **Daily backup** (`drust-backup.timer`): `VACUUM INTO` snapshots both `meta.sqlite` and `meta_logs.sqlite` → `backups/drust-YYYY-MM-DD-HHMMSS.tar.zst` (30d retention). Admin UI at `/admin/backups`: list + per-snapshot inspect (extract meta.sqlite, list tenants + sizes) + restore-to-`_trash` (admin manually `mv`s back after review). Filename whitelisted, tenant_id strictly uuid-v4-shaped; both paths 400 on traversal. Lives in `src/mgmt/backups.rs`.

### Admin UI

Two pages (v1.5.1+): `/admin/tenants` (search-able list) and `/admin/tenants/{id}/<datatable>` (2-pane shell). `GET /admin/tenants/{id}` 302s to `/admin/tenants/{id}/_overview`. Eight virtual sidebar entries always shown in order: `⌂ _overview`, `🔑 _api_keys`, `⚡ _rpc`, `🔒 _system_files`, `👤 _system_users`, `🔐 _oauth_providers`, `🔔 _webhooks`, `📋 _logs` — then real collections from `sqlite_master`. Canonical order in `src/mgmt/templates/_collection_sidebar.html`.

- Every page renders inside a viewport-fixed `.macwin` with container-scoped scroll. 2-pane grid `var(--sidebar-w) minmax(0, 1fr)` lets right track shrink below content min-content (long URLs, wide tables). `/admin/tenants/{id}/collections` 302s to first collection; empty tenants get a dedicated empty-state page. **LiveChonk** pixel-cat mascot (`_mascot.html`) renders on any `<canvas class="pix" data-chonk=... data-size=...>`.
- **Collection editor** (v1.28 rewritten): `/admin/tenants/<id>/collections/<coll>` renders a Supabase-style page with sticky header (title + `[⚙]` settings popover + inline description), a non-sticky Table-mode toolbar (`[+ Filter]` chip popover, `[Sort]`, `[Per page]`), and a sticky footer with `[Table] [Definition]` view tabs + pager. Two view modes only: `Table` fetches rows via `POST /admin/tenants/<id>/collections/<coll>/_list` (FilterAst-backed); `Definition` shows fields + indexes inline. Anon caps, realtime broadcast toggle, SSE quickstart docs, and the EXPLAIN tool live in the `[⚙]` popover. Legacy `?tab=…` URLs 302-redirect to `?view=…`.
- **Audit UI** (v1.7+, rewritten v1.24+): `/admin/audit` (host) + `/admin/tenants/<id>/_logs` (per-tenant). SQL queries against `meta_logs.sqlite` via `src/mgmt/audit.rs` — total counts are honest by construction (no `MAX_ENTRIES` cap or in-memory scan cache). Browse-tab rows click-to-open via `drustUI.detail()` reading from an embedded `<script id="audit-entries">` JSON blob — the embed routes through the canonical `src/mgmt/script_json.rs` escaper (v1.33.1: `</`→`<\/`, `<!--`, U+2028/9 — losslessly `JSON.parse`-identical; HTML5 §8.2.6.4 closes `<script>` on any literal `</script>` regardless of `type=`). Every admin JSON-into-`<script>` island MUST route through that one escaper — never re-inline the `.replace` dance. Toolbar uses native `<datalist>` dropdowns sourced from meta.
- **i18n** (v1.22+): `drust_locale` cookie → `Accept-Language` → `en`. `src/mgmt/i18n.rs` (`Locale` + `Translator`) and `src/mgmt/locale_layer.rs` (outermost middleware on admin router). 20+ admin Templates carry `pub t: Translator`. Bundles compiled in via `include_str!`; `build.rs` panics on missing keys at compile time. ~690 keys.
- **Theming** (v1.23+, v1.25 hardened, v1.28.1 cookie unified): three themes `system` / `cozy-dark` / `soft-light`. `drust_theme` cookie + `admins.theme` DB column. `src/mgmt/theme.rs` + `src/mgmt/theme_layer.rs` registered TWICE — outer cookie-only layer covers unauthenticated routes (`/login`, OAuth callback); inner DB-aware layer inside `protected` (after `admin_session_layer`) reads `admins.theme` when cookie is absent. Both share one resolver via `ThemeLayerState.allow_db_fallback: bool`. Palettes in `themes/<code>.toml`, embedded via `include_str!`; `build.rs` enforces drift vs `EXPECTED_THEMES`. Cookie attrs `Path=/drust + Secure` (dev override `DRUST_DEV_NO_SECURE_COOKIES=1`); login + `/admin/settings` both route through `build_theme_cookie` / `build_locale_cookie` so attributes match (otherwise duplicate-Path cookies shadow saves — v1.28.1 fix).
- **CORS** (v1.5.1+) on tenant routes only, applied OUTSIDE `bearer_auth_layer` so OPTIONS preflight short-circuits before auth. Allow-list from `DRUST_CORS_ORIGINS` (exact origins or single-`*` patterns like `https://*.tzuchi.org` or `http://localhost:*`; multi-`*` rejected at parse). Wildcard tests in `tenant::origin_matches` cover suffix-injection + hyphen-confusion. Mgmt UI routes have no CORS layer.

## Storage integration (Garage client, v1.4.0+)

Optional. Activated by setting `GARAGE_S3_ENDPOINT` + friends in `.env`. When enabled, drust gains `/drust/admin/files` (list / upload / delete / reconcile) backed by `_system_files` in `meta.sqlite`.

- **Garage is an independent service** (see `tool/garage/CLAUDE.md`). drust speaks plain S3 via `object_store::aws::AmazonS3`. drust boots with Garage unreachable — storage tab shows "not configured" / admin ops return 503; rest of drust unaffected.
- **Reads bypass drust.** Anonymous GETs hit Caddy `/public/*` and `/t-public/<tenant>/*`, which reverse-proxy to Garage `s3_web` (`127.0.0.1:47831`) with `Host: public.web.local` or `Host: tenant-<id>-pub.web.local`. drust is only in the *write* path.
- **SQLite-first upload / S3-first delete.** Upload inserts metadata row, puts to Garage, compensates by deleting row on S3 failure. Delete calls Garage first (idempotent on NotFound), then clears row. Orphans surfaced by `reconcile` page.
- **`_system_*` drop-protected.** `storage::schema::is_protected_collection()` is consulted by `drop_collection` MCP tool, for both admin-level `_system_files` and per-tenant `_system_files`.

## Per-tenant files (v1.5.0+)

On tenant create, drust auto-provisions `tenant-<id>-pub` (website enabled) + `tenant-<id>-prv` (private) buckets and grants the drust-client key owner access. Rollback on partial failure is compensating; leftover local state captured in `_trash_pending_revokes` / `_orphan_buckets` for the `reconcile` page to retry.

- **REST** at `/drust/t/<id>/files`: POST multipart upload / GET list / GET one / DELETE one / POST `<key>/sign` (pre-signed URL) / GET `<key>/bytes` (private proxy). Service-key-only.
- **MCP tools**: `list_files`, `delete_file`, `get_file_url`. No upload tool by design — the tenant MCP's `instructions` field points the LLM at the REST endpoint with a curl example.
- **Admin UI parity** at `/drust/admin/tenants/<id>/files`.
- **Disk guard**: uploads return 507 when `/var/lib/garage` has less than `DRUST_DISK_MIN_FREE_PCT` (default 20) percent free.

## Invariants

> [!WARNING]
> **Bearer tokens are the sole authorization boundary for data-plane access.** If a token leaks, it grants full read + structured write on the bound tenant until revoked. Never share tokens across tenants; never commit `.env`. The SQL authorizer in `src/query/authorizer.rs` is the in-SQL cross-tenant guarantee — if you loosen it (new `AuthAction` allow arms), re-prove: (a) ATTACH stays denied, (b) sqlite_master reads stay denied, (c) all write actions stay denied on read connections.

> [!CAUTION]
> **`header_up Host "127.0.0.1:47826"` is mandatory on the Caddy block** for `/drust/t/<tenant>/mcp` — rmcp's DNS-rebinding guard rejects non-loopback Hosts with a 403/421 that looks like a WAF. Same family for Garage `/public/*` which routes by `Host: <bucket>.web.local` (see Storage section).

Three further invariants are enforced in code; they don't need callouts but must not be loosened without re-reasoning:

- **User tokens (`drust_user_*`) cannot use `/query`, `/query/explain`, or `/mcp`.** drust does not rewrite user-supplied SQL, so `owner_field` cannot be enforced on those surfaces. Reject with `403 QUERY_USER_DENIED` / `MCP_USER_DENIED`. For per-user reads of owner-scoped data, expose a stored RPC with `:user_id` (auto-bound from `AuthCtx`), or use `/search` (v1.10+) / `/list` (v1.21+) where drust builds the SQL.
- **`/search` and `/list` accept user tokens; `/query` does not.** All three take structured input from users, but `/query` accepts raw SELECT (un-rewritable) while `/search` and `/list` take only `FilterAst` (`src/query/vector_filter.rs`) compiled with `?` binds, so `owner_field` is always enforceable. Any new endpoint accepting user input that lands in SQL must explicitly pick a camp.
- **Anon SSE access requires `realtime_enabled AND anon_caps[select]`.** Both flags surface the same row content — opening one without the other is a side-channel leak. Disable order: PUT `/realtime` and MCP `set_realtime` invalidate `pool.schema_cache` BEFORE `bus.evict_collection`, so subscribers racing the gap read fresh schema and fail the gate immediately.
- **Mode B keeps every HTTP request small by design (chunks ≤ `DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES`, default 64 MiB) so it stays under the 200 MB Caddy/.221 ingress limit.** Never raise a body-limit to accommodate large uploads — the tus chunking protocol exists precisely so each individual request stays small.

## Directory map

See [`docs/architecture.md`](docs/architecture.md) — auto-generated per-file index of what each `.rs` declares, imports, and is imported by. Rebuild with `bash docs/gen-architecture.sh`.

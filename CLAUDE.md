---
type: service
kind: http
name: drust
port: 47826
path: /drust
status: production
updated: 2026-05-05
version: 1.7.2
---

# drust — Rust multi-tenant SQLite BaaS

Self-hosted service providing a management UI (PocketHost-like) and per-tenant REST + MCP endpoints backed by isolated SQLite files. Design: [`docs/superpowers/specs/2026-04-20-drust-design.md`](../docs/superpowers/specs/2026-04-20-drust-design.md). Implementation plan: [`docs/superpowers/plans/2026-04-20-drust.md`](../docs/superpowers/plans/2026-04-20-drust.md).

> [!TIP]
> For a per-file orientation index — which file declares what, imports from where, is imported by whom — see [`docs/architecture.md`](docs/architecture.md). Auto-generated from `src/**/*.rs`; rebuild after structural changes with `bash docs/gen-architecture.sh`. The file lists public items, `use crate::...` edges, and `mod X;` module tree, so you can navigate without re-reading every `.rs`.

## Build & restart

```bash
cd /home/kaelsohappy1/tool/drust
cargo build --release
sudo systemctl restart drust
curl -s http://127.0.0.1:47826/health   # → ok
```

## Architecture at a glance

- `meta.sqlite` (management plane): admins, sessions, tenants, hashed bearer tokens. Admin password rotation: `src/bin/set_admin_password.rs` CLI, reads the new password from stdin and hashes via argon2id.
- `tenants/<id>/data.sqlite` (data plane): one SQLite per tenant.
- Reads route through `SQLITE_OPEN_READONLY` connections with `sqlite3_set_authorizer` whitelist (see `src/query/authorizer.rs`). Cross-tenant `ATTACH` is denied.
- **Per-collection DML capability** (v1.6.0+): every collection's schema metadata declares `anon_caps`, a subset of `{select, insert, update, delete}`. Default `[select]` (status quo). Service is unrestricted. The check fires at REST handler entry against a per-tenant `SchemaCache` (`src/storage/schema_cache.rs`); cache invalidation lives in the DDL paths and the admin UI's anon_caps endpoint. Persisted in the per-tenant `_system_collection_meta` table (one row per collection).
- **Stored RPCs** (v1.6.0+): tenant-local `_system_rpc` table holds named SELECT functions, callable via REST `POST /drust/t/<id>/rpc/<name>` and the MCP `call_rpc` tool. Service-only authoring; per-RPC `anon_callable` flag gates the REST anon path (MCP is service-only unconditionally). Counters (`anon_calls`, `service_calls`, `last_called_at`) bumped through the writer mutex regardless of caller. SQL is validated at create time via `prepare()` under the read-only authorizer. **Test playground** (v1.7.2+): `/admin/tenants/{id}/_rpc/{name}/test` renders type-aware param inputs, runs against a read connection, and shows result rows + `duration_ms` + `EXPLAIN QUERY PLAN`. Reuses `execute_read_query_with_named` + `validate_and_bind` directly — no duplication of the gating logic.
- Writes go through structured REST/MCP tools against a serialized writer mutex; schema enforcement at tool layer. `FieldSpec` supports allowlisted SQL defaults (`{"sql": "datetime('now')"}`) and foreign keys (`foreign_key: "<target>"` emits `ON DELETE RESTRICT`).
- **Per-tenant rmcp Streamable HTTP MCP endpoint at `/t/<tenant>/mcp`** serving all 21 tools. One `StreamableHttpService<DrustMcpService>` per tenant, cached in `src/mcp/http_registry.rs`. MCP is **service-key-only** — anon bearers get `403 WRITE_DENIED`. Enforced in `src/tenant/mcp_dispatch.rs` before the dispatch; the route still runs through `bearer_auth_layer` so auth + rate-limit + audit all cover it.
- Admin UI is **two pages** (v1.5.1+): `/admin/tenants` (search-able list) and `/admin/tenants/{id}/<datatable>` (2-pane shell). The old stand-alone `/admin/tenants/{id}` detail page is gone — `GET /admin/tenants/{id}` 302-redirects to `/admin/tenants/{id}/_api_keys`. Three sidebar entries are virtual / always-shown: `🔑 _api_keys` (anon · service · MCP setup, rendered by `tenant_api_keys.html`), `🔒 _system_files` (storage, rendered by `tenant_files_admin.html`), then the real collections from `sqlite_master`. The MCP `claude mcp add-json` command lives inside `_api_keys` and copies via `window.location.origin` — no backend URL template needed.
- Admin UI (v1.2.0+): every page renders inside a viewport-fixed `.macwin` with container-scoped scroll. The 2-pane shell uses `grid-template-columns: var(--sidebar-w) minmax(0, 1fr)` so the right track can shrink below content min-content (long URLs, wide tables) instead of pushing cards past the sidebar boundary. `/admin/tenants/{id}/collections` 302-redirects to the first collection; empty tenants see a dedicated empty-state page. Breadcrumbs were removed from every admin page in v1.5.1 — the topbar `path` (`~/tenants/{id}/...`) carries clickable anchors per segment. The **LiveChonk** pixel-cat mascot (`_mascot.html`) is wired to any `<canvas class="pix" data-chonk=... data-size=...>` — 18 px in the topbar, 48 px on login, 96 px on empty states, 56 px on errors.
- **Admin audit UI** (v1.7.0+): two GET routes serving the existing audit JSONL files. `/admin/audit` (host) and `/admin/tenants/{id}/_logs` (per-tenant via sidebar virtual entry `📋 _logs`). Stateless: every request rescans `$DRUST_LOG_DIR/audit-*.jsonl{,.N,.N.gz}` via `src/mgmt/audit.rs`; no in-memory ring buffer, no SQLite index. `AuditEntry` (`src/safety/audit.rs`) now derives `Deserialize` (and `status` is `String`). `flate2` reads rotated `.gz` archives. Hard cap 50 000 entries per request — overflow truncated newest-first with UI footer warning.
- **Rate-limit + audit middleware are wired** into `bearer_auth_layer` (v0.1.0 Known issues closed in v1.1.1). Each tenant request produces one `audit-YYYY-MM-DD.jsonl` entry in `$DRUST_LOG_DIR`; denials get `error_code: HTTP_<status>`.
- **CORS** (v1.5.1+): tenant routes (`/t/<tenant>/...`) carry a `tower_http::cors::CorsLayer` applied **outside** `bearer_auth_layer` so `OPTIONS` preflight short-circuits before auth (preflight by spec carries no token). Allow-list comes from `DRUST_CORS_ORIGINS`; empty/unset disables the layer. Each entry is either an exact origin (`https://app.example.com`) or a single-`*` pattern — e.g. `https://*.tzuchi.org` matches any subdomain (refuses the bare apex), `http://localhost:*` matches any dev port. Multi-`*` patterns are rejected at parse time. Wildcard semantics live in `tenant::origin_matches` with unit tests against suffix-injection (`https://tzuchi.org.attacker.com`) and hyphen-confusion (`https://attacker-tzuchi.org`). Real GET/POST/etc. still flow through `bearer_auth_layer` unchanged — CORS only intercepts preflight and appends `Access-Control-Allow-Origin` to responses. Mgmt UI routes (`/admin/*`) have no CORS layer; they're server-rendered.
- SSE broadcast channels per `(tenant, collection)` fan events from record CRUD.
- Soft-delete moves `tenants/<id>/` into `_trash/<id>-<ts>/`; `drust-janitor.timer` deletes after 7d.
- Daily `drust-backup.timer` runs `VACUUM INTO` snapshots → `backups/drust-YYYY-MM-DD-HHMMSS.tar.zst` (30d retention). **Admin UI** (v1.7.1+): `/admin/backups` lists snapshots with size + age + ISO mtime, `/admin/backups/{filename}/download` streams the .tar.zst (`tokio_util::io::ReaderStream`, no buffering). v1.7.2 adds `/admin/backups/{filename}/inspect` (extract meta.sqlite on a blocking thread, list tenants + per-tenant data.sqlite size in archive) and `POST /admin/backups/{filename}/restore` (extract a single tenant's data.sqlite + meta.json to `_trash/<tid>-restored-<ts>/` — does **not** overwrite the live dir; admin `mv`s back manually after review). tenant_id strictly uuid-v4-shaped, filename whitelisted to `drust-…tar.zst`; both paths 400 on traversal. Lives in `src/mgmt/backups.rs`. Deps: `tar`, `zstd`, `tempfile`.

## Storage integration (Garage client, v1.4.0+)

Optional. Activated by setting `GARAGE_S3_ENDPOINT` + friends in `.env`. When enabled, drust gains `/drust/admin/files` (list / upload / delete / reconcile) backed by a `_system_files` metadata collection in `meta.sqlite`.

- **Garage is an independent service** (see `tool/garage/CLAUDE.md`). drust speaks plain S3 to it via `object_store::aws::AmazonS3`. drust boots with Garage unreachable — the storage tab shows "not configured" / admin operations return 503, but the rest of drust (tenants, MCP, REST, auth) is unaffected.
- **Reads bypass drust.** Anonymous GETs hit Caddy `/public/*` and `/t-public/<tenant>/*`, which reverse-proxy to Garage `s3_web` (`127.0.0.1:47831`) with `Host: public.web.local` or `Host: tenant-<id>-pub.web.local` respectively. drust is only in the *write* path.
- **SQLite-first upload / S3-first delete.** Upload inserts the metadata row, puts to Garage, and compensates by deleting the row on S3 failure. Delete calls Garage first (idempotent on NotFound), then clears the row. Orphans from partial failures are surfaced by the `reconcile` page.
- **`_system_*` collections are drop-protected.** `storage::schema::is_protected_collection()` is consulted by the `drop_collection` MCP tool. Applies to both the admin-level `_system_files` (in `meta.sqlite`) and the per-tenant `_system_files` (in each `data.sqlite`).

## Per-tenant files (Y scope, v1.5.0+)

When a tenant is created, drust auto-provisions two Garage buckets — `tenant-<id>-pub` (website enabled) and `tenant-<id>-prv` (private) — and grants the drust-client key owner access to both. Rollback on partial failure is compensating; leftover local state after Garage errors is captured in `_trash_pending_revokes` / `_orphan_buckets` for the `reconcile` page to retry.

- **Per-tenant file REST** at `/drust/t/<id>/files` — POST multipart upload / GET list / GET one / DELETE one / POST `<key>/sign` (pre-signed URL) / GET `<key>/bytes` (private proxy). Service-key-only.
- **Three file MCP tools**: `list_files`, `delete_file`, `get_file_url`. MCP has no upload tool; the `instructions` field on each tenant's MCP server directs the LLM to the REST endpoint with a curl example.
- **Admin UI parity** at `/drust/admin/tenants/<id>/files` — same upload/list/delete/sign form as the host-level `/admin/files`, scoped to the tenant's own buckets.
- **Disk guard**: uploads refuse with 507 when `/var/lib/garage` has less than `DRUST_DISK_MIN_FREE_PCT` (default 20) percent free.

> [!IMPORTANT]
> Garage's `s3_web` endpoint routes by **Host header** (`<bucket>.web.local`). The Caddy `reverse_proxy` for `/public/*` MUST carry `header_up Host "public.web.local"` or every request returns `NoSuchBucket`. Same family of gotcha as the MCP `header_up Host "127.0.0.1:47826"` below.

## Invariants

> [!WARNING]
> **Bearer tokens are the sole authorization boundary for data-plane access.** If a token leaks, it grants full read + structured write on the bound tenant until revoked. Never share tokens across tenants; never commit `.env`.

> [!CAUTION]
> **`header_up Host "127.0.0.1:47826"` is mandatory on the Caddy block** for the MCP sub-route `/drust/t/<tenant>/mcp`. rmcp's DNS-rebinding guard rejects non-loopback Hosts with a 403/421 that looks like a WAF.

> [!IMPORTANT]
> The SQL authorizer in `src/query/authorizer.rs` is the cross-tenant isolation guarantee at the SQL layer. If you loosen it (e.g. add new `AuthAction` allow arms), re-prove: (a) ATTACH stays denied, (b) sqlite_master reads stay denied, (c) all write actions stay denied on read connections.

## Directory map

See `docs/superpowers/plans/2026-04-20-drust.md` `## File layout this plan builds`.

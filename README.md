---
type: index
name: drust
status: production
updated: 2026-06-04
---

# drust

> Self-hosted, multi-tenant SQLite Backend-as-a-Service in Rust — REST + MCP per tenant, admin UI, optional S3 file storage.

[繁體中文 README](README.zh.md) · [Architecture index](docs/architecture.md) · [Changelog](CHANGELOG.md) · [Internal guide for AI agents](CLAUDE.md)

---

## What is drust?

**drust** is a single-binary HTTP service that turns a Linux host into a PocketHost-like tenant database platform: each tenant gets an isolated SQLite database, a structured write API, an MCP endpoint that LLMs can call directly, and an admin UI for schema editing. Built with [axum](https://github.com/tokio-rs/axum) and [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk).

**Why it exists.** Spinning up a Postgres / Supabase per project is overkill for the hundreds of small CRUD apps and AI-agent scratchpads in our org. drust gives each project its own self-contained `tenant.sqlite`, a hashed bearer token, and a fully-typed API — no schema migration tooling, no separate database server, no manual SQL injection audit.

## Key features

- **Per-tenant SQLite isolation.** One file per tenant under `tenants/<id>/data.sqlite`. Cross-tenant `ATTACH` is denied at the SQL authorizer layer.
- **Structured REST + MCP write API.** Writes never accept raw SQL; tools enforce schema, types, FK constraints, and an opt-in DML capability allowlist (`anon_caps`) per collection. WebSocket broadcast frames are serialized once per publish regardless of subscriber count.
- **Read-only SQL via authorizer whitelist.** Read connections open `SQLITE_OPEN_READONLY` and run under [`sqlite3_set_authorizer`](https://www.sqlite.org/c3ref/set_authorizer.html) — no `sqlite_master`, no `ATTACH`, no writes.
- **Streamable HTTP MCP per tenant.** `/t/<tenant>/mcp` exposes the full CRUD / schema / index / RPC / file / vector-search / webhook tool surface. One server instance per tenant, served over the [Streamable HTTP transport](https://spec.modelcontextprotocol.io/specification/2024-11-05/basic/transports/#streamable-http). Service-key only.
- **AI introspection helpers.** Every REST error JSON carries a context-aware `suggested_fix` field; the same hint reaches MCP clients via `ErrorData.data`. Destructive tools (`delete_record`, `drop_collection`, `drop_index`) accept `dry_run: true` and return blast-radius counts without mutating. A service-only `recent_writes` MCP tool lets a retrying model recover what its previous attempt already did.
- **Per-tenant schema codegen.** `GET /t/<id>/openapi.json`, `GET /t/<id>/types.ts`, and `GET /t/<id>/zod.ts` emit OpenAPI 3.1, TypeScript `Row` / `Insert` / `Update` interfaces, and Zod runtime validators tailored to the tenant's current schema (vector fields → `z.array(z.number()).length(N)`). Anon vs service views differ; `X-Drust-Schema-Source` header records which was rendered.
- **Stored RPCs.** Tenants can define named SELECT functions (Supabase-style) callable via `POST /t/<id>/rpc/<name>` or the MCP `call_rpc` tool. SQL is validated at create-time under the read-only authorizer; a built-in admin test playground runs them with `EXPLAIN QUERY PLAN`.
- **Vector storage + similarity search.** Per-collection `vector` field type (packed f32 BLOB) with `POST /t/<id>/collections/<c>/search` for cosine / L2 / L1 top-k under a Filter AST. `sqlite-vec` is registered as a SQLite auto-extension so `vec_distance_*` are also callable from `/query` and stored RPCs.
- **Realtime broadcast.** Two surfaces: SSE channel per `(tenant, collection)` at `/t/<id>/records/<c>/subscribe` (gated by per-collection `realtime_enabled` and `anon_caps[select]`), and the v1.31 per-tenant WS multiplex at `/t/<id>/realtime` with rooms, rate-limit / lagged-recovery frames, and an in-admin Broadcast Inspector for end-to-end smoke testing. Room subscribe is open to anon / user / service; publish is service-key-only by default, with opt-in per-tenant `allow_user_publish` / `allow_anon_publish` flags.
- **End-user auth + per-tenant OAuth.** Per-tenant `_system_users` with Google / GitHub OAuth providers configured per tenant; opt-in self-registration; row-level filter via `owner_field` + `read_scope`; argon2id password hashing with timing-equalized login.
- **Outbound webhooks.** Per-tenant CRUD-event subscriptions, HMAC-SHA256-signed POST with 4-attempt retry (+0s / +1s / +5s / +30s); admin UI + REST + MCP write surfaces; SSRF guard rejects private/loopback/CGNAT and IPv6-mapped equivalents at every dispatch attempt; HTTP client reused across attempts with per-Request DNS so the resolver still runs on every connection.
- **Schema descriptions for LLM bootstrap.** Optional plain-text `description` on every collection / field / index / RPC, surfaced through `describe_collection` and `get_schema_overview` so an LLM can read the schema's intent in one MCP call.
- **Admin UI.** Two-page web UI (`/admin/tenants` + per-tenant `/admin/tenants/<id>/<datatable>`) with a Supabase-style collection editor (sticky header, FilterAst-backed Table mode via `POST /_list`, Definition view), file management, RPC editor + test playground, anon capability matrix, MCP setup snippets, audit log browser, backup browser with single-tenant restore, Broadcast Inspector. Localized (`en` / `zh-Hant`) with three themes (`system` / `cozy-dark` / `soft-light`).
- **Admin Personal Access Tokens.** Each admin gets their own PAT for CLI / MCP use instead of sharing the per-tenant service key. PATs are admin-scoped (not bound to a single tenant) and revoked centrally from the admin UI.
- **S3 file storage (optional).** When configured, every tenant gets two S3 buckets — `<id>-pub` (website-enabled) and `<id>-prv` (private) — provisioned automatically. Implemented against [Garage](https://garagehq.deuxfleurs.fr/) but the data path is plain S3 (`object_store::aws::AmazonS3`).
- **Resumable large-file upload (tus 1.0).** A second ingest path at `/t/<id>/uploads/*` (Mode B) accepts 200 MB–1 GB+ files without raising any infrastructure body-limit: tus `PATCH` chunks are capped (default 64 MiB) and appended to a durable per-tenant spool, so the filesystem byte-count is the resume offset — uploads survive client disconnect and server restart. Finalize is SQLite-first + idempotent, then streams the spool to the object store. Service-key only; Mode A (`POST /t/<id>/files`) is unchanged.
- **Admin OAuth.** `/admin/login` accepts Google / GitHub OAuth alongside username + password; controlled via env allowlist; id_token `iss` / `aud` / `exp` claims validated per OIDC §3.1.3.7.
- **Observability.** Admin-session-gated `/admin/_metrics` Prometheus endpoint exposes audit drops, bearer denials, webhook attempts, active WS connections, and per-tenant DB bytes. Audit rows land in `meta_logs.sqlite` with a 90-day retention sweep + monthly VACUUM, queryable from the admin UI.
- **Operational basics.** Per-tenant rate limiting, daily `VACUUM INTO` snapshots with 30-day retention (covers `meta.sqlite` + `meta_logs.sqlite`), soft-delete with 7-day grace, CORS allow-list with subdomain wildcards.

## Architecture at a glance

```
                            ┌─────────────────── drust :47826 ──────────────────┐
       ┌──────────┐         │                                                   │
client │ TLS edge │ ── HTTP ▶│  axum router                                     │
       └──────────┘         │   ├─ /admin/*           (cookie session)         │
                            │   ├─ /t/<id>/...        (bearer auth)            │
                            │   └─ /t/<id>/mcp        (rmcp Streamable HTTP)   │
                            │                                                   │
                            │  ┌─ meta.sqlite ────┐  ┌─ tenants/<id>/data.sqlite│
                            │  │ admins (+ PAT)   │  │ user collections         │
                            │  │ tenants          │  │ _system_collection_meta  │
                            │  │ tokens (hash)    │  │ _system_users / _sessions│
                            │  │ sessions         │  │ _system_rpc              │
                            │  └──────────────────┘  │ _system_files            │
                            │  ┌─ meta_logs.sqlite ┐ │ _system_webhooks         │
                            │  │ audit (rolling)  │  │ _system_oauth_providers  │
                            │  └──────────────────┘  └──────────────────────────│
                            └─────────────────┬─────────────────────────────────┘
                                              │ optional S3 (Garage / MinIO / R2)
                                              ▼
                                    ┌────────────────────┐
                                    │ public bucket +    │
                                    │ tenant-<id>-pub /  │
                                    │ tenant-<id>-prv    │
                                    └────────────────────┘
```

Public-bucket reads bypass drust entirely — they're served straight from the S3 web endpoint via reverse proxy. drust only sits in the *write* path.

## API surfaces

| Surface | Path | Auth | Use |
|---|---|---|---|
| Admin UI | `/admin/*` | Cookie session | Tenant + schema management, file ops |
| Tenant REST | `/t/<id>/...` | Bearer (`anon` or `service`) | CRUD, RPC calls, file ops |
| Tenant MCP | `/t/<id>/mcp` | Bearer (`service` only) | LLM tool calls — CRUD, schema, indexes, RPCs, files, vector search, webhooks |
| Health | `/health` | none | Liveness probe |

The full per-file index of public items, module imports, and call graph lives in [`docs/architecture.md`](docs/architecture.md) (auto-generated from `src/**/*.rs`).

## Quick start

```bash
git clone https://github.com/KaelLim/drust.git
cd drust
cp .env.example .env             # edit DRUST_INIT_ADMIN_* and friends
cargo build --release
./target/release/drust            # binds 127.0.0.1:47826 by default
curl -s http://127.0.0.1:47826/health   # → ok
```

For systemd-based deployment behind a reverse proxy, see [`CLAUDE.md`](CLAUDE.md) §"Build & restart" and the upstream `tool/services.md` runbook.

> **MCP gotcha.** rmcp's DNS-rebinding guard rejects any non-loopback `Host` header. If MCP requests return `403/421` from behind a proxy, your reverse proxy must rewrite `Host: 127.0.0.1:47826` upstream. Full diagnostic write-up linked from [`CLAUDE.md`](CLAUDE.md).

## Configuration

Configured via environment variables (loaded from `.env` by systemd or your shell):

| Variable | Required | Purpose |
|---|---|---|
| `DRUST_DATA_DIR` | yes | Base directory for `meta.sqlite` and `tenants/` |
| `DRUST_INIT_ADMIN_USERNAME` | yes (first boot) | Bootstrap admin account |
| `DRUST_INIT_ADMIN_PASSWORD` | yes (first boot) | Bootstrap admin password |
| `DRUST_LOG_DIR` | yes | Reserved log directory (audit rows themselves write to `meta_logs.sqlite` since v1.24) |
| `DRUST_CORS_ORIGINS` | optional | Comma-separated allow-list, supports `https://*.example.com` |
| `DRUST_DISK_MIN_FREE_PCT` | optional (default 20) | Upload guard for tenant file storage |
| `GARAGE_S3_ENDPOINT` + `GARAGE_S3_ACCESS_KEY` + `GARAGE_S3_SECRET_KEY` | optional | Enables S3 storage features |
| `GARAGE_ADMIN_ENDPOINT` + `GARAGE_ADMIN_TOKEN` | optional | Required to auto-provision per-tenant buckets |

The data-plane S3 path uses `object_store::aws::AmazonS3` so any S3-compatible service works (Garage, MinIO, Cloudflare R2, AWS S3, B2). Auto-bucket provisioning is Garage-specific — for other backends, buckets must be pre-created and per-tenant key issuing handled out-of-band.

## Project structure

```
src/
  main.rs            entry point, router assembly
  config.rs          env-driven configuration
  auth/              cookie sessions, bearer tokens, argon2id hashing
  oauth/             OAuth provider library (Google + GitHub adapters)
  db/                meta.sqlite migrations
  mgmt/              admin UI handlers + askama templates
  tenant/            tenant lifecycle, REST router, bearer middleware
  storage/           sqlite pool, schema, file/object metadata, Garage client
  query/             SQL authorizer whitelist + structured filter AST
  rpc/               stored RPC: prepare, registry, REST + MCP handlers
  mcp/               rmcp tool definitions, Streamable HTTP service registry
  codegen/           per-tenant OpenAPI / TypeScript / Zod schema generators
  safety/            audit log + audit-DB writer, rate limiter, blast-radius probes
  bin/set_admin_password.rs   out-of-band password rotation CLI
  bin/set_admin_role.rs       admin role flip (owner / member)
  bin/drust_session_janitor.rs  expired-session sweeper (daily systemd timer)
docs/
  architecture.md    auto-generated source-graph index (rebuild via gen-architecture.sh)
CHANGELOG.md         keepachangelog format, semver
CLAUDE.md            internal guide for AI coding agents
```

## Status

Production. Currently `v1.33.2`. See [CHANGELOG.md](CHANGELOG.md) for full history.

## License

drust is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

Self-hosting for personal, internal, or non-commercial use is fully covered by AGPL-3.0. If you intend to (a) offer drust — or a modified version of it — as a hosted service to third parties, or (b) integrate drust into a proprietary product whose source you cannot release under AGPL, you will likely need a separate **commercial license**.

For commercial-license inquiries, please open a GitHub issue with the `commercial-license` label, or contact the maintainer via the email listed on the GitHub profile.

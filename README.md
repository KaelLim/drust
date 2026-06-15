---
type: index
name: drust
status: production
updated: 2026-06-15
---

# drust

> A self-hosted, multi-tenant **SQLite Backend-as-a-Service** in a single Rust binary — per-tenant REST **and** an MCP endpoint LLMs call directly, row-level security, realtime, vector search, edge functions, and S3 file storage. One file per tenant, no database server to run.

[繁體中文 README](README.zh.md) · [Architecture index](docs/architecture.md) · [Changelog](CHANGELOG.md) · [Internal guide for AI agents](CLAUDE.md)

---

## What is drust?

**drust** turns a single Linux host (or container) into a PocketHost-like database platform. Each tenant gets an isolated `data.sqlite`, a hashed bearer token, a fully-typed structured API, a per-tenant **MCP** server that AI agents can drive without glue code, and a Supabase-style admin UI for schema editing. Built on [axum](https://github.com/tokio-rs/axum) and [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk).

**Why it exists.** Standing up a Postgres or Supabase project per app is overkill for the hundreds of small CRUD apps, internal tools, and AI-agent scratchpads a team accumulates. drust gives each project its own self-contained `tenant.sqlite`, a typed API that never accepts raw SQL on the write path, and row-level security — no migration tooling, no separate DB server, no per-app injection audit. It targets **fast and dense**: idle ~15 MB RAM, ~13k req/s on a laptop, dozens of tenants on a 256 MB box.

## What you can build

- **A backend for a CRUD app or SaaS MVP** without running a database server — define collections in the admin UI, get REST + typed TypeScript/Zod clients instantly, ship.
- **An AI-agent-native datastore** — point any MCP client at `/t/<id>/mcp` and the agent can inspect the schema, CRUD rows, run vector search, and manage files through typed tools. Every error carries a `suggested_fix`; destructive ops support `dry_run`; the agent is productive on first connect because the MCP `instructions` prologue is a structured intent→tool map.
- **A multi-tenant platform** — one drust process hosts many fully-isolated tenants; cross-tenant access is denied in-SQL by the authorizer, not just in app code.
- **Per-user secured data** — declare an `owner_field`, or write **PocketBase-style row-level policies** (per-operation `using` / `check` predicates), and every read, write, and realtime event is filtered for you.
- **Realtime apps** — subscribe to a collection over SSE, or multiplex many rooms over one WebSocket and broadcast JSON to them.
- **Semantic / vector search** — add a `vector` field and query cosine / L2 / L1 top-k over a structured filter.
- **Event-driven automation** — upload a small WebAssembly **edge function** that runs in-process on `record.created/updated/deleted` or `file.uploaded`.
- **File-heavy apps** — per-tenant public/private object storage with resumable (tus 1.0) uploads for large files.

## Key features

### Data & isolation
- **Per-tenant SQLite isolation.** One file per tenant under `tenants/<id>/data.sqlite`. Cross-tenant `ATTACH` is denied at the SQL authorizer layer.
- **Structured REST + MCP write API.** Writes never accept raw SQL; tools enforce schema, types, FK constraints, SQL defaults, and an opt-in per-collection DML capability allowlist (`anon_caps`).
- **Read-only SQL via authorizer whitelist.** Read connections open `SQLITE_OPEN_READONLY` and run under [`sqlite3_set_authorizer`](https://www.sqlite.org/c3ref/set_authorizer.html) — no `sqlite_master`, no `ATTACH`, no writes.
- **Row-level security.** `owner_field` + `read_scope` give per-user row filtering; **explicit RLS policies** (`PUT /t/<id>/collections/<c>/policies`, or MCP `set_policy`) add PocketBase-style per-operation `using`/`check` predicates expressed as a structured Filter AST, compiled to `?`-bound SQL and AND-composed alongside the owner clause. Service keys bypass; user and anon callers are filtered on every read, write, and realtime surface.

### AI-native surface
- **Streamable HTTP MCP per tenant.** `/t/<tenant>/mcp` exposes the full CRUD / schema / index / RPC / file / vector-search / webhook / policy / function tool surface over the [Streamable HTTP transport](https://spec.modelcontextprotocol.io/specification/2024-11-05/basic/transports/#streamable-http). Service-key only; one server instance per tenant. The MCP `instructions` prologue is a structured capability map so an agent maps intent → tool without exhausting `tools/list`.
- **One-call schema bootstrap.** `get_schema_overview` returns every collection's schema + access state (owner_field, anon_caps, realtime, vector dims, RLS policies) and every RPC's callable contract in a single call.
- **AI introspection helpers.** Every REST error JSON carries a context-aware `suggested_fix`; the same hint reaches MCP clients via `ErrorData.data`. Destructive tools (`delete_record`, `drop_collection`, `drop_index`) accept `dry_run: true` and return blast-radius counts without mutating. A service-only `recent_writes` tool lets a retrying model recover what its previous attempt already did.
- **Per-tenant schema codegen.** `GET /t/<id>/openapi.json`, `types.ts`, and `zod.ts` emit OpenAPI 3.1, TypeScript `Row`/`Insert`/`Update` interfaces, and Zod validators tailored to the tenant's current schema. Anon vs service views differ; an `X-Drust-Schema-Source` header records which was rendered.

### Compute & realtime
- **Edge functions (WebAssembly).** Per-tenant user-uploaded `.wasm` (wasm32-wasip2 component) functions run in-process via [wasmtime](https://wasmtime.dev/), triggered by `record.created/updated/deleted` (per collection) or `file.uploaded`. The host API is the same transport-agnostic tool layer the REST/MCP faces use, so a function's writes fan out to SSE + webhooks for free. Sandboxed by capability absence + per-tenant isolation + an epoch deadline + a memory cap. A guest SDK template ships under `sdk/edge-function-template/`.
- **Stored RPCs.** Named SELECT functions (Supabase-style) callable via `POST /t/<id>/rpc/<name>` or the MCP `call_rpc` tool; SQL validated at create time under the read-only authorizer; an in-admin test playground runs them with `EXPLAIN QUERY PLAN`. `:user_id` auto-binds from the caller's user token.
- **Vector storage + similarity search.** Per-collection `vector` field (packed f32 BLOB) with `POST /t/<id>/collections/<c>/search` for cosine / L2 / L1 top-k under a Filter AST. `sqlite-vec` is a registered auto-extension, so `vec_distance_*` is also callable from `/query` and stored RPCs.
- **Realtime broadcast.** SSE per `(tenant, collection)` at `/t/<id>/records/<c>/subscribe` (gated by `realtime_enabled` + `anon_caps[select]`, owner/policy-filtered for anon), and a per-tenant WS multiplex at `/t/<id>/realtime` with rooms, rate-limit / lagged-recovery frames, and an in-admin Broadcast Inspector. Subscribe is open; publish is service-key-only by default, with opt-in `allow_user_publish` / `allow_anon_publish`.

### Auth, files & ops
- **End-user auth + per-tenant OAuth.** Per-tenant `_system_users` with Google / GitHub providers configured per tenant; opt-in self-registration; argon2id hashing with timing-equalized login; sliding 30-day sessions.
- **Object storage (optional, S3-compatible).** Two host-wide buckets — `public` (website-served) and `private` (drust-proxied) — namespaced by a `<tenant-id>/` key prefix. Public reads bypass drust entirely. A per-file visibility toggle moves bytes between buckets. Implemented against [Garage](https://garagehq.deuxfleurs.fr/) but the data path is plain S3 (`object_store::aws::AmazonS3`), so MinIO / R2 / S3 / B2 all work.
- **Resumable large-file upload (tus 1.0).** A second ingest path at `/t/<id>/uploads/*` accepts 200 MB–1 GB+ files without raising any infrastructure body-limit: capped `PATCH` chunks (default 64 MiB) append to a durable per-tenant spool, so uploads survive client disconnect and server restart. Finalize is SQLite-first + idempotent.
- **Outbound webhooks.** Per-tenant CRUD-event subscriptions, HMAC-SHA256-signed POST with 4-attempt retry; an SSRF guard rejects private / loopback / CGNAT / IPv6-mapped targets at every dispatch attempt.
- **Admin UI.** Two-page web UI with a Supabase-style collection editor (FilterAst-backed Table mode, Definition view, RLS policy editor, anon capability matrix, MCP setup snippets), file management, RPC + edge-function editors, audit log browser, and a backup browser with single-tenant restore. Localized (`en` / `zh-Hant`), three themes. Admins get personal access tokens (PATs) for CLI / MCP use.
- **Observability & ops.** Prometheus `/admin/_metrics` (audit drops, bearer denials, webhook attempts, WS connections, per-tenant bytes); audit rows in `meta_logs.sqlite` with 90-day retention + monthly VACUUM; daily `VACUUM INTO` backups (30-day retention); soft-delete with 7-day grace; per-tenant rate limiting; CORS allow-list with subdomain wildcards.

## Run with Docker

The fastest way to a running instance. drust serves plain HTTP — front it with a TLS-terminating reverse proxy (Caddy, nginx, Traefik) in production.

```bash
# 1. Compose — drust on http://localhost:47826 (SQLite only, no object storage)
docker compose up -d
#    ...or with S3 file storage (drust + MinIO):
docker compose --profile storage up -d

# 2. Open the admin UI and log in with DRUST_INIT_ADMIN_* from docker-compose.yml
open http://localhost:47826/admin/login

# 3. Health check
curl -s http://localhost:47826/health        # → ok
```

Plain `docker` instead of compose:

```bash
docker build -t drust:latest .
docker run -d --name drust -p 47826:47826 \
  -v drust-data:/data -v drust-logs:/logs \
  -e DRUST_INIT_ADMIN_USERNAME=admin \
  -e DRUST_INIT_ADMIN_PASSWORD=change-me \
  drust:latest
```

`/data` holds `meta.sqlite`, `meta_logs.sqlite`, every `tenants/<id>/`, and backups — back up that one volume. See [Configuration](#configuration) for the full env list.

> [!CAUTION]
> Do not run the container under a seccomp/AppArmor profile that blocks `mmap(PROT_EXEC)`. Edge functions execute guest WebAssembly via wasmtime's Cranelift JIT, which must map executable memory; Docker's default profile permits this, but a hardened "no exec memory" profile makes every edge-function upload/invoke fail. The guest sandbox is enforced *inside* wasmtime, not by process-wide W^X.

## Build from source

```bash
git clone https://github.com/KaelLim/drust.git
cd drust
cp .env.example .env             # edit DRUST_INIT_ADMIN_* and friends
cargo build --release
./target/release/drust            # binds 127.0.0.1:47826 by default
curl -s http://127.0.0.1:47826/health   # → ok
```

For systemd deployment behind a reverse proxy, see [`CLAUDE.md`](CLAUDE.md) §"Build & restart" and the `deploy/` unit templates.

> [!NOTE]
> rmcp's DNS-rebinding guard rejects any non-loopback `Host` header. If MCP requests return `403/421` from behind a proxy, the proxy must rewrite `Host: 127.0.0.1:47826` upstream. (Direct, no-proxy access is unaffected.)

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
                            │  └──────────────────┘  │ _system_functions        │
                            │                        └──────────────────────────│
                            └─────────────────┬─────────────────────────────────┘
                                              │ optional S3 (Garage / MinIO / R2)
                                              ▼
                              ┌──────────────────────────────────┐
                              │ host-wide buckets, key-prefixed   │
                              │  public/<id>/…   private/<id>/…   │
                              └──────────────────────────────────┘
```

Public-bucket reads bypass drust entirely — they're served straight from the S3 web endpoint via reverse proxy. drust only sits in the *write* path.

## API surfaces

| Surface | Path | Auth | Use |
|---|---|---|---|
| Admin UI | `/admin/*` | Cookie session | Tenant + schema management, policies, files, functions |
| Tenant REST | `/t/<id>/...` | Bearer (`anon` / `user` / `service`) | CRUD, `/list`, `/search`, RPC, files, uploads, realtime |
| Tenant MCP | `/t/<id>/mcp` | Bearer (`service` only) | LLM tool calls — CRUD, schema, indexes, RPCs, files, vector search, webhooks, policies, functions |
| Codegen | `/t/<id>/{openapi.json,types.ts,zod.ts}` | Bearer | Typed clients for the tenant's current schema |
| Health | `/health` | none | Liveness probe |

The full per-file index of public items, imports, and call graph lives in [`docs/architecture.md`](docs/architecture.md) (auto-generated from `src/**/*.rs`).

## Configuration

Configured via environment variables (from `.env`, systemd `EnvironmentFile`, or the container env):

| Variable | Required | Purpose |
|---|---|---|
| `DRUST_DATA_DIR` | yes | Base dir for `meta.sqlite`, `meta_logs.sqlite`, `tenants/`, backups |
| `DRUST_LOG_DIR` | yes | Reserved log directory |
| `DRUST_INIT_ADMIN_USERNAME` | first boot | Bootstrap admin account |
| `DRUST_INIT_ADMIN_PASSWORD` | first boot | Bootstrap admin password |
| `DRUST_BIND` | optional (`127.0.0.1:47826`) | Listen address — set `0.0.0.0:47826` in a container |
| `DRUST_PUBLIC_URL` | optional | Public base URL — required for OAuth redirect/callback links |
| `DRUST_CORS_ORIGINS` | optional | Comma-separated allow-list; supports `https://*.example.com`, `http://localhost:*` |
| `DRUST_DISK_MIN_FREE_PCT` | optional (20) | Upload guard for tenant file storage |
| `GARAGE_S3_ENDPOINT` + `GARAGE_S3_ACCESS_KEY` + `GARAGE_S3_SECRET_KEY` | optional | Enables S3 storage features |
| `GARAGE_ADMIN_ENDPOINT` + `GARAGE_ADMIN_TOKEN` | optional | Garage-only: auto-provision buckets |

The data-plane S3 path uses `object_store::aws::AmazonS3`, so any S3-compatible service works (Garage, MinIO, R2, AWS S3, B2). Auto-bucket provisioning is Garage-specific; for other backends, pre-create the buckets.

## Project structure

```
src/
  main.rs            entry point, router assembly
  config.rs          env-driven configuration
  auth/  oauth/       cookie sessions, bearer tokens, argon2id, OAuth adapters
  db/                 meta.sqlite migrations
  mgmt/               admin UI handlers + askama templates
  tenant/             tenant lifecycle, REST router, bearer middleware, rooms, uploads
  storage/            sqlite pool, schema, file/object metadata, Garage client, visibility
  query/              SQL authorizer whitelist, filter AST, RLS policy engine
  rpc/                stored RPC: prepare, registry, REST + MCP handlers
  mcp/                rmcp tool definitions, Streamable HTTP service registry
  codegen/            per-tenant OpenAPI / TypeScript / Zod generators
  functions/          edge-function runtime (wasmtime), dispatcher, executor
  safety/             audit log + audit-DB writer, rate limiter, blast-radius probes
  bin/                set_admin_password, set_admin_role, drust_session_janitor
sdk/edge-function-template/   guest SDK scaffold for edge functions (WIT is the SoT)
deploy/              systemd units, Caddyfile snippet, backup + janitor timers
Dockerfile · docker-compose.yml      container build + single-command self-host
CHANGELOG.md · CLAUDE.md             semver history · internal guide for AI agents
```

## Status

Production. Currently `v1.38.3`. See [CHANGELOG.md](CHANGELOG.md) for full history.

## License

drust is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

Self-hosting for personal, internal, or non-commercial use is fully covered by AGPL-3.0. If you intend to (a) offer drust — or a modified version — as a hosted service to third parties, or (b) integrate drust into a proprietary product whose source you cannot release under AGPL, you will likely need a separate **commercial license**.

For commercial-license inquiries, open a GitHub issue with the `commercial-license` label, or contact the maintainer via the email on the GitHub profile.

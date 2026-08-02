---
paths:
  - "src/mcp/handler.rs"
  - "src/mcp/resources.rs"
  - "src/mcp/prompts.rs"
  - "src/mcp/http_registry.rs"
  - "src/mcp/server.rs"
---

# MCP protocol surface

Fires when you open the per-tenant MCP server: tool dispatch, resources, prompts, or the per-tenant service registry.

## Transport & gate

**Per-tenant MCP** at `/t/<tenant>/mcp` — Streamable HTTP via `rmcp`, one `StreamableHttpService<DrustMcpService>` per tenant cached in `src/mcp/http_registry.rs`. Tool list in `src/mcp/handler.rs` (`#[tool]` annotations). **Service-key-only** — anon → `403 WRITE_DENIED`, user tokens → `403 MCP_USER_DENIED`. `whoami` returns tenant identity + both bearer tokens plaintext + REST/upload paths so models can hit the multipart upload route (which has no MCP tool by design).

`call_rpc` stays on the read-only executor regardless of the RPC's stored `mode`, so REST, the admin playground, and cron fires are the only write-RPC execution surfaces. MCP `call_rpc` is service-only unconditionally (the per-RPC `anon_callable` flag gates only the anon REST path).

## Resources & Prompts

`src/mcp/{resources,prompts}.rs` — hand-written `ServerHandler` methods; **rmcp has no resource/prompt macro**. Read surface only; all **service-only** by the same `mcp_dispatch` gate, tenant + pool from the per-tenant `self.state` (no request-context plumbing). Resources address tenant knowledge as `drust://<tenant>/<path>`: 9 static (`schema`, `schema.md`, `collections`, `openapi.json`, `types.ts`, `zod.ts`, `functions`, `rpcs`, `cron`) thin-routing to the existing `get_schema_overview`/codegen/inventory readers, + 4 templates (`collections/{collection}/schema`, `collections/{collection}/records{?page,per_page,sort,order}`, `collections/{collection}/records/{id}`, `rpcs/{name}`).

> [!CAUTION]
> **A resource is auto-fetchable into model context (spec §3), unlike a tool that needs an explicit call** — so anything credential-bearing must stay behind a TOOL. `rpcs`/`rpcs/{name}` strip RPC `sql` + param `default`; `cron` strips `payload_json` **and `last_error`** (rusqlite's `SqlInputError` `Display` embeds the whole failing statement, so a prepare-failing RPC cron job would publish through `cron` the very SQL the `rpcs` resource strips — `redact_cron` replaces it with a `last_error_present` boolean, and the full text stays behind the `list_cron_jobs` TOOL); the `history` + `functions/{name}/logs` templates are **deliberately NOT exposed as resources** (old-row snapshots / function stdout can carry secrets — they stay behind the `get_record_history` / `get_function_logs` TOOLS).

**URI parser** (`parse_resource_uri`) is a SINGLE `url::Url::parse` + deny-by-default: authority gate + `as_str()==raw` (rejects every url normalization incl. literal AND `%2e`-encoded dot-segments) + no-`%` segments + per-route query hardening (reject `%`/`+`/duplicate/unknown query keys — `query_pairs()` form-decodes past `as_str()==raw`, e.g. `?p%61ge=2`→`page`); **cross-tenant guard is `host_str()==tenant_id`**; `{c}` runs the `identifier` + `is_protected_collection` gate; `{id}` is a canonical i64 (rejects `/records/05`).

`Record{c,id}` uses a **dedicated bound-i64 single-row reader** (the `/list` filter validator only accepts declared fields, so an id-filter is `FILTER_UNKNOWN_FIELD`).

Bodies capped at `DRUST_MCP_RESOURCE_MAX_BYTES` (default 256 KiB, UTF-8-boundary truncation + marker); one `mcp.resource.read` audit row per read — a **failed** resource read writes no audit row (known gap).

> [!WARNING]
> Read TOOLS carry a **top-level** `resource_link` (concrete on `insert_record`) / `resource_uri_template` (on `list_records` + `search_collection`) — **never per-row**: the default projection omits `id`, and `resource_link` is a legal user column name.

**Prompts** (`prompts/list` + `prompts/get`): 6 task recipes — `bootstrap` (embeds the live `schema.md` + core rules), `design_collection{purpose}`, `secure_collection{collection}` (embeds `describe_collection`), `debug_write{collection}`, `write_edge_function{trigger}`, `review_history{collection}`; bodies mirror existing service tools (no new exposure), unknown/missing-arg → `-32602`.

Capabilities declare `resources` + `prompts` but **`listChanged` is NOT declared** — `resources/list_changed` notifications and subscriptions are deferred: both need a per-tenant schema-change notification bus + live MCP-peer subscription; the `#[tool]` handlers don't receive the peer, and schema also mutates from REST/admin faces — disproportionate infra for a re-listable convenience.

## AI introspection helpers

Every REST error JSON includes a `suggested_fix` field with a context-aware remediation hint; same applied to MCP `ErrorData.data`. Catalog of fixes in `src/safety/error_fixes.rs`; blast-radius probes in `src/storage/blast_radius.rs`.

Destructive ops `delete_record` / `drop_collection` / `drop_index` accept `dry_run: true` and return `would_*` counts + blast radius without mutating.

`recent_writes` (service-only) reads mutation rows from `meta_logs.sqlite` filtered to the calling tenant — lets a retrying model recover what its previous attempt already did. Default limit is **100**, matching what the tool description and the MCP prologue tell the model; an explicit `limit` wins and is clamped to `1..=200`.

## Provenance

Extracted from CLAUDE.md "Tools & endpoints" (MCP bullets, Resources+Prompts, AI introspection helpers) during the 2026-08-02 restructure.

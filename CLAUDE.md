---
type: service
kind: http
name: drust
port: 47826
path: /drust
status: production
updated: 2026-04-21
---

# drust — Rust multi-tenant SQLite BaaS

Self-hosted service providing a management UI (PocketHost-like) and per-tenant REST + MCP endpoints backed by isolated SQLite files. Design: [`docs/superpowers/specs/2026-04-20-drust-design.md`](../docs/superpowers/specs/2026-04-20-drust-design.md). Implementation plan: [`docs/superpowers/plans/2026-04-20-drust.md`](../docs/superpowers/plans/2026-04-20-drust.md).

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
- Writes go through structured REST/MCP tools against a serialized writer mutex; schema enforcement at tool layer. `FieldSpec` supports allowlisted SQL defaults (`{"sql": "datetime('now')"}`) and foreign keys (`foreign_key: "<target>"` emits `ON DELETE RESTRICT`).
- **Per-tenant rmcp Streamable HTTP MCP endpoint at `/t/<tenant>/mcp`** serving all 11 tools. One `StreamableHttpService<DrustMcpService>` per tenant, cached in `src/mcp/http_registry.rs`. MCP is **service-key-only** — anon bearers get `403 WRITE_DENIED`. Enforced in `src/tenant/mcp_dispatch.rs` before the dispatch; the route still runs through `bearer_auth_layer` so auth + rate-limit + audit all cover it.
- Admin UI on the tenant detail page has a **Copy MCP config** button next to the service key card that emits a ready-to-paste `mcpServers` JSON snippet using `window.location.origin` — no backend URL template needed.
- Admin UI (v1.2.0+): every page renders inside a viewport-fixed `.macwin` with container-scoped scroll. The collection-detail page is a 2-column shell — a left-side sidebar lists every collection for the active tenant (`_collection_sidebar.html`), independent scroll from the main content. `/admin/tenants/{id}/collections` 302-redirects to the first collection; empty tenants see a dedicated empty-state page. The **LiveChonk** pixel-cat mascot (`_mascot.html`) is wired to any `<canvas class="pix" data-chonk=... data-size=...>` — 18 px in the topbar, 48 px on login, 96 px on empty states, 56 px on errors.
- **Rate-limit + audit middleware are wired** into `bearer_auth_layer` (v0.1.0 Known issues closed in v1.1.1). Each tenant request produces one `audit-YYYY-MM-DD.jsonl` entry in `$DRUST_LOG_DIR`; denials get `error_code: HTTP_<status>`.
- SSE broadcast channels per `(tenant, collection)` fan events from record CRUD.
- Soft-delete moves `tenants/<id>/` into `_trash/<id>-<ts>/`; `drust-janitor.timer` deletes after 7d.
- Daily `drust-backup.timer` runs `VACUUM INTO` snapshots → `backups/drust-YYYY-MM-DD-HHMMSS.tar.zst` (30d retention).

## Invariants

> [!WARNING]
> **Bearer tokens are the sole authorization boundary for data-plane access.** If a token leaks, it grants full read + structured write on the bound tenant until revoked. Never share tokens across tenants; never commit `.env`.

> [!CAUTION]
> **`header_up Host "127.0.0.1:47826"` is mandatory on the Caddy block** for the MCP sub-route `/drust/t/<tenant>/mcp`. rmcp's DNS-rebinding guard rejects non-loopback Hosts with a 403/421 that looks like a WAF.

> [!IMPORTANT]
> The SQL authorizer in `src/query/authorizer.rs` is the cross-tenant isolation guarantee at the SQL layer. If you loosen it (e.g. add new `AuthAction` allow arms), re-prove: (a) ATTACH stays denied, (b) sqlite_master reads stay denied, (c) all write actions stay denied on read connections.

## Directory map

See `docs/superpowers/plans/2026-04-20-drust.md` `## File layout this plan builds`.

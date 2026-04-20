---
type: service
kind: http
name: drust
port: 47826
path: /drust
status: production
updated: 2026-04-20
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

- `meta.sqlite` (management plane): admins, sessions, tenants, hashed bearer tokens.
- `tenants/<id>/data.sqlite` (data plane): one SQLite per tenant.
- Reads route through `SQLITE_OPEN_READONLY` connections with `sqlite3_set_authorizer` whitelist (see `src/query/authorizer.rs`). Cross-tenant `ATTACH` is denied.
- Writes go through structured REST/MCP tools against a serialized writer mutex; schema enforcement at tool layer.
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

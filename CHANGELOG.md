# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Admin UI minimum text size raised to 18px for readability; layout reflowed proportionally
- Removed remaining Chinese strings — UI is now English-only
- Replaced emoji glyphs (📊, ⚠) with inline SVG icons (Lucide), bundled offline
- Topbar/auth-foot version string now sourced from `Cargo.toml` at compile time

### Added
- `CHANGELOG.md` (this file)
- `_icons.html` template partial with reusable SVG sprite block

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

[Unreleased]: https://example.invalid/drust/compare/v0.1.0...HEAD
[0.1.0]: https://example.invalid/drust/releases/tag/v0.1.0

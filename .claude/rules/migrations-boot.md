---
paths:
  - "src/db/**"
  - "src/main.rs"
  - "src/storage/meta.rs"
---

# Boot path & migration discipline

Fires on `src/db/` (migrations), `src/main.rs` (boot), `src/storage/meta.rs` (fresh-install schema).

> [!WARNING]
> **`run_migrations` runs on every boot, so every step MUST be idempotent — never unconditionally revoke/mint/delete a credential there.** Per-tenant anon/service tokens (`tokens`) and admin PATs (`_admin_tokens`) are **stable across restarts** — nothing on the boot path rerolls them. A regression existed until v1.41.5: the v1.29.3 "collapse legacy PATs" migration step revoked every active PAT unconditionally, and since `run_migrations` runs on every boot it rerolled every admin PAT on every restart — breaking any PAT-keyed integration with a 401 after each deploy. The legacy revoke is now qualified `AND plaintext IS NULL`.

The same discipline elsewhere:

- **MCP OAuth cleanup is not a migration.** Expired and orphaned `_mcp_oauth_*` rows are
  deleted by the hourly `mcp_oauth::sweep` in the device-code reaper loop, never by
  `run_migrations` — the boot path creates those tables and deletes nothing.
- **T4 (CLI multi-PAT)**: legacy-revoke + backfill probe qualified `AND label IS NULL`, index relax guarded on `sqlite_master.sql NOT LIKE '%label%'`, reroll revokes only the unlabeled UI PAT.
- **One-shot backfills that must NEVER re-run.** `tenants.owner_admin_id`: the boot backfill (assigns legacy live tenants to the lowest-id owner; soft-deleted stay NULL) **runs exactly once** — inside the `owner_admin_id` column-create branch, NOT every boot — so a later deliberate NULL (orphan / transfer-to-null) is never re-owned. The **egress allowlist** seed from each tenant's existing `_system_webhooks` origins is guarded by a marker — the "never resurrect a removed entry every boot" idempotency invariant.
- **`strict_rebuild_tenant`**: boot-time **idempotent** migration (gated on `pragma_table_list.strict`) rebuilding pre-STRICT collections via per-table copy-then-swap, reconstructing DDL verbatim from `sqlite_master.sql` (temp table `_system_strict_tmp_<name>`, collision-proof; the pre-commit `foreign_key_check` is scoped to the rebuilt table so one orphan can't block clean siblings).
- **`scan_unsafe_anon_rpcs`**: startup migration that neutralizes pre-guard legacy rows fail-closed (`anon_callable=0`), including `:user_id` RPCs over policy-protected collections.
- **Boot scans use the reader lane and never create tables** — e.g. the cron boot scan repopulates `CronIndex` that way.
- **`SQLITE_DBCONFIG_DEFENSIVE` is set on every tenant writer open** (v1.60): the two `tenant_db` writer opens (`open_write`/`open_write_existing`), the `migrate_tenant_db` bare open, and the `strict_rebuild_tenant` open. It is what refuses direct SQL on fts5 module shadow tables (the writable authorizer allows those by name). The egress-backfill reader open is deliberately left untouched (a harmless no-op there, outside scope). `sqlite_sequence` DML (the AUTOINCREMENT fix-up) and all drust writer behavior are verified unaffected.

## Three databases

- **`meta.sqlite`** — admins, sessions, tenants, bearer tokens (hashed **plus** a plaintext copy, so `whoami` / the admin UI can echo the key), and the MCP OAuth AS tables:
  - **`_mcp_*` tables in `meta.sqlite`** — `_mcp_oauth_grants`, `_mcp_oauth_codes`, `_mcp_oauth_refresh`, `_mcp_oauth_access`, `_mcp_upload_tickets`, one shared const `SQL_CREATE_MCP_OAUTH_IF_NOT_EXISTS` run by both `open_meta` and `run_migrations`. **Never name a meta table `_oauth_*`**: `run_migrations` DROPs four such tables on every boot (the v1.29.2 AS retraction), so a table under that prefix is silently emptied on each restart. Every `*_at` column is SQLite `datetime()` text written and compared **in SQL** — never bind a Rust `to_rfc3339()` string, which compares wrong against `datetime()` text for up to a day. The DDL — including the `--` comments inside each `CREATE TABLE` body, which `sqlite_master` stores verbatim — is frozen from the first deploy, because `IF NOT EXISTS` never reshapes a table a host already has; new columns only through `add_column_if_missing`, appended last. The exact `sqlite_master.sql` text is pinned by `mcp_oauth_ddl_text_is_frozen`. These tables store hashes only; a backup's plaintext credentials remain `tokens.plaintext`, `_admin_tokens.plaintext`, and the dual-write `sessions.token`.
- **`tenants/<id>/data.sqlite`** — one per tenant.
- **`meta_logs.sqlite`** — audit rows.

**Fresh install and the migration path must stay in lockstep.** `open_meta` executes `SCHEMA_SQL` and then the *same shared `SQL_CREATE_*_IF_NOT_EXISTS` consts `run_migrations` uses*, so fresh and upgraded DBs get byte-identical schema; never hand-write a second copy of a table's DDL in `meta.rs`. `tests/meta_sqlite.rs` asserts the fresh-install table list **exactly**, so UNINTENDED drift fails the build and ANY new meta table is a deliberate contract change that updates that expectation in the same commit.

## Provenance

Extracted from CLAUDE.md "Data plane", Auth (CLI multi-PAT / tenant ownership), Egress allowlist, and Stored RPC sections during the 2026-08-02 restructure.

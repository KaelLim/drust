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

- **T4 (CLI multi-PAT)**: legacy-revoke + backfill probe qualified `AND label IS NULL`, index relax guarded on `sqlite_master.sql NOT LIKE '%label%'`, reroll revokes only the unlabeled UI PAT.
- **One-shot backfills that must NEVER re-run.** `tenants.owner_admin_id`: the boot backfill (assigns legacy live tenants to the lowest-id owner; soft-deleted stay NULL) **runs exactly once** — inside the `owner_admin_id` column-create branch, NOT every boot — so a later deliberate NULL (orphan / transfer-to-null) is never re-owned. The **egress allowlist** seed from each tenant's existing `_system_webhooks` origins is guarded by a marker — the "never resurrect a removed entry every boot" idempotency invariant.
- **`strict_rebuild_tenant`**: boot-time **idempotent** migration (gated on `pragma_table_list.strict`) rebuilding pre-STRICT collections via per-table copy-then-swap, reconstructing DDL verbatim from `sqlite_master.sql` (temp table `_system_strict_tmp_<name>`, collision-proof; the pre-commit `foreign_key_check` is scoped to the rebuilt table so one orphan can't block clean siblings).
- **`scan_unsafe_anon_rpcs`**: startup migration that neutralizes pre-guard legacy rows fail-closed (`anon_callable=0`), including `:user_id` RPCs over policy-protected collections.
- **Boot scans use the reader lane and never create tables** — e.g. the cron boot scan repopulates `CronIndex` that way.

## Three databases

- **`meta.sqlite`** — admins, sessions, tenants, bearer tokens (hashed **plus** a plaintext copy, so `whoami` / the admin UI can echo the key).
- **`tenants/<id>/data.sqlite`** — one per tenant.
- **`meta_logs.sqlite`** — audit rows.

**Fresh install and the migration path must stay in lockstep.** `open_meta` executes `SCHEMA_SQL` and then the *same shared `SQL_CREATE_*_IF_NOT_EXISTS` consts `run_migrations` uses*, so fresh and upgraded DBs get byte-identical schema; never hand-write a second copy of a table's DDL in `meta.rs`. `tests/meta_sqlite.rs` asserts the fresh-install table list **exactly**, so UNINTENDED drift fails the build and ANY new meta table is a deliberate contract change that updates that expectation in the same commit.

## Provenance

Extracted from CLAUDE.md "Data plane", Auth (CLI multi-PAT / tenant ownership), Egress allowlist, and Stored RPC sections during the 2026-08-02 restructure.

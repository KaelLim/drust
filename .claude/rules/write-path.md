---
paths:
  - "src/tenant/records*.rs"
  - "src/mcp/tools/**"
  - "src/storage/record_history.rs"
  - "src/storage/quota.rs"
  - "src/storage/schema.rs"
  - "src/query/**"
  - "src/functions/enforce.rs"
---

# The write path: authorization, history, quota, SQL construction

Fires when you open a record handler, an MCP tool, a query builder, the quota/history/schema modules, or the edge-function enforcement core. CLAUDE.md holds the *enumeration* invariants; this file holds the MECHANISM.

## Row-authorization matrix

**`anon_caps` / `user_caps`** — each a subset of `{select, insert, update, delete}`, default `[select]`, stored side-by-side on `_system_collection_meta`. `anon_caps` gates the **Anon** role; `user_caps` gates the **User** role (`drust_user_*` login/OAuth tokens) — **distinct columns, distinct `has_dml_cap` branches**, so granting one never opens the other (the User does not inherit `anon_caps`; `owner_field` is not *required* to let logged-in users write). Service is unrestricted. **Both govern `/records/*`, `/list`, `/search` ONLY** — `/query` + `/query/explain` are service-only.

The `owner_field.is_some()` short-circuit in the User arm is **read_scope-aware**: the cap is open for writes (the owner clause is always applied — see `compute_owner_write_filter`) and for `read_scope="own"` reads (the per-row filter applies), but a `read_scope="all"` READ is unfiltered and is therefore gated by `user_caps[select]`, in lockstep with the `POST /list` matrix and `/search`.

> [!WARNING]
> **The two cap-gate sites — `has_dml_cap` and the `records_list.rs` matrix — must stay in lockstep.** Both read `user_caps` for the User role (`tests/user_caps.rs` guards the swap), and both gate a User READ on a `read_scope="all"` owner-scoped collection by `user_caps[select]` (`tests/audit3_readscope_all_caps.rs` pins this). The `owner_field` short-circuit is open only where a row filter actually applies.

**`owner_field` + `read_scope`** — row-level filter for user tokens. INSERT auto-populates owner_field; UPDATE/DELETE foreign rows → 404; anon → 403 on owner-scoped collections; service bypasses but must populate owner_field on INSERT (`409 OWNER_FIELD_REQUIRED`). WRITES are always owner-scoped for the User role regardless of `read_scope`.

- **Known gap, being fixed in v1.58:** MCP `insert_record` (`src/mcp/tools/write.rs`) does NOT enforce `OWNER_FIELD_REQUIRED`, while REST, edge (`functions/enforce.rs`) and batch (`mcp/tools/batch.rs`) all do.

**`_system_*` tables** are blocked from `/records/*` AND from MCP write tools (`insert_record` / `update_record` / `delete_record` return `PROTECTED_COLLECTION`) for both anon and service (404 / 403); independent of cap setting.

- **Known gap, being fixed in v1.58:** `storage::schema::is_protected_collection` currently matches only `name.starts_with("_system_")`, while the read authorizer separately blocks `sqlite_` — so `sqlite_*` is read-blocked but write-allowed.

## RLS policies (`src/query/policy.rs`)

Per-operation `Policy {using, check}` in four nullable `{select,insert,update,delete}_policy_json` columns, expressed as the existing `FilterAst` extended with three operands — `{"$auth":"id"}` (caller's `_system_users` id, or SQL `NULL` for anon), `{"$data":"<field>"}` (post-image field, CHECK only), `{"$authenticated":true}`. Service bypasses.

Two evaluators share the grammar: `compile_policy_using` → `?`-bound SQL `WHERE` (reads + update/delete target pre-flights), `eval_policy` → in-memory bool (insert/update CHECK + anon SSE filtering); a consistency corpus (`tests/policy_expression.rs`) proves they agree. **Any grammar change updates both `compile_policy_using` and `eval_policy` and the corpus.**

Explicit policies **AND-compose with the unchanged owner clause**: policy USING is `?`-compiled and AND-ed into the same `WHERE` the owner clause already builds; policy CHECK runs `eval_policy` on the read-back row INSIDE the `with_writer_tx` closure (sentinel `POLICY_CHECK_FAILED` → rollback → `403`). Policy USING/CHECK and the owner stamp/strip run after & independent of caps. Policy input must stay structured (`FilterAst`, never raw user SQL) so enforcement is by construction.

## Structured vs raw: which camp does a new endpoint join

`/search`, `/list`, and `/aggregate` take only `FilterAst` (`src/query/vector_filter.rs`) compiled with `?` binds, so `owner_field` is always enforceable **by construction**. `/query` accepts raw SELECT (un-rewritable) and is therefore service-only. **Any new endpoint accepting user input that lands in SQL must explicitly pick a camp.**

The **legacy `GET /records/<c>?filter=/?sort=`** params are raw (interpolated verbatim into `build_list_sql`, no `?` binds), and the read-only authorizer allows reads of any non-`_system_` sibling table — so they are the *raw* camp: **service-only**. Anon/User get `403 RAW_FILTER_DENIED` and must use the structured `/list`; the param is deprecated (Sunset 2027-01-01).

**`/aggregate` is in lockstep with `/list` by construction**: the owner/policy/cap matrix is the shared `records_list::compute_read_auth`, and the WHERE (filter + owner clause + policy USING) the shared `list_builder::build_where_clause` — both faces call them verbatim, so a User only aggregates rows they may read. Ops are a fixed allowlist; group/metric/sort identifiers go through the schema field allowlist + `q()` quoting; every value is `?`-bound; duplicate output-column names reject with `AGG_ALIAS_DUPLICATE`.

## Batch insert + upsert

Each runs MANY rows through the SAME per-row guards as a single insert (`write::insert_row_in_tx`) inside ONE `pool.with_writer_tx`, **atomically**: any invalid row rolls back every data row AND every `_system_record_history` row (capture is in-tx). Quota re-measures per row (`usage_on_conn` reflects in-tx page growth so the row that crosses the tier fails and the whole tx rolls back). Schema read + vector pre-encode happen OUTSIDE the tx so typed errors surface before the writer lock. `owner_field`-required per row on owner-scoped collections (stricter than single-insert); `_system_*` refused (`PROTECTED_COLLECTION`).

**Upsert** = `INSERT ... ON CONFLICT(<on_conflict cols>) DO UPDATE SET <non-key col>=excluded.<col>, updated_at=datetime('now') RETURNING *` (`write::upsert_row_in_tx`): a **pre-image probe by the conflict key** decides the per-row op — hit → `op=update` (old=pre-image), miss → `op=insert` — so record-history and the `Created`/`Updated` fan-out are correct per row. Quota gates the **INSERT branch only** (a conflict UPDATE mirrors `update_record_checked`: never block a shrink); the convergent `updated_at` in the SET keeps `RETURNING *` equal to the committed post-AFTER-trigger row.

> [!CAUTION]
> **Conflict-target validation (`validate_conflict_target`) queries `PRAGMA index_list`/`index_info`/`table_info` DIRECTLY** (incl. the `sqlite_autoindex` a `UNIQUE` column creates, a named UNIQUE index, and the single/composite PK) — NOT `describe_collection().indices`, which deliberately filters autoindexes out and would wrongly reject a `UNIQUE`-column or PK target; order-insensitive set match.

## Record history mechanism (`src/storage/record_history.rs`)

Captured **inside the same write transaction** at EVERY write choke point. Projections are `materialize_row`-identical: BLOB → `{"__blob_bytes": n}`, vector fields omitted. A rolled-back write leaves no history row (atomicity pinned by tests).

Three capture shapes, and a new write path must wire one of them:

1. **Structured writes** call `record_history::capture()` explicitly — REST `records.rs`, MCP/edge `write.rs`.
2. **Bulk owner-cascades** call `capture_owner_cascade` **BEFORE** their DELETE, in the same tx. The `delete_user` owner cascade has **two parallel sites** and *both* call it — a fix applied to only one of them silently loses history for half the cascades.
3. **Raw write-RPC SQL** cannot call `capture()`, so it is covered by the connection-scoped preupdate hook installed in `run_write_rpc` for exactly the savepoint's lifetime (below).

**Actor attribution**: `AuditActor {kind: service|anon|user, id, hint}` from `AuthCtx` — a PAT-driven service call carries `admin_id`; user `hint` = first 12 chars of the **base64** (URL_SAFE_NO_PAD) SHA-256 session-token hash, prefix-joinable to `_system_sessions.token_hash` ONLY (NOT the access log's plaintext `token_hint`); empty token hash (edge-function host identity) → NULL.

**RPC preupdate hook**: raw write-RPC SQL can't call `capture()`, so `run_write_rpc` (`src/rpc/exec_write.rs`) installs a connection-scoped SQLite preupdate hook for exactly the savepoint's lifetime; buffered rows flush inside the savepoint (rollback discards data + history together). Trigger-driven events (`get_query_depth() > 0` — the convergent `<coll>_updated_at` trigger) **merge into their depth-0 change** so `new_json` matches the committed row; without the merge every RPC UPDATE double-captures. The audited-table set is precomputed BEFORE `attach_writable_authorizer` (which denies the needed `sqlite_master`/`_system_*` reads; RPC SQL also cannot write `_system_collection_meta`, so the set cannot go stale mid-run); the hook is NOT installed on `dry_run` or when no table is audited. Blob content is never buffered (`CapturedValue::BlobLen`); the caps fail closed → RPC rolls back with `409 CAPTURE_LIMIT_EXCEEDED`.

History rows are PII-dense — old images of updated/deleted rows persist in the tenant DB file for the retention window; **disabling audit stops NEW capture but does not purge existing rows.**

## Quota mechanism (`src/storage/quota.rs`)

Usage is measured **live inside the writer transaction** (`usage_on_conn`: `PRAGMA page_count × page_size` for the tenant `data.sqlite` + `SUM(_system_files.size_bytes)`, `no such table` → 0) — no cross-DB counter is possible: `_system_files` lives in the tenant DB, `tenants` in meta.sqlite — no shared tx. `check_tenant_quota(usage, incoming, tier)` rejects when `usage + incoming > tier × 10 GiB`; over-limit is `507 TENANT_QUOTA_EXCEEDED`.

`delete`, ALL `update` (a shrink/recovery update must never be blocked), reads, and the visibility bucket-move (net-zero) are NOT checked. **v1.58 narrows this**: update will be checked only when it BOTH grows AND crosses the cap. **DDL** (`create_index`) is also outside the enumeration — a service/admin key can transiently exceed the cap by building one index; the next record/upload write then blocks. Untrusted anon/user cannot reach DDL, so this is a documented trusted-caller scope boundary, not a bypass.

The sentinel `error::quota_exceeded_error` produces a `TENANT_QUOTA_EXCEEDED:`-prefixed rusqlite error; `error::is_quota_exceeded` (substring match — a drust-produced sentinel, never a native SQLite message) maps it to 507 on REST + MCP. Low-frequency sites (MCP/edge/cron/tus) read the tier via `quota::read_tier(meta, tenant_id)`; a `None` meta handle fails **safe to tier 1** (most-restrictive) — every PROD construction site wires `Some(meta)`, only test ctors pass `None`.

## `prepare` vs `prepare_cached`

**`SELECT *` reads on a pooled reader use plain `prepare`, never `prepare_cached`.** rusqlite's per-connection statement cache is keyed by SQL text, which is STABLE across `add_field`/`drop_field`, so a cached `SELECT *` statement (whose `column_names()` is read before stepping) serves a STALE column set on a long-lived reader — silently dropping an added column or 500-ing on a dropped one. DDL flushes the schema cache + SSE bus, NEVER the reader's rusqlite statement cache. `get_handler`, `list_bound_rows`, and the stored-RPC named-exec path (`src/query/executor.rs`) therefore use plain `prepare`; only an EXPLICIT schema-derived projection (`/list` builder, whose SQL text changes on DDL → cache self-heals) or `COUNT(*)` may be `prepare_cached`.

The `RETURNING *` read-back also feeds the post-image policy CHECK; it equals the COMMITTED row only because the sole `<coll>_updated_at` AFTER trigger is convergent (writes the same statement-stable `datetime('now')` the SET clause writes) and tenants cannot create triggers — a future non-convergent AFTER trigger would require re-reading the committed row before the CHECK.

## CHECK constraints and TOCTOU

`FieldSpec.{min,max,enum,max_length}` compile to ONE inline `CHECK(...)` via `compile_check` — drust-controlled escaped literals only, same camp as `SQL_DEFAULT_ALLOWLIST`. The app-layer pre-check `write.rs::check_constraints` is **type-aware** (numeric enums compared numerically) and yields a typed `CHECK_CONSTRAINT_FAILED` before the native CHECK; `error::is_check_violation` (gated on the EXTENDED code `SQLITE_CONSTRAINT_CHECK`, never a message substring) maps a native CHECK failure on REST AND MCP.

Existence checks are done INSIDE the same `pool.with_writer` closure as the write to close TOCTOU vs `drop_collection`; sentinels `COLLECTION_NOT_FOUND` / `FIELD_NOT_FOUND` / `INDEX_NOT_FOUND` are distinct.

## Provenance

Extracted from CLAUDE.md "Per-collection schema metadata", "Record history", the /list + /aggregate + batch/upsert bullets of "Tools & endpoints", "Per-tenant quota", and the write-path invariants during the 2026-08-02 restructure.

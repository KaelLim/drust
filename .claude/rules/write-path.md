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

The two evaluators order a **cross-storage-class comparison** differently (SQLite affinity vs in-memory `value_cmp`), so `validate_policy` rejects at config time any operand whose class mismatches the target column. As of v1.61.1 (#954) that check (`operand_class` + `check_operand_class`) covers **dynamic** refs too, not just literals: `$auth` classes as `text` (the `_system_users` id), `$data:"<field>"` as that field's column class. So a numeric column compared to `$auth` (always text) is refused at save — closing a fail-closed-pre-existing gap where a mismatched-class dynamic operand reached `eval_leaf` and its `value_cmp` `None`→`Unknown` could diverge from SQL. NULL/array operands and BLOB/system targets are never class-checked (never value-compared across a class boundary).

Explicit policies **AND-compose with the unchanged owner clause**: policy USING is `?`-compiled and AND-ed into the same `WHERE` the owner clause already builds; policy CHECK runs `eval_policy` on the read-back row INSIDE the `with_writer_tx` closure (sentinel `POLICY_CHECK_FAILED` → rollback → `403`). Policy USING/CHECK and the owner stamp/strip run after & independent of caps. Policy input must stay structured (`FilterAst`, never raw user SQL) so enforcement is by construction.

## Structured vs raw: which camp does a new endpoint join

`/search`, `/list`, and `/aggregate` take only `FilterAst` (`src/query/vector_filter.rs`) compiled with `?` binds, so `owner_field` is always enforceable **by construction**. `/query` accepts raw SELECT (un-rewritable) and is therefore service-only. **Any new endpoint accepting user input that lands in SQL must explicitly pick a camp.**

The **legacy `GET /records/<c>?filter=/?sort=`** params are raw (interpolated verbatim into `build_list_sql`, no `?` binds), and the read-only authorizer allows reads of any non-`_system_` sibling table — so they are the *raw* camp: **service-only**. Anon/User get `403 RAW_FILTER_DENIED` and must use the structured `/list`; the param is deprecated (Sunset 2027-01-01).

**`/aggregate` is in lockstep with `/list` by construction**: the owner/policy/cap matrix is the shared `records_list::compute_read_auth`, and the WHERE (filter + owner clause + policy USING) the shared `list_builder::build_where_clause` — both faces call them verbatim, so a User only aggregates rows they may read. Ops are a fixed allowlist; group/metric/sort identifiers go through the schema field allowlist + `q()` quoting; every value is `?`-bound; duplicate output-column names reject with `AGG_ALIAS_DUPLICATE`.

**A `kind='query'` stored RPC (#950) is the structured camp reached through a stored template** — a named `FilterAst` (in `query_json`), not raw SQL, so it joins `/list` rather than `/query`. The auth split lives in ONE place: `compute_read_auth_inner(cap: CapMode, …)` with two private-mode wrappers — `compute_read_auth` (`CapMode::Collection`, the `/list` + `/aggregate` callers) and `run_structured_list_rpc_grant` → `CapMode::RpcGrant` (the RPC arm, the ONLY door to the grant mode; there is deliberately no `pub` escalating enum). `RpcGrant` skips a cap check **only** where an independent row gate protects rows; the `read_scope="all"` and owner-scoped `NULL`-scope arms keep `user_caps[select]` because there the cap IS the row gate (`tests/audit3_readscope_all_caps.rs` pins the /list side; `tests/rpc_query_kind.rs` pins the RPC side). Caller args substitute into template operands at the JSON level via `query_template::resolve_args` (fused check-args + default-fill, the ONLY arg entry) then `substitute_to_filter_ast` (the ONLY path to `FilterAst`, strict `from_value`, never the string-tolerant `parse_filter_value`) — an object/array arg is `RPC_PARAM_NOT_SCALAR` (the AST-injection gate). `/search` (`vector_search.rs`) and edge `functions/enforce.rs::enforced_list` remain PARALLEL read-auth matrices this did not unify — a new read gate touches all of them.

## Batch insert + upsert

Each runs MANY rows through the SAME per-row guards as a single insert (`write::insert_row_in_tx`) inside ONE `pool.with_writer_tx`, **atomically**: any invalid row rolls back every data row AND every `_system_record_history` row (capture is in-tx). Quota re-measures per row (`usage_on_conn` reflects in-tx page growth so the row that crosses the tier fails and the whole tx rolls back). Schema read + vector pre-encode happen OUTSIDE the tx so typed errors surface before the writer lock. `owner_field`-required per row on owner-scoped collections (stricter than single-insert); `_system_*` refused (`PROTECTED_COLLECTION`).

**Upsert** = `INSERT ... ON CONFLICT(<on_conflict cols>) DO UPDATE SET <non-key col>=excluded.<col>, updated_at=datetime('now') RETURNING *` (`write::upsert_row_in_tx`): a **pre-image probe by the conflict key** decides the per-row op — hit → `op=update` (old=pre-image), miss → `op=insert` — so record-history and the `Created`/`Updated` fan-out are correct per row. Quota gates the **INSERT branch before the write**; the conflict UPDATE mirrors `update_record_checked` — gated after the write on growth only, so a shrink is never blocked; the convergent `updated_at` in the SET keeps `RETURNING *` equal to the committed post-AFTER-trigger row.

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

`delete`, reads, and the visibility bucket-move (net-zero) are NOT checked. **`update` is checked only when it BOTH grows the tenant AND leaves it over the cap** (v1.58): `check_update_growth(tx, usage_before, tier)` runs POST-write inside the same tx at all three update sites (REST `update_handler`, MCP/edge `update_record_checked`, the conflict branch of `upsert_row_in_tx`), so a shrink/no-op — the recovery write the old blanket exemption existed to protect — still passes, while unbounded growth by repeated overwrite does not. `decide_update_growth` is the pure decision, split out because `check_tenant_quota` clamps `tier.max(1)` and no test DB can cross a 10 GiB cap.

**`check_update_growth` must be the LAST statement in the write tx — after `record_history::capture`, not before it.** The history row stores the full old AND new image and audit defaults on, so it is ~2× the payload; a gate measured pre-capture never counts it. Overwriting a row with a DIFFERENT value of the SAME length frees exactly the overflow pages it re-allocates, so a pre-capture measurement reads `after == before`, takes the shrink branch, and the tx still commits ~2× payload of growth — unbounded across repeated requests (reproduced against sqlite3: 1028 → 1028 at the gate, +2050 pages committed, every iteration). Measuring last counts the whole transaction. It does **not** close the recovery shrink, because SQLite serves allocations from the freelist first: within one tx the pages a shrinking UPDATE frees are the pages the history row consumes, so `page_count` does not move (`tests/quota_update_growth.rs` pins both halves). **DDL** (`create_index`) is also outside the enumeration — a service/admin key can transiently exceed the cap by building one index; the next record/upload write then blocks. Untrusted anon/user cannot reach DDL, so this is a documented trusted-caller scope boundary, not a bypass.

The sentinel `error::quota_exceeded_error` produces a `TENANT_QUOTA_EXCEEDED:`-prefixed rusqlite error; `error::is_quota_exceeded` (substring match — a drust-produced sentinel, never a native SQLite message) maps it to 507 on REST + MCP. Low-frequency sites (MCP/edge/cron/tus) read the tier via `quota::read_tier(meta, tenant_id)`; a `None` meta handle fails **safe to tier 1** (most-restrictive) — every PROD construction site wires `Some(meta)`, only test ctors pass `None`.

## `prepare` vs `prepare_cached`

**`SELECT *` reads on a pooled reader use plain `prepare`, never `prepare_cached`.** rusqlite's per-connection statement cache is keyed by SQL text, which is STABLE across `add_field`/`drop_field`, so a cached `SELECT *` statement (whose `column_names()` is read before stepping) serves a STALE column set on a long-lived reader — silently dropping an added column or 500-ing on a dropped one. DDL flushes the schema cache + SSE bus, NEVER the reader's rusqlite statement cache. `get_handler`, `list_bound_rows`, and the stored-RPC named-exec path (`src/query/executor.rs`) therefore use plain `prepare`; only an EXPLICIT schema-derived projection (`/list` builder, whose SQL text changes on DDL → cache self-heals) or `COUNT(*)` may be `prepare_cached`.

The `RETURNING *` read-back also feeds the post-image policy CHECK; it equals the COMMITTED row only because the sole `<coll>_updated_at` AFTER trigger is convergent (writes the same statement-stable `datetime('now')` the SET clause writes) and tenants cannot create triggers — a future non-convergent AFTER trigger would require re-reading the committed row before the CHECK.

## CHECK constraints and TOCTOU

`FieldSpec.{min,max,enum,max_length}` compile to ONE inline `CHECK(...)` via `compile_check` — drust-controlled escaped literals only, same camp as `SQL_DEFAULT_ALLOWLIST`. The app-layer pre-check `write.rs::check_constraints` is **type-aware** (numeric enums compared numerically) and yields a typed `CHECK_CONSTRAINT_FAILED` before the native CHECK; `error::is_check_violation` (gated on the EXTENDED code `SQLITE_CONSTRAINT_CHECK`, never a message substring) maps a native CHECK failure on REST AND MCP.

Existence checks are done INSIDE the same `pool.with_writer` closure as the write to close TOCTOU vs `drop_collection`; sentinels `COLLECTION_NOT_FOUND` / `FIELD_NOT_FOUND` / `INDEX_NOT_FOUND` are distinct.

## FTS search (`$fts`, `_system_search_*`)

Tenant-scoped FTS5 full-text search (v1.60). Three service-only MCP tools
(`create_fts_index` / `drop_fts_index` / `list_fts_indexes`, `src/mcp/tools/fts.rs`) build
external-content fts5 vtables; a `$fts` filter operand searches them on `/list`, `/search`,
`/aggregate` and their MCP mirrors.

**Naming grammar** (`src/storage/search_names.rs`): the delimiter is `$`, which
`identifier()`'s `[a-z0-9_]` grammar can never emit — head `_system_search_fts$<coll>$<name>`,
sync triggers `<head>_ai|_ad|_au`. `validate_fts_index_name` rejects the reserved module
suffixes (`_data`/`_idx`/`_docsize`/`_config`/`_content`, `FTS_NAME_RESERVED`) up front for a
clean message; SQLite also reserves those shadow names process-wide as a bonus defense.

**Head-vs-internal classification is POSITIVE by `pragma_table_list.type`, never by name**
(`snapshot_search_tables` → `SearchTables`): `type='virtual'` → head, `type='shadow'` →
module internal. `is_internal` is deliberately NOT "prefix-and-not-a-head" — that negation
classified an ORDINARY table a service could create under the `_system_search_` prefix (a
leading `_` is a legal identifier) as internal, and the writable arm's by-name allowance
would then let caller-authored write-RPC SQL write it (a cross-owner hole DEFENSIVE does not
cover, since it is a real table, not a module shadow — codex caught this pre-merge). An
ordinary `_system_search_`-prefixed table is `type='table'` → in NEITHER set → falls through
to the `is_protected_collection` deny. `SearchTables` has **no `empty()`/`Default`** — an
empty head-set is fail-OPEN, so callers propagate a snapshot error, never substitute a blank.

**Two authorizer arms** (`src/query/authorizer.rs`), both resting on
`SQLITE_DBCONFIG_DEFENSIVE` (on every writer open — see migrations-boot.md):
- The **writable arm** takes a `&SearchTables`. Two writable clauses: (1) an index HEAD is
  writable only when the authorizer `accessor` is one of its own `_system_search_`-prefixed
  sync triggers — top-level RPC SQL (accessor `None`) is denied, so no caller can poison an
  index by hand; (2) a real module internal (`is_internal`, `type='shadow'`) is writable
  by-name, safe only because DEFENSIVE refuses direct SQL on shadows.
- The **additive search-reader** is a SEPARATE `attach_search_readonly_authorizer`, used
  ONLY at drust-built read sites (`/list`, `/search`, `/aggregate` + MCP mirrors + edge
  list). Caller-SQL sites (`validate_rpc_sql`, `execute_read_query_with_named`) keep the
  strict `attach_readonly_authorizer` — widening the shared reader would let an
  `anon_callable` read-RPC `SELECT … FROM "<head>"` dodge owner-scope and leak indexed
  columns to anon.

**Row authorization is on the PARENT.** `$fts` compiles to `"id" IN (SELECT rowid FROM
"<head>" WHERE "<head>" MATCH ?)`; the unchanged owner/RLS/caps `WHERE` on the parent decides
row access, so a User only searches their own rows. The head name is always
`fts_head_name(coll, entry.name)`, never caller input; `index` unknown → `FTS_INDEX_NOT_FOUND`.

**Mandatory `('rebuild')` backfill + DDL quota carve-out.** `create_fts_index` runs
`INSERT INTO "<head>"("<head>") VALUES('rebuild')` inside the same `with_writer_tx` — without
it, later deleting/updating a pre-index row raises `SQLITE_CORRUPT`. The rebuild holds the
writer mutex for the whole corpus and is unbounded growth with **no `check_tenant_quota`** —
the documented DDL trusted-caller carve-out (a service/admin key can transiently exceed the
cap by building one index; the next record/upload write then blocks). Untrusted anon/user
cannot reach the tool.

**Per-term trigram fallback.** Default tokenizer is `trigram` (CJK-friendly). If ANY
whitespace-separated term in the query is < 3 chars, the whole operand compiles to
`?`-bound `LIKE '%<raw query>%' ESCAPE '\'` over the concatenation of the indexed columns
(phrase-substring semantics) — because fts5 silently treats a short trigram term as a
satisfied no-op and would otherwise return over-broad rows (`'zz 醫院年度'` would match rows
lacking `zz`). A documented v1.60 semantic simplification. `unicode61` never falls back.

**`FTS_QUERY_INVALID` is STRUCTURAL, never message-substring.** A malformed MATCH is decided
by a pre-probe `SELECT rowid FROM "<head>" WHERE "<head>" MATCH ? LIMIT 1` before the main
statement, mapped to `400 FTS_QUERY_INVALID`. Substring-classifying a native SQLite error is
banned here.

**`$fts` is a reserved Leaf KEY, rejected in policies.** It is special-cased in `compile_leaf`
(like `$auth`/`$data`), NOT a `FilterAst` variant. All three policy entry points —
`compile_policy_using`, `eval_policy`, and the save-time `check_ast_operand_classes` — reject
it with `POLICY_OPERAND_UNSUPPORTED` (CLAUDE.md invariant 12; drust cannot enforce row-access
on a policy that searches a shadow).

## Provenance

Extracted from CLAUDE.md "Per-collection schema metadata", "Record history", the /list + /aggregate + batch/upsert bullets of "Tools & endpoints", "Per-tenant quota", and the write-path invariants during the 2026-08-02 restructure. FTS search section added for v1.60.

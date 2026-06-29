## v1.44.1 — 2026-06-29

### fix — LOW-severity findings from the v1.44.0 caller-identity-invoke review

Follow-up to the adversarial review of v1.44.0 (LOW findings only; two MEDIUMs —
`enforced_update`'s non-atomic pre-flight-then-write vs REST's in-tx atomicity, and
the `fn_invoke_rl` ordering / writer-starvation vector — are tracked but deferred).
The `Privileged` (service / event / cron) invoke path is **unchanged**; these
harden the anon/user enforcement core and the HTTP invoke gate.

- **Invoke-gate function-name parse is end-anchored** (`src/functions/invoke_gate.rs`).
  `function_name_from_path` anchors on the terminal `/invoke` segment instead of the
  first `functions` marker, so a tenant id — or a function literally named
  `functions` / `invoke` — resolves correctly (F11).
- **No function-name enumeration oracle on the invoke gate** (F5). A missing function
  denies **identically** to an existing-but-flag-off one
  (`403 FN_INVOKE_{ANON,USER}_DENIED`), never a distinct `404` — a public anon key can
  no longer probe which function names exist.
- **`enforced_list` surfaces honest errors** (`src/functions/enforce.rs`,
  `src/query/list_builder.rs`). A failed count query propagates with `?` instead of
  masking as `total=0` beside a non-empty page, and list errors carry a typed code via
  the new `list_builder::list_error_code` (mirrors REST's `map_list_error`) instead of
  a `Debug`-formatted enum (F3, F10).
- **Authorizer no longer stranded on a pooled reader** (F7). `is_writable_target`
  detaches the read-only authorizer before the `?`, so a non-`NoRows` error cannot
  leave it attached on a reused connection.
- **`enforced_delete` not-found matches `enforced_update`** (F8) — a foreign-row
  delete returns the same typed `RECORD_NOT_FOUND` shape.
- **Atomic invoke-ACL PATCH** (`src/functions/schema.rs`). `set_invoke_acl_partial`
  (single `COALESCE` UPDATE) replaces the REST PATCH read-merge-write that could drop a
  concurrent one-sided flag change (F9).
- **Perf + coverage** (F13, F14): skip `load_file_caps` for `Privileged` callers,
  `load_schema` cache-hit fast path, `prepare_cached` count; new `load_file_caps` and
  delete-foreign-row test coverage.

### docs — code-intelligence tooling switch

`docs/gen-architecture.py` and `docs/architecture.md` now reference **codebase-memory-mcp**
(`search_graph` / `trace_path` / `get_code_snippet`) for ground-truth call graphs,
replacing the retired CodeGraph MCP; `architecture.md` regenerated.

## v1.44.0 — 2026-06-25

### feat — caller-identity edge-function invoke (anon/user-invokable functions, phase 1)

Edge functions can now be invoked by **anon and end-user (`drust_user_*`) bearers**,
not only by the service key — faithfully matching Supabase Edge Functions. An
anon/user invocation runs the function **under the caller's own identity**, so its
host data-plane access is gated by exactly the same `anon_caps` / `user_caps` +
`owner_field` + RLS policy + file caps the caller would hit calling REST directly.
**Config — including granting/revoking who may invoke — stays service-only.** Built
end-to-end under workflow orchestration with explicit cross-privilege escalation
tests as the oracle. Cron / scheduled jobs are **phase 2** (separate spec).

- **`CallerCtx` execution identity** (`src/functions/caller.rs`). A three-variant
  enum (`Privileged` | `Anon` | `User{user_id}`) threaded `Invocation` → executor →
  host. **No `Default`, no fallthrough to `Privileged`** — by type design, an
  anon/user invocation can never reach god-mode by accident (a CRITICAL
  cross-privilege escalation if it could); every construction site names the
  variant. `Privileged` (service invoke, event triggers, future cron) keeps
  **god-mode, byte-for-byte unchanged**.
- **Reusable enforcement core** (`src/functions/enforce.rs`). Transport-agnostic
  per-op authorization keyed on `AuthCtx`, reproducing the REST handlers' decision
  order EXACTLY — cap-gate (`has_dml_cap`), anon-owner-scoped deny, owner
  stamp/filter (`compute_owner_*`) by `read_scope`, RLS USING pre-flight + in-tx
  CHECK, per-verb file caps (`get-file-bytes`=read, `put-file`=upload) — then
  delegates to the existing `mcp::tools::{write,read}` writers (so a function write
  still fans out to SSE + webhooks). The function host calls this core for any
  non-`Privileged` `CallerCtx`. The REST handlers are deliberately **not** refactored
  onto the core in phase 1 — they remain the regression oracle, so the existing
  `tests/` suite proves the core's decisions match REST.
- **Invoke ACL — default-deny, service-only config.** Two columns on
  `_system_functions` (`invoke_anon` / `invoke_user`), idempotent `ADD COLUMN` boot
  migration guarded on `pragma_table_info`, **default 0** — every existing function
  stays service-only; the migration mints/grants nothing. Granting AND revoking are
  both config = **service-only** across three faces: REST `PATCH
  /t/<id>/functions/<name>` (one-sided merge so a partial PATCH can't clobber the
  other flag), MCP **`set_function_invoke_acl`** (**MCP tool count 58 → 59**), admin
  `ƒ _functions` toggle.
- **DiD ≥ 2 on the new HTTP exposure.** (1) `invoke_gate_layer`
  (`src/functions/invoke_gate.rs`) on the `/invoke` route only — service→allow
  (`Privileged`); user→allow iff `invoke_user` else `403 FN_INVOKE_USER_DENIED`;
  anon→allow iff `invoke_anon` else `403 FN_INVOKE_ANON_DENIED` (alias
  `WRITE_DENIED`); plus a per-IP `fn_invoke_rl` rate-limit (30/60s, `429
  RATE_LIMITED_IP`) on non-service callers. CRUD + `/logs` keep
  `require_service_layer`. (2) The executor re-asserts the function's flag against
  the **freshly-read** row before running — a flag flipped off between gate and run
  fails closed — and the enforcement core applies caps/owner/RLS regardless of how
  invoke was reached. MCP `invoke_function` stays **service-only** by MCP dispatch.
  `depth=1` / `functions:None` unchanged (no recursion relaxation); caller-supplied
  `event_json` is no longer an escalation lever for anon/user, because the run is
  capability-gated.

### live-smoke (run against the running service on `:8793`, service key = `tokens.plaintext`)

```bash
# 0) deploy + version check
cd /home/kaelsohappy1/tool/drust
cargo build --release && sudo systemctl restart drust
curl -sI http://127.0.0.1:47826/health | grep -i x-drust-version   # → 1.44.0

# 1) service-seed: a collection with anon_caps/user_caps + owner_field, a user,
#    and a function. SVC = a tenant service key (tokens.plaintext); T = tenant id.
#    Create an owner-scoped collection where User has insert+select via user_caps:
#      create_collection notes  (owner_field="owner", read_scope="own",
#                                anon_caps=[], user_caps=[select,insert])
#    Upload a .wasm that inserts a row into `notes` on invoke, then:
#      set_function_invoke_acl name=ins invoke_user=true invoke_anon=false
#    Register a user (drust_user_*) → USER bearer.

# 2) user-invoke runs under the caller → owner stamped, caps enforced
curl -s -H "Authorization: Bearer $USER" \
  -X POST http://127.0.0.1:47826/t/$T/functions/ins/invoke -d '{}'
#   ⇒ inserted row's owner == the user's id; a foreign-row UPDATE the fn attempts → 404;
#     an op the user lacks the cap for → cap-denied INSIDE the function (not god-mode).

# 3) anon-invoke denied while invoke_anon=0
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $ANON" \
  -X POST http://127.0.0.1:47826/t/$T/functions/ins/invoke -d '{}'
#   ⇒ 403 FN_INVOKE_ANON_DENIED

# 4) event-trigger path still god-mode (Privileged, unchanged): insert a record that
#    fires record.created → the bound function writes WITHOUT cap/owner restriction.
#    Confirm via _system_function_logs that the trigger run succeeded.

# 5) MCP invoke stays service-only: invoke_function via a USER/ANON MCP bearer → denied.
```

## v1.43.0 — 2026-06-24

### feat — native SQLite adoption (STRICT, CHECK, RETURNING, prepare_cached, PRAGMA optimize)

Lean harder on the bundled SQLite (3.53) so the BaaS gets typed columns, native
value constraints, and one-round-trip writes — built end-to-end under workflow
orchestration and adversarially reviewed by three independent engines.

- **STRICT tables (WS1).** New tenant collections are created `STRICT` (typed
  columns rejected at the engine, not just the tool layer). A boot-time migration
  rebuilds **existing** pre-STRICT collections via per-table copy-then-swap
  (`src/db/migrations.rs::strict_rebuild_tenant`): DDL is reconstructed verbatim
  from `sqlite_master.sql` (preserving FK `ON DELETE`, CHECK, COLLATE, composite
  PK, defaults), rows + indexes + the `updated_at` trigger + the `sqlite_sequence`
  high-water are preserved, and each table runs in its own transaction with
  DROP-after-copy ordering so a failure leaves the original intact. Idempotent
  (gated on `pragma_table_list.strict`), so the per-boot `run_migrations` re-runs
  as a no-op. A table holding STRICT-incompatible legacy data stays non-STRICT,
  fail-safe.
- **CHECK constraints (WS6).** `FieldSpec` gains structured `min` / `max` /
  `enum` / `max_length`, compiled into ONE inline `CHECK(...)` clause built only
  from drust-controlled, escaped literals (`compile_check`, never raw tenant SQL —
  same camp as `SQL_DEFAULT_ALLOWLIST`). Persisted to
  `_system_collection_meta.field_constraints_json`, mirrored by an app-layer
  pre-check (typed `CHECK_CONSTRAINT_FAILED` before the native CHECK would raise a
  raw string) and reflected by codegen (zod `.min/.max/z.enum`, OpenAPI
  `minimum/maximum/maxLength/enum`, TS literal union + JSDoc). Config is
  service-only via the existing `create_collection` / `add_field` — **no new MCP
  tool** (tool count stays **58**).
- **RETURNING read-back (WS2).** `INSERT … RETURNING *` / `UPDATE … RETURNING *`
  collapse the post-write read-back into one round-trip on both the MCP and REST
  write paths, with a shared row-materializer. Byte-identical to the old
  `SELECT`-after-write: vector-hide, `BLOB→{__blob_bytes}`, owner stamp, the
  post-image policy CHECK inside the write tx, and the zero-row→404 arm all
  preserved.
- **prepare_cached on hot reads + PRAGMA optimize (WS3/WS4).** The structured
  `/list` (explicit schema-derived projection) and `COUNT(*)` reads use
  `prepare_cached`; `get_by_id` and the legacy list move their owner clause to a
  `?`-bind. `PRAGMA optimize` runs best-effort every N writes per pool on the
  writer connection (`analysis_limit`-bounded), refreshing the query planner
  without ever failing a write.

### fix — review hardening (3-engine adversarial review: implementer workflow + fresh workflow + codex)

Every finding below shipped with a regression test.

- **`prepare_cached` on `SELECT *` served a stale column set after
  `add_field`/`drop_field`** (HIGH). rusqlite keys its per-connection statement
  cache by SQL text, which is stable across DDL, so a `SELECT *` read on a
  long-lived pooled reader silently dropped a newly added column (or 500'd on a
  dropped one) — DDL flushes only the drust schema cache + SSE bus, never the
  reader's statement cache. Reverted the three `SELECT *` read sites
  (`get_handler`, `list_bound_rows`, and the stored-RPC named-exec path) to plain
  `prepare`; the explicit-projection `/list` self-heals and keeps caching.
- **STRICT-rebuild `foreign_key_check` was whole-DB** (MEDIUM) — one pre-existing
  orphan in any table blocked STRICT migration of every clean table; now scoped to
  the rebuilt table.
- **STRICT-rebuild temp table could collide** with a tenant collection literally
  named `<x>__strict_tmp` (MEDIUM); now a `_system_`-prefixed name no tenant can
  occupy.
- **CHECK error path** (MEDIUM): numeric/boolean enums sent as JSON numbers
  bypassed the app pre-check (now type-aware); `is_check_violation` mislabeled
  UNIQUE/NOT-NULL/FK errors on columns named like `check_*` (now gated on the
  extended code `SQLITE_CONSTRAINT_CHECK`); the MCP write path gained the same
  `CHECK_CONSTRAINT_FAILED` backstop REST has.
- **Codegen rendered numeric enums as a string union** (MEDIUM) → generated
  clients rejected real numeric payloads; now numeric literals.
- **Config-time validation** (`compile_check`): rejects `min > max`,
  `max_length == 0`, fractional enum members on integer fields, NUL bytes in enum
  values, and oversized enums — unsatisfiable or unsafe constraints fail at
  create time.

## v1.42.0 — 2026-06-24

### feat — file-storage caps (anon + user)

File storage was service-key-only. A tenant can now grant `anon` and `user`
bearers an opt-in subset of `{read, list, upload, delete}` over its file pool — a
Supabase-style **cap-gated shared bucket** (access decided by caps, NOT per-file
ownership). Service stays unrestricted; **make-public (set-visibility) stays
service-only**. Default is **all-off** (empty `[]`), so every existing tenant
keeps today's exact service-only behaviour until it opts in.

- **Model:** `FileVerb{read,list,upload,delete}` (mirrors `DmlVerb`). Caps live as
  JSON on the `tenants` row (`file_anon_caps_json` / `file_user_caps_json`,
  default `'[]'`), loaded in `SQL_BEARER_AUTH_CTE` (cols 8,9) onto a
  `TenantFileCaps` request extension, cached in `CachedAuth` (both paths).
- **Enforcement:** a new `file_caps::file_caps_layer` replaces the blanket
  `require_service_layer` on the data-plane files_router and gates each route
  per-verb (service bypasses; anon/user checked against their cap set). The
  route→verb classification is a pure, unit-tested fn. Mode-A handlers are
  untouched (they are also mounted under `/admin`, which has no `TenantRef`); the
  tus (Mode-B) handlers add an inline cap check as defense-in-depth layer 2.
- **Config (service-only):** MCP `set_file_caps` (hook 12 — clears the auth cache
  on change, like publish-policy). **MCP tool count → 58.** No data-plane REST
  route (mirrors `anon_caps`/`user_caps`).
- **Guardrails (platform integrity, always on):** per-IP rate-limit on
  non-service `upload`+`delete` (30/60s, XFF-keyed) bounds the public anon-key DoS
  vector; the existing disk-guard (507) + per-tenant quota still apply; uploads
  default `private`. Deny codes `FILE_{READ,LIST,UPLOAD,DELETE}_DENIED` (alias
  `WRITE_DENIED`).
- **tus sessions are per-bearer bound:** the `_system_upload_sessions.uploader`
  column (reused, no migration) records the creator's identity (service / anon /
  `<user_id>`); `HEAD`/`PATCH`/`DELETE` require a non-service caller's identity to
  match (404 on mismatch, no existence leak). Service manages any session.
- **Deferred to a fast-follow** (documented, not a gap): the admin `_files` caps
  editor — MCP `set_file_caps` is the config surface this release; the admin UI
  needs i18n keys across all locale bundles.

Spec: `docs/superpowers/specs/2026-06-24-drust-file-storage-caps-design.md`.

## v1.41.5 — 2026-06-23

### fix — admin PATs no longer reroll on every restart

The v1.29.3 "one PAT per admin" migration (`src/db/migrations.rs`, the
`collapse legacy PATs` block) revoked **every active** `_admin_tokens` row with an
unqualified `UPDATE … SET revoked_at = now WHERE revoked_at IS NULL`, then the
backfill loop minted a fresh PAT per admin. That step was written as a one-time
upgrade but had **no run-once guard**, and `run_migrations` runs on **every boot**
(`main.rs`) — so **every restart rerolled every admin's PAT**: the previous (now
plaintext-bearing) PATs were re-revoked and replaced. In production this churned
admin 1's PAT 68 times and accumulated a revoked row per restart, and — the
practical symptom — any integration keyed on an admin PAT (e.g. an MCP server
configured with a `drust_pat_*` bearer) returned **401 after every deploy**,
because the token it held had just been rotated out.

Diagnosed from the live token timestamps: every admin's newest PAT `created_at`
matched the deploy-restart instant to the second.

**Fix** (`src/db/migrations.rs`): qualify the legacy revoke with `AND plaintext
IS NULL`. Legacy rows (Task-8 `kind='manual'` and v1.29.2 `kind='auto_mcp'`) are
exactly the plaintext-less ones, so the one-time upgrade still works; on every
subsequent boot the active, plaintext-bearing PATs no longer match and the step
is a no-op, so PATs survive restarts. Regression:
`run_migrations_does_not_reroll_pat_on_every_boot` (run migrations twice → same
active PAT). The existing `bootstrap_then_migrate_results_in_one_active_pat`
(legacy/fresh path) stays green.

> [!NOTE]
> Per-tenant **service** and **anon** tokens were never affected (they live in
> `tokens`, not `_admin_tokens`, and nothing on the boot path touches them — a
> per-tenant MCP server keyed on the tenant **service token** has always survived
> restarts). The recommended MCP bearer remains the tenant service token, not an
> admin PAT. Accumulated revoked PAT rows are harmless (lookup filters
> `revoked_at IS NULL`); the fix stops further accumulation.

## v1.41.4 — 2026-06-23

### security — ISO & code-review batch (dual-AI: codex + adversarial workflow)

A second whole-system isolation/security review (external `codex` gpt-5.5 pass +
a 10-dimension codegraph-backed adversarial workflow, each finding refuted by an
independent skeptic) surfaced four real intra-tenant authorization gaps and one
documented footgun the maintainer chose to close. The recurring shape: drust
grew two newer row-access mechanisms — `user_caps` (v1.41) and RLS policies
(v1.38) — but several enforcement sites written for the original `owner_field`
mechanism were never extended to mirror them. Each fix ships with a regression
test; the implemented fixes were then re-verified by a second adversarial
workflow before release. No new MCP tool; no schema change.

- **F1 (High) — `read_scope="all"` cap/owner lockstep break (intra-tenant).**
  `has_dml_cap` returned `true` for any User verb whenever `owner_field.is_some()`
  ("the row filter handles access"), but `compute_owner_filter` only emitted that
  filter for `read_scope="own"`. So on an owner-scoped collection set
  `read_scope="all"`: (a) `GET /records` + `POST /search` returned every row even
  with `user_caps=[]` — diverging from `POST /list`, which already gated on
  `user_caps[select]`; and (b) `PATCH`/`DELETE` (incl. the `dry_run` blast-radius
  pre-flight) became ID-only, letting a user **modify or delete another user's
  row**, violating the documented "UPDATE/DELETE foreign rows → 404" invariant.
  Now: reads under `read_scope="all"` are gated by `user_caps[select]` (lockstep
  with `/list`), and writes ALWAYS carry the owner clause regardless of
  `read_scope` (new `compute_owner_write_filter`) so a user can only mutate their
  own rows. `read_scope="own"`, service bypass, and anon-on-owner-scoped (403)
  are unchanged. (codex F2; independently confirmed.)
- **F2 (Medium) — RPC anon-guard was blind to RLS policies (intra-tenant).** The
  v1.41.3 `guard_anon_owner_scoped_rpc` probed only `owner_field`; a collection
  with `owner_field=NULL` but a `select_policy` (a valid v1.38 policy-only config)
  passed the guard. Since drust never rewrites stored-RPC SQL, an `anon_callable`
  RPC `SELECT * FROM articles` then returned the rows the policy hides to anon —
  the structural twin of the owner_field RPC leak. The guard now also refuses any
  RPC referencing a collection with ANY `*_policy_json` (a `:user_id` param does
  NOT exempt the policy case — a policy need not key on the caller), mirroring
  `/query` fail-closing on policy adoption. New symmetric config-time guard
  `guard_policy_change_against_anon_rpcs` wired into all three policy-attach sites
  (REST `put_policies`, MCP `set_policy`, admin `admin_update_policies`); the
  startup `scan_unsafe_anon_rpcs` migration now also flags `:user_id` RPCs over
  policy collections (its `:user_id` early-skip was removed). Runtime `call_rpc`
  is intentionally not re-checked — config-time remains the boundary.
  (adversarial-workflow completeness critic; confirmed.)
- **F3 (Medium) — revoking `anon_caps`/tightening a policy did not drop in-flight
  anon SSE subscribers (intra-tenant).** The `subscribe` handler captures
  `anon_caps` + the select-policy ONCE at connect and never re-reads them. The
  realtime-DISABLE path force-closes subscribers (`bus.evict_collection` after
  `schema_cache.invalidate`), but the caps-revoke and policy-tighten paths called
  only `schema_cache.invalidate` — which affects only the *next* connect. An
  already-connected anon therefore kept receiving `Created`/`Updated`/`Deleted`
  events for the full connection lifetime after losing read access, defeating the
  "anon SSE requires realtime_enabled AND anon_caps[select]" invariant. Every
  write path that reduces anon read access now evicts the broadcast channel so
  subscribers reconnect and re-gate: MCP `set_anon_caps`/`set_policy`/`clear_policy`,
  REST `put_policies`/`delete_policy`, admin `update_anon_caps`/`admin_update_policies`,
  and `set_owner_field` (REST + MCP — owner-scoping a collection denies anon
  subscribe, the parallel site the second adversarial workflow caught). `user_caps`
  paths intentionally do not evict (user tokens cannot subscribe to SSE).
  (adversarial workflow; the `set_owner_field` site found + closed in the
  self-verification pass.)
- **F4 (Medium) — `remove_admin` skipped the `clear_admin_pat` auth-cache hook.**
  Deleting an admin cascade-revokes their PATs (`_admin_tokens` FK
  `ON DELETE CASCADE`), but a freshly-used PAT served on a cache hit bypasses the
  meta lookup, so a removed admin kept service-level data-plane access until the
  10s safety TTL. `remove_admin` now calls `s.auth_cache.clear_admin_pat(target_id)`
  after the commit, mirroring the self-reroll hook. (adversarial workflow;
  confirmed.)
- **D1 — `/query` + `/query/explain` are now service-only.** `anon_caps` never
  governed the raw, un-rewritable `/query` surface, so a tenant with an anon token
  plus a cap-restricted collection (`anon_caps=[]`, no owner_field/policy) leaked
  that collection via raw SELECT (the documented mitigations were "revoke the anon
  token" or "adopt a policy"). `/query` and `/query/explain` now deny every
  non-Service caller: User keeps `QUERY_USER_DENIED`; Anon — previously allowed
  until the tenant adopted a policy/owner_field — is denied unconditionally
  (`QUERY_ANON_DENIED`, with `ANON_QUERY_DENIED_ON_POLICY` retained as an alias).
  Anon/User read through the structured, `?`-bound `POST /collections/<c>/list`
  or `/search`. (codex F1, rated a footgun; maintainer chose service-only.)

### deploy hardening — from the owner's live gray-box pentest (v1.41.3 Docker)

A live gray-box penetration test of the v1.41.3 Docker image (two independent
offensive engines, 175 cross-tenant probes, **0 cross-tenant breach / 0 Critical /
0 High** — isolation, the SQL authorizer, FilterAst `?`-binding, role gates, and
SSRF defenses all held; BUG-1 confirmed closed) surfaced two deploy-side items,
folded into this release as `docker-compose.yml` changes:

- **F2-RL-001 (Medium) — login/register rate-limit bypassable via X-Forwarded-For
  rotation on the direct app port.** `client_ip` trusts the XFF chain
  (`TRUSTED_TRAILING_HOPS=1` → `parts[len-2]`) and `IpRateLimit` keeps only per-IP
  buckets with no global counter, so on the all-interfaces-published `:47826` an
  attacker rotating a forged `X-Forwarded-For` gets a fresh 5/min budget per
  spoofed IP (through Caddy the XFF normalizes to one bucket — no bypass). Fixed
  by binding the published port to host loopback (`127.0.0.1:47826:47826`); Caddy
  reaches drust over the Docker network, so external direct reach is the only
  thing removed. (In-app global-rate-limit defense-in-depth considered and
  deferred — it sits behind the now-closed door and carries a lockout/DoS design
  tradeoff.)
- **INFO-1 (Low) — `x-drust-version` fingerprint.** The header is on by default
  (the v1.41.3 `DRUST_HIDE_VERSION` gate only suppresses it on opt-in). The
  distributed compose now ships `DRUST_HIDE_VERSION` enabled so the public image
  does not leak the exact build; the in-app default stays ON for deploy/live-smoke
  version checks.
- **INFO-3 (Low) — cleartext `tokens.plaintext` / admin PATs in `meta.sqlite`** is
  the already-documented, risk-accepted DEPLOY-3 (backups are a secret store); no
  change. The whoami dual-token disclosure was refuted as by-design
  self-disclosure (service-key-gated, same tenant).

Audit report: `docs/superpowers/specs/2026-06-23-drust-iso-security-audit.md` (internal, not published). Refuted /
accepted-as-documented items (anon `/query` design, codegen anon schema
structure, edge-function service privilege, exotic IPv6 SSRF forms, OAuth state
secret) recorded there. `cargo audit` clean.

## v1.41.3 — 2026-06-22

### security — authorized pentest + code-review batch (Docker v1.41.1)

An authorized owner-conducted penetration test against the Docker v1.41.1
instance, plus a code-review sweep that traced each finding's root cause to
every enforcement site, surfaced two real anon read leaks (BUG-1, RPC guard), a
fail-open authorization probe (BUG-2), an SSRF carve-out shipped in production
(DEPLOY-1), a config-time policy divergence, and a version-fingerprinting header.
No schema change, no new MCP tool. Each fix ships with a regression test.

- **BUG-1 (High) — anon read leak on owner-scoped collections with
  `read_scope="all"`.** The legacy `GET /records` list, `/search`, and SSE
  `subscribe` anon-owner guards each denied only when `read_scope=="own"`. An
  owner-scoped collection configured `read_scope="all"` (a valid config)
  therefore leaked **every user's** rows/events to an anonymous caller — anon
  passed the guard, passed the default `[select]` cap, and no owner row-filter
  is ever applied to the Anon role. `POST /list` already denied anon on any
  `owner_field`; the three legacy surfaces disagreed, violating the invariant
  "anon → 403 on owner-scoped collections". All three now deny anon on **any**
  `owner_field` regardless of `read_scope`. User/Service paths unchanged. The
  pentest flagged the list surface; code review found the same root cause at
  `/search` and SSE.
- **BUG-2 (High) — fail-open protected-collection probe.**
  `tenant_has_protected_collection` swallowed all DB errors via `.unwrap_or(0)`,
  so a real DB failure on a policy/owner-protected tenant returned `Ok(false)`
  and **allowed** anon `/query` + `/query/explain` (intra-tenant policy bypass);
  the callers' `.unwrap_or(true)` fail-closed branches were dead code. The probe
  now distinguishes the legitimate absent meta table on a brand-new tenant
  (`no such table` → `Ok(false)`) from every other error (→ `Err`, callers fail
  closed).
- **RPC guard (Medium) — anon-callable read RPC over an owner-scoped
  collection.** drust does not rewrite stored-RPC SQL, so an `anon_callable=true`
  read RPC whose body SELECTs an owner-scoped collection returns every user's
  rows to an anonymous caller (no owner row-filter is injected at call time,
  unlike `/list` and `/search`). A create-time guard
  (`guard_anon_owner_scoped_rpc`, sentinel `RPC_ANON_OWNER_SCOPED`) now refuses
  this shape on every mutation entry point — both create paths (MCP `create_rpc`
  + admin form) **and the MCP `update_rpc` path** (`guard_anon_owner_scoped_rpc_update`
  re-checks the effective post-update values against the stored row, so a
  flag-flip or sql-swap update cannot reopen the leak) — and in **both read and
  write modes** (an anon-callable write RPC over an owner-scoped collection is
  strictly worse: it lets anon mutate every user's rows). The escape hatch is a
  declared `:user_id` param; service-only RPCs and non-owner-scoped collections
  pass untouched. (The update-path and write-mode coverage were added after a
  pre-release adversarial review caught the create-read-only guard as
  incomplete — drust's recurring "fixed one enforcement site, missed the
  parallel one" pattern.) A second review pass added the remaining two
  enforcement layers (defense-in-depth ≥ 2): a **config-time guard**
  (`guard_owner_scope_change_against_anon_rpcs`) refuses to make a collection
  owner-scoped via `set_owner_field` (MCP + REST) while an existing anon-callable
  RPC reads/writes it without `:user_id` — closing the reachable
  "becomes-owner-scoped-later" gap the create-time guard never re-checks — and a
  **one-time startup migration** (`scan_unsafe_anon_rpcs`) neutralizes any
  pre-guard legacy row fail-closed (`anon_callable=0`, logged) so an in-place
  upgrade cannot leave the leak open. The runtime `call_rpc` path is unchanged.
- **DEPLOY-1 (Medium) — webhook loopback SSRF carve-out now opt-in.** The
  `http://localhost` (`127.0.0.1`/`::1`) dev carve-out in the webhook SSRF
  defense shipped unconditionally in production at both the register-time
  `check_url` gate and the dispatch-time `is_loopback_dev` bypass, letting a
  tenant SSRF host-loopback internal services that `PinnedPublicResolver`
  otherwise blocks. Both carve-outs are now AND-gated through a pure
  `webhook_loopback_allowed(cfg!(debug_assertions), DRUST_WEBHOOK_ALLOW_LOOPBACK)`
  helper — a prod release build with the env unset blocks loopback at both sites
  (defense in depth ≥ 2). The `INVALID_URL` rejection message now names the
  opt-out. (This tightens the v1.41.2 F5 dev carve-out that was "intentionally
  left unchanged".)
- **Policy `$data`-in-USING rejected at config time (Medium).**
  `validate_policy` compiled both USING and CHECK against a probe ctx with
  `data: Some(...)`, so a `$data` ref in a USING clause passed validation. `$data`
  is CHECK-only (post-image row); at read time a USING `$data` ref was fail-closed
  but **divergent** — REST `compile_policy_using` (`data: None`) returned `500
  POLICY_COMPILE_ERROR` while SSE `eval_policy` resolved `$data` to NULL and
  silently dropped every event. validate now probes USING with `data: None` (the
  real read context, surfacing `PolicyError::DataUnavailable`) and CHECK with
  `data: Some`, keeping the two evaluators in lockstep by construction.
- **DEPLOY-4 (Low) — `x-drust-version` opt-out via `DRUST_HIDE_VERSION`.** The
  version header was emitted unconditionally, fingerprinting the exact build to
  unauthenticated callers. Default (env unset) still emits it byte-for-byte (the
  deploy/live-smoke check curls it); `DRUST_HIDE_VERSION` suppresses the layer.
  The same flag now also blanks the version rendered in the unauthenticated
  `/login` page footer (the most important fingerprint surface — caught in the
  same adversarial review as the only remaining unauthenticated leak).
- **GAP-1 (test only) — `$data` operand added to the RLS lockstep corpus.** The
  consistency corpus proving `compile_policy_using` and `eval_policy` agree never
  exercised `{"$data":"<field>"}`. Added: both evaluators resolve `$data` from
  `PolicyCtx.data` identically, plus the CHECK-only fail-closed contract. No
  source change — would RED on a future `$data` lockstep divergence.
- **Dependencies — `quinn-proto` 0.11.14 → 0.11.15** (RUSTSEC-2026-0185, HIGH:
  remote memory exhaustion via unbounded out-of-order QUIC stream reassembly,
  transitive through `reqwest → quinn`). Caught by a pre-push `cargo audit`;
  lockfile-only patch bump, no API change. Relevant because drust's outbound
  `reqwest` targets include tenant-controlled webhook URLs.

> [!CAUTION]
> **DEPLOY-3 (documented, not code-fixed) — backups contain live plaintext
> credentials.** The daily `VACUUM INTO meta.sqlite` snapshot carries the
> `tokens.plaintext` (per-tenant keys, v1.1c) and `_admin_tokens.plaintext`
> (admin PATs, v1.29) columns verbatim, so a `backups/*.tar.zst` grants full
> data-plane (and admin-PAT cross-tenant) access until tokens are rerolled. Risk
> accepted for now; treat the backup directory as a secret store. See the backup
> CAUTION in `CLAUDE.md`.

## v1.41.2 — 2026-06-22

### security — four fixes from an independent second-AI (codex) audit

A read-only security audit by codex (driven over codegraph), cross-verified
against the code, surfaced four intra-tenant authorization/lockstep gaps. No
schema change, no new config. Two are real privilege/oracle bypasses (F1, F2);
two are hardening (F3, F4). Each fix ships with a regression test.

- **F1 (High) — legacy `?filter=`/`?sort=` raw-SQL cap bypass.** `GET
  /records/<c>?filter=…` interpolated the filter verbatim into `build_list_sql`,
  and the read-only SQL authorizer allows reads of any non-`_system_` sibling
  collection. An anon/user caller with `select` on one collection could smuggle
  a subquery (`EXISTS(SELECT 1 FROM "other" …)` / `UNION`) to read sibling
  collections their role has no caps on — bypassing the per-collection cap
  boundary. The owner-scoped and policy guards only covered some shapes; a plain
  collection slipped past both. Raw `?filter=/?sort=` is now `403
  RAW_FILTER_DENIED` for anon/user on every collection (service keeps it; the
  param is deprecated, Sunset 2027-01-01) — use the structured `POST /list`.
- **F2 (Medium) — DELETE `?dry_run=true` blast-radius oracle.** The dry_run
  preview returned FK topology + child-row counts before any cap / owner /
  policy check, so anon/user could probe rows they cannot delete (and may not
  read). Authorization now runs before the dry_run branch, plus an owner +
  policy-USING target pre-flight inside it (non-target → 404, like a real delete
  miss). `_system_` now 404s via `require_write_cap`.
- **F3 (Low) — anon SSE leaked policy-hidden deletes.** The per-event select
  policy filter only ran on Created/Updated; `Deleted{id}` always passed,
  leaking deletion id/timing for rows a select policy hides. Deleted events are
  now dropped for an anon subscriber whenever a select policy is active.
- **F4 (Low) — RLS evaluator lockstep on empty `$nin`/`$in`.** `eval_policy`'s
  NULL-lhs guard fired before the empty-set check, so empty `$nin` on a NULL
  field disagreed with the compiled SQL (`NOT IN ()` is true for all rows),
  fail-open once wrapped in `not`. eval now decides the empty set first, matching
  the compiler. (The v1.38.2 H3 fix covered only non-empty arrays.) Policy config
  is service-only, so this is correctness/lockstep, not a direct attacker vector.

F5 (webhook loopback dev carve-out — trusted-actor + documented), F6 (refuted:
`object_store::path::Path` normalizes `..`), and F7 (tenant-id slug vs strict
UUID — admin-only, no traversal/collision) were assessed and intentionally left
unchanged.

## v1.41.1 — 2026-06-18

### fixes — admin toggle switches + Docker disk panel

Two bug fixes surfaced by the GHCR/Docker deployment. No schema change, no new
config, no behavior change for the existing systemd host.

- **Cap-switch toggles stuck until refresh** (`_api_keys` self-register +
  publish-policy tiles). Each `.cap-tile` is a `<label>` wrapping a
  `display:none` checkbox; the click handlers manually flipped `checked` but
  never called `preventDefault()`, so the browser's native label→control
  activation toggled it a second time and desynced the switch from its state —
  after one flip the toggle stuck until a page reload. Both handlers now cancel
  the native toggle with `e.preventDefault()`.
- **`_setSelfRegPill` printed English on a localized page.** The pill rewrite
  hardcoded `'enabled'`/`'disabled'` instead of the bundle strings, so flipping
  self-register on a zh-TW page showed "enabled" rather than "已啟用". It now
  emits `t.s("common.pill.enabled")` / `t.s("common.state.disabled")`.
- **Disk panel showed `?` under Docker.** `build_disk_view` and the Mode-A /
  edge-function upload guards `statvfs`'d a hardcoded `/var/lib/garage` — a path
  that only exists on the original co-located-Garage host and is absent inside
  the container, so the panel rendered `?` and the guards silently skipped. They
  now route through a process-global `disk_check_root()` set at startup from
  `Config.data_dir` (host `/var/lib/drust`, Docker `/data`), so the panel reports
  the filesystem the service actually writes to. The root falls back to
  `/var/lib/garage` when uninitialised, so the entire existing test suite is
  byte-identical — zero regression.

## v1.41.0 — 2026-06-17

### per-collection `user_caps` — the User role gets its own grants

Logged-in users (`drust_user_*` login/OAuth tokens) now have a per-collection
**`user_caps`** capability set (subset of `{select, insert, update, delete}`),
exactly parallel to `anon_caps` and stored beside it on
`_system_collection_meta`. Previously the User role had no caps of its own and
*inherited* `anon_caps` on non-owner-scoped collections, so the only ways to let
logged-in users write were to widen `anon_caps` (also opening anonymous tokens)
or set `owner_field` (forcing per-user row scoping). `user_caps` decouples the
two: grant write verbs to the User role without touching anon and without
requiring `owner_field`.

- **Default `[select]`** (identical to `anon_caps`), so every existing
  collection keeps its current effective behavior — read by default, write
  opt-in. A nullable `user_caps_json TEXT` column is added and back-filled from
  each row's `anon_caps_json` on boot (`IS NULL`-guarded, idempotent), so the
  upgrade is a faithful inherit with no behavior change until an admin grants
  write.
- **Anon is structurally untouched** — distinct column, distinct
  `has_dml_cap` branch; widening `user_caps` can never open a verb to anonymous
  tokens (`tests/user_caps.rs` locks this with an executable regression).
- **`owner_field` short-circuit unchanged** — owner-scoped collections behave
  exactly as before; `user_caps` only becomes the deciding gate on
  non-owner-scoped collections.
- **Caps remain a pure gate** — RLS policy USING/CHECK and the owner
  stamp/strip still run *after* and independent of the cap set; a widened
  `user_caps` cannot bypass a configured policy or owner rule.
- **Must-stay-denied** — User tokens are still hard-denied on `/query`,
  `/query/explain`, `/mcp`, and SSE subscribe regardless of `user_caps`.
- **Config surfaces mirror `anon_caps`**: a second checkbox section in the
  collection-editor `[⚙]` settings popover and a new MCP `set_user_caps` tool
  (service-only; tool count 56 → 57). No data-plane REST route (anon_caps has
  none).

## v1.40.0 — 2026-06-17

### redirect-URIs-only edit for per-tenant OAuth providers

Adds a path to edit a configured OAuth provider's `allowed_redirect_uris` without re-supplying `client_id` / `client_secret`, fixing the rough edge that the only writer was a full upsert (and the secret is masked on read, so every redirect tweak forced re-fetching the secret from the provider console). New `oauth_config::update_redirect_uris` updates only that column, so credentials are structurally untouchable. Surfaced on all three faces: MCP `set_redirect_uris` (tool #56), REST `PUT /t/<id>/admin/oauth-providers/<provider>/redirect-uris`, and an inline per-provider edit form (no secret field) on the admin `🔐 _oauth_providers` page. Service-key-only; exact-match unchanged (no wildcards); each write emits an audit row; updating a non-configured provider returns NOT_FOUND.

## v1.39.0 — 2026-06-16

### Configurable base path, OAuth/isolation hardening, Docker + GHCR distribution

**DRUST_BASE_PATH (feature).** The external URL mount is now configurable
(`src/base_path.rs`): the default `/drust` keeps the existing reverse-proxy
deployment byte-identical, and `""` serves at the root so the container image
runs standalone. Routes live at root (Caddy `handle_path` strips the prefix);
every browser-facing string — redirect `Location`, `Set-Cookie` `Path`, OAuth
`redirect_uri`, admin `href`/`action`/`fetch`, and JSON-returned paths — re-adds
it via `base()`/`cookie_path()` (`.rs`) or `{{ crate::base_path::base_path() }}`
(templates). `tests/base_path_root.rs` proves the empty-prefix mode; the existing
`/drust` assertions remain the default-mode oracle.

**OAuth account-claim + isolation hardening.** An OAuth login that matches an
existing unverified password account now atomically *claims* it inside a single
`with_writer_tx` rather than silently authenticating as it (closes a
pre-account-hijacking window). `iss`/`aud` mismatch errors no longer echo
untrusted `id_token` claim values, loopback detection accepts IPv6, and callback
failures redirect gracefully. Includes the `$nin`-against-NULL policy lockstep
fix (eval vs compile) from the audit series.

**Docker image + GHCR publishing.** The container image ships `DRUST_BASE_PATH=""`
(root mode) with a root-mounted bundled-Caddy compose file. A new
`release-image.yml` workflow builds a multi-arch (amd64/arm64) image on native
runners and publishes it to `ghcr.io/kaellim/drust` on every `v*` tag, attesting
build provenance on the final manifest. README/README.zh gain a `docker run`
prebuilt-image quickstart.

**Repo de-branding.** Organization-specific host/email references were replaced
with neutral `example.com` / `example.org` placeholders across source, docs, and
tests; no behavior change.

## v1.38.4 — 2026-06-15

### Hotfix: bare serde_json::Value MCP tool args rejected by strict clients

`invoke_function`'s `event`, `broadcast`'s `payload`, and `search_collection`'s
`vector` were typed as bare `serde_json::Value`, which schemars 1.x renders as an
untyped "AnyValue" property schema. Strict MCP clients (Claude Code's Zod
validation) reject it — the per-tenant `tools/list` failed with `Invalid input`
at `properties.event` and the client fetched **no** tools at all. Each now
overrides its schema via `#[schemars(with = ...)]` to an explicit type (object
for event/payload, array of numbers for vector); the runtime type stays `Value`,
so any JSON is still accepted. A tree sweep confirms these are the only three
bare-Value tool args (`Option<Value>` fields render an accepted
`{description, default}` schema, no override needed). + a regression test
asserting all three render explicitly-typed schemas.

## v1.38.3 — 2026-06-15

### Audit follow-up: correctness + security fixes

Closes the substantive correctness/security items from the 2026-06-15 audit (after
the v1.38.2 HIGH fixes). (M1) Per-tenant OAuth `start`/`callback` now validate the
tenant exists in meta before opening its pool — mirroring the login/register
disk-fill guard — and `start` is rate-limited, so an unauthenticated caller can no
longer spray arbitrary tenant ids to create junk tenant databases. (2) A policy
whose literal operand's type mismatches the target column's storage class is now
rejected at config time (`POLICY_INVALID`), completing the eval/compile lockstep
the v1.38.2 `$nin`/NULL fix began. (3) The admin `_list` endpoint now detaches the
read-only authorizer on an errored early-return, so a failed list no longer leaves
a restrictive authorizer on the pooled reader and intermittently over-denies a
later `_system_*` list. (4) The admin OAuth allowlist match is now `COLLATE NOCASE`,
so a mixed-case bootstrap admin email is no longer locked out of OAuth login. (5)
Edge-function `put-file` now derives `cache_control` from the object's visibility
(private → `private, no-store`) like Mode A/B, instead of hardcoding a public value.
No cross-tenant, owner-clause, or RLS-enforcement change. Deferred to a later pass:
the DRY/perf cleanups (incl. SSE Arc fan-out) and the `handler.rs` god-object split.

## v1.38.2 — 2026-06-15

### Security: close three intra-tenant RLS/realtime fail-open read bypasses

A holistic audit found no cross-tenant breach but three HIGH intra-tenant
authorization gaps on the SELECT/realtime read surface, all fixed here. (1) The
legacy `GET /records/<coll>` list applied the owner clause but not the explicit
select-policy USING, so a collection with a select policy and no owner_field
returned every row to a bare anon/user GET; it now AND-composes the `?`-bound
policy USING (mirroring `POST /list`) and refuses raw `?filter`/`?sort` on a
policy-protected collection. (2) Anon SSE subscribe gated on realtime + anon
select cap but not owner_field, so anon could receive every user's row events on
an owner-scoped collection; it now 403s `ANON_FORBIDDEN_OWNER_SCOPED` like the
REST read paths. (3) `eval_policy` and `compile_policy_using` diverged on `in`/
`nin` against a NULL field (and ASCII `LIKE` case), so a NULL-field row hidden
from reads could leak over the anon SSE filter; the two evaluators are realigned
and the consistency corpus now exercises `$nin`/NULL and case-varying `LIKE`.
Also: added the missing `ANON_DENIED` suggested_fix, dropped the never-emitted
`MODE_MISMATCH` catalog entry, and removed ~110 LOC of dead in-memory aggregate
code in the audit module. No cross-tenant, owner-clause, or writer-path change.

## v1.38.1 — 2026-06-13

### MCP comprehension: advertise RLS policies in the server prologue

v1.38.0 shipped the three RLS tools (`set_policy` / `get_policies` /
`clear_policy`) with thorough individual descriptions and enriched the
`get_schema_overview` payload to always carry a per-collection `policies` key, but
the v1.37.0 comprehension scaffold — the per-tenant MCP `initialize.instructions`
prologue — was not updated, so a model reading the prologue learned RLS only by
exhausting `tools/list`. This release integrates RLS into that scaffold:
`build_instructions` now lists `RLS policies` in the START-HERE access-state
summary, registers the three tools as an `RLS:` line in the SCHEMA capability
group, and adds a `"Restrict who sees rows" → set_policy` recipe. The
`get_schema_overview` tool description now also enumerates the `policies` key it
already returns. A new `instructions_register_rls_policy_tools` test asserts the
three tool names appear in the prologue, closing the gap that let the omission
ship silently (the existing tests only guard against referencing *removed*
tools). Comprehension/documentation only — no behaviour, payload, route, auth, or
enforcement change; `whoami` is intentionally unchanged.

## v1.38.0 — 2026-06-13

### Row-Level Security (RLS) policies: per-collection, per-operation

PocketBase-style row-level policies layered on top of — not replacing — the
existing `owner_field`/`read_scope` model. A policy is a per-operation pair of
bounded predicates over the existing `FilterAst`: `using` (which existing rows
this caller may read/target) and `check` (is the new/post-image row allowed).
`owner_field`, `compute_owner_filter`, the cap-gate, and the insert-stamp /
update-strip transforms are **100% unchanged**; explicit policies AND-compose
alongside the unchanged owner clause. No new auth surface, no new auth-cache
hook (policies live in per-tenant `_system_collection_meta`, not in
`meta.sqlite` token/session state).

**Expression engine** (`src/query/policy.rs`). The `FilterAst` grammar gains
three operands — `{"$auth":"id"}` (binds the caller's `_system_users` id, or SQL
`NULL` for anon), `{"$data":"<field>"}` (the post-image row field, CHECK only),
and the special leaf `{"$authenticated":true}`. Two evaluators share the one
grammar: `compile_policy_using` → `?`-bound SQL `WHERE` fragment (reads +
update/delete target pre-flights), `eval_policy` → in-memory bool (insert/update
CHECK + anon SSE event filtering). A load-bearing consistency corpus
(`tests/policy_expression.rs`) inserts each `(ast, row, ctx)` into a throwaway
SQLite and asserts the SQL verdict equals the in-memory verdict, so the two
paths can never silently diverge.

**Tiers.** Service bypasses all policy (resolver returns `None`). User is
subject to the op policy with `@auth.id` = their `_system_users` id. Anon passes
the existing `anon_caps` gate, then the policy USING with `auth_id = NULL` (so an
owner-comparison naturally yields no rows).

**Enforcement, every data-plane surface:**
- Reads — `/list`, `/search`, and `GET /records/<id>` AND the select-policy USING
  into the SQL `WHERE` (single-row read uses a pre-flight visibility SELECT; the
  existing owner clause + `record_as_json` path is untouched).
- Writes — insert/update CHECK runs on the persisted/post-image row INSIDE the
  `with_writer_tx` closure; a failing CHECK returns the `POLICY_CHECK_FAILED`
  sentinel that rolls the transaction back (`403`). update/delete USING is a
  pre-flight SELECT against the writer tx (non-matching target → `404`, identical
  to a missing row — no existence oracle).
- Deny posture — anon `/query` / `/query/explain` and legacy `GET ?filter/?sort`
  are raw, un-rewritable SQL, so once a tenant adopts row-level rules (any
  collection with `owner_field` or a policy) anon is denied them tenant-wide
  (`ANON_QUERY_DENIED_ON_POLICY`, fail-closed); anon uses `/list` / `/search`.
- Realtime — SSE subscribers are only ever anon or service; for anon on a
  collection with a select policy, each `Created`/`Updated` event's record runs
  through `eval_policy` and is dropped if it doesn't match. `Deleted` events are
  id-only (no field leak) and pass — a documented v1 limitation.

**Configuration (service-only, three faces):** REST `PUT/GET/DELETE
/t/<id>/collections/<c>/policies` (validated at write time — unknown field / bad
operand → `400 POLICY_INVALID`), MCP `set_policy` / `get_policies` /
`clear_policy` (live tool count 52 → 55; service-key-only by MCP dispatch), and a
guided builder in the collection `[⚙]` settings popover. `suggested_fix` catalog
entries added for `POLICY_CHECK_FAILED` / `ANON_QUERY_DENIED_ON_POLICY` /
`POLICY_INVALID` / `POLICY_COMPILE_ERROR`.

**Isolation & security.** Policies are per-tenant (`_system_collection_meta`),
never cross-tenant. All policy/runtime values reach SQL via `?` binds — only
fixed column names from a closed match arm are interpolated. Defense in depth:
the un-rewritable `/query` surface is closed for anon at the tenant level AND
`/search` + `/list` enforce structurally; write CHECK is atomic-with-rollback
inside the writer tx. `_system_*` collections stay drop/policy-protected.
Backward-compat goldens (`tests/policy_backward_compat.rs`) pin that
`owner_field` behaviour is byte-identical with no explicit policy, and that anon
cannot bypass a select policy via `/query`. Full suite green: **1326 tests, 0
failed** across 158 binaries.

Four new nullable `*_policy_json` columns on `_system_collection_meta` (migration
is additive — absent/NULL = no explicit policy). `regex-lite` promoted to a
normal dependency (runtime `LIKE` in `eval_policy`).

## v1.37.0 — 2026-06-12

### MCP comprehension & activation overhaul (AI time-to-competence)

Sharpens the surfaces a freshly-connected LLM reads first and prunes 4 genuine
duplicates so first-pick is less confusable. Capability-only shrink — no new auth
surface, no new auth-cache invalidation hook (same conclusion as v1.35/v1.36);
`_system_*` write-protection and service-key-only MCP gating preserved.

**MCP tool surface: prune 4 duplicates (57 -> 52).** Removed tools have no alias
shim (drust has no external MCP consumers; a removed tool simply stops appearing
in `tools/list`). Mapping for any future integrator:

- `set_collection_description` / `set_field_description` / `set_index_description`
  -> `set_description{target:"collection"|"field"|"index", ...}` (one tool).
- `clear_owner_field` -> `set_owner_field{field: null}` (null / "" clears).
- `count_rows` removed -> `list_records` already returns `total`.
- `sample_rows` removed -> `list_records{per_page: n}` with no filter.

MCP-surface only: REST `/records/*`, `/list`, `/query`, the REST
`DELETE /collections/<c>/owner-field` clear, and all data-plane SQL building are
unchanged. `tool_count()` is annotation-counted and self-adjusts to 52; the admin
`_api_keys` pill tracks it live.

- feat(mcp): `get_schema_overview` enriched into a true one-call bootstrap.
  - Per-collection access state is now ALWAYS present: `owner_field` and
    `read_scope` emit explicit `null` when the collection is not owner-scoped
    (previously the keys were omitted), and `vector_fields` is always an array.
  - Each RPC entry gains a derived `user_id_autobound` boolean (true when the
    RPC declares a `user_id` param, which drust auto-binds from a user token).
  - The REST `GET /t/<id>/schema/overview` mirror keeps the lean serde shape
    (omits empty owner_field/read_scope/vector_fields, no `user_id_autobound`);
    the enrichment is MCP-surface-only by design.
  - No new auth-cache hook: this adds no token/session/publish surface, only
    post-processes already-read schema metadata. owner_field-by-construction
    (src/query/list_builder.rs) and service-only MCP gating are unchanged.
- MCP: rewrote the connect-time `instructions` prologue — leads with the two bootstrap calls (`get_schema_overview` + `whoami`), adds a `CHOOSING A READ TOOL` block disambiguating `list_records` vs `query` vs `search_collection`, names the recovery affordances (`dry_run` / `suggested_fix` / `recent_writes`, satisfying Lever 5), and reflects the merged tool set (`set_description`, `set_owner_field{field|null}`).
- MCP tool descriptions (Lever 3): rewrote the read-cluster (`list_records` / `query` / `search_collection`) with use / not / vs-sibling disambiguation, embedded copy-pasteable example calls in `list_records` (FilterAst), `create_collection` (FieldSpec) and `search_collection` (search body), and made `list_records`'s `owner_field` framing explicit. A description-introspection test guards every tool description against naming a removed tool.
- Onboarding eval harness (Lever 0, greenfield `eval/mcp_onboarding/`): a pure, network-free scorer (turns-to-success, wrong-tool count, overview-first / dry-run-before-destructive flags) with a green pytest suite, plus an agentic before/after runner that drives the live per-tenant MCP against a throwaway tenant. Before/after comparison **deferred** — the scorer is validated by its pytest suite; the live agentic run is pending an `ANTHROPIC_API_KEY` in the deploy environment (harness is ready to run on demand).

## v1.36.0 — 2026-06-11

### Edge functions: per-tenant Rust→Wasm, triggered by data events

drust now runs per-tenant user-uploaded `.wasm` functions (wasm32-wasip2
components) in-process via wasmtime 45. A function declares triggers and fires
on `record.created` / `record.updated` / `record.deleted` (per collection) and
`file.uploaded`. The whole vertical lives in `src/functions/`: two lazy
`_system_` tables (`_system_functions` + `_system_function_logs`), an
invalidate-on-write trigger-binding cache, a `FunctionDispatcher` mirroring
`WebhookDispatcher` (global bounded mpsc + per-tenant depth counters), an
executor (global concurrency semaphore + per-tenant FIFO serialization), and a
wasmtime runtime (`OnceLock` Engine + epoch ticker + compiled-component LRU).

- **Host API** = the existing transport-agnostic tool layer. A guest calls
  `insert/update/delete-record`, `list-records`, `put-file`, and
  `get-file-bytes`; these route through the same `mcp/tools/{write,read}.rs`
  functions the MCP/REST surfaces use, so a function write fans out to SSE +
  webhooks with zero extra code. Guest SDK template:
  `sdk/edge-function-template/` (WIT is the single source of truth).
- **Three surfaces**: service-only REST (`/t/<id>/functions/*` — CRUD + sync
  `/invoke` playground + `/logs`), admin UI (`ƒ _functions` sidebar page —
  upload / toggle active / delete / test-invoke / logs), and 5 new MCP tools
  (`list_functions`, `delete_function`, `set_function_active`,
  `invoke_function`, `get_function_logs`) — MCP tool count 52 → 57. No upload
  MCP tool by design; the multipart REST route is the only ingest path.
- **Isolation model** (spec §7, proven not asserted): capability absence — a
  guest can reach only the host functions explicitly linked, nothing else;
  tenant-scoping by construction — the executor builds its per-tenant `DrustMcp`
  bound to one tenant; depth = 1 — that `DrustMcp` is built with
  `functions: None` (`HostStateSeed::build_mcp`), so a function-initiated write
  can never re-trigger functions; CPU + memory caps — epoch-deadline wall clock
  (`DRUST_FN_TIMEOUT_SECS`) + a `ResourceLimiter` linear-memory ceiling
  (`DRUST_FN_MEMORY_MAX_BYTES`). `_system_functions` / `_system_function_logs`
  inherit `_system_`-prefix drop-protection for free.
- **Failure semantics**: no retry, ever — a failed invocation writes a log row
  and stops. Queue saturation drops the invocation (per-tenant depth counter +
  sampled warn); loss-on-crash is accepted (no outbox). REST `/create` compiles
  the component eagerly and returns `422` on a bad artifact.
- **8 env knobs**: `DRUST_FN_MAX_WASM_BYTES` (20 MiB), `DRUST_FN_MEMORY_MAX_BYTES`
  (256 MiB), `DRUST_FN_TIMEOUT_SECS` (30), `DRUST_FN_MAX_PER_TENANT` (10),
  `DRUST_FN_QUEUE_DEPTH` (100), `DRUST_FN_CONCURRENCY` (2),
  `DRUST_FN_FILE_READ_MAX_BYTES` (32 MiB), `DRUST_FN_MODULE_CACHE` (32).

## v1.35.1 — 2026-06-10

### Admin UI: MCP tool-count pill is now live, not hardcoded

The "N tools" pill on `_api_keys` (`tenant_api_keys.html`) hardcoded `48`
while the MCP router actually serves 52 tools — it had silently drifted
across four tool additions. The template now renders
`DrustMcpService::tool_count()` (new, `OnceLock`-cached
`tool_router().list_all().len()`), threaded through `ApiKeysPage` as
`mcp_tool_count`, so the pill can never drift again. A regression test
(`tool_count_tests` in `src/mcp/handler.rs`) locks the router count against
the number of tool annotations in the source.

## v1.35.0 — 2026-06-10

### Auth cache: the global meta-mutex leaves the hot path

Every authenticated tenant request used to serialize on one global
`Arc<Mutex<Connection>>` (`meta`) to run the bearer-auth CTE — the top
contention point at ~13k rps. `bearer_auth_layer` now consults a process-local
invalidate-on-write `DashMap<token_hash, CachedAuth>` (`src/tenant/auth_cache.rs`)
first: a hit reconstructs `AuthCtx` + publish policy (+ PAT email snapshot for
audit parity) without touching `meta.sqlite`; user-session hits self-check the
cached `expires_at` and reject expired sessions without a DB read.

Security posture (defense-in-depth ≥ 2, see the spec):

- **Layer 1 — 11 synchronous invalidation hooks**: token reroll (scan-clear by
  tenant+role), admin-PAT reroll (scan-clear by admin), tenant soft-delete +
  id-recycle (tenant-scoped clear), logout / revoke-by-hash / revoke-all
  (per-user clear, REST + MCP), user-delete cascade, change-password session
  wipe, publish-policy change. Janitor (hook 10) is a documented no-op — it
  runs out-of-process; cached `expires_at` self-reject + TTL cover it.
- **Layer 2 — per-entry 10 s safety TTL** (`safety_ttl` is an injectable
  `Duration` field): a future revoke path that forgets its hook degrades to a
  ≤ 10 s window, never a permanent bypass.
- The cache consult runs AFTER the rate-limit probe; audit rows still emit on
  hits; negative results are NEVER cached (no poisoning, no timing oracle);
  Bearer/User hits cross-check `bound_tenant_id` against the path tenant.

New: `tests/auth_cache_*.rs` (14 files, 17 tests) + 4 unit tests.

### XFF client-IP extraction: named constant + warn-not-silent

`src/safety/ip.rs::client_ip` now pins the trusted trailing-hop count as
`TRUSTED_TRAILING_HOPS = 1` (client = `parts[len-2]`, same value as before —
all six existing tests pass unchanged) and replaces the silent
`unwrap_or(fallback)` with `tracing::warn!` + socket-peer fallback on too-short
or unparseable chains, so topology drift is loud instead of silently herding
clients into a shared rate-limit bucket. The cross-host nginx invariant
(`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` on `.221`) is
now documented in `services.md` with a tracked manual verification item.
Three new forge-resistance tests (9 total in `tests/auth_xff.rs`).

### tenants.rs split (behavior-preserving)

`src/mgmt/tenants.rs` (1920 lines) is now a 167-line re-export anchor +
six submodules under `src/mgmt/tenants/` (`common`, `crud`, `overview`,
`files_page`, `oauth_page`, `webhooks_page`). Pure relocation: `routes.rs` and
all sibling importers are byte-unchanged; the only visibility change is
`load_tenant_shell` / `ensure_tenant_exists` widening to `pub(crate)` in
`common.rs`. New GET→200 smoke tests for the relocated overview + files pages.

## v1.34.2 — 2026-06-09

### Record bodies up to 8 MiB (was capped at axum's 2 MiB default)

`POST`/`PATCH /t/<id>/records/<coll>[/<id>]` buffered the request body under
axum's built-in 2 MiB default, so saving a record larger than 2 MiB failed with
`413 Failed to buffer the request body: length limit exceeded` (reported in
production on `PATCH /records/docs/16`). The two records routes now carry an
explicit `DefaultBodyLimit` of 8 MiB, overridable via
`DRUST_MAX_RECORD_BODY_BYTES`. Records are buffered fully in memory so the limit
stays bounded, and 8 MiB is well under the ~200 MB Caddy/.221 ingress cap. Large
binary/file content should still use the file-upload API, not a record field.

## v1.34.1 — 2026-06-09

### Data-plane files routes are service-key-only at the router layer

Anon and end-user (`drust_user_*`) bearer tokens could reach the data-plane
tenant-files routes. Only `set_visibility` (`PATCH /t/<id>/files/<key>`) and the
Mode-B tus handlers carried an inline `require_service` check; the other Mode-A
handlers (`upload`, `list`, `get_one`, `delete_one`, `stream_bytes`, `sign_url`)
had no guard at the router. This closes the gap with one fail-closed middleware.

- **Core** (`src/tenant/router.rs::require_service_layer`): a `from_fn`
  middleware that reads the `TenantRef` injected by `bearer_auth_layer` and
  returns `403 WRITE_DENIED` for `TokenRole::Anon` / `TokenRole::User` (same
  response shape as the inline checks). A missing `TenantRef` is treated as a
  denied request (fail closed), not an allowed one.
- **Wiring** (`src/tenant/mod.rs`): the layer is applied INNER to
  `bearer_auth_layer` on `files_router`, so it runs after bearer (when the
  `TenantRef` exists) on every routed method — `POST/GET /t/<id>/files`,
  `GET/DELETE/PATCH /t/<id>/files/<key>`, `GET …/bytes`, `POST …/sign`, and all
  `…/uploads*` (Mode-B tus) routes.
- **Defense-in-depth retained**: the inline `require_service` in `set_visibility`
  and the six `uploads/*` handlers is unchanged (layer 2).
- No handler signature changes; the admin files router (`set_visibility_admin`)
  is untouched; CORS OPTIONS preflight is unaffected (CORS stays outermost).

## v1.34.0 — 2026-06-07

### File visibility toggle (public ⇄ private)

Files could only be made public/private at upload time; changing it meant
delete + re-upload. This adds an in-place toggle on all three surfaces. Because
`public` and `private` are two distinct host-wide Garage buckets, a toggle is a
**bucket move**, not a flag flip.

- **Core** (`src/storage/visibility.rs::change_visibility`): reads the
  `_system_files` row, copies the object to the target bucket, UPDATEs
  `visibility` + `cache_control` (reset to the target's default so a now-private
  file never keeps a public cache header), then deletes the old object. Ordering
  **copy → UPDATE → delete-old** keeps the live row always pointing at an
  existing object; a crash leaves only a space-only reconcile orphan and retries
  are idempotent. This is the first (and only) UPDATE path on `_system_files`.
- **MCP** `set_file_visibility { id, visibility }` (service-only by dispatch).
- **REST** `PATCH /t/<id>/files/<key>` `{"visibility":"public|private"}`
  (service-only via `require_service` → 403 `WRITE_DENIED`; 422
  `INVALID_VISIBILITY`).
- **Admin UI** per-row make-public / make-private toggle on the tenant files
  page (admin-session-authed).
- **Test affordance**: `GarageClient::{put,get,delete}_object_in` now route to
  the in-memory store (namespaced `<bucket>/<key>`) when `s3_endpoint` is empty,
  so the cross-bucket move is exercised in tests. Production (non-empty endpoint)
  is unchanged. Covered by `tests/file_visibility.rs` (11 tests).

## v1.33.3 — 2026-06-04

### Performance

Internal request hot-path optimizations. All three are **behaviour-preserving**
(same API, same response bytes, same permission semantics — proven by the
existing suite plus a per-cut test) and were profiled first. The auth surface
was the surprise: v1.32.3's "D9" had already lock-collapsed bearer resolution to
a single `meta.sqlite` query, so the planned auth-token *cache* was measured,
found marginal, and **deferred** in favour of a cheaper, security-neutral cut.

- **Stored-RPC SQL now uses `prepare_cached`** (`src/query/executor.rs`).
  `execute_read_query_with_named_inner` recompiled its fixed-per-name SQL on
  every call; it now uses rusqlite's per-connection statement cache (as
  `audit_db`/`stats` already do), a near-100% hit on the pooled read
  connections. The ad-hoc `/query` path stays on `prepare()`. A
  `cached_stmt_reprepares_after_schema_change` test proves no stale results
  after a schema change (rusqlite auto-re-prepares on `SQLITE_SCHEMA`).
- **`_system_sessions` lookup is skipped for non-user bearers**
  (`src/tenant/router.rs`, `src/auth/user_session.rs`). `bearer_auth_layer` ran
  a per-request `pool.with_reader(lookup_session)` against `_system_sessions`
  for *every* request, including service/anon/PAT tokens that can never be a
  user session. User session tokens are minted only via `generate_token()` and
  always carry the `drust_user_` prefix, and `lookup_session` matches on the
  full-token hash, so gating the lookup on `is_user_token()` removes a read-pool
  checkout + indexed query from the service/anon hot path with **no behaviour
  change and no new security surface**. (Chosen over a token cache, which would
  have needed invalidation wiring at every revoke site plus a
  stale-grant-after-revoke window — not justified by the measured ~13 % slice
  that D9 already minimized.)
- **Result rows buffer as a `Cell` enum** instead of
  `Vec<Vec<serde_json::Value>>` (`src/query/executor.rs`). Each cell was a heap
  `serde_json::Value` (text cells a fresh `String`), then serde walked the tree
  a second time to emit bytes. A lightweight `Cell` enum with a hand-written
  `Serialize` drops the intermediate tree and the double pass; output is
  **byte-identical** (proven by an `o2_golden` byte-diff test over control
  chars, U+2028/U+2029, emoji, `i64::MIN`, `-0.0`). `column_types` is emitted
  before `rows` and a column's type isn't settled until the scan completes, so
  the buffer is kept by necessity — only the redundant `Value` tree is removed.
  Value-manipulating consumers bridge via `Cell::to_json()`.

> **Deferred (recorded, not dropped):** the auth-token *cache* (revisit only if a
> release microbench of the bearer CTE under real cross-tenant contention lands
> ≥77 µs) and the authorizer attach-once trim (provisional; needs a coupling
> audit of every `detach_authorizer` site — its own spec when pulled).

> **Benchmark (paired A/B, measured):** the shared 2-core host's run-to-run
> drift (±20 %) initially swamped the per-cut deltas in an absolute-rps
> comparison. A paired design fixes that: the v1.33.2 baseline (`fb09293`) and
> v1.33.3 binaries were measured **alternately within each round** (~25 s apart,
> server pinned to core 0, load generator to core 1, same seeded datadir),
> across 10 rounds — drift hits both equally, so it cancels in the paired
> difference. Median throughput gains, all paired-significant (95 % CI excludes
> zero; 9–10/10 rounds favour the new binary):
>
> | hot path | workload | median Δ |
> |---|---|---|
> | auth skip (O1′) | `POST /query SELECT 1` | **+8.5 %** |
> | result serialization (O2) | `POST /query SELECT *` (5 000 rows) | **+12.5 %** |
> | RPC `prepare_cached` (O3, + O1′) | `POST /rpc/<name>` | **+4.3 %** |
>
> Each binary carries all three cuts; the workloads isolate where each dominates.
> No regression on any leg.

---

## v1.33.2 — 2026-06-04

### Fixed

- **tus capability discovery (`OPTIONS /t/<id>/uploads`) now works over
  HTTP.** A live end-to-end smoke test of the deployed Mode B endpoint
  found the `.options(uploads::options)` handler unreachable: the CORS
  layer is mounted outside `bearer_auth` (so preflight short-circuits
  before auth) and answered every `OPTIONS` with a bare CORS 200,
  shadowing the handler — so a tus client never saw `Tus-Version` /
  `Tus-Extension` / `Tus-Max-Size`. (The v1.33.1 note advertising
  "`OPTIONS`-based capability discovery" was therefore not actually
  reachable; this makes it true.) The upload core — `POST`/`HEAD`/
  `PATCH`/`DELETE`, chunking, disconnect-resume, and finalize-to-Garage
  — was always fine and is unaffected. Fixed with a small
  `inject_tus_capabilities` layer mounted OUTSIDE the CORS layer
  (`src/tenant/mod.rs`) that re-attaches the static tus headers onto the
  CORS-generated preflight response, scoped to `OPTIONS` on paths ending
  `/uploads`. The handler-level unit test couldn't catch this (it calls
  the handler directly, bypassing the layer stack); a new
  `tus_capabilities_survive_cors_preflight` test pins the full stack.
  Tus version/extension strings are now shared consts in
  `src/tenant/uploads/mod.rs` so handler and layer can't drift.
- **`mascot_to_json` (theme palette `<script>` embed) now routes through
  the canonical `script_json` escaper** (`src/mgmt/theme.rs`), closing
  the last JSON-into-`<script>` island that still serialized inline.
  Palette values are compile-time hex so output is byte-identical today;
  this is defense-in-depth so a future non-hex value can't break out.

---

## v1.33.1 — 2026-06-03

### Security

- **Stored-XSS fix in the admin collection editor (tenant → operator
  privilege escalation).** `src/mgmt/browse.rs` serialized a
  collection's fields — including the v1.19 per-field `description`,
  which is tenant-controlled free text — into an executable `<script>`
  in `collection_rows.html` with no escaping, so a tenant could set a
  field description to `</script>…` and have the trailing markup
  execute in the drust operator's authenticated admin session the
  moment the operator opened that collection's editor. Fixed by adding
  one canonical `<script>`-safe JSON escaper
  (`src/mgmt/script_json.rs`: `escape_json_for_script` /
  `json_for_script`) that neutralizes `</`, `<!--`, U+2028 and U+2029
  — all losslessly, so the escaped output is `JSON.parse`-identical —
  and routing every JSON-into-`<script>` island through it: the
  collection editor, the audit-log embed (previously escaped inline),
  the settings themes blob, and the broadcast-inspector i18n bundle.
  No consumer behavior changes for legitimate data.

### Changed

- **MCP clients now discover the Mode B resumable upload endpoint.**
  The per-tenant MCP `initialize.instructions` prologue gained an
  `Upload (large / resumable)` block pointing at `POST /t/<id>/uploads`
  (tus 1.0) with `OPTIONS`-based capability discovery, and `whoami`
  now returns `endpoints.files_upload_resumable`. No new MCP tool and
  no route change — `/uploads` was already service-key-gated; this only
  makes the existing endpoint visible to LLM clients.

---

## v1.33.0 — 2026-06-03

### Added

- **Mode B large-file upload (tus 1.0 resumable).** A second ingest
  path at `/t/<id>/uploads/*` enables reliable upload of 200 MB–1 GB+
  files without raising any infrastructure body-limit. Four tus
  endpoints: `OPTIONS` (capability probe), `POST` (session creation),
  `HEAD` (offset probe for resume), `PATCH` (chunk append), `DELETE`
  (abort); plus service-only `GET` (session list). Each `PATCH` chunk
  is capped by `DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES` (default 64 MiB)
  via a per-route `DefaultBodyLimit`, keeping every HTTP request well
  under the 200 MB Caddy/.221 ingress limit. Chunks are appended to a
  durable per-tenant spool file (`tenants/<id>/_uploads/<token>.part`);
  the filesystem byte-count is the offset source of truth, so resume
  survives both client disconnect and server restart. On completion,
  finalize is SQLite-first + idempotent: `INSERT OR IGNORE` a
  `_system_files` row, stream the spool to Garage via `put_file_in`
  (multipart over loopback), then delete the spool and session row.
  Service-key-only — anon and user tokens receive `403 WRITE_DENIED`.
  New per-tenant `_system_upload_sessions` table tracks in-progress
  uploads. Four new env knobs: `DRUST_LARGE_UPLOAD_MAX_BYTES` (default
  2 GiB), `DRUST_LARGE_UPLOAD_CHUNK_MAX_BYTES` (default 64 MiB),
  `DRUST_LARGE_UPLOAD_MAX_SESSIONS_PER_TENANT` (default 5),
  `DRUST_LARGE_UPLOAD_SESSION_TTL_SECS` (default 86400 = 24 h). Hourly
  in-process janitor reclaims abandoned sessions (spool file + DB row +
  advisory lock); deliberately never touches `_system_files` or Garage.
  Mode A (`POST /t/<id>/files`) is byte-for-byte unchanged.
  Spec: `docs/superpowers/specs/2026-06-03-drust-large-upload-design.md`.

---

## v1.32.13 — 2026-06-02

### Added

- **MCP server setup modal with multi-client snippets.** The per-
  tenant `_api_keys` page now ships a `[More clients ▸]` button
  next to the existing `[Copy]` button on the MCP server card.
  Clicking it opens a modal with three OS tabs (Windows / macOS /
  Linux, auto-selected by `navigator.userAgentData?.platform` and
  manually switchable) and five client setup cards: Claude Code
  CLI, Codex CLI, Cursor, Claude Desktop, Gemini CLI. Each card
  has a per-OS config-file-path hint and a ready-to-paste snippet
  with its own `[Copy]` button. Claude Desktop greys out on the
  Linux tab since Anthropic does not officially support it there.
  Frontend-only: no new backend route, no DB column, no migration,
  no new Rust tests — the PAT source and tenant URL come from the
  same server-injected DOM nodes the existing single-click copy
  button already reads. Spec:
  `docs/superpowers/specs/2026-06-02-mcp-multi-client-setup.md`.

### Fixed

- **Single-click `[Copy]` button on MCP card now emits a
  cross-shell-safe command.** v1.29.3's `claude mcp add-json
  drust-<tenant> '<JSON>'` payload relied on POSIX single-quote
  string literal semantics, which `cmd.exe` and PowerShell do not
  honour — Windows operators pasting the snippet hit
  `Invalid configuration: : Invalid input` and had to manually
  rewrite the JSON quoting. v1.32.13 switches to the flag form:
  `claude mcp add drust-<tenant> <url> --transport http --header
  "Authorization: Bearer <pat>"`, which has no nested JSON quoting
  and parses identically in bash / zsh / cmd / PowerShell / WSL.
  Same string is also surfaced as the "Claude Code CLI" tab inside
  the new multi-client modal so the one-click and explore paths
  agree byte-for-byte.

### Notes

- Version number v1.32.12 is deliberately skipped. The standalone
  flag-form fix was bumped to v1.32.12 mid-development but was
  superseded by v1.32.13 before any tagged release, because the
  modal needs the same flag-form string as its Claude Code tab —
  shipping v1.32.12 as a separate release would have been replaced
  in the same week.

---

## v1.32.11 — 2026-06-01

### Fixed

- **Cell-expand modal was silently dead on the collection-rows
  page.** v1.32.9 / v1.32.10 wired the click handler against
  `window.drustUI.detail(...)`, but `collection_rows.html` was
  the one admin page in the entire `_modal.html` consumer set
  that never `{% include "_modal.html" %}`'d the modal infra
  (every other page — files, settings, audit, backup_inspect,
  tenants_list, admin_team, rpc, api_keys — does). On the
  collection rows page `window.drustUI` was therefore
  `undefined`, every click threw a `TypeError: Cannot read
  properties of undefined (reading 'detail')` and the browser
  swallowed it inside the event handler boundary. Now
  `{% include "_modal.html" %}` ships with the template,
  mirroring the canonical placement (just before
  `{% endblock %}`) used by `files.html` and the rest. No code
  changes outside the include — the textarea-mode behavior
  from v1.32.10 lights up unchanged once the modal DOM is in
  the page.

---

## v1.32.10 — 2026-06-01

### Changed

- **Cell-expand modal switched from `<pre>`/plain text to Supabase-
  style readonly `<textarea>`.** v1.32.9 reused the audit-detail
  `<pre>` / `<dd>` rendering for the click-to-expand cell viewer,
  which read fine for short JSON but felt cramped for long
  Chinese prose or 200-line documents — single scroll axis, no
  resize, label column ate 120px. v1.32.10 adds two opt-in flags
  to `drustUI.detail`:
  - `f.textarea: true` — value renders inside `<textarea readonly
    class="modal-detail-area">`, the dd spans the full grid width,
    and the user gets independent scroll + a drag-resize handle on
    the bottom edge. Mono font, dark surface, focus ring matches
    the rest of the form inputs.
  - `opts.wide: true` — promotes the modal box to ~720px (default
    460px) so the editor reads ~80 mono chars per line — wide
    enough for typical JSON / SQL / prose without horizontal scroll.
  Cell click handler in `collection_rows.html` now sets both, so
  the JSON pretty-print path (already in v1.32.9) renders its
  newlines naturally inside the textarea. Other callers of
  `drustUI.detail` (audit detail panel's 15-row read-out) are
  unchanged — they don't pass the new flags and keep their grid
  layout.

---

## v1.32.9 — 2026-06-01

### Changed

- **Collection-rows table is now Supabase-/Sheets-style.** Three
  long-standing usability papercuts collapsed into one pass:
  1. **Natural column widths + horizontal overflow.** v1.28.5
     pinned the table to its container with `width:100%` +
     `table-layout:fixed`, which clamped every column to 280px and
     hid the left half of long Chinese / URL / vector-preview
     cells while wasting space on tiny columns (id, ts, count).
     The wrap container is now `overflow-x:auto`; the table
     itself takes `max-content` with `table-layout:auto`; each
     `td` retains a per-cell ceiling (raised 280 → 360) so a
     single absurd value can't bloat its column.
  2. **Sticky first column.** PK / id stays visible while the
     user scrolls horizontally through wide rows. Header cell sits
     above body cell on z-index so the sticky thead doesn't lift
     over it.
  3. **Click-to-expand cells.** Every cell is now clickable and
     opens the shared detail modal (`drustUI.detail`) with the
     full pre-escape value. JSON-shaped strings (leading
     `{`/`[` + matching close, JSON-parseable) are auto
     pretty-printed via `<pre>`; everything else falls back to
     wrapped mono. The pre-v1.32.9 browser-native `title`
     tooltip is gone — it was single-line, ~256-char-truncated,
     unstyleable, and disappeared on hover-out.
- **Vector cells render `[vec dim=N · 0.12, -0.45, 0.78, …]`
  instead of the opaque `[blob]` sentinel.** `admin_list_inner`
  passes the schema's declared `vector_fields` into the read
  closure; when a BLOB cell's column is a declared vector AND
  the on-disk byte length matches `dim * 4`, the first three f32
  values are decoded from the packed little-endian layout
  produced by `vector_codec::pack` and inlined into the cell
  preview. Non-vector BLOBs (or vector cells whose byte length
  disagrees with the declared `dim`) get an honest
  `[blob bytes=N]` placeholder so the row count is visible
  rather than misleading. The full vector array is still
  available via the `/records/<id>` REST endpoint — the list
  view is intentionally a teaser, not a dump (a 384-dim cell
  rendered in full would dominate every other column on the
  page).
- **Broadcast sidebar icon swapped to a bilaterally symmetric
  beacon glyph.** The pre-v1.32.9 WiFi-arc icon's bounding box
  was 16w × 18h (taller than wide) which read as vertically
  stretched at the 15×15 `.nav-icon svg` render size. The new
  glyph is a centred dot with two pairs of concentric arcs
  radiating left + right — same line weight as the other
  sidebar icons, symmetric on both axes inside the 24×24
  viewBox.

---

## v1.32.8 — 2026-06-01

### Fixed

- **Newly-created tenants were missing `_system_users` /
  `_system_sessions` until restart.** `src/storage/tenant_db.rs::
  apply_schema` (run from `open_write` whenever a tenant DB is
  first opened) predates the v1.9 end-user auth tables and was
  never updated when those tables were introduced. They only ever
  got created from `db::migrations::migrate_tenant_db`, which is
  driven by the startup migration loop iterating
  `meta.sqlite.tenants` — so the path correctly covered every
  tenant that existed at boot, but a tenant created AT RUNTIME
  hit the `open_write` → `apply_schema(SCHEMA_SQL)` path only,
  never the migration path. Symptom on a fresh tenant: clicking
  the `_system_users` sidebar entry returned
  `collection not found` because `describe_collection` saw no such
  table. Fix: `apply_schema` now also runs
  `SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS` and
  `SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS` from the migration
  module, so the create path and the migrate path produce
  identical schema. Existing affected tenants are repaired
  automatically on the next process restart via the existing
  startup migration loop (the same SQL is `CREATE TABLE IF NOT
  EXISTS`, so it's idempotent on tenants that already had the
  tables).

---

## v1.32.7 — 2026-06-01

### Changed

- **Per-tenant files admin page renamed from `/files` to `/_files`**
  for consistency with the other virtual sidebar entries
  (`_overview`, `_api_keys`, `_rpc`, `_broadcast`, `_oauth_providers`,
  `_webhooks`, `_logs`). The legacy `/admin/tenants/<id>/files` URL
  now returns 301 → `/_files`, so existing bookmarks and browser
  history still resolve. Sub-routes under `/files/...` (upload,
  `<key>`, `<key>/sign`, `<key>/bytes`) are unchanged — those are
  API/action endpoints, not page URLs.
- **`collection`/「集合」 unified to「資料表」 across the zh-TW bundle.**
  Eleven `集合` occurrences plus three stray English `collection`
  references inside Chinese sentences renamed in one pass. The
  English bundle is unchanged. Tool/identifier names like
  `create_collection` and template placeholders like `{collection}`
  are left intact — only display text changed.

### Fixed

- **Several admin surfaces still rendered English on the zh-TW
  locale.** Hardcoded prose and label strings replaced with `t.s`/
  `t.fmt1`/`t.fmt3` calls plus the matching translations:
  - `_broadcast` inspector — `Room` → `房間`, `Tail` →
    `即時訊息`, plus the page sub-heading 改寫成一般 user 看得
    懂的詞 (no more "tail"/"room" left untranslated).
  - `_api_keys` page — the two intro paragraphs (`Two personalities
    for this tenant...` and the `Treat it like a database root
    password...` banner body) now resolve via i18n + `|safe` so the
    embedded `<b>`/`<code>` tags survive rendering.
  - Storage page — the `Two Garage buckets per tenant — ...`
    description and the low-disk banner body (`Free up /var/lib/
    garage...`) translated.
  - `_logs` table header column `operation` → `操作` (was a single
    hardcoded English `<th>`). The detail panel's 15 raw field
    labels (timestamp, tenant, tenant_id, token_hint, operation,
    status, duration, collection, record_id, sql_hash, error_code,
    error_message, auth_method, oauth_email, oauth_error_code,
    extra) now read from a server-rendered `L = {...}` map so all
    of them honour the active locale.
- **`_system_users` column headers no longer render raw SQL names.**
  The admin `_list` endpoint now returns an optional
  `column_labels: Option<Vec<String>>` alongside `columns`. Server
  fills it for known system collections via
  `system_column_labels()` (currently `_system_users` only;
  `_system_*` family is the natural extension point); user-defined
  tables get `None` so the schema author's raw column names render
  as before. Client JS in `collection_rows.html` prefers
  `column_labels[i]` when present, falls back to `columns[i]`
  otherwise. Adds 7 `[system_users.col]` keys in en + zh-TW bundles
  for id / email / password_hash / verified / profile / created_at /
  updated_at.

### Internal

- `build.rs` orphan scanner: a `SYSTEM_USERS_COL_KEYS` static array
  inside `src/mgmt/collection_list.rs` lists each key consumed via
  `format!("{prefix}.{raw}")` so the scanner's `.rs` walk picks them
  up as references. Without this, every dynamically-keyed translation
  would re-surface as a "safe to remove" orphan warning each build —
  the same false-positive pattern v1.32.6 closed for `t.fmt[0-9]*`
  call sites.

---

## v1.32.6 — 2026-06-01

### Fixed

- **Ghost CSS vars purged from admin templates.** Seven templates
  (`_styles.html`, `_cmdk.html`, `collection_rows.html`,
  `tenant_overview.html`, `tenant_webhooks_admin.html`, `login.html`,
  `design.html`) still referenced `var(--line)` / `var(--line-2)` /
  `var(--bg-soft)` — three CSS custom properties that have not been
  defined by any theme since v1.23. They silently fell back to
  `currentColor` for borders and `transparent` for backgrounds,
  which made hairline dividers, cmdk hint bars, sticky filter
  popovers, the login card border, and the OAuth-button hover
  surface invisible in `cozy-dark` and incorrect in `soft-light`.
  All references now use the canonical tokens already defined in
  `themes/<code>.toml [ui]`: `--border-mid`, `--border-strong`,
  `--surface-2`. The v1.28.10 checkbox-skin fix used the same
  pattern; this commit finishes the sweep.
- **i18n orphan scanner now sees Rust-side references AND `fmtN`
  variants.** `build.rs` previously had two blind spots:
  - it only walked `src/mgmt/templates/**/*.html`, so any key
    consumed exclusively from a `.rs` file (e.g.
    `tenant_broadcast.rs` injecting `broadcast_inspector.conn.state_*`
    into a JS `I18N` global, or `i18n.rs` tests asserting on
    `common.button.copy`) surfaced as a "safe to remove" orphan
    warning on every release build;
  - and its regex was `(?:s|fmt)`, which silently missed every
    numbered `t.fmt1(...)` / `t.fmt2(...)` / `t.fmt3(...)` call
    site — so every key formatted with one positional binding
    looked dead.
  The scanner now walks `src/**/*.rs` recursively (any quoted
  literal that matches a known `en.toml` key counts; line-comment
  strings skipped so stale `// TODO: rename foo.bar` notes can't
  hold keys alive) and the template regex is now
  `(?:s|fmt[0-9]*)`. With both blind spots closed, build warnings
  on a clean tree dropped from 4 (with ~125 false negatives hidden
  by the broken regex) to 0.

### Removed

- **127 genuinely-orphan i18n keys deleted** from `en.toml` +
  `zh-TW.toml` — keys that templates and `.rs` files genuinely
  no longer reference (renamed surfaces, removed buttons, replaced
  copy-paste sections from earlier iterations). The set was
  enumerated by the scanner fix above, then triaged: every key
  the scanner flagged was confirmed unused with `grep -rn
  <key> src/` before removal. Empty `[section]` headers and their
  preceding REVIEW comments were collapsed in the same pass.

---

## v1.32.5 — 2026-06-01

### Changed

- **Broadcast publish is no longer hard-pinned to service tokens.**
  REST `POST /t/{tenant}/rooms/{room}` and WebSocket `op:publish`
  on `/t/{tenant}/realtime` now consult two opt-in tenant flags:
  `allow_user_publish` and `allow_anon_publish`. Both default to
  `false`, so the historical service-only behaviour is preserved
  on upgrade; admins must explicitly enable user or anon publish.
  Service-key publish is unaffected. The MCP `broadcast` tool
  stays service-only by MCP dispatch and is **not** affected by
  these flags.
- **Role-specific deny codes on the publish surfaces.** REST
  denials now emit `PUBLISH_USER_DENIED` / `PUBLISH_ANON_DENIED`
  as the primary `error_code`, with the previous `WRITE_DENIED`
  retained as an alias in `error_aliases` for clients still
  pattern-matching on the legacy value. WS denials emit
  `WS_PUBLISH_USER_DENIED` / `WS_PUBLISH_ANON_DENIED`. Both
  surfaces carry a `suggested_fix` pointing at the new
  `PATCH /admin/tenants/{id}/publish-policy` endpoint.

### Added

- **`PATCH /admin/tenants/{id}/publish-policy`** (and matching
  `GET`) for admin partial-update of either flag. Body
  `{"allow_user_publish"?: bool, "allow_anon_publish"?: bool}`.
- **`set_publish_policy` MCP tool** mirroring the same partial
  semantics for tenant-admin automations.
- **Admin UI: two checkboxes on `_api_keys`.** A new card under
  the Self-registration tile renders the live state of both
  flags and PATCHes optimistically on click. Failure rolls back
  the checkbox and surfaces a localized error.

### Security

- **Default-off keeps anon writes locked.** A pre-v1.32.5
  deployment upgraded in place has both flags at `false`, so
  the broadcast surface remains service-only until an admin
  flips a flag — no silent loosening of an existing tenant's
  ACL. The same per-tenant rate-limit (`PublishBucket`) and
  payload-size cap still apply on every publish, regardless of
  flag state.

### Fixed

- **MCP `broadcast` is double-gated for defense in depth.** The
  tool already required service-key MCP dispatch; the new
  policy helper documents that explicitly, and the WS / REST
  code paths share one helper (`check_publish_allowed`) so a
  future change can't open one surface without the other.

---

## v1.32.4 — 2026-05-31

### Performance

- **Webhook delivery reuses a single HTTP client across attempts.**
  Previously each delivery attempt rebuilt a `reqwest::Client`
  (rustls context + connection pool + DNS resolver wiring, ~5–20ms
  cold per build) so at N webhooks × 4 attempts client setup
  dominated dispatch CPU at moderate volume. The dispatcher now
  caches one `Arc<reqwest::Client>` built at startup and threads it
  through every attempt, while still forcing a fresh TCP connection
  per Request so the SSRF guard (`PinnedPublicResolver`) runs on
  every DNS lookup. Redirect policy stays disabled and the
  wrap-time public-IP pre-check is unchanged, so DNS-rebind defense
  is preserved end-to-end. Wire shape on receivers (HMAC signature,
  headers, body, HTTP status, retry classification) is unchanged.
  Loopback dev hosts (127.0.0.1 / localhost / ::1) fall back to the
  per-attempt build path.

---

## v1.32.3 — 2026-05-31

### Performance

- **Tenant bearer auth: 4 sequential meta-DB locks collapsed to 1.**
  Every tenant request previously acquired the global `meta.sqlite`
  mutex 3–4 times in sequence (tenant lookup, per-admin PAT lookup,
  shared service/anon tokens lookup, post-handler email snapshot
  for audit). Under cross-tenant load `meta` was the top contention
  point. One CTE round-trip now returns everything the layer needs.
  Wire shape preserved end-to-end: 401 UNAUTHENTICATED for
  unresolved bearers, 404 TENANT_NOT_FOUND for invalid tenant
  (including cross-tenant bearers), AuthCtx variants, audit fields,
  and `bearer_denied_total` counter labels — all unchanged.
  User-session bearers (separate connection via the pool reader)
  resolve after the CTE; their precedence over a None CTE result
  is preserved.

### Tests

- New `meta_lock_contention` stress test: 1000 concurrent oneshot
  requests with mixed bearer shapes (valid service / anon / invalid
  bearer / invalid tenant) asserts zero false-allow and zero
  false-deny — pins the auth-layer correctness invariant across
  the refactor.

---

## v1.32.2 — 2026-05-31

### Performance

- **WebSocket broadcast: serialize each frame once instead of per
  subscriber.** Every WS subscriber previously deep-cloned the
  payload `Arc` and re-ran `serde_json::to_string(&ServerMessage)`
  — N subscribers × K-byte payload meant N × (deep-clone +
  serialize) per publish, defeating the point of the `Arc<Value>`.
  The publish hot path now pre-serializes the full
  `ServerMessage::Message` envelope into `bytes::Bytes` once and
  the send loop forwards bytes verbatim. Per-publish time is now
  roughly O(1) in subscriber count. Bytes received are byte-identical
  to the pre-v1.32.2 path (same `ServerMessage` Serialize impl,
  pinned by a regression test). Lagged-recovery envelopes still
  rebuilt per subscriber (they carry the room name).

  Synthetic bench, µs/publish:

  | subscribers × payload KB | baseline | now    | change  |
  |--------------------------|----------|--------|---------|
  | 10 × 1                   | 1,310    | 289    | −77.9%  |
  | 100 × 16                 | 103,316  | 2,964  | −97.1%  |
  | 100 × 64                 | 316,784  | 6,528  | −97.9%  |
  | 1000 × 16                | 793,202  | 6,520  | −99.2%  |

---

## v1.32.1 — 2026-05-31

### Changed

- **JSONL audit dual-write retired.** Audit rows now route directly
  to `meta_logs.sqlite` (the source of truth since v1.25.2). The
  per-request `write_all + flush().await` to daily `.jsonl` files
  is removed. Pre-existing `audit-YYYY-MM-DD.jsonl` files are left
  on disk; operators may delete manually.

- **RoomBus / EventBus DashMap keys → `Arc<str>`.** The publish hot
  path no longer allocates a `String` per call for the
  (tenant, collection) key. Reads use `&str` directly; only first
  insert allocates an `Arc`. Side win: per-tenant subscriber and
  channel counts now scale with that tenant's channels, not the
  global total.

- **Stats sampler reuses the reader pool and batches meta updates.**
  Per-tenant `Connection` open removed (was 1–3ms cold × N tenants
  per cycle). N+1 meta-lock acquisitions collapsed to 2 via a
  single `BEGIN IMMEDIATE / COMMIT`. Per-tenant errors are logged
  and skipped; the batch commits what succeeded.

- **`list_handler`: skip the redundant `collection_exists` reader.**
  The DML-cap check already loads schema (cached); successful return
  implies the collection exists. Same 200 / 404 outcomes and bodies.

- **`bearer_auth_layer`: lazy audit field capture.** `path`,
  `tenant`, and `hint` `String` allocations deferred to the
  audit-emit branch.

- **Session cookies honor `DRUST_DEV_NO_SECURE_COOKIES`.** Already
  the convention for theme / locale / per-tenant OAuth cookies.
  Both build and clear paths fixed so logout works in HTTP dev
  runs. Production unaffected (env unset → `Secure` flag stays).

### Fixed

- **Per-tenant OAuth multi-tab redirect_uri confusion.** Two
  parallel OAuth starts in different tabs (each for a different
  allowlisted frontend) could land the first callback on the
  second tab's redirect URI — still allowlisted so no token leak,
  but wrong destination. The `redirect_uri` is now embedded into
  the state token via an HMAC-SHA256 envelope (16B nonce + length-
  prefixed URI + 32B HMAC, base64url; constant-time compare).
  Callback decodes → verifies HMAC → re-checks against the
  per-tenant allowlist (TOCTOU-safe; defense in depth across
  cookie match, PKCE, HMAC, URI allowlist). Per-process secret
  regenerated at boot; restart invalidates in-flight flows
  (5-min PKCE TTL bounds the window). Admin OAuth flow unchanged.

### Notes

- Wire-identical across REST, MCP, and audit-DB consumers. No DB
  migration, no env var addition, no admin UI change.

---

## v1.32.0 — 2026-05-31

### Security

- **RPC `:user_id` user-token spoofing closed (CRITICAL).** A
  User-token caller could supply `{"user_id":"<victim>"}` in an
  RPC body and the auto-bind would honor it, letting any user
  impersonate any other user on any RPC declaring a `:user_id`
  parameter. Auto-bind now always overwrites for User tokens
  (both read and write arms). Anon callers are rejected
  categorically on RPCs declaring `:user_id`. Service tokens
  unchanged.

- **OAuth id_token iss/aud/exp validation.** The Google id_token
  decode path skipped signature verification per OIDC §3.1.3.7
  (confidential client + TLS-trusted token endpoint), but the same
  section also requires `iss` / `aud` / `exp` claim checks — which
  were missing. Now validated:
  `iss ∈ {accounts.google.com, https://accounts.google.com}`,
  `aud == client_id`, `exp > now`. Closes the hijack path where a
  misconfigured `token_endpoint` or an attacker with a Google
  project + allowlisted email could log in as any drust admin.

- **Webhook resolver: IPv6 and CGNAT private ranges blocked.** SSRF
  guard now also rejects `100.64.0.0/10` (RFC 6598 CGNAT), `::/128`
  (IPv6 unspecified), `::ffff:0:0/96` (IPv4-mapped wildcard), and
  `2001:db8::/32` (RFC 3849 docs prefix) at every dispatch attempt.

- **EventBus subscribe race closed (mirrors v1.31.2 RoomBus fix).**
  `EventBus::subscribe` now holds the DashMap entry guard across
  `tx.subscribe()`, so a parallel `evict_collection` cannot orphan
  a freshly-subscribed receiver. Latent — no user report;
  structural fix.

### Observability

- **`/admin/_metrics` Prometheus endpoint.** Admin-session-gated
  GET endpoint exposing five metrics:
  - `drust_audit_drops_total` (counter — audit channel-full drops)
  - `drust_bearer_denied_total{role,status}` (counter)
  - `drust_webhook_attempts_total{result}` (counter)
  - `drust_ws_connections_active` (gauge — RAII guard)
  - `drust_tenant_db_bytes{tenant_id}` (gauge — refreshed at scrape)

  Built on `prometheus 0.13` with no process-metric or protobuf
  dependencies. Closes ISO/IEC 27001 A.8.16 (Monitoring) gap.

- **GitHub Actions CI workflow.** `.github/workflows/ci.yml` runs
  `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --lib`, and `cargo audit` on every push to main and
  on manual dispatch. Passive — push is not blocked on red. Closes
  ISO/IEC 27001 A.8.8 (Vulnerability management) gap.

### Cleanup

- Five cargo warnings resolved (unused struct fields, redundant
  `mut`, private-interface visibility). `cargo check` is now
  warning-free for Rust code.

- `tokio-test` dev dependency dropped (single test site converted
  to `#[tokio::test]`).

- Backup restore now emits an `admin.backup.restore` audit row
  with archive filename and restore destination — closes the
  LOW-severity audit gap for the most destructive admin operation.

### Notes

- No DB migration, no env var addition, no admin UI change visible
  to operators, no MCP tool signature change. Wire shape preserved
  across REST, MCP, admin UI, and audit-DB.

## v1.31.9 — 2026-05-30

### Changed

- **Broadcast Inspector — single-room workspace redesign (Supabase
  style).** First-time-user testing surfaced that the prior layout
  conflated three things into one page (multi-room subscription
  manager, publisher, tail) and the labels did not match user
  expectations: "Subscriptions 0" read as "0 other people are
  subscribed" rather than "0 rooms I've subscribed to", and the
  per-chip `Evict` button was a destructive admin op that 99% of
  users never touch. Rewrote the page as a Supabase-Realtime-Inspector
  shape:
  - **Top bar:** Room textbox + `[Connect]` button + connection
    pill. Connect implicitly subscribes; Disconnect implicitly
    unsubscribes. Room field locks when connected (to change rooms,
    Disconnect first).
  - **Two-column workspace** (≥900px wide): Publish card on the left
    (~380px), Tail card on the right (fills). Below 900px the grid
    collapses to a single column.
  - **Payload textarea + Send disabled until Connect succeeds.**
    Subscribe ack is the gate event.
  - **Removed entirely:** the Subscriptions card, per-chip Evict
    button, Subscriptions count badge. The admin REST endpoint
    `POST /admin/tenants/<id>/realtime/rooms/<room>/evict` is
    unchanged — operators who need to drop hung subscribers `curl`
    directly.
  - **Connection pill** now reads `connected · room <name>` (was
    `connected · N rooms` which was confusing in any room count).
  - **Tail table** drops the `Room` column (single-room session
    makes it redundant) → 4 columns now: Time / Source / Payload / →.
  - **LAGGED auto-recovery**: a LAGGED frame now auto-resubscribes
    to the room transparently (single-room mode means LAGGED
    otherwise leaves the WS alive but silent forever). Prior UX
    asked the user to manually unsub + resub.

## v1.31.8 — 2026-05-30

### Changed

- **Broadcast Inspector Tail — table layout + payload-first rendering.**
  Rewrote the Tail from a `<div>` grid into a proper
  `<table class="data">` (Time / Room / Source / Payload / →) so it
  matches the rest of the admin data-table convention (`tenants_list`,
  `collection_rows`, `_audit_body`). Payload column now shows the
  actual JSON content. Ack rows for publishes to rooms you are NOT
  subscribed to now render with the payload (pulled from a local
  per-ref memory) so a "fire and check delivered_to" workflow shows
  what you sent; ack rows for publishes to rooms you ARE subscribed
  to are suppressed (the inbound `message` row already carries the
  payload, tagged `me`). Source column uses pill chips: `me` for
  self-publishes, `LAGGED` / `RATE_LIMITED` / `evict` / etc. for
  control rows. Pre-v1.31.8 the row only said "delivered to N"
  without ever showing what was actually published — first-time
  users had no way to confirm their payload reached the wire.

## v1.31.7 — 2026-05-30

### Fixed

- **WebSocket / SSE `?token=` auth broken since v1.31.2** — browsers'
  native WebSocket and EventSource APIs cannot set custom headers, so
  drust accepts the bearer in `?token=<value>` and rewrites it into
  `Authorization` via the `ws_query_token_adapter` middleware. v1.31.2
  F4 moved the adapter from a router-level outer layer to a per-route
  inner layer to avoid auto-rewriting `?token=` on non-WS routes —
  but reversed its position relative to `bearer_auth_layer` (which is
  applied router-level → runs OUTERMOST). Every WS / SSE upgrade with
  `?token=` was rejected as `UNAUTHENTICATED` before the adapter
  could rewrite. The `tests/rooms_ws.rs` integration suite that would
  have caught this was `#[ignore]`d due to tokio runtime contention
  (see file header), and the unit tests in `ws_auth.rs` exercised the
  adapter in isolation. The Broadcast Inspector shipped in v1.31.5
  surfaced the bug on first browser smoke. **Fix:** isolate the two
  affected routes (`/t/<id>/realtime` + `/t/<id>/records/<coll>/subscribe`)
  in a dedicated `ws_router` sub-router with `bearer_auth_layer`
  INNER + `ws_query_token_adapter` OUTER, then `.merge()` with the
  main `core` router. New regression test
  `ws_subrouter_layer_order_lets_query_token_reach_auth` in
  `src/tenant/rooms/ws_auth.rs` pins both the post-fix shape (200
  OK) and the buggy pre-fix shape (401) so the bug class can't
  silently re-regress.

### Changed

- **Publish form textarea uses `.textarea` class instead of `.input`**
  — `.input` is `padding: 0 11px` (designed for single-line height-34px
  inputs), which made the textarea content stick to the top edge.
  `.textarea` is `padding: 10px 12px` + line-height 1.55 + mono font
  by default — the existing design-system class for this exact
  purpose.

## v1.31.6 — 2026-05-30

### Fixed

- **Broadcast Inspector page broken on load** (`Uncaught SyntaxError:
  Unexpected end of input`) — a JS comment inside
  `tenant_broadcast.html` contained the literal string `</script>` to
  describe the i18n escape rationale. HTML5 §8.2.4.6 terminates a
  `<script>` element on any literal `</script` regardless of JS
  string or comment context, so the browser truncated the inline JS
  at the comment and the IIFE never closed. Rewrote the comment to
  use `<\/script>` (which is NOT the script-end pattern). Connect /
  Subscribe / Send all work again. v1.31.5 commit `454ccb0`
  introduced the comment as part of fixing the same class of bug for
  i18n_js values — got hoist by its own petard.

### Changed

- **Publish card UX rework** — replaced the cramped
  `160px / 1fr / 120px` 3-column grid with a vertical-stack composer
  (Supabase / Discord pattern): full-width Room input with placeholder
  + regex `pattern`, full-width Payload textarea (5 rows, 110px min
  height, `spellcheck=false`), and a bottom action bar with
  `[validation msg]  [byte counter]  [Send]`. Added `Ctrl/⌘ + Enter`
  keyboard shortcut on the payload textarea (plain Enter still inserts
  a newline for multi-line JSON) and Enter on the Room input.

## v1.31.5 — 2026-05-30

### Added

- **Admin Broadcast Inspector** — new page at
  `/admin/tenants/<id>/_broadcast` (sidebar entry `🛰 Broadcast`) for
  exercising the v1.31 broadcast rooms surface end-to-end from the
  browser. Connect a WS to the existing `/t/<id>/realtime` multiplex
  endpoint, subscribe to any room by name, watch a live tail of
  inbound messages, publish hand-crafted JSON payloads, and evict
  misbehaving rooms (reuses the v1.31.3 admin evict endpoint with
  `admin.broadcast.evict_room` audit). Service bearer is
  server-injected into a hidden form field (same shape `_api_keys`
  uses); tenants with hash-only service tokens get a "regenerate
  service key" banner with the Connect button disabled. Inspector
  does not enumerate active rooms — type the room name you want to
  watch (fire-and-forget contract, same as Supabase Realtime
  Inspector / Kafka topics / Redis pub/sub channels). Zero new wire
  frames, zero new tenant-facing endpoints — everything composes
  existing v1.31 surface. Vanilla JS, no framework. Design:
  `docs/superpowers/specs/2026-05-30-drust-admin-broadcast-inspector-design.md`.

### How to verify

1. Open `/drust/admin/tenants/<id>/_broadcast` in a browser, click
   `[Connect]` → connection pill turns green.
2. Type `smoke-1` in Subscribe input, click `[Subscribe]` → chip
   appears.
3. Open a second browser tab (or `websocat`) to the same room with
   the service bearer (`Authorization: Bearer $TOKEN`).
4. In tab A: type `{"hello":"world"}` in payload, click `[Send]` →
   both tabs see the message in their tail; tab A sees `←me` tag and
   `delivered=2` ack row.
5. Spam-publish ~300 fast frames → `RATE_LIMITED` red row appears in
   tail; Send button briefly disables with a countdown.
6. Resize payload textarea to 70 KiB of JSON → Send disables; byte
   counter goes red at `70000 / 65536 B`.
7. Click `[Evict]` on `smoke-1`, confirm → both tabs disconnect for
   that room; meta_logs.sqlite has a fresh
   `admin.broadcast.evict_room` row with `actor_admin_id` populated.

### Compatibility

None breaking. New admin page; existing routes unchanged; no DB
migration; no env var; no bearer-shape change.

## v1.31.4 — 2026-05-30

### Changed

- **MCP `initialize.instructions` rewrite** — Replaced the legacy 50-tool-name
  conga line with a structured onboarding map: `START HERE` pointers, 5
  capability groups (Schema / Data / Storage / Identity+Integrations /
  Observability), per-group tool lists with 1-line "when to use me" notes,
  6 task recipes ("Look around" → `get_schema_overview`, "Write rows
  safely" → `<op>_record` with `dry_run: true`, …), and a notes block
  covering `dry_run`, `suggested_fix`, and irreversibility. Industry
  pattern (Phil Schmid / Anthropic GitHub MCP) — the `initialize.instructions`
  string is the natural server prologue: zero round-trip, every client sees
  it once. Extracted to `build_instructions(tenant_id, base)` so a unit test
  pins the structure (5 group headings, recipes, no cross-tenant leaks).
  No tool surface change, no wire-format change, no DB / schema / env
  change. Design: `docs/superpowers/specs/2026-05-30-drust-mcp-instructions-onboarding-design.md`.

### Compatibility

None breaking. `instructions` is an opaque string per MCP spec; clients
display or forward it to the model verbatim.

## v1.31.3 — 2026-05-30

### Fixed

- **F11.5** — WS event-loop upstream arm collapsed `None` (clean client
  disconnect) and `Some(Err(_))` (WebSocket protocol error — malformed
  control frame, frame too large, etc.) into a silent `break`. Now
  protocol errors log a `tracing::warn!` line carrying the error,
  tenant, and token_hint. Clean disconnects continue to break silently.
- **F12** — `broadcast.publish` audit rows reported `actor_admin_id: NULL`
  even when the publish came from an admin PAT. Thread `ctx.admin_id()`
  through both the REST `publish_handler` and the WS `handle_socket`
  paths into the audit helpers. **Known limitation:** MCP `broadcast`
  still reports `actor_admin_id: NULL` — rmcp's `#[tool]` macro doesn't
  pass `AuthCtx` to the tool method, and threading it through requires
  a substantive refactor. Tracked for a future patch.
- **F14** — Admin broadcast endpoints (`POST /admin/tenants/{id}/realtime/
  evict-all`, `POST /admin/tenants/{id}/realtime/rooms/{room}/evict`)
  accepted any string as `tenant_id` and inserted it into the DashMap
  key space. Reject malformed ids with `400 INVALID_TENANT_ID` via
  `validate_tenant_id`.
- **F15** — Same two admin broadcast endpoints emitted no audit row,
  breaking the v1.24+ admin convention that every admin mutation gets
  an `admin.<area>.<verb>` audit entry. Emit `admin.broadcast.evict_all`
  and `admin.broadcast.evict_room` with `actor_admin_id`,
  `rooms_evicted`, and `subscribers_dropped` extras.

### Compatibility

None breaking. Existing API responses are unchanged. The MCP `actor_admin_id`
limitation is pre-existing — no regression.

## v1.31.2 — 2026-05-30

### Fixed

- **F4 (security)** — `?token=<bearer>` query-string adapter was layered on
  the entire per-tenant `core` router, meaning every REST + admin + MCP
  per-tenant route accepted the bearer in the URL. Tokens ended up in
  browser history, Referer headers, and Caddy access logs. Narrowed to
  the two routes that actually need it: `/t/{tenant}/realtime` (WebSocket
  upgrade) and `/t/{tenant}/records/{coll}/subscribe` (SSE) — both of which
  browsers cannot send custom headers on.
- **F5** — Empty `StreamMap` in the WS event loop returned
  `Poll::Ready(None)` immediately, and combined with `continue` this select
  arm fired every poll. An idle WS connection (post-upgrade, pre-`Subscribe`)
  pegged a CPU core. Added `if !stream_map.is_empty()` precondition to the
  arm.
- **F6** — A separate `subscribed: HashSet<String>` could drift out of sync
  with `StreamMap`. When admin `evict_tenant` dropped a channel, the stream
  yielded `None` and `StreamMap` removed the entry, but the `HashSet` still
  claimed the room — re-`Subscribe` became a silent no-op. Dropped the
  `HashSet` entirely; `StreamMap` is the single source of truth.
- **F7** — `RoomBus::subscribe` released the DashMap entry's write lock
  before calling `Sender::subscribe()`, so the sweeper's
  `retain(|_, tx| tx.receiver_count() > 0)` could observe a 0-receiver
  Sender and remove it. The subscribe call appeared to succeed but the
  Receiver was orphaned. Hold the `RefMut` across `subscribe()`.
- **F8** — `BroadcastStreamRecvError::Lagged(n)` on any one room closed
  the entire multiplex connection. A single noisy room (e.g. `metrics`)
  dropped the client's `chat` and `notifications` subscriptions too.
  Send a `LAGGED` error frame with `room=<lagging room>`, remove that
  room from the `StreamMap`, and continue the loop. Client can
  `op:subscribe` again to resync.
- **F9** — `PublishBucket::try_consume` did `swap(last_refill_ms) →
  load(tokens) → compute → store(tokens)` as three independent atomics;
  concurrent callers from the same tenant could both observe tokens
  available and both decrement. Documented 100 QPS cap drifted to
  120–140 QPS at 10 concurrent publishers. Replaced atomics with per-tenant
  `Arc<std::sync::Mutex<BucketState>>`; critical section is non-await
  compute so `std::sync::Mutex` is correct.
- **F10** — `WebSocketUpgrade::max_message_size(128 * 1024)` was hardcoded,
  silently overriding `DRUST_BROADCAST_PAYLOAD_MAX_BYTES`. Setting the env
  to 256 KiB made REST + MCP publish accept larger payloads but WS rejected
  at the frame layer with a generic close. Thread `RoomsConfig::
  payload_max_bytes` into both `max_message_size` and `max_frame_size`.

### Compatibility

`?token=<bearer>` on routes other than `/realtime` and
`/records/{coll}/subscribe` now returns 401 (Authorization header required).
This was a documented-as-incorrect surface — the bearer was always supposed
to travel in the header. Any clients depending on the broken behavior
should move the bearer to the `Authorization: Bearer <token>` header.

## [1.31.1] — 2026-05-30

### Fixed

- **F1** — `cargo check --tests` compile break in `tests/mcp_exploration.rs` and
  `tests/admin_users.rs`. v1.31.0 widened `McpRegistry::with_bus_and_storage`
  from 10 to 13 args; two test call sites were not updated. Append the three
  new args via `RoomBus::new()` + `RoomsConfig::test_defaults().bucket()` +
  `RoomsConfig::test_defaults()`.
- **F2** — `POST /admin/tenants/{id}/realtime/evict-all` returned
  `rooms_evicted: null`. `RoomBus::evict_tenant` returns `()`; the handler
  bound the unit value into the JSON field. Snapshot `tenant_channel_count`
  before the evict call.
- **F11** — Admin "evict all WebSocket subscribers" on the English locale
  silently destroyed every subscriber without showing the confirmation
  dialog. The string `"… this tenant's broadcast rooms …"` was inlined into
  an `onsubmit="return confirm('…')"` attribute; Askama escapes `'` to
  `&#39;` which the browser parses back to `'`, breaking the JS string.
  Rewritten to avoid the apostrophe.
- **F13** — Broadcast rooms sweeper used `tokio::time::interval` with the
  default `MissedTickBehavior::Burst`. After VM suspend/resume, this fires
  N catch-up `tick()` events back-to-back. Set `MissedTickBehavior::Skip`
  to preserve "every N seconds" semantics.

### Compatibility

None breaking. `rooms_evicted: null` → `rooms_evicted: <integer>` restores
the documented response contract; clients reading the field as nullable
continue to work.

## v1.31.0 — 2026-05-30

Broadcast rooms — WebSocket multiplex publish/subscribe for tenant
event fan-out. Service-key publish (REST + WS + MCP), tenant-public
subscribe (anon-callable), fire-and-forget, per-tenant rate-limited.
Backward-compatible: zero changes to existing record / RPC / file /
SSE routes; new bus is independent of the v1.10 SSE record channels.

### Added

- **`RoomBus`** (`src/tenant/rooms/bus.rs`) — `DashMap<(tenant, room),
  tokio::sync::broadcast::Sender<RoomMessage>>` with `BUFFER = 256`.
  Methods: `publish`, `subscribe`, `evict_tenant`, `evict_room`,
  `sweep_empty`, per-tenant `channel_count` / `subscriber_count`.
- **`POST /t/<id>/rooms/<room>`** REST publish — service-key only.
  Body is any JSON; replies `{room, delivered_to, byte_count}`.
  Room-name regex `^[a-zA-Z][a-zA-Z0-9_:.-]{0,127}$`; `_system_`
  prefix returns 403 PROTECTED_ROOM. Per-tenant 100 msg/s token bucket
  (`DRUST_BROADCAST_PUBLISH_QPS`), payload cap 64 KiB
  (`DRUST_BROADCAST_PAYLOAD_MAX_BYTES`).
- **`GET /t/<id>/realtime`** WebSocket multiplex — one socket ⇒ N rooms.
  Wire protocol (text JSON frames):
    - client → `{op:subscribe|unsubscribe|publish|ping, room, payload?, ref?}`
    - server → `{kind:ack|message|pong|error, room?, payload?, code?, msg?, delivered_to?, ref?}`
  Service / anon / user tokens may subscribe; only service may publish
  (anon/user `op:publish` → WS_PUBLISH_DENIED). LAGGED subscribers
  receive a 1011 close. Per-conn cap 100 rooms; per-room subscriber
  cap 1000.
- **`?token=<bearer>`** query-string auth on all per-tenant routes —
  rewritten to `Authorization: Bearer <…>` by `ws_query_token_adapter`
  before `bearer_auth_layer`. Lets browsers open WS (native
  WebSocket API can't set custom headers) and EventSource SSE
  (`/records/<coll>/subscribe`). Explicit header wins over query;
  param is stripped from URI before tracing spans / access logs.
- **MCP `broadcast` tool** — publishes through the same
  `publish_into_bus` pipeline as REST + WS. Service-only via existing
  MCP dispatch gate. `whoami` now surfaces `endpoints.realtime_ws`,
  `endpoints.rooms_publish_rest`, and four `limits.broadcast_*`
  fields.
- **Admin evict endpoints** — `POST /admin/tenants/<id>/realtime/evict-all`
  and `…/rooms/<room>/evict` drop hung subscribers without bouncing
  systemd. Tenant overview page gains a compact broadcast card
  (room + subscriber count snapshot + "Evict all" button when > 0).
- **Background sweeper** — every `DRUST_BROADCAST_SWEEPER_INTERVAL_SECS`
  (default 300, 0 disables) `bus_rooms.sweep_empty()` removes channels
  with zero subscribers so DashMap doesn't accumulate stale rooms.
- **`broadcast.publish` audit row** on every successful + failed
  publish across REST / WS / MCP, with `source` ∈ {`rest`, `ws`,
  `mcp`} so operators can attribute throughput.
- **i18n** — 4 new keys × 2 locales:
  `tenant_overview.broadcast.{title,summary,evict_btn,evict_confirm}`.

### Environment variables

| Var | Default |
|---|---|
| `DRUST_BROADCAST_PUBLISH_QPS` | 100 |
| `DRUST_BROADCAST_PAYLOAD_MAX_BYTES` | 65536 |
| `DRUST_BROADCAST_ROOM_SUBSCRIBER_MAX` | 1000 |
| `DRUST_BROADCAST_CLIENT_ROOM_MAX` | 100 |
| `DRUST_BROADCAST_SWEEPER_INTERVAL_SECS` | 300 |

### Migration

No DB migration. No schema changes. No breaking changes to existing
routes. Upgrading just by restarting drust on the new binary enables
the bus and routes; clients opt-in by connecting to `/realtime` or
calling the new endpoints. Existing `realtime_enabled` per-collection
SSE behavior is independent.

### Known issues

- `tests/rooms_ws.rs` integration tests ship `#[ignore]` due to
  tokio-rs/tokio#2374 (per-test runtime starvation under
  `cargo test` parallelism — spawned `axum::serve` on_upgrade closure
  gets starved between HTTP 101 and the WS read loop). Each test
  passes individually:
  `cargo test --test rooms_ws <name> -- --ignored --nocapture`.
  Follow-up will migrate to a shared-runtime harness.

## v1.30.0 — 2026-05-29

Stored RPC v2 — multi-statement mutation support. Backward-compatible
for v1.6 SELECT RPCs (response shape byte-for-byte unchanged).

### Added

- **`_system_rpc.mode`** column (`TEXT NOT NULL DEFAULT 'read' CHECK(mode IN ('read','write'))`).
  Fresh DBs get the CHECK constraint; upgrade DBs rely on the
  application-layer `RpcMode` enum being the only insert surface.
  Existing rows backfill to `mode='read'` on first start.
- **`attach_writable_authorizer`** in `src/query/authorizer.rs` — sibling
  to `attach_readonly_authorizer`. Allows Insert/Update/Delete on
  non-`sqlite_*`, non-`_system_*` tables; denies everything else
  including `Transaction` / `Savepoint` / DDL / ATTACH / triggers /
  vtables / views / AlterTable / Reindex / Analyze. Default arm Deny.
- **`src/rpc/exec_write.rs`** module with `split_statements`
  (`sqlite3_complete`-validated, handles `;` inside string literals
  and comments correctly), `execute_one`, `StatementOutcome`,
  `WriteRpcOutcome`, `RpcStatementError`. Plus the shared
  `run_write_rpc` helper called from both REST and admin playground.
- **`POST /t/<id>/rpc/<name>?dry_run=true`** for `mode='write'` RPCs —
  SAVEPOINT auto-rolled-back; response carries `dry_run:true` +
  `would_commit:<bool>` so callers can preview a mutation.
- **Admin UI mode radio** on `_rpc/new` and `_rpc/<name>/edit` forms;
  per-row mode pill on the `_rpc` list; "Actually commit" checkbox on
  the playground with amber dry-run / green committed result banners.
  PrepareError on create-time validation surfaces `error_code=INVALID_SQL_FOR_MODE`
  via `data-error-code` attribute on the form's error banner.
- **Audit `rpc.call` extension**: every audit row now carries
  `rpc_mode` (`'read'` or `'write'`). Write-mode rows additionally
  carry `rpc_affected_rows`, `rpc_dry_run`, `rpc_statement_count`.
  Write-mode error rows (StatementFailed, WriteRoleDenied,
  UserIdBindingRequired, TxCommitFailed) all carry `rpc_mode:"write"`
  for cross-arm uniformity. Stored in the existing JSON `extra` blob
  — no `meta_logs.sqlite` migration.
- **Suggested-fix catalog entries** for `INVALID_SQL_FOR_MODE`,
  `MODE_MISMATCH`, `RPC_DENIED`, `RPC_STATEMENT_FAILED`,
  `TX_COMMIT_FAILED`, `USER_ID_BINDING_REQUIRED`.

### Changed

- **`src/rpc/handler.rs::call_rpc`** now branches on `stored.mode`.
  Read arm is the unchanged v1.6 implementation (case-1 regression
  test guards byte-for-byte response equality). Write arm enters
  `pool.with_writer` and executes the critical-ordering sequence:
  defensive `detach_authorizer` → `SAVEPOINT drust_rpc_v2` →
  `attach_writable_authorizer` → statement loop → `detach_authorizer`
  → `RELEASE` (commit) or `ROLLBACK TO` + `RELEASE` (dry-run / failure).
  Logic extracted into reusable `exec_write::run_write_rpc` helper.
- **`registry::create`** and **`registry::update`** signatures gain
  a `mode: RpcMode` (resp. `Option<RpcMode>`) parameter.
- **`validate_rpc_sql`** signature gains `mode: RpcMode`; write-mode
  bodies are validated under `attach_writable_authorizer`. Multi-statement
  bodies validated per-statement.

### Security invariants (preserved)

- `_system_*` tables remain unwritable from any RPC (denied by
  `is_protected_collection` in BOTH `attach_writable_authorizer` and
  create-time validation — defense-in-depth ≥2 layers).
- DDL, ATTACH/DETACH, triggers, vtables, views, AlterTable are
  denied in BOTH authorizers.
- `:user_id` auto-bind from `AuthCtx` cannot be spoofed via body;
  anon callers of RPCs declaring `:user_id` get
  `403 USER_ID_BINDING_REQUIRED` before any SQL runs.
- SAVEPOINT rollback runs on EVERY error path; drust never
  partially commits a multi-statement RPC.
- Dry-run unconditionally rolls back even on success.
- `execute_one` documented panic-free contract + asserting test
  (`execute_one_never_panics_on_bad_sql`); a panic would leak the
  SAVEPOINT into the next request because tokio Mutex doesn't poison.

### Migration

- **Single-release rollout, no feature flag.** First-boot
  `migrate_tenant_db` adds the `mode` column with `DEFAULT 'read'`;
  all existing RPCs become `mode='read'` and route to the unchanged
  v1.6 path. Migration is idempotent.
- **No client-visible wire format break** for existing read RPCs.
  Write RPCs surface the new fields (`affected_rows`,
  `last_insert_rowid`, `statement_count`) only when the RPC is
  `mode='write'`.

## v1.29.7 — 2026-05-29

Bugfix release closing three correctness findings from the v1.29.6
code review. All changes backward-compatible — no client breakage.

### Fixed

- **Sunset day-of-week** (`tenant/records.rs::attach_deprecation_headers`)
  — `Wed, 01 Jan 2027` was wrong (2027-01-01 is a Friday). Strict
  RFC 7231 IMF-fixdate parsers reject malformed dates and either drop
  the Sunset header or escalate as malformed. Corrected to
  `Fri, 01 Jan 2027 00:00:00 GMT`. The v1.29.6 CHANGELOG quoted line
  is updated to match the new wire output.
- **CORS expose_headers** (`tenant/mod.rs::build_cors_layer`) — added
  `Access-Control-Expose-Headers: deprecation, sunset, link` so
  cross-origin browser SPAs can actually read the H5-1 phase 1
  deprecation signal via `response.headers.get('deprecation')`.
  Without this, the browser strips them from the JS-visible response
  even though the bytes arrive.
- **Link header URL** (`tenant/records.rs::attach_deprecation_headers`)
  — v1.29.6 pointed at `/docs/migration/list-filter.md`, which did not
  exist. Replaced with the GitHub blob URL of the new
  `docs/migration/list-filter.md` (added in this release), so
  clients following RFC 8288 `rel="deprecation"` resolve to a real,
  versioned migration guide instead of 404.

### Added

- `docs/migration/list-filter.md` — migration guide for
  `GET ?filter`/`?sort` → `POST /list` with FilterAst. Public via the
  Link header above. Covers operator grammar (nested-object shape),
  before/after curl examples, permissions matrix, sunset timeline.

### Testing

- `tests/records_crud.rs::legacy_filter_emits_deprecation_headers`
  rewritten to assert **exact** header values for Deprecation, Sunset
  and Link instead of only `is_some()`. Future day-of-week or URL
  regressions are now caught by `cargo test`.
- `src/tenant/mod.rs::cors_tests::cors_exposes_deprecation_headers`
  added — mounts the CORS layer on a stub axum service and asserts
  `Access-Control-Expose-Headers` lists all three RFC 8594 headers.

### Migration

No schema, error-code, or wire-format change. Existing clients keep
working unchanged. Cross-origin browser clients on the affected
endpoint will *now* see the Deprecation/Sunset/Link headers they
should already have been seeing in v1.29.6.

## v1.29.6 — 2026-05-29

Post-review fix cycle, release 3 of 3. Error-code namespace
harmonisation + legacy GET filter deprecation. All changes backward-
compatible — clients catching existing codes keep working.

### Added

- `error::json_error_with_aliases` helper — emits both primary
  `error_code` and an `error_aliases` JSON array. Lets the wire format
  carry "this code === that code" during code-namespace migration
  without breaking existing clients.
- Suggested-fix catalog entries for `SERVICE_REQUIRED` (canonical for
  v1.30+ service-only rejection) and `ANON_CAP_DENIED` (canonical for
  cap-denial responses).

### Changed

- **Service-only WRITE_DENIED sites** (H2-1, mcp_dispatch + router
  `require_service` + realtime + collections description handlers +
  schema overview) now emit `error_aliases: ["SERVICE_REQUIRED"]`
  alongside the primary `error_code: "WRITE_DENIED"`. The genuine
  "anon can't write to this collection" path on `/records/*` keeps
  `WRITE_DENIED` only.
- **`vector_search.rs` + `records.rs` ANON_DENIED sites** (H2-2 + C3.1)
  now emit canonical `ANON_CAP_DENIED` with `ANON_DENIED` as alias
  for backward compat. Harmonises with `records_list.rs` (v1.21).
  `rpc/handler.rs::ANON_DENIED` (RPC callability gate, different
  semantic) deferred to v1.30 RPC v2.
- **GET `/t/<id>/records/<coll>?filter=` / `?sort=`** (H5-1 phase 1)
  now responds with `Deprecation: true` + `Sunset: Fri, 01 Jan 2027
  00:00:00 GMT` + `Link` headers. Behavior unchanged; phase 2 (post-
  sunset) will refuse raw filter strings.

### Migration

No schema changes. Client error-code matchers continue to work via
`error_code`; new code can read `error_aliases`. GET `?filter=` callers
should plan migration to POST `/collections/<c>/list` with FilterAst
before 2027-01-01.

## v1.29.5 — 2026-05-29

Post-review fix cycle, release 2 of 3. Schema additions laying
groundwork for v1.30 RPC v2 + admin-session-cookie-hash.

### Added (schema, backward-compat)

- `meta.sqlite.sessions.token_hash` (H4-2 phase 1) — SHA-256 of the
  cookie. create_session writes both `token` and `token_hash`;
  validate_session and revoke_session match either column. Legacy
  plaintext-only rows still resolve. Phase 2-4 (v1.31+): lookup
  hash-first → stop writing plaintext → drop `token` column.
- `_system_rpc.callable_by` (H3-1 phase 1) — JSON array
  (`["anon","user"]` etc.). Backfill: anon_callable=1 →
  `["anon","user"]`, =0 → `[]`. Service implicit. v1.30 RPC v2
  reads from this; v1.29 handler unchanged.
- `_system_rpc.user_calls` (H3-2 phase 1) — per-role counter column.
  v1.30 RPC v2 splits User+Anon attribution; v1.29 still lumps to
  `anon_calls`.

### Migration

All 3 column additions go through idempotent `add_column_if_missing`.
Existing tenants migrate automatically on next drust boot. No data loss,
no client-facing API changes.

## v1.29.4 — 2026-05-28

Post-review fix cycle, release 1 of 3. Closes 9 of 16 🟠 high findings
from the 2026-05-28 code review notes
(docs/superpowers/notes/2026-05-28-drust-pre-v130-code-review.md).

### Added

- `pool::with_writer_tx` — canonical multi-statement-write helper that
  wraps writer mutex + SQLite transaction. Commits on `Ok`, rolls back
  on `Err` (or panic, via `Transaction::drop` rollback default). Pure
  addition; no caller of `with_writer` was touched.

### Fixed

- **Partial-state risk on `create_collection`** (H1-3, the highest-risk
  site identified in the review). The pre-existing comment "in the same
  transaction as the table DDL + anon_caps seed" claimed atomicity that
  the code did NOT provide — failure between the table DDL and the
  anon_caps / realtime / vector_fields / description writes left a
  half-created collection with default fallbacks that looked normal.
  All 6 write steps now run inside one `with_writer_tx`.
- **Multi-statement writes on `tenant/records.rs` + `mcp/tools/write.rs`**
  (H1-2, H1-4). DESCRIBE → INSERT/UPDATE/DELETE → readback sequences
  now atomic; a mid-sequence panic rolls back instead of returning 500
  with the row already persisted.
- **Pool-writer sites in `mgmt/rpc_admin.rs`** (H1-5). admin_team.rs and
  meta.sqlite paths keep `unchecked_transaction` for v1.29.4; a parallel
  `with_meta_tx` helper is deferred.
- **Event dispatch timing** (H5-2). `bus.publish` + `webhooks.dispatch`
  now run AFTER the response payload is constructed, eliminating the
  phantom-event window where subscribers would see an event but the
  client would see 500.
- **Audit drain on SIGTERM** (H5-4). `main.rs` graceful shutdown now
  flushes the SQLite audit writer's in-flight buffer (200ms flush
  window) before exit. Previously only the JSONL writer was drained;
  the dual-write path masked the gap until JSONL retirement (v1.25.2,
  scheduled 2026-06-22).
- **PAT plaintext leak defense-in-depth** (H5-3). `reroll` endpoint now
  emits `X-Drust-Sensitive: true` response header; `should_log_body()`
  blacklist extended to `/admin/settings/token/*` paths.
- **Admin session pruning** (H4-1). `drust_session_janitor` now sweeps
  `meta.sqlite.sessions` in addition to per-tenant `_system_sessions`.
  Admin browser sessions previously accumulated forever (zero production
  caller of `auth::session::purge_expired`).

### Migration

None — no schema changes, no client-facing API changes. `with_writer_tx`
is purely additive; existing `with_writer` callers unchanged.

## [1.29.3] — 2026-05-28

Simplifies the PAT model: one PAT per admin, plaintext-retrievable from
/admin/settings, auto-created on admin invite + bootstrap. The
v1.29.0 Task 8 /admin/settings/tokens multi-PAT page and the v1.29.2
/admin/me/mcp-pat/* ensure/remint endpoints are deleted.

### Breaking
- `_admin_tokens.kind` and `_admin_tokens.name` columns dropped. Any
  caller reading them via raw SQL must update.
- All v1.29.0 / v1.29.2 PATs are soft-revoked on first boot — admins
  must visit /admin/settings to view their fresh plaintext-bearing
  PAT and re-paste into mcp.json on every machine that was using a
  v1.29.0 or v1.29.2 PAT.
- bearer_auth_layer now filters `AND revoked_at IS NULL` on the PAT
  lookup. Soft-revoked PATs no longer authenticate.

### Removed
- `/drust/admin/settings/tokens` page + POST/DELETE handlers
  (v1.29.0 Task 8).
- `/drust/admin/me/mcp-pat/{ensure,remint}` endpoints (v1.29.2 S3b).
- `[admin_tokens.*]` and `[mcp_pat.modal]` + `[mcp_pat.confirm]` i18n
  sections.
- Sidebar "Tokens" nav-item (now lives as a card on /admin/settings).

### Added
- `_admin_tokens.plaintext` column (mirrors `tokens.plaintext` for
  service/anon).
- Partial unique index `uniq_admin_tokens_active ON _admin_tokens(admin_id)
  WHERE revoked_at IS NULL` — at-most-one-active-PAT-per-admin invariant.
- `POST /drust/admin/settings/token/reroll` — atomic revoke-current +
  mint-new.
- "Personal MCP token" card on `/drust/admin/settings`: PAT plaintext
  with [Reveal] / [Copy] / [Reroll] (rotation warning mirrors v1.29.2
  S4 service-token reroll text).
- `tenant_api_keys.html` "Copy MCP config" reads the caller's PAT
  from a server-injected `<span data-plain>` and writes the
  `claude mcp add-json` snippet to clipboard — single-click, same
  shape as the existing service-token copy.
- Admin invite (`POST /admin/team`) now creates the admin and their
  PAT atomically in a single unchecked_transaction. Bootstrap admin
  (DRUST_INIT_ADMIN_*) gets its PAT via the run_migrations backfill
  loop (no transaction needed — single-threaded boot).

### Migration notes
- **From v1.29.2**: schema migrates automatically. All existing PATs
  (manual + auto_mcp) are soft-revoked. Each admin gets one fresh PAT
  with plaintext on first boot. Admins log in, copy from
  /admin/settings, paste into mcp.json on every machine that was
  using a v1.29.0 or v1.29.2 PAT.
- **From v1.28.x**: same as v1.29.2 path plus the new schema. No
  legacy PATs to revoke (none existed).
- **Rollback to v1.29.2**: not safe in general — `kind` and `name`
  columns are gone. Restore meta.sqlite from `drust-backup.timer`
  (30-day retention) if needed.

## [1.29.2] — 2026-05-28

Retracts the v1.29.0 OAuth 2.1 Authorization Server bundle for MCP and
replaces it with per-admin PAT auto-binding. Same attribution outcome,
one-click UX instead of a browser-OAuth dance.

### Removed (retracts v1.29.0 bundle C — MCP OAuth 2.1 AS)
- `_oauth_clients`, `_oauth_authorization_codes`, `_oauth_access_tokens`,
  `_oauth_refresh_tokens` tables. Dropped on startup via idempotent
  migration; fresh installs never see them.
- `/drust/oauth/{register,authorize,token}` endpoints and the
  `/.well-known/oauth-{authorization-server,protected-resource}`
  metadata endpoints (host-level and per-tenant). All return 404.
- `/drust/admin/oauth/clients` Owner-only UI.
- In-process `oauth_janitor` daily sweep task.
- MCP transport gate that rejected shared per-tenant service tokens on
  `/t/<id>/mcp`. **The gate is gone — shared service tokens work again
  on MCP**, matching v1.28.11 behavior. Existing Claude Code / Cursor
  configurations continue to work without changes.
- All v1.29.0 OAuth-AS tests and the `tests/login_return_url.rs` test
  for `drust_oauth_intent`.

### Added
- `_admin_tokens.kind` column (`'manual'` | `'auto_mcp'`, default
  `'manual'`, CHECK-constrained) + partial unique index
  `uniq_admin_tokens_auto_mcp` enforcing at most one active `auto_mcp`
  PAT per admin. Also added `_admin_tokens.revoked_at` column to
  support the partial-index `WHERE revoked_at IS NULL` clause.
- `POST /drust/admin/me/mcp-pat/ensure` — idempotent. Mints a fresh
  `auto_mcp` PAT on first call, returns hash fingerprint on subsequent
  calls.
- `POST /drust/admin/me/mcp-pat/remint` — revokes existing `auto_mcp`
  PAT, mints new, returns plaintext.
- "Copy MCP config" button on `/drust/admin/tenants/<id>/_api_keys` now
  (a) calls `ensure` server-side to obtain a per-admin PAT, (b) embeds
  the PAT in the copied `claude mcp add-json` snippet inside the
  drustUI.alert codeBlock (plaintext lives only in modal DOM until
  close), and (c) offers a [Remint] confirm flow for the lost-mcp.json
  case. Admins never mint PATs by hand.
- Key-rotation warning copy on service / anon reroll buttons, manual
  PAT revoke buttons, and the Copy-MCP-config [Remint] button —
  explicitly states that running websites / Claude Code clients /
  scripts will receive 401 until the token is updated on each client.

### Kept from v1.29.0
- Admin team (Owner / Member), `/drust/admin/team` CRUD + UI + sidebar
  entry.
- DB-driven OAuth admin allowlist; env var
  `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS` remains deprecated (warning logged
  on startup if set).
- Personal access tokens (`_admin_tokens`),
  `/drust/admin/settings/tokens` self-mint UI — now coexists with the
  auto_mcp path via the `kind` column.
- Audit attribution columns `actor_admin_id` + `actor_email_snapshot`.
- `set_admin_role` break-glass CLI.
- `AuthCtx::Service { admin_id: Option<i64> }` struct variant.

### Migration notes
- **Upgrade from v1.29.0 / v1.29.1**: the four `_oauth_*` tables are
  dropped on first startup. Any registered OAuth clients are lost
  (Claude Code re-uses MCP via shared service token or per-admin
  auto-MCP PAT). No data loss otherwise.
- **Upgrade from v1.28.x**: full v1.29 schema (`admins.role`,
  `_admin_tokens` with `kind` column, audit attribution) plus the new
  auto-MCP PAT plumbing. OAuth-AS tables are never created.
- **Rollback to v1.28.11**: safe — v1.28.11 ignores `admins.role`,
  `_admin_tokens`, `audit.actor_admin_id`. Existing data preserved.

## [1.29.0] - 2026-05-27 — admin team + MCP OAuth 2.1

### Added
- **Admin team management** — `/admin/team` with Owner + Member roles. Owner can invite/promote/demote/remove other admins via UI. Existing admins backfilled to Owner on migration. `≥1 Owner` invariant enforced TOCTOU-safely inside the writer mutex. New `set_admin_role` recovery CLI for break-glass restoration when all owners get locked out.
- **Personal access tokens** — `/admin/settings/tokens` lets every admin mint named `drust_pat_*` tokens for headless attribution (cron, scripts, CI). PAT carries `admin_id` through `bearer_auth_layer`; audit log shows `actor_admin_id` + `actor_email_snapshot`.
- **OAuth 2.1 Authorization Server** for MCP — drust is now an OAuth 2.1 AS conforming to MCP spec 2025-06-18 §Authorization. Endpoints: `/oauth/authorize` (with consent screen), `/oauth/token` (PKCE S256, refresh rotation, reuse detection per RFC 6819 §5.2.2.3), `/oauth/register` (RFC 7591 Dynamic Client Registration, IP-rate-limited 10/hour), `/.well-known/oauth-authorization-server` (RFC 8414), `/.well-known/oauth-protected-resource` (RFC 9728). Token TTLs: access 1h, refresh 30d sliding. Resource-bound per RFC 8707.
- `/admin/oauth/clients` Owner page — list + revoke OAuth clients. Revoke soft-marks the client and hard-deletes all access + refresh + authorization codes for it in one transaction.
- Audit columns `actor_admin_id` + `actor_email_snapshot` on the `audit` table; matching top-level `AuditEntry` struct fields (NOT inside `extra` so SQL queries can `WHERE actor_admin_id = ?`). `bearer_auth_layer` populates them for PAT and OAuth-bound calls.
- 11 new audit ops: `admin.team.{invite,role_change,remove}`, `admin.token.{mint,revoke}`, `admin.oauth.{client_register,consent,token_issue,token_refresh,token_refresh_reuse_detected,client_revoke}`.
- ~50 new i18n keys for the v1.29 UI surfaces (en + zh-TW).
- In-process daily janitor (`src/mgmt/oauth_janitor.rs`) sweeps expired OAuth codes + access + refresh tokens at 03:00 UTC. Pattern mirrors the audit-retention loop; OAuth tables live host-level in `meta.sqlite` (the existing `drust_session_janitor` bin still handles per-tenant `_system_sessions` only).

### Changed
- `AuthCtx::Service` is now a struct variant `Service { admin_id: Option<i64> }`. Three bearer sources resolve to it: shared per-tenant service token (`None`), PAT (`Some`), OAuth-issued access token (`Some`). 17 match sites updated mechanically across 9 files — no behavioral change for existing callers.
- OAuth admin allowlist is now derived from `admins.email` instead of `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS` env var. Adds/removes are immediate via `/admin/team` — no restart needed.
- Login flow (`login_submit` + admin OAuth `oauth_callback`) honors a short-lived `drust_oauth_intent` cookie set by `/oauth/authorize` when bouncing unauthenticated callers through `/login`. Without the cookie, behavior unchanged (redirects to `/drust/admin/tenants`).

### Deprecated
- `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS` env var. Still parsed for compatibility; if non-empty, drust logs a `WARN` at boot pointing admins to `/admin/team`. Will be removed in v1.31.

### Breaking
- **MCP transport gate now rejects the shared per-tenant service token.** `/t/<tenant>/mcp` requests must use either a personal access token (`drust_pat_*`) or an OAuth-issued access token (`drust_at_*`). The 401 response includes a `WWW-Authenticate: Bearer realm="drust", resource_metadata="…/.well-known/oauth-protected-resource", error="invalid_token"` header so spec-compliant MCP clients (Claude Desktop, Cursor, Claude Code) follow the OAuth flow automatically. REST endpoints (`/records/*`, `/query`, `/list`, `/search`, etc.) still accept the shared service token for backwards compat — only `/mcp` is gated.
- **Operational note:** existing MCP clients configured with the per-tenant service token will need to reconnect after v1.29 deploys (~3 minutes per admin via browser-based OAuth flow).

## [1.28.11] - 2026-05-27 — admin profile fixes

> Consolidates the prior patch tags `v1.28.14` + `v1.28.15` into one release line. Those tags are removed; this entry covers their combined scope.

### Fixed
- v1.28.9 sidebar always rendered the placeholder (`??` avatar + `admin` name + empty email) even after the OAuth UPDATE wrote `display_name` / `picture_url` into the `admins` row. Two stacked bugs:
  1. **Middleware order inverted.** The `protected` router applied layers as `.layer(session_layer).layer(profile_layer).layer(theme_layer)`. axum's `.layer()` makes the LAST-applied layer the OUTERMOST — request flow was `theme → profile → session → handler`. `admin_profile_layer` read `Extension<AdminId>` BEFORE `admin_session_layer` had set it, so `load_admin_profile` always saw `None` and fell back to `AdminProfileExt::placeholder()`. The "runs after admin_session_layer" comment was aspirational — the code didn't match. Order reversed: theme/profile applied first (innermost), session applied last (outermost). `theme_layer` had the same latent issue but stayed hidden because the `drust_theme` cookie short-circuits its AdminId-dependent path.
  2. **Empty strings ≠ NULL.** rusqlite maps SQL `NULL → None` but `'' → Some("")`. OAuth providers occasionally return `picture` / `name` as empty strings (e.g. Google user with no avatar) which then hit the template's `Some(url)` arm and rendered `<img src="">`. `load_admin_profile` now trims and normalizes blank strings to `None` for `display_name`, `email`, and `picture_url` so the sidebar's `{% match %}` falls through to the initials block.

### Changed
- `AdminProfileExt::compute_initials` returns a single character instead of two. CJK names ("林宇軒") render as "林", Western names ("Kael Lim") as "K", email fallback ("kael1996@…") as "K". The two-char "林宇" / "KL" shape from v1.28.9 was visually noisy in the 28-px avatar circle; one character reads cleaner. Placeholder is now "?" (was "??").

## [1.28.10] - 2026-05-26 — collection page polish

> Consolidates the prior patch tags `v1.28.10` (original) + `v1.28.11` + `v1.28.12` + `v1.28.13` into one release line. The `v1.28.10` tag now points at the original `v1.28.13` commit (final state of the polish wave); intermediate tags removed.

### Fixed
- v1.28.9 collection editor shipped four visual rough edges that the new component skin exposed:
  - **Checkbox border invisible.** Custom skin referenced `var(--bg-soft)` + `var(--line)` — both ghost vars with no theme definition since the v1.23 palette refactor (`09af66a` removed the legacy `--line: oklch(…)` declarations without sweeping the 19 remaining references). With both undefined, background fell back to `transparent` and border to `currentColor`. Now uses `var(--bg-deep)` + `var(--border-strong)` with `var(--accent-border)` hover — clearly visible across all three themes.
  - **Filter popover form controls unstyled.** `<select>` + `<input>` inside `.filter-popover` had no background/text color set — UA defaults (white bg + black text) read as broken against the dark popover shell. Now mirrors canonical `.input` / `.select` tokens (`var(--bg-deep)` + `var(--fg)` + `var(--border-mid)` + `var(--accent-soft)` focus ring). Popover container border swapped from `var(--line)` to `var(--border-mid)`; box shadow opacity bumped 0.12 → 0.35 for dark themes.
  - **Footer not pinned to viewport.** `.coll-sticky-bottom` was `position:sticky` inside the page scroll — on short pages it floated mid-air below the table. Now `position:fixed` to viewport bottom, Excel/Supabase status-bar shape (46px tall, `var(--bg-deep)`, single hairline top border). Left edge anchored at 248px to match `.app-shell` sidebar column; right edge at viewport edge. Height matches `.sidebar-foot` so both anchor points read as one continuous horizontal band.
  - **Table / Definition tabs.** v1.28.12 briefly buried them entirely (reachable only via `?view=definition` URL hack); v1.28.13 restored as a slim segmented control on the footer's left side — 26px tall, transparent default, `var(--surface)` fill when active, not the chunky 6px-padding pill of earlier shapes.

### Internal
- `.coll-sticky-bottom` top border swapped `var(--line-2)` (ghost var since v1.23) → `var(--border-mid)`. ~14 other ghost-var references (`var(--line)` / `var(--line-2)` / `var(--bg-soft)`) remain in `_styles.html` — see `project_drust_ghost_css_vars.md`. Cleanup deferred to a future sweep.

## [1.28.9] - 2026-05-26

### Added
- Admin sidebar now renders the real Google/GitHub profile (display name + avatar URL) instead of the hardcoded `AK` placeholder. Both OAuth callbacks (`oauth_login.rs`) persist `name` + `picture` claims onto two new `admins` columns (`display_name`, `picture_url`) on every sign-in; sidebar resolves to an `<img referrerpolicy="no-referrer">` when `picture_url` is set, else a `<div>{{ initials }}</div>` derived from name (`Kael Lim` → `KL`) or email local-part (`kael1996@…` → `KA`). New `AdminProfileExt` extension + `admin_profile_layer` middleware inside the protected scope.

### Changed
- Collection page settings popover (gear button) is now a right-side drawer: `min(420px, 33vw)`, no backdrop dim, 220ms slide-in via transform, independent scroll. The page behind stays interactive (`aria-modal="false"`). Close via `[×]`, ESC, or click outside.
- All admin checkboxes now have a custom CSS-only skin (`appearance: none`). Unchecked = `--bg-soft` + line border (no more stark-white square against dark themes); checked = `--accent` fill + white check mark drawn as a rotated rectangle via `::after`. `:focus-visible` and `:disabled` states included.

### Internal
- Two new nullable columns on `admins` (`display_name`, `picture_url`) via the existing `add_column_if_missing` migration helper.
- New `src/mgmt/admin_profile.rs` — `AdminProfileExt` struct + `compute_initials` + `load_admin_profile` + `admin_profile_layer`. 8 unit tests cover the initials algorithm.
- Every askama admin page struct gains a sibling `pub admin: AdminProfileExt` field next to `pub t: Translator`. Handlers extract `Extension<AdminProfileExt>` and pass it through.
- Four orphan i18n keys retired: `admin_sidebar.foot.username`, `admin_sidebar.foot.scope`, `collection_sidebar.foot.admin`, `collection_sidebar.foot.scope`. Values are now derived from the admin profile, not translated strings.
- `design.html`'s sample `<div class="who-av">AK</div>` at line 451 is kept as a literal — it's the design-system reference, not tied to a live session. (`design.html`'s role-badge showcase at line 249 was migrated to `common.role.admin` since `admin_sidebar.foot.username` no longer exists.)

## [1.28.8] - 2026-05-26

### Fixed
- `/admin/settings` Save was still a no-op for admins who only ever signed in via OAuth (Google / GitHub). v1.28.1 added a `Max-Age=0` cleanup of legacy `Path=/` cookies inside the password-login handler (`routes.rs:411-416`), but the OAuth callback handler (`oauth_login.rs`) was not touched — so OAuth-only admins who logged in between `61fd078` (first `drust_theme` on callback) and `622b44f` (2026-05-24 migration to the canonical `Path=/drust` builders) still had the stale `Path=/` cookies in their jar after every OAuth sign-in. The fresh `Path=/drust` cookies coexisted with them, and `CookieJar::get` returned the stale value on some browsers, masking the Save. OAuth callback now mirrors the v1.28.1 cleanup: two extra `Set-Cookie` headers expire `drust_locale` / `drust_theme` at `Path=/`. Affected users see the bug clear after one fresh OAuth sign-in.

## [1.28.7] - 2026-05-26

### Changed
- `/list` denial code for anon callers on owner-scoped collections is now `ANON_FORBIDDEN_OWNER_SCOPED`, matching `/records/*` and `/search`. The previous code `OWNER_SCOPED_ANON_DENIED` is removed. The HTTP status and the error message are unchanged. External clients pattern-matching the old string need to update.

### Fixed
- Webhook `x-drust-delivery-id` and `x-drust-timestamp` headers now match the corresponding fields in the HMAC-signed body for the same delivery. Previously `dispatch()` generated one UUID/timestamp pair for the body and `deliver_for_test()` generated a second pair for the headers, silently breaking log correlation between a subscriber's request log and drust's `last_failure_reason`. Both values are now generated once in `dispatch()` and threaded through.

### Internal
- `webhook_dispatcher::deliver_for_test` accepts an optional `PreCheckResolveFn` (`Arc<dyn Fn(String, u16) -> BoxFuture<Result<(), String>> + Send + Sync>`) for tests to fake the wrap-first DNS check. Production callers pass `None` — the path is bit-for-bit unchanged. Three previously-`#[ignore]`d integration tests in `tests/webhook_dns_rebind.rs` (`mixed_resolve_dials_only_public`, `ipv6_private_literal_terminal`, `dns_failure_terminal`) are now active.

## [1.28.6] - 2026-05-26

### Fixed
- Collection editor + end-users pages had content sitting at 50px from the page edge while every other admin page (overview, api_keys, rpc, files, oauth providers, webhooks, logs, audit) sits at 32px — the canonical `.page` horizontal padding. Caused by `.coll-sticky-top` / `.coll-toolbar` / `.coll-table-wrap` / `.coll-sticky-bottom` each adding their own 18px on top of `.page`'s 32px. UX felt off when navigating between sidebar entries (content jumped further in).
- Fix: negative-margin on the sticky chrome cancels `.page`'s horizontal padding so background + border render full-bleed; internal 32px padding restores content alignment. Middle sections drop horizontal padding and inherit `.page`'s 32px. Net result: all admin pages share one content-edge position.

### Changed
- `.coll-sticky-bottom` background changes from `var(--bg)` to `var(--bg-deep)` for stronger visual separation from the scrolling content above.

## [1.28.5] - 2026-05-25

### Changed
- Collection page Table rows truncate each cell to a single line with `…` ellipsis instead of wrapping long content. Hover the cell to read the full value (already exposed via `title=…` from the JS renderer). Uses `table-layout:fixed` + `max-width:280px` per td. Matches the pre-v1.28 `.trunc`-cell look.

## [1.28.4] - 2026-05-25

### Added
- Collection page sticky-top now shows the eyebrow `Tenant · <tenant_name>` above the collection title, matching the pre-v1.28 `.view-head` chrome. Uses the existing `.eyebrow` style + `common.label.tenant` i18n key (no new keys).

## [1.28.3] - 2026-05-25

### Changed
- Collection page sticky-top `<h1>` font reverts to the pre-v1.28 `.view-title` look (34px `var(--font-display)`, 500 weight, -0.6px letter-spacing, 1.08 line-height) instead of the 18px sans the v1.28 redesign shipped with. Per user preference — keeps the page title visually anchored consistent with the rest of the admin UI.

## [1.28.2] - 2026-05-25

### Fixed
- v1.28 explain modal popped open on page load and refused to close. Root cause: the modal `<div>` carried both `hidden` attribute AND inline `style="...display:flex..."`; the inline `display:` value beats the UA stylesheet's `[hidden] { display:none }`, so the modal was always visible. Moved the modal styling into a new `.coll-modal` / `.coll-modal-body` class pair in `_styles.html` (no `display:` collision on the host element) so `hidden` is once again the single source of truth for visibility.

## [1.28.1] - 2026-05-25

### Fixed
- `/admin/settings` Save was a no-op for any admin who had logged in via the password flow. The login handler wrote `drust_locale` / `drust_theme` cookies with `Path=/` and no `Secure` flag, while `/admin/settings` writes them with `Path=/drust; Secure` (the canonical attributes). After Save, the browser kept both cookies; `axum_extra::CookieJar::get` then returned the stale `Path=/` value, masking the new one and making the page appear unchanged. Login now routes through `build_locale_cookie` / `build_theme_cookie` so attributes match, and proactively expires any pre-v1.28.1 `Path=/` cookies still in the browser jar via `Max-Age=0`.

## [1.28.0] - 2026-05-25

### Added
- `POST /admin/tenants/<id>/collections/<coll>/_list` — admin-session-protected JSON endpoint that backs the redesigned collection editor's chip filter. Accepts `{filters:[{field,op,value}], sort, page, per_page}`; bridges UI ops (`contains`, `starts_with`, `ends_with`, `between`, `is_true`, `is_false`, `is_null`, `is_not_null`) onto FilterAst and compiles to SQL with `?` binds. Returns `{columns, rows, total, page, per_page, total_pages}`.
- `is_null` and `is_not_null` operators on `FilterAst` leaves (`src/query/vector_filter.rs`).

### Changed
- **Admin collection editor (`/drust/admin/tenants/<id>/collections/<coll>`) — Supabase-style redesign.** Six tabs collapse to two view modes (Table, Definition). Per-collection settings (anon caps, realtime toggle, SSE quickstart docs, EXPLAIN tool) move into a `[⚙]` popover anchored to the sticky header. Description renders inline in the header (no tile, no label). Pagination + view switcher move into the sticky footer; the duplicated meta-row is gone. Filter UI is a structured chip row (column × operator × value), backed by the new `_list` endpoint — no more raw SQL `WHERE` input.
- Layout: single viewport scroll (removed `.records-scroll{max-height:600px}`); full-content-width (no central column cap).
- URL params: `?tab=schema|indexes` → 302 to `?view=definition`; `?tab=anon|realtime|explain` → 302 to `?view=table`. `?filter=<raw SQL>` is dropped (no safe translation); a `tracing::info!` records each hit on the legacy URL.

### Removed
- Server-side rendering of rows from `collection_rows_page` — the template ships a shell and the browser fetches via `_list` (~170 LOC cleanup in `src/mgmt/browse.rs`).
- 33 orphan i18n keys (deleted tab blocks).

## [1.27.0] - 2026-05-25

### Added
- Per-tenant schema codegen endpoints: `GET /t/<id>/openapi.json` (OpenAPI 3.1), `GET /t/<id>/types.ts` (TypeScript types), `GET /t/<id>/zod.ts` (Zod schemas). All three are generated live from `_system_collection_meta` + PRAGMA. Auth follows `/records/*` — anon and service both read schema shape; description text is only included for service bearers. Response header `X-Drust-Schema-Source: anon|service` declares the mode.
- OpenAPI paths auto-emit `POST /records/<c>`, `POST /collections/<c>/list`, `GET/PUT/DELETE /records/<c>/{id}`, plus `POST /collections/<c>/search` for vector collections and `GET /records/<c>/subscribe` for realtime collections. FilterAst is a shared `$ref`.

### Notes
- RPC codegen deliberately out of scope for v1.27 — output column inference for arbitrary stored SELECTs is brittle (aggregates, JSON funcs, computed exprs). Will revisit when there's demand signal.
- Schema codegen is read-only metadata: no writes, no audit emission, no webhook fires.

## [1.26.0] - 2026-05-25

### Added
- `suggested_fix` field on every REST error response and MCP `ErrorData.data`. Static catalog (~25 entries, one per error code) plus four context-aware sites (`FIELD_NOT_FOUND`, `COLLECTION_NOT_FOUND`, `VECTOR_DIM_MISMATCH`, `OWNER_FIELD_REQUIRED`) that substitute actual variable values into the hint.
- `dry_run: true` parameter on `delete_record` / `drop_collection` / `drop_index` (MCP); query string `?dry_run=true` on the matching REST routes (`DELETE /records/<c>/<id>` and `DELETE /collections/<c>/indexes/<n>`). Returns a blast-radius preview (FK blockers, dependent indexes, RPCs that reference the collection, reverse FKs) without mutating storage, writing audit, or firing webhooks.
- `recent_writes` MCP tool. Service-key only. Returns the latest write events (ts/op/collection/status/error_code) for the calling tenant from `meta_logs.sqlite`. Params: `limit` (1..=200, default 50), `collection`, `since_ts`.

### Notes
- All additions are byte-compatible with v1.25.2: `suggested_fix` is optional (omitted when no catalog entry), `dry_run` defaults to `false`, `recent_writes` is a new tool that did not exist.

## [1.25.2] - 2026-05-24

### Removed
- JSONL dual-write path and the `AUDIT_DUAL_WRITE` env var. SQLite is the only audit storage now; a startup WARN is logged if the env is still set.
- Historical `/var/log/drust/audit-*.jsonl*` archives (~520M; all data already in `meta_logs.sqlite`).

### Notes
- Same-day retirement overrode the original 30-day SQLite validation window: v1.24.x ran clean for ~24h on the canonical path, marginal value of dual-write fell below operational cost. Pre-retirement implementation remains at git tag `v1.24.2`.

## [1.25.1] - 2026-05-24

### Removed
- v1.24.2 one-time migration block that promoted the legacy `audit-backfill.done` filesystem marker to the in-DB sentinel — already fired exactly once per install.
- `/var/lib/drust/audit-backfill.done` filesystem marker on the live host.
- `deploy/logrotate-drust` + `/etc/logrotate.d/drust` — no-op for date-named files, deprecated since v1.24.0.

## [1.25.0] - 2026-05-24

### Fixed
- Theme persistence when cookies are cleared but admin session remains. Split the theme middleware: cookie-only outer (covers `/login` + OAuth callback) + DB-aware inner (after admin-session layer).
- `drust_theme` and `drust_locale` cookies now use `Path=/drust + Secure`, matching `drust_session`. Dev override: `DRUST_DEV_NO_SECURE_COOKIES=1`.
- Build now panics on theme TOML ↔ enum drift instead of failing at runtime.

## [1.24.2] - 2026-05-24

### Changed
- Audit backfill is now atomic — synchronous before the writer task spawns, wrapped in a single transaction including the sentinel row. No partial-state on mid-drain kill.
- Retention anchored to wall-clock 03:00 UTC instead of uptime-relative interval. VACUUM no longer skips a month if drust restarts on day 1.

### Added
- `_meta` key/value table inside `meta_logs.sqlite` holds `backfill_done` and `last_vacuum_ts`.
- Channel-full WARN sampled to 1st + every 10,000th to bound journal spam; 60s drop-summary task with non-zero delta logging; "Audit drops" chip on the admin overview (only renders when non-zero).

## [1.24.1] - 2026-05-24

### Fixed
- Backup script now snapshots `meta_logs.sqlite` alongside `meta.sqlite`. Without this, a disk failure would have lost the entire 90-day audit trail introduced in v1.24.0.

## [1.24.0] - 2026-05-24

### Added
- Audit log SQLite storage at `meta_logs.sqlite` (batched writer; channel-full drops counted + warned). JSONL writes ran in parallel during a 30-day validation window via `AUDIT_DUAL_WRITE` (default `true`); retired in v1.25.2.
- One-shot JSONL backfill on first start, idempotent. v1.24 launch backfilled ~2.58M rows in ~9s.
- In-process retention: daily DELETE rows older than 90d, monthly VACUUM on the 1st (UTC).
- Audit row `caller_ip` and `user_agent` promoted out of `extra` into dedicated indexed columns.

### Changed
- Audit Overview totals are SQL aggregates. `MAX_ENTRIES=50_000` cap and 10s `SCAN_CACHE` removed — counts are honest by construction.
- Browse pagination uses `(ts DESC, id DESC)` cursor for stable ordering across timestamp ties.

### Deprecated
- `/etc/logrotate.d/drust` (no-op for date-named files). Removed in v1.25.1.

## [1.23.0] - 2026-05-23

### Added
- Server-side theming for the admin UI: three themes (`system` / `cozy-dark` / `soft-light`). `system` auto-switches via `prefers-color-scheme`. Persisted via `drust_theme` cookie + `admins.theme` column.
- Palettes shipped as `themes/<code>.toml` embedded via `include_str!`. `build.rs` enforces structural validity at compile time.

## [1.22.0] - 2026-05-22

### Added
- Server-side i18n for the admin UI: English (default) and 繁體中文. Resolved from `drust_locale` cookie → `Accept-Language` → `en`. Topbar language switcher. Missing keys fall back to `en` with a dev-only warn.
- Translation bundles compiled into the binary; `build.rs` panics on missing keys at compile time. 705+ keys across 25 templates.

## [1.20.0] - 2026-05-21

### Changed
- Admin REST writers in `mgmt/{browse,rpc_admin,tenant_files}.rs` migrated from raw `open_write` to `pool.with_writer`, unifying admin writes with the data-plane concurrency model.
- `drust_session_janitor` is now async; per-tenant DELETEs go through `pool.with_writer` and inherit `busy_timeout=5000`, closing a deadlock window when drust is actively writing.

### Fixed
- MCP `insert_record` / `update_record` / `delete_record` now block writes against `_system_*` tables (`PROTECTED_COLLECTION`), symmetric with the existing REST block.
- MCP `delete_record` returns `RECORD_NOT_FOUND` instead of `COLLECTION_NOT_FOUND` when the table exists but the id is absent.
- TOCTOU race closed in 6 schema helpers (`set_anon_caps`, `set_realtime`, `set_owner_field`, `set_collection_description`, `set_field_description`, `set_index_description`): existence check now runs inside the same writer closure as the write. Distinct `COLLECTION_NOT_FOUND` / `FIELD_NOT_FOUND` / `INDEX_NOT_FOUND` sentinels preserved.

## [1.19.2] - 2026-05-21

### Security
- Closed `?filter` / `?sort` SQL-injection bypass on `owner_field` for user tokens on owner-scoped collections. Returns `400 USER_FILTER_DENIED_ON_OWNER_SCOPED`.
- Per-IP rate limit (5/min) added to admin login + admin OAuth callback. Closes the parallel-thread argon2 grind window.
- Webhook SSRF defense: redirect-following disabled; `check_url` resolves the registered host and rejects any private/loopback/link-local IP. Residual DNS-rebinding window queued for v1.21.

## [1.19.1] - 2026-05-21

### Fixed
- Admin UI schema-row column-count mismatch (8 cells against 7 grid tracks).
- Schema cache invalidation now fires on every description write.
- Admin description handlers block `_system_*`, check existence before write, and route JSON-blob read-modify-write through the writer mutex.
- `add_field` now persists `FieldSpec.description` (silently dropped before).
- `drop_index` runs `DROP INDEX` + JSON cleanup in a single writer closure.
- `create_collection_with_desc` validates every description before `CREATE TABLE`, eliminating the half-described-collection failure mode.
- Description readers parse JSON per-key — one bad value no longer wipes the whole map.

### Added
- Live UTF-8 byte counter beside the description textarea; save button disables when over 2048 bytes.
- Inline error banner on validator-failure redirect (`?desc_error=<code>`).

## [1.19.0] - 2026-05-21

### Added
- Schema descriptions for collections, fields, indexes, and RPCs (RPC was already supported since v1.6 — now surfaced uniformly across the API).
- MCP tools `set_collection_description`, `set_field_description`, `set_index_description`, `get_schema_overview`.
- REST: PUT routes for description + `GET /t/<id>/schema/overview`.
- Admin UI: inline-editable description tile + Description column on fields and indexes tables.

### Changed
- `Collection`, `Field`, `IndexInfo`, `CollectionSchema` gain optional `description` with `skip_serializing_if = "Option::is_none"` — payloads byte-identical when no description set.

## [1.17.2] - 2026-05-21

### Removed
- Audit overview SVG chart grid (v1.17.0 feature). Used wrong design tokens that fell back to GitHub-cold-blue, clashing with drust's warm palette. User-decided removal rather than refactor.

### Changed
- Tenant name shown everywhere (audit overview tables, backup restore flash, empty-tenant page, reconcile pending revokes, API keys sub-header). UUID still on hover.
- Audit timeline timestamp format: `MM-DD HH:MM:SS` (15 chars) instead of full RFC3339 (24 chars). Raw still on hover.
- Audit timeline grid widened to fit the new format; wrapping cleaned up.

## [1.17.1] - 2026-05-21

### Added
- `X-Drust-Version` response header on every reply.
- Audit log row → modal detail: click-to-open via `drustUI.detail()` reading from an embedded JSON blob. Keyboard parity (Enter/Space).
- Audit toolbar `<datalist>` dropdowns: tenant filter (host scope), op filter from window's distinct ops (capped at 200).
- Audit row tenant pill shows resolved name instead of UUID.
- 6 new icon symbols; leading icons on `/admin/tenants` search input and `/admin/backups` row actions.

### Fixed
- `/admin/backups` DB glyph rendered solid black (missing fill/stroke on inline SVG).
- XSS via literal `</script>` inside the audit `op` string in the embedded JSON blob. Now `</` → `<\/` swapped before serialization.

## [1.13.0] - 2026-05-16

### Added
- Outbound webhooks on record CRUD events. Per-tenant `_system_webhooks` table; HMAC-SHA256 signed POSTs; 4 inline attempts (+0/+1/+5/+30s, 10s each); 5xx/network/timeout retryable, 4xx terminal.
- Service-only REST: `POST/GET/PATCH/DELETE /t/<id>/admin/webhooks[/<wid>]`. Secret returned plaintext exactly once; redacted as `●●●●` everywhere else. PATCH cannot rotate (rotate = delete + create).
- MCP tools: `create_webhook` / `list_webhooks` / `update_webhook` / `delete_webhook`.
- Admin UI virtual sidebar entry `🔔 _webhooks`; raw secret surfaced once via short-lived HttpOnly cookie + `Referrer-Policy: no-referrer`.

## [1.12.3] - 2026-05-15

### Fixed
- MCP HTTP idle-timeout extended from rmcp default 5 min to 24 h. Interactive MCP clients (Claude Code) idling >5 min would otherwise hit `404 Session not found` on the next tool call with no auto-recovery.

## [1.12.2] - 2026-05-15

### Fixed
- `POST /drust/login` equalises argon2 timing on unknown-username via a fixed dummy hash. Closes admin-username-existence wall-clock oracle.
- Admin audit UI no longer renders a broken `/admin/tenants/-/_logs` link for admin-plane rows.

### Changed
- Tenant + admin `register` / `login` / `oauth_callback` audit rows now carry `auth_kind`. Failure rows carry the attempted kind so probing surfaces in the same query.
- Password auth flows now set `auth_method = "password"`, matching OAuth's typed value.
- Admin audit UI renders the typed `auth_method` / `oauth_email` / `oauth_error_code` + the `extra` flatten map.

## [1.12.1] - 2026-05-15

### Fixed
- Admin DELETE / upsert on `_oauth_providers` against a nonexistent tenant_id no longer materialises an empty `tenants/<bogus>/data.sqlite`.
- `_system_users.profile` for OAuth-auto-created rows now carries `picture` (Google `id_token.picture` / GitHub `avatar_url`) — silently dropped in v1.12.0.

### Changed
- Admin REST PUT/DELETE `/admin/oauth-providers` attach typed `AuditExtra`.
- `_oauth_providers` validation failures return specific codes (`INVALID_PROVIDER`, `INVALID_REDIRECT_URI`, `EMPTY_REDIRECT_URIS`, `INVALID_CLIENT_ID`, `INVALID_CLIENT_SECRET`) instead of umbrella `INVALID_OAUTH_CONFIG`.

## [1.12.0] - 2026-05-15

### Added
- Per-tenant OAuth (Google + GitHub) for end users. End-user flow returns to frontend with `<cb>#access_token=drust_user_xxx` (Supabase / Auth0 URL-fragment pattern).
- Per-tenant `_system_oauth_providers` table. Admin REST `GET/PUT/DELETE /admin/oauth-providers[/{provider}]` (service-key only; `client_secret` redacted on GET).
- 3 MCP tools: `set_oauth_provider`, `list_oauth_providers`, `delete_oauth_provider`.
- Admin UI virtual sidebar entry `🔐 _oauth_providers`.
- Sentinel `password_hash="$oauth-only$"` for OAuth-only users. Password login returns `401 INVALID_CREDENTIALS`; `/me/password` returns `409 OAUTH_ONLY_NO_PASSWORD`.
- Per-IP rate-limit (5/min) on `/callback`.
- Audit rows enriched with `auth_method=oauth_<provider>`, `oauth_email`, `oauth_error_code`, `auth_user_id`.

## [1.11.1] - 2026-05-15

### Fixed
- OAuth state + PKCE cookies now use `Path=/drust/admin` (was `/admin`, didn't match Caddy `handle_path /drust/*` strip behavior). Every callback was failing `oauth_state_mismatch` because the browser refused to send the cookie.
- Admin session cookie `SameSite=Strict` → `Lax`. Strict broke the OAuth callback redirect chain.

## [1.11.0] - 2026-05-15

### Added
- Admin OAuth login (Google + GitHub) alongside username + password. Buttons render only when both client id and secret are env-set.
- `admins.email` nullable column (idempotent migration; partial unique index when present). Populate via `set_admin_password --email <addr>`.
- Email allowlist via `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS`; provider `email_verified` flag required.
- PKCE (RFC 7636 S256) + CSRF state cookie (constant-time compare); conformant to RFC 9700 OAuth 2.0 Security BCP.
- New actor-agnostic OAuth library: `OauthProvider` trait + Google OIDC + GitHub OAuth 2.0 adapters. Reused by v1.12 per-tenant OAuth.

## [1.10.1] - 2026-05-14

### Fixed
- `/search`'s `where` AST refuses bool trees nested deeper than 32 levels (`400 FILTER_TOO_DEEP`). Prevents stack exhaustion from a deeply-nested payload that fits inside axum's 2MB body cap.

## [1.10.0] - 2026-05-13

### Added
- Vector storage as a first-class field type: `vector(dim)`, dim 1..=4096. Lowers to a SQLite BLOB of packed little-endian f32. Dim mismatch / NaN / Inf rejected at 422 (`VECTOR_DIM_MISMATCH` / `VECTOR_NON_FINITE` / `VECTOR_TYPE_ERROR`).
- `POST /t/<id>/collections/<c>/search` with structured `{field, vector, k, metric, where, select}`. Metric: `cosine` / `l2` / `l1`. drust constructs SQL from a Filter AST — no raw SQL accepted.
- MCP `search_collection` tool (mirrors REST shape).
- User tokens can call `/search` even though they cannot call `/query` — drust builds the SQL, so `owner_field` enforcement is by construction.
- Vector fields excluded from GET/list responses by default (v1 has no opt-in mechanism).
- sqlite-vec registered as a SQLite auto-extension at process start. Side benefit: `vec_distance_*` is callable from `/query` (service token) and stored RPCs.

## [1.9.0] - 2026-05-12

### Added
- Per-tenant end-user authentication: `_system_users` + `_system_sessions` tables. Tokens `drust_user_*`, SHA-256-hashed at rest, sliding 30d expiry. argon2id verify with fixed dummy-hash timing equalization. Self-register opt-in via `tenants.allow_self_register`.
- Three-kind bearer resolution: `Anon` / `Service` / `User { user_id }` exposed as `AuthCtx`.
- REST: `POST /auth/{register,login,logout,logout-all}`; `GET/PATCH /me`; `POST /me/password`. Service-only admin user CRUD with cascade delete.
- Per-collection `owner_field` + `read_scope` (`own` / `all`): user tokens see only their rows; foreign UPDATE/DELETE returns 404 (no enumeration); anon denied on owner-scoped collections; service must populate `owner_field` on INSERT (`409 OWNER_FIELD_REQUIRED`).
- Stored RPCs accept user tokens when `anon_callable=true`; auto-bind `:user_id` from `AuthCtx` if declared.
- 9 MCP tools mirroring the REST surface; admin UI virtual entry `👤 _system_users`.
- Daily `drust_session_janitor` binary sweeps expired sessions with 1d grace.
- Audit rows enriched: `auth_kind`, `auth_user_id`, `email` / `ip_at_login` on auth endpoints, `deleted_records` / `revoked_sessions` on admin user delete. Auth bodies are never persisted.

### Security
- User tokens denied on `/query`, `/query/explain`, `/mcp` (`403 QUERY_USER_DENIED` / `MCP_USER_DENIED`) — drust does not rewrite user-supplied SQL, so `owner_field` cannot be enforced on those surfaces.
- Per-IP rate-limit: login 5/min, register 3/min. IP from `XFF[-2]` per the `.221 → :8793 → 127.0.0.1` hop chain.

## [1.8.0] - 2026-05-08

### Added
- Per-collection indexes: MCP `create_index` / `drop_index`, REST `POST/DELETE /t/<id>/collections/<coll>/indexes`. Composite + unique supported, auto-named `idx_<coll>_<f1>_<f2>...`.
- Large-table guard: `DRUST_INDEX_LARGE_TABLE_ROWS` (default 1M); `create_index` returns `409 LARGE_TABLE` over threshold unless `force: true`.
- `POST /t/<id>/query/explain` returns EXPLAIN QUERY PLAN rows. Anon-allowed.
- Admin UI Indexes section + EXPLAIN textarea on each collection page.
- `AuditEntry::with_extra` — op-specific keys flatten into the audit row.

### Changed
- `/records/<coll>` get-by-id now consults `anon_caps` (was missed). `/records/_system_*` blocked for both anon and service regardless of caps (404).
- MCP tool count: 21 → 23.

### Fixed
- Soft-delete now evicts the per-tenant pool, MCP service, and SSE bus before moving the directory — quick re-create on the same tenant id no longer hits stale handles.
- Rate-limit bucket map is now bounded with background cleanup.
- Graceful shutdown waits for audit-writer mpsc to drain on SIGTERM.

## [1.7.3] - 2026-05-08

### Added
- MCP tool `set_anon_caps` — toggle per-collection anon DML caps without going through the admin UI cookie session.
- MCP tool `whoami` — returns tenant identity, both bearer tokens in plaintext, REST/MCP/files/rpc paths, and `max_upload_bytes`. Bootstraps the multipart file-upload flow that has no MCP tool by design.

### Notes
- Tokens minted before v1.1c stored only the hash; for those, `whoami.tokens.<role>.plaintext` is `null`. Admin UI reroll is the recovery path.

## [1.7.2] - 2026-05-05

### Added
- RPC test playground at `/admin/tenants/{id}/_rpc/{name}/test` — type-aware param inputs, runs against a read connection, returns result rows + `duration_ms` + `EXPLAIN QUERY PLAN`.
- Backup snapshot inspect at `/admin/backups/{filename}/inspect` — streams the `.tar.zst` on `spawn_blocking`, extracts `meta.sqlite` to a tempfile, lists tenants with each tenant's `data.sqlite` size in the archive.
- Backup tenant restore: `POST /admin/backups/{filename}/restore` extracts a tenant's `data.sqlite` to `_trash/<tid>-restored-<ts>/`. **Does not overwrite live data** — admin `mv`s back manually. Filename strictly whitelisted; tenant id validated as uuid-v4-shaped.

## [1.7.1] - 2026-05-05

### Added
- Backup snapshot UI: `/admin/backups` (read-only list) + per-file download (streamed `.tar.zst`, no buffering). Filename pattern whitelisted; traversal returns 400 before any FS access.
- Audit drill-down links: tenant cell → `/admin/tenants/{id}/_logs`, collection cell → `/admin/tenants/{id}/collections/{coll}`.
- Per-row audit detail panel via `<details>` (full key/value block; `error_message` in red-tinted wrapping `<pre>`).
- Per-tenant disk breakdown: `db` / `files` / **total** columns on the tenants list (auto-scaled B/KB/MB/GB).
- `GarageClient::bucket_usage(name)` admin API wrapper.

### Changed
- `tenant_name` now shown in topbar paths on per-tenant pages (URLs still carry the UUID).
- Audit table styling unified to `.data` admin grid; stat cards equal-height.
- `_rpc` and `_system_files` pages gain pagination.

### Fixed
- Tenant-scope `_logs` page hides the redundant tenant column.

## [1.7.0] - 2026-05-05

### Added
- Admin audit log UI: `/admin/audit` (host) + `/admin/tenants/{id}/_logs` (per-tenant). Stateless file scan over `audit-YYYY-MM-DD.jsonl{,.N,.gz}`. Modes: Overview (totals, error rate, p50/p99, avg QPS, top tenants on host scope, top slow ops) + Browse (paginated `<details>` rows). Window: `1h | 24h | 7d`.

### Changed
- `AuditEntry.status` from `&'static str` to `String` so the type derives `Deserialize` for the audit JSONL parser.
- `MgmtState` + `TenantsState` carry `log_dir: PathBuf`.

### Notes
- No migration. Audit JSONL files were already produced by all prior releases; this only adds a read path.

## [1.6.0] - 2026-04-30

### Added
- Per-collection DML capability allowlist (`anon_caps`): subset of `{select, insert, update, delete}`, default `[select]`. Persisted in per-tenant `_system_collection_meta`. Service is unrestricted.
- Stored RPCs (Supabase-style named SQL functions): per-tenant `_system_rpc` table; REST `POST /drust/t/<id>/rpc/<name>` (anon allowed per-RPC via `anon_callable`); MCP tools `create_rpc` / `update_rpc` / `delete_rpc` / `list_rpc` / `call_rpc` (service-only on the MCP transport regardless of `anon_callable`).
- Admin UI: `_rpc` virtual sidebar entry (list / create / edit / delete with SQL prepare-time validation) + anon_caps editor on the Schema tab.

### Changed
- SQL authorizer Read arm extended to deny any `_system_*` table (was: only `sqlite_*`). Both anon and service affected.
- REST DML write handlers now consult per-collection `anon_caps` (was: always `require_service`). Legacy collections preserve "anon = read-only" via the `[select]` default.
- MCP tool count: 16 → 21.

### Security
- The "anon = read-only" guarantee becomes "anon = subset of DML defined per-collection in `anon_caps`, default `[select]`". RLS deliberately out of scope.

## [1.5.1] - 2026-04-29

### Added
- CORS support on tenant routes. New `DRUST_CORS_ORIGINS` (comma-separated allow-list, empty = layer disabled). Applied OUTSIDE `bearer_auth_layer` so OPTIONS preflight is intercepted before auth. Subdomain wildcards (single `*`) supported — `https://*.example.org`, `http://localhost:*`; multi-`*` rejected at parse.
- Tenants index search box (client-side filter on name + id-prefix; `/` to focus, `Esc` to clear).

### Changed
- Admin UI collapsed from 3 pages to 2. Old `/admin/tenants/{id}` detail page is gone; `GET /admin/tenants/{id}` 302s to `/admin/tenants/{id}/_api_keys`. New virtual sidebar entries `🔑 _api_keys` and `🔒 _system_files`.
- MCP protocol upgrade: rmcp 0.4.1 → 1.5.0; protocol version 2025-03-26 → 2025-11-25. Fixes Claude Code 2.1.119 `/mcp` panel crash.
- MCP tool parameter names unified to `collection` (was: split between `name` and `collection`). `create_collection` keeps `name`.
- `sample_rows.n` renamed to `limit`.

### Removed
- Breadcrumbs across all admin pages; the topbar path is now the clickable navigation.

### Fixed
- Claude Code zod-validator silently rejected the entire MCP tool list because `insert_record` / `update_record` had top-level `data: serde_json::Value` (schemars emits no `type`). Switched to `HashMap<String, Value>`.
- `query` tool error messages: collapsed `ExecError → InvalidQuery` produced "Query is not read-only", wrong for sqlite_master and other authorizer denials. Each variant now surfaces a specific message.
- `insert_record` / `update_record` error messages: unknown collection / unknown field no longer say "Query is not read-only".
- `sql_type` discoverability: error message and tool descriptions now enumerate allowed types.
- `.shell` grid track set to `minmax(0, 1fr)` so cards no longer overflow the `.macwin` boundary on long content.

## [1.5.0] - 2026-04-23

### Added
- Per-tenant Garage buckets: auto-provision `tenant-<id>-pub` (website on) and `tenant-<id>-prv` (private) on tenant create. Rollback on failure is compensating.
- Per-tenant `_system_files` system table.
- Per-tenant file REST at `/drust/t/<id>/files`: multipart upload / list / get / delete / `/sign` (pre-signed URL) / `/bytes` (private proxy). Service-key-only.
- 3 new MCP tools: `list_files` (pagination + visibility filter), `delete_file`, `get_file_url`. **No upload tool by design** — MCP can't carry binary; instructions point the LLM at the REST endpoint.
- Admin tenant-files UI at `/drust/admin/tenants/<id>/files` (parity with `/drust/admin/files`).
- Disk-usage guard: uploads return 507 when free disk drops below `DRUST_DISK_MIN_FREE_PCT` (default 20).
- Reconcile-page extensions: `_trash_pending_revokes` and `_orphan_buckets` surface compensating failures.

### Changed
- `_system_public_files` (admin-level) → `_system_files` with new columns `visibility` / `cache_control` / `meta_json`. Idempotent on boot.
- `/drust/admin/public-files` → `/drust/admin/files` (308 redirect).
- MCP `instructions` field is now dynamic per-tenant.
- MCP tool count: 13 → 16.

## [1.4.0] - 2026-04-21

### Added
- Garage (S3-compatible) integration. Optional, activated by `GARAGE_S3_ENDPOINT` in `.env`; without env vars, drust behaves exactly as before.
- Admin UI at `/drust/admin/public-files` (list / upload / delete / reconcile for the host-level public bucket).
- System collection `_system_public_files` in `meta.sqlite`.
- `_system_*` prefix drop-protection via `is_protected_collection()` enforced by `drop_collection`.
- New env: `GARAGE_S3_ENDPOINT`, `GARAGE_ADMIN_ENDPOINT`, `GARAGE_S3_ACCESS_KEY`, `GARAGE_S3_SECRET_KEY`, `GARAGE_ADMIN_TOKEN`, `GARAGE_PUBLIC_BUCKET` (default `public`), `GARAGE_MAX_UPLOAD_SIZE` (default 50MB), `DRUST_PUBLIC_BASE_URL`.

### Notes
- Reads bypass drust: anonymous GETs hit Caddy `/public/*`, reverse-proxied to Garage `s3_web`. drust is only in the write path.
- Garage gracefully unavailable: upload/delete return 503; list page renders from SQLite metadata. Tenants, MCP, REST, and auth unaffected.

## [1.3.1] - 2026-04-21

### Added
- Favicon — 16×16 LiveChonk (happy pose) as inline SVG via `data:image/svg+xml`.
- Per-page `<meta name="description">` on all five admin templates (≤160 chars).
- `<meta name="theme-color" content="#1a2327">` matches the terminal pane on mobile browsers.

## [1.3.0] - 2026-04-21

### Added
- MCP `drop_field(collection, field)` — `ALTER TABLE ... DROP COLUMN`. Rejects the three system columns (`id`, `created_at`, `updated_at`); SQLite rejects drops that would break a UNIQUE / index / FK / CHECK / trigger / view.
- MCP `drop_collection(name)` — `DROP TABLE` + matching `_updated_at` trigger. Rejects the drop when another collection still has a foreign-key column pointing at this one.
- MCP tool count: 11 → 13.

## [1.2.2] - 2026-04-21

### Changed
- Tenant detail: MCP setup now lives in its own card, separate from the API keys card.

## [1.2.1] - 2026-04-21

### Changed
- "Copy MCP config" emits a `claude mcp add-json` command instead of a `mcpServers` JSON block (one paste into a terminal vs hand-edit a config file).

## [1.2.0] - 2026-04-21

### Added
- LiveChonk pixel-cat mascot — 16×16 silhouette with mouse-tracking eyes, blinking, occasional ear twitch. Wires any `<canvas class="pix" data-chonk=... data-size=...>` automatically.
- Left-side collection sidebar on the collection-detail page. Sidebar scroll independent of main-content scroll.

### Changed
- All admin pages render inside a viewport-fixed `.macwin` shell; internal scroll is container-scoped.
- `/admin/tenants/{id}/collections` 302s to the first collection; empty tenants land on a dedicated empty-state page.
- Login page now renders inside the `.macwin` frame.

## [1.1.1] - 2026-04-21

### Added
- rmcp Streamable HTTP transport wired at `/t/:tenant/mcp`. Each tenant is a self-contained MCP server. Closes the v0.1.0 Known issue.
- MCP is service-key-only — anon keys get `403 WRITE_DENIED`.
- "Copy MCP config" button on the tenant detail page.
- Schema fields may declare `foreign_key: String` naming the target collection. Emits `REFERENCES "<target>"("id") ON DELETE RESTRICT`. Target must already exist at DDL time.
- Field `default_value` accepts `{"sql": "<expression>"}` against an allowlist (`datetime('now')`, `date('now')`, `time('now')`, `CURRENT_TIMESTAMP`, `CURRENT_DATE`, `CURRENT_TIME`).
- Audit log now written on every tenant-data-plane request — closes the v0.1.0 Known issue.
- Per-token rate limit now enforced — closes the v0.1.0 Known issue.
- `set_admin_password` CLI to rotate an admin's `password_hash` (reads from stdin so it doesn't appear in `ps`).

### Changed
- `describe_collection` reports each field's `foreign_key` target (omitted when null; existing consumers unaffected).
- Rate-limit budget / window from `DRUST_RATE_LIMIT_PER_TOKEN` (default 60) / `DRUST_RATE_LIMIT_WINDOW_SECS` (default 10). Audit log dir from `DRUST_LOG_DIR`.

## [1.1.0] - 2026-04-21

### Added
- `anon` / `service` role split on bearer tokens (Supabase-style). `service` is full-power; `anon` is read-only — list / get / filter / subscribe / `POST /query` work, but write methods return `403 WRITE_DENIED`. No RLS — per-row policy deliberately out of scope.
- 2-slot fixed-key model with reroll. Each tenant has exactly one anon and one service slot. Tokens cannot be issued ad-hoc — only rerolled, which atomically revokes the current active token of that role.
- `POST /drust/admin/api/tenants/{id}/tokens/{role}/reroll`.
- Reveal / copy / reroll API keys inline on the tenant detail page. Tokens stored both as SHA-256 hash (auth) and plaintext (display, admin UI only). Pre-v1.1c tokens have `NULL` plaintext and show a "reroll to enable" hint.
- `tokens.plaintext TEXT` column (idempotent migration).
- `_icons.html` partial with reusable SVG sprite block.

### Changed
- Tenant detail page redesigned around a 2-card API-keys layout (one card per role with last-rotated timestamp + reroll button).
- Admin UI minimum text size raised to 18px for readability.
- Removed remaining Chinese strings — UI is English-only.
- Replaced emoji glyphs with inline SVG icons (Lucide), bundled offline.
- Version string now sourced from `Cargo.toml` at compile time.
- `meta.sqlite` migration: `tokens.role TEXT NOT NULL DEFAULT 'service'` column added idempotently.

### Removed
- Arbitrary token issuance endpoint and per-token revoke endpoint — supplanted by reroll.

## [0.1.0] - 2026-04-20

Initial production release.

### Added
- Multi-tenant management plane: session-authenticated admin UI, tenant CRUD, bearer-token issuance / revocation.
- Per-tenant data plane: REST CRUD with PocketBase-style URLs; `POST /query` with `sqlite3_set_authorizer` whitelist for read-only SQL; `?filter=` URL parameter through the same authorizer pipeline; SSE subscribe per `(tenant, collection)`.
- 11 MCP tool functions: `list_collections`, `describe_collection`, `sample_rows`, `count_rows`, `query`, `explain`, `insert_record`, `update_record`, `delete_record`, `create_collection`, `add_field`.
- Read-only data browser in admin UI with filter / sort / pagination.
- Authentication primitives: Argon2id admin password hashing; bearer tokens stored as SHA-256, constant-time compared; 7-day session cookies (`HttpOnly; Secure; SameSite=Strict; Path=/drust`).
- Storage layer: one isolated `data.sqlite` per tenant; WAL + memory-mapped I/O + 64MB cache PRAGMAs; per-tenant connection pool (serialized writer + N-reader); per-tenant quota checks.
- Operations: daily `drust-backup.timer` (`VACUUM INTO` snapshots → tarball, 30-day retention); daily `drust-janitor.timer` (prunes soft-deleted tenants after 7d); logrotate for `/var/log/drust/*.jsonl`.
- Deployment artefacts: `deploy/drust.service` (sandboxed systemd unit); `deploy/Caddyfile` snippet (with `header_up Host` for rmcp DNS-rebinding guard).
- Dark macOS Terminal aesthetic admin UI: traffic-light window chrome, terminal-prompt topbar, monospace typography, terminal-green accent.

### Known issues
- Per-token rate-limit middleware exists but is not wired into the HTTP stack (fixed in v1.1.1).
- Audit-log middleware exists but is not wired (fixed in v1.1.1).
- rmcp HTTP endpoint at `/t/{tenant}/mcp` is deferred (shipped in v1.1.1).

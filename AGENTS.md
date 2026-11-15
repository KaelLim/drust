# drust — reviewer's brief

drust is a multi-tenant SQLite BaaS: one admin plane plus per-tenant REST and MCP
endpoints over isolated SQLite files.

This repo is one service inside the `tool.tzuchi-org.tw` monorepo, but the **git root is
`drust/`**, so `../AGENTS.md` is above the project root and is **not** loaded automatically
(verified empirically, 2026-08-02). Everything you need is therefore repeated here; read
`../AGENTS.md` and `../services.md` by hand only if a finding crosses service boundaries.

This file exists because a reviewer arriving with only the diff has two characteristic
failure modes here, and both are expensive:

1. **Missing a bypass** that is invisible locally, because the property being violated is
   enforced by *enumeration across parallel sites* rather than by one abstraction.
2. **Flagging a load-bearing check as redundant**, because the reason it exists is a
   production incident recorded in prose, not in the code.

> [!IMPORTANT]
> Before you report that a check is redundant, defensive, or dead: grep `CLAUDE.md` and
> `.claude/rules/` for the identifier. If it appears in an enumerated invariant, the check
> is one of N parallel sites and removing it opens a hole.

## Review posture

- Tenant isolation and authorization correctness outrank everything else. Style findings
  are noise unless a compile-time gate enforces the style.
- Cite `file:line`. A finding without a concrete trigger — inputs, state, caller role — is
  a hypothesis, not a finding.
- **Current code beats prose.** Every doc in this repo carries version annotations and some
  have drifted. If `CLAUDE.md` and the source disagree, the source is right and the doc is
  a bug worth reporting.
- Distinguish a production invariant from an implementation detail. The former is usually
  stated with a reason ("otherwise X ships green and breaks in prod"); the latter is not.

## Enumerated invariants — the families where one missed site is a hole

Each of these is enforced by calling the same thing at every relevant site. A new code path
that forgets is a real bug, and it will look locally correct.

| Obligation | Every… |
|---|---|
| `check_tenant_quota` before the growth | write or upload path that can grow a tenant, for **all** caller roles |
| `record_history::capture` in the **same transaction** | path that mutates tenant data-collection rows (three shapes: structured writes, owner-cascade pre-DELETE, the write-RPC preupdate hook) |
| Auth-cache eviction after commit | write that sets `revoked_at`, changes a tenant's `deleted_at`/id, deletes `_system_sessions` rows, cascade-deletes `_admin_tokens`, mutates a publish flag, or changes an admin's `role` or a tenant's `owner_admin_id` |
| `bus.evict_collection` after `schema_cache.invalidate` | write that **reduces** anon read access to a realtime collection — the SSE handler captures caps once at connect, so invalidating the cache alone only affects the next connect (`drop_field` is adjudicated exempt — see Adjudicated verdicts) |
| **Both** `check_egress` **and** `PinnedPublicResolver`, per attempt, fail-closed | host-outbound HTTP path. They are orthogonal; dropping either reopens SSRF |
| `tenant_authz::sees_all_tenants` (never a bare `is_owner`) | new tenant-visibility decision |
| `require_owner_layer` | new **host-wide** admin surface with no `{id}` in its path — the ownership guard cannot catch those, which is exactly how `/admin/files*` was missed |
| `insert_content_type_headers` | byte responder |

## Near-misses worth knowing before you judge a line

- `prepare_cached` on a `SELECT *` over a pooled reader serves a **stale column set** after
  `add_field`/`drop_field` — rusqlite keys its statement cache by SQL text, which does not
  change, and DDL never flushes it. Plain `prepare` there is deliberate.
- The systemd unit deliberately **omits** `MemoryDenyWriteExecute`; wasmtime's JIT needs
  `PROT_EXEC`. Re-adding it fails every edge-function invoke — and the test suite stays
  **green**, because tests do not run under systemd.
- `copy_response` is mandatory inside a Caddy `handle_response` block. A block with only a
  `header` directive returns 200 with a **zero-byte body**.
- `run_migrations` runs on **every boot**. A step that unconditionally revokes a credential
  rerolls it on every restart. Every step must be idempotent.
- `SANDBOX_CSP` must never gain `allow-same-origin` or `allow-scripts` — either defeats the
  same-origin stored-XSS defense entirely.
- `CallerCtx` has no `Default` and no fallthrough to `Privileged`. That absence is the
  escalation guard.

## Adjudicated verdicts — findings already judged, with the module that compensates

Full review rounds keep re-deriving the same suspicions about the #975 PAT-eviction family,
because each one looks wrong *locally* while another module carries the missing half.
Every entry below was adjudicated against the live code (2026-08-17, `v1.65.0..HEAD`
11-finding round, cross-checked per compensating module) and **re-derived after #976
landed**, which fixed three of them rather than compensating for them — the entries that
survive describe v1.66.0 code, not the shape the round found. Re-reporting one as a bug wastes
a round; **"fixing" one regresses a deliberate design**. If the compensating code itself
changed in the diff under review, re-derive from scratch — that is the one case this list
does not cover.

**Deliberate — the "fix" would be the bug:**

- All five `pat_evict` callers read the reach **inside the critical section their revoking
  write already holds** and apply it after commit (v1.66.0, #976 T4 — the earlier
  post-commit live re-read, and the `evict_pat_rooms_sockets` delegator that did it, are
  gone). Reach and revocation are one atomic decision, so do not "simplify" it back to a
  read after the commit: at the four self-service sites that reopens the promote-vs-reroll
  over-evict, and at `remove_admin` the row is DELETED by then, so the fail-direction
  fallback answers `HostWide` and over-evicts the host for a member removal. The snapshot is
  pinned structurally, not behaviourally — the plan's proposed behavioural mutant was
  measured GREEN at the self-service sites, so the pin
  `every_reach_snapshot_is_read_inside_the_revoking_critical_section` counts
  `s.meta.lock().await` acquisitions instead.
- `change_role` decides its evict **inline on the pre-image role** instead of calling
  `pat_evict` — `read_pat_reach` answers off `admins.role` as it stands when it reads, which
  at this one site is the new, narrower reach, so routing it through there under-evicts
  (CLAUDE.md invariant 5). It is deliberately outside the snapshot unification above. Not a
  second role model: both sides classify through the one `tenant_authz::sees_all_tenants`
  predicate.
- The PAT family is **enumerated per site**, unlike `revoke_user_realtime`'s choke point.
  The structural control is `pat_evict_pin`'s tree-wide scan
  (`no_revocation_site_hides_outside_the_pinned_files`), which caught a planted 8th site
  during T2 review.
- `read_pat_reach` re-reads `admins.role` from the DB even where the caller already knows
  the role: two of its five callers sit on the public router with **no profile extension**,
  and the DB column is the same one the bearer CTE consults, so the eviction set cannot
  disagree with what the PAT can actually reach (`src/mgmt/pat_evict.rs`, doc on
  `read_pat_reach`). It takes a `&Connection`, not the `Arc<Mutex<…>>`, which is what makes
  the snapshot above impossible to move out of the guard without a visible second lock.
- `remove_admin` reads `role` twice under the one meta lock (`target_snap` +
  `read_pat_reach`). The duplicate point-read is the price of keeping `read_pat_reach` a
  sealed single decision point; passing the role in would split the reach logic across
  call sites.
- The E2′ SSE revocation signal is **per ADMIN, not per token**: `cli_token_revoke` — and
  the routine `cli_token_refresh`, roughly daily with the default 24 h CLI-PAT lifetime —
  also ends the same admin's UI-PAT SSE streams once (they reconnect with the still-valid
  key). Per-token signalling was rejected in design: it needs the token id in
  `CachedRole::AdminPat` and a `bearer_auth_layer` change. Do not "narrow" it. The same
  per-admin granularity applies to the two reach-narrowing sites: transferring a tenant away
  from a `member` old owner, and demoting an admin (sees-all → not), each also end that
  admin's PAT streams on the OTHER tenants they can still reach (they reconnect and are
  re-admitted). This is deliberate, not over-eviction to fix.
- Owner transfer does **not** send the SSE signal when the old owner is sees-all
  (`owner`/`admin`): their reach did not change, so signalling would only restart their
  streams host-wide for nothing. The role is snapshotted under the transfer's own meta guard
  (`tenant_settings::patch_tenant_owner`).

**Accepted residuals — what remains after #976 (v1.66.0); re-report only if the exposure changes:**

- The auth→baseline fail-open window at WS connect, **narrowed to one `next.run` poll hop**
  by `ws_auth::ws_baseline_capture` (v1.66.0, #976 F1) and not closed: a revocation landing
  between the auth decision and that layer's capture is still adopted as the socket's
  baseline. The `evict_all_tenants` shard-walk-vs-concurrent-first-connect race is the
  **same window** — a socket can only be missed if its bearer auth passed before
  `clear_admin_pat` — not a new hole. Capture may only ever move EARLIER. **For SSE this
  window is closed (E2′)**: `ws_auth::pat_gen_capture` reads the revocation generation
  before any auth read; rooms keep the one-hop window above.
- The auth-cache "insert after clear" race (pre-dates E2′, applies to SSE and rooms alike):
  the bearer DB arm releases the `meta` lock after its CTE and inserts into the auth cache
  later; a revocation that commits, clears and signals exactly between those two points
  lets that request re-insert the revoked entry (`AuthCache::insert` has no generation
  check against `clear_admin_pat`). Precondition: a concurrent request with the same PAT at
  the moment of revocation. Bound: the 10 s safety TTL for new requests — but an SSE stream
  newly opened from that entry inside those 10 s takes a post-revocation `g0`, so it gets no
  signal, and a UI PAT has no `PatDeadline`. A fix touches `bearer_auth_layer` and
  `AuthCache`; out of E2′ scope.
- `pat_evict_pin` keys on the `clear_admin_pat(` needle — a future site that forgets the
  cache clear *too* is invisible to the pin; the guard there is invariant-4 review.

**Deliberate — data-plane response shape (not the PAT family):**

These entries are outside the #975 scope above; they record response shapes on the
anon/user data plane that were judged deliberate during the E-track access-gate review.

- INSERT responses still return the full `record` for anon/user (only UPDATE is narrowed,
  by `records::readback_for`): the row is the caller's own write plus id/timestamps/schema
  defaults — no exploit path, and narrowing it breaks insert-only anon forms. DELETE's
  204/404 existence signal is likewise accepted (ids are AUTOINCREMENT).
- A native SQLite refusal (UNIQUE, NOT NULL, STRICT type) on the REST single-record write
  (`POST /t/<id>/records/<c>`, `PATCH …/<id>`) still answers `400 text/plain` with SQLite's
  message, while `records:batch` and MCP each report it in their own shape. Deliberate
  until one cross-face classifier lands for all three: converting one face alone creates a
  fourth shape. The unknown-field and dropped-collection refusals on that path are already
  typed (`FIELD_NOT_FOUND`, `NOT_FOUND`) by `tenant/records.rs`'s sentinels.

**Deliberate — schema DDL vs stored policies (not the PAT family):**

- `drop_field` neither refuses (409) nor evicts when it drops a policy-referenced field.
  Compensated by `query::policy::eval_policy_materialized` in `tenant/sse.rs` (per-event
  fail-closed; see also the `bus.evict_collection` row of Enumerated invariants) and the
  response's `warnings`; the SQL faces already answer `POLICY_COMPILE_ERROR`. A 409 would
  block a trusted caller with no exploit path left (`FTS_FIELD_INDEXED` differs: there the
  sync triggers break every write).

**Deliberate — MCP annotations and error faces (not the PAT family):**

- `openWorldHint` is `false` on every tool but `invoke_function`, even on record writes
  that fan out to webhooks / edge functions and on `broadcast`: the hint describes the call
  itself, and Claude Code's retry logic does not read it.
- The 21 idempotent writes in `RETRY_SAFE_WRITES` (incl. `set_anon_caps` / `set_policy` /
  `set_owner_field` / `set_realtime`, whose repeat re-evicts SSE subscribers) are
  deliberately retry-safe: a repeat converges to the same state; the extra eviction only
  makes subscribers reconnect and re-gate.
- Only five tools (+ `list_files`) return `isError: true`; every other tool error is still
  a JSON-RPC error. The blanket conversion is the planned outer `call_tool` (MA1), which
  reuses `tool_error`. `delete_record`'s dry_run miss and `get_file_url`'s `expires_in`
  range stay `-32603` until then.
- Edge Privileged `delete-record` still returns `{"ok":false,"error_code":"RECORD_NOT_FOUND"}`
  on the WIT ok-branch; M1 converted only the MCP wrapper.
- `list_files` refuses only a misspelt `public` / `private` (`looks_like_misspelt_visibility`);
  any other unknown `visibility` still lists every file. That is the documented "anything
  else is ignored" contract kept on purpose — tightening it to reject every unknown value
  turns documented successful calls into failures.
- `set_file_visibility` is `destructiveHint: true` although it looks like a toggle: it
  resets `cache_control`, and a publish cannot be recalled once Caddy serves the object
  (invariant 19).

**Deliberate — write-mode stored RPC deadline (not the PAT family):**

- Write-mode stored RPCs run **without** a deadline for service / admin PAT / admin
  playground / cron: deliberate (trust tiers — a tenant's nightly cron write RPC that
  legitimately runs for 20 s must not start failing). Untrusted callers are bounded by
  `exec_write::deadline_for`, the only producer of `Some`; the playground and cron pass a
  literal `None`. Do not "fix" it by arming the deadline for every caller.
- The deadline guard in `run_write_rpc` is armed **only around the statement loop**, not
  at the top of the closure: an interrupt inside the history flush is a 500, and one inside
  STEP 5c would interrupt invariant 2's last-in-tx quota gate. `abandon_savepoint` skips
  `ROLLBACK TO`/`RELEASE` only when the run timed out AND the connection is back in
  autocommit (SQLite already rolled back an interrupted DML statement); widening it to every
  error class would relabel SQLITE_FULL/IOERR/NOMEM for trusted callers.
- Anon/user write RPCs take a per-tenant admission slot (`TenantPool::untrusted_write_rpc_gate`,
  one permit) in the REST write arm and answer `429 RATE_LIMITED` after waiting one deadline
  for it; service, admin PAT, playground and cron never touch it. Deliberate (owner decision
  2026-11-15): the deadline bounds one occupancy of the writer, the slot bounds the untrusted
  queue in front of it. Do not move the acquire into `with_writer` (it would sit under the
  mutex and invert the bound) and do not extend it to trusted callers.

## Canonical sources — do not hand-verify against prose

| Fact | Authority |
|---|---|
| MCP tool count | `grep -c '#\[tool(' src/mcp/handler.rs` |
| MCP tool annotations | `annotation_tests::TABLE` + `RETRY_SAFE_WRITES` in `src/mcp/handler.rs` |
| Routes | the router builders in `src/mgmt/routes.rs`, `src/tenant/mod.rs` |
| Per-file structure | `docs/architecture.md` (generated — `bash docs/gen-architecture.sh`) |
| Edge-function host API | `sdk/edge-function-template/wit/world.wit` |
| Admin UI macros and build gates | `src/mgmt/templates/_ui.html`, `build_support/ui_gates.rs` |
| Release history, version deltas, milestone labels | `CHANGELOG.md` — **not** `CLAUDE.md` |

## Surfaces that must stay in lockstep

Changing one side of any of these without the other is a bug, and the diff will not show
the other side:

- `/list` and `/aggregate` — both call `compute_read_auth` and `build_where_clause` verbatim.
- `compile_policy_using` (SQL) and `eval_policy` (in-memory) — same grammar, two evaluators,
  with `tests/policy_expression.rs` as the corpus proving they agree (the SSE and UPDATE
  read-back faces via `eval_policy_materialized`, which adds the missing-field deny).
- `has_dml_cap` and the `records_list.rs` cap matrix — both read `user_caps` for the User role.
- `storage::files::is_unsafe_inline_type` and the Caddy `@markup` matcher in
  `../garage/deploy/Caddyfile` — the Rust side is case-insensitive, Caddy's is not.
- The four config-time `RPC_ANON_OWNER_SCOPED` sites (create, update, `set_owner_field`,
  policy-attach). The runtime path is deliberately not re-checked, so a missed config site
  is a real bypass — one shipped this way once.
- REST `create_handler`/`update_handler` and edge `enforced_insert`/`enforced_update` — all
  four call `records::reject_system_id`; a fifth anon/user-reachable structured write must too.
- REST `update_handler` and edge `enforced_update` — both hand the `RETURNING *` post-image to
  `records::readback_for` before answering; a third anon/user-reachable UPDATE response site
  must do the same.

## Where the deployment contract lives — and why code review cannot see it

Three of the four production incidents this project has recorded were in files no Rust
reviewer would open:

| Concern | File |
|---|---|
| Reverse-proxy routing, headers, response rewriting | `/etc/caddy/Caddyfile` (live, un-versioned). Snippets: `deploy/Caddyfile` for `/drust/*`, **`../garage/deploy/Caddyfile` for `/public/*`** |
| Process sandbox, environment, restart policy | `deploy/drust.service` |
| Secrets | `.env`, mode 0640 — a non-root read fails **silently**, so an unprivileged `grep` that finds nothing proves nothing |

Cross-service rules that also bind drust:

- **TLS terminates upstream at `.221`, never on this host.** Local Caddy is plain HTTP on
  `:8793`. Never add `tls` or `auto_https`.
- **MCP SDKs reject a non-loopback `Host` header** with a 403/421 that reads like a WAF
  block, so the `/mcp` Caddy block needs `header_up Host "127.0.0.1:47826"`. Garage's
  `s3_web` is the mirror image — it routes *by* Host, so `/public/*` sends
  `Host: public.web.local`.
- **`backups/*.tar.zst` contains plaintext credentials** for every tenant and every admin
  PAT. Treat as a secret store.

## Scope limits

`.env` (0640) and `/etc/caddy/Caddyfile` are outside the repo and outside a code review's
reach. If a finding depends on their contents, say so rather than assuming.

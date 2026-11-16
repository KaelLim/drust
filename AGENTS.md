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
  message, while `records:batch` reports it in its own shape. MCP already reports the
  reserved names (`UNIQUE_VIOLATION`, `NOT_NULL_VIOLATION`, `FK_VIOLATION`,
  `TYPE_MISMATCH`, see the MCP verdicts below). Deliberate until the cross-face classifier
  lands for both REST faces: converting one REST face alone creates another shape. The
  unknown-field and dropped-collection refusals on that path are already typed
  (`FIELD_NOT_FOUND`, `NOT_FOUND`) by `tenant/records.rs`'s sentinels.

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
- Only five tools (+ `list_files`) return `isError: true` for their own failures, and any
  tool returns it for an argument that fails to deserialize (`INVALID_PARAMS`, reshaped
  from rmcp ≥ 1.8 in `handler.rs::finish_tool_call`). Every other tool error is still a
  JSON-RPC error, and since v1.67.0 always with a `data.error_code` from
  `mcp::error_code::mcp_error_code`. Its output is a constant from its tables, or a
  message's own leading `UPPER_SNAKE:` token — drust's prefix, as long as no message
  starts with caller text, which is pinned for the tool-module literals but not for
  verbatim forwards (none found today; the surface is service-only).
  The blanket conversion is the planned account-level `call_tool` (MA1), which reuses
  `finish_tool_call` / `tool_error`. `delete_record`'s dry_run miss and `get_file_url`'s
  `expires_in` range stay `-32603` until then.
- A per-tenant MCP session is not bound to the bearer that opened it. A key reroll or a
  PAT revocation leaves its GET stream open, while every POST re-authenticates (old key →
  401). Deliberate until MA1, which removes sessions: the server's capabilities are exactly
  tools / resources / prompts with no push, so the stream carries nothing.
  `server_capabilities_declare_no_server_push` fails the moment any capability is added,
  and `mcp_sources_never_push` the moment code under `src/mcp/` names the peer (rmcp
  does not stop a push the capabilities never declared).
- MCP native constraint codes (`UNIQUE_VIOLATION`, `NOT_NULL_VIOLATION`, `FK_VIOLATION`,
  `TYPE_MISMATCH`) ship ahead of REST on purpose (owner decision 2026-11-15): they are the
  names the deferred cross-face classifier reserves, so REST adopts them later without MCP
  changing again. Do not "align" MCP back to REST's `text/plain` 400 or to `SQL_ERROR`, and
  do not add a `TYPE_MISMATCH` catalogue entry — `json_error` would attach it to REST's
  existing, unrelated `TYPE_MISMATCH` bodies (`type_mismatch_stays_uncatalogued`).
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
  mutex and invert the bound) and do not extend it to trusted callers. Two consequences are
  accepted, not bugs: (a) the slot is held while its holder waits for the writer, so a fast
  anon/user write RPC queued behind a long trusted write (service/cron write RPC, playground,
  FTS rebuild, large batch) occupies it, and a second one gets 429 after one deadline;
  (b) known residual — one untrusted caller hitting a caller-cost-controlled (or slow by
  nature) `anon_callable` write RPC about once per deadline, well under the per-token rate
  limit, can keep the tenant's OTHER anon/user write RPCs at 429. That shifts the old
  "delay every writer, trusted included, without bound" onto untrusted callers only; the
  operator's remedy is to move that RPC behind a service key or make its cost independent of
  caller parameters.

**Deliberate — the k3s chart is on hold (not the PAT family):**

- `deploy/helm/drust/` is frozen at chart 0.2.0 / `appVersion` 1.67.0 and is not kept in step
  with the two active targets, bare-metal systemd and Docker (CLAUDE.md invariant 17). A
  Docker or bare-metal change with no chart counterpart — a new env knob, path, route or
  recurring job, a `Cargo.toml` version past `appVersion`, `deploy/compose-rustfs/*` or the
  Compose `/public/*` block differing from the chart's copies — is expected drift, not a
  defect. Do not report it and do not "fix" the chart. The chart's render test lives in
  `.github/workflows/helm-chart.yml` and runs only when `deploy/helm/**` or that workflow
  changes, or by hand, so it does not gate those edits. Resuming the chart is a separate,
  deliberate step (`.claude/rules/build-deploy.md` §Deployment targets, "Resuming k3s"); a
  diff that edits `deploy/helm/**` outside such a resume is itself the finding.

**Deliberate — admin login CSRF (not the PAT family):**

- `Sec-Fetch-Site: cross-site` is checked in `login_submit` **only**. Threat: a third-party
  page signs a visitor's browser in as an account whose credentials the page author holds
  (any admin or member on the same host). The admin OAuth callback (`mgmt/oauth_login.rs`)
  is a cross-site top-level GET from the IdP by construction — adding the check there
  refuses every Google / GitHub login. Its login-CSRF defence is the state + PKCE cookie
  pair verified at callback; `tests/admin_login_cross_site.rs` drives the full callback
  success path with `cross-site` to pin that it stays unchecked.
- `/login` deliberately has **no required CSRF field** and no `Origin` / `Host` comparison.
  The eval harness and ~33 test files POST `/login` directly; a required field would block
  that trusted automation, operators who browse the admin UI by an internal hostname send an
  `Origin` that is not `DRUST_PUBLIC_URL`, and the proxy rewrites `Host`. Requests with no
  Fetch Metadata (non-browser clients) pass by design — only a browser can carry a login
  CSRF, and page script cannot set or strip a `Sec-` header. Unknown or unparseable values
  also pass: the Fetch Metadata spec says servers SHOULD ignore an invalid value.
- The check runs **before** the per-IP login limiter. Moving it after would let a
  cross-site page spend the victim IP's 5/min login budget — a test pins the order
  (`tests/admin_login_cross_site.rs`).
- Not covered, accepted: browsers that send no Fetch Metadata; plain-HTTP non-localhost
  deployments with `DRUST_DEV_NO_SECURE_COOKIES` set (Fetch Metadata is sent only to HTTPS
  or localhost; otherwise the `Secure` session cookie cannot be set over HTTP at all); a
  sibling-subdomain (`same-site`) attacker — the pre-existing cookie-tossing residual, not
  addressed here; and same-origin active content, which is invariant 14's job
  (`SANDBOX_CSP`, the Caddy `/public/*` `@markup` matcher), not this check's.

**Deliberate — MCP OAuth AS (not the PAT family):**

- `_mcp_upload_tickets.tenant_id` has **no FK to `tenants`** — deliberate. The tenant
  id-recycle branch hard-`DELETE`s the `tenants` row (`mgmt::tenants::crud`); a non-CASCADE
  FK would make that recycle fail on any leftover ticket. Tickets are deleted explicitly in
  that branch from MA1b on. Do not "add the missing FK".
- An unrecognised `DRUST_MCP`, or an unusable `DRUST_PUBLIC_URL` with `DRUST_MCP=on`,
  **boots with MCP off and an `error` line**, never a boot failure — fail closed for the new
  surface without taking the trusted planes down. Do not turn it into a startup error.
- `remove_admin` deletes `_mcp_oauth_grants` **explicitly** although the FK cascades: the
  cascade needs `PRAGMA foreign_keys = ON` on the deleting connection, and the
  `admin_created_at` check that backs both up fails on a same-second rowid recycle
  (`admins.created_at` is second precision). The explicit DELETE is layer 1
  (`.claude/rules/auth-tenancy.md` §MCP OAuth). Pinned by
  `remove_admin_deletes_grants_even_without_fk_cascade`.
- `revoke_mcp_grant` and the MCP sweep do **not** clear the auth cache or evict any bus:
  MCP OAuth tokens are never cached and open no SSE or rooms stream. That is also why no
  MCP revoke site appears in `pat_evict_pin`'s `SITES`.
- The MCP OAuth sweep runs **even when `DRUST_MCP` is off** — a host that was once `on`
  keeps rows. It is not a boot step (invariant 1).
- `find_grant_for_revocation` accepts an expired, revoked, rotated or superseded token
  of an unrevoked grant: revoking the grant is the narrowing direction (RFC 7009 §2.1),
  and requiring a live token made `/oauth/revoke` answer 200 while the grant stayed
  alive. Its `GrantRef` may only feed `GrantOwner::holder`; only `find_grant_by_access`
  authorizes. `find_grant_by_refresh` likewise ignores rotation state on purpose:
  rotation, grace and reuse are `refresh::rotate`'s decision alone.
- `GrantOwner::holder` is pinned to the grant its `GrantRef` proves: a token of G1 can
  never revoke G2, even of the same admin. `caller` is not pinned and is only ever fed
  the request's `Extension<AdminId>`.
- `remove_admin` does **not** also delete the four MCP child tables: the production meta
  connection is FK ON, and a child row orphaned on an FK-OFF connection is dead because
  every validity read INNER JOINs grants and admins (`.claude/rules/auth-tenancy.md`
  §MCP OAuth, "Child rows never vouch for themselves").

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
  `../garage/deploy/Caddyfile` (bare-metal host) **and `deploy/compose.Caddyfile`** (Compose;
  pinned by `deploy/tests/compose_public_route_test.sh`) — the Rust side is case-insensitive,
  Caddy's is not.
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
| Reverse-proxy routing, headers, response rewriting | `/etc/caddy/Caddyfile` (live, un-versioned). Snippets: `deploy/Caddyfile` for `/drust/*`, **`../garage/deploy/Caddyfile` for the host's `/public/*`**. Compose: `deploy/compose.Caddyfile` for both |
| Process sandbox, environment, restart policy | `deploy/drust.service` |
| Secrets | `.env`, mode 0640 — a non-root read fails **silently**, so an unprivileged `grep` that finds nothing proves nothing |

Cross-service rules that also bind drust:

- **TLS terminates upstream at `.221`, never on this host.** Local Caddy is plain HTTP on
  `:8793`. Never add `tls` or `auto_https`.
- **MCP SDKs reject a non-loopback `Host` header** with a 403/421 that reads like a WAF
  block, so the `/mcp` Caddy block needs `header_up Host "127.0.0.1:47826"`. On the
  bare-metal host Garage's `s3_web` is the mirror image — it routes *by* Host, so `/public/*`
  sends `Host: public.web.local`. The Compose block talks to RustFS's S3 API path-style and
  must not.
- **`backups/*.tar.zst` contains plaintext credentials** for every tenant and every admin
  PAT. Treat as a secret store.

## Scope limits

`.env` (0640) and `/etc/caddy/Caddyfile` are outside the repo and outside a code review's
reach. If a finding depends on their contents, say so rather than assuming.

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
| `bus.evict_collection` after `schema_cache.invalidate` | write that **reduces** anon read access to a realtime collection — the SSE handler captures caps once at connect, so invalidating the cache alone only affects the next connect |
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

**Accepted residuals — filed in #976; re-report only if the exposure changes:**

- The auth→baseline fail-open window at WS connect, **narrowed to one `next.run` poll hop**
  by `ws_auth::ws_baseline_capture` (v1.66.0, #976 F1) and not closed: a revocation landing
  between the auth decision and that layer's capture is still adopted as the socket's
  baseline. The `evict_all_tenants` shard-walk-vs-concurrent-first-connect race is the
  **same window** — a socket can only be missed if its bearer auth passed before
  `clear_admin_pat` — not a new hole. Capture may only ever move EARLIER.
- `pat_evict_pin` keys on the `clear_admin_pat(` needle — a future site that forgets the
  cache clear *too* is invisible to the pin; the guard there is invariant-4 review.

## Canonical sources — do not hand-verify against prose

| Fact | Authority |
|---|---|
| MCP tool count | `grep -c '#\[tool(' src/mcp/handler.rs` |
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
  with `tests/policy_expression.rs` as the corpus proving they agree.
- `has_dml_cap` and the `records_list.rs` cap matrix — both read `user_caps` for the User role.
- `storage::files::is_unsafe_inline_type` and the Caddy `@markup` matcher in
  `../garage/deploy/Caddyfile` — the Rust side is case-insensitive, Caddy's is not.
- The four config-time `RPC_ANON_OWNER_SCOPED` sites (create, update, `set_owner_field`,
  policy-attach). The runtime path is deliberately not re-checked, so a missed config site
  is a real bypass — one shipped this way once.

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

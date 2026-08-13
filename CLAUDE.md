---
type: service
kind: http
name: drust
port: 47826
path: /drust
status: production
updated: 2026-08-13
---

# drust — Rust multi-tenant SQLite BaaS

Self-hosted service providing a PocketHost-like management UI plus per-tenant REST and MCP
endpoints backed by isolated SQLite files.

> [!IMPORTANT]
> **This file describes the system's current shape, not the path it took to get here.**
> Per-release changes belong in [`CHANGELOG.md`](CHANGELOG.md); version deltas, milestone
> labels, and "we tried X then switched to Y" narratives do not belong here. When this file
> and the source disagree, **the source is right and this file is a bug** — fix it in the
> same commit.

Detailed mechanism lives in [`.claude/rules/`](.claude/rules/), loaded automatically when
you touch a matching path — see [Where the rest lives](#where-the-rest-lives). A generated
per-file index is in [`docs/architecture.md`](docs/architecture.md)
(`bash docs/gen-architecture.sh`). Reviewers arriving without this context should read
[`AGENTS.md`](AGENTS.md).

## Build & restart

```bash
cargo build --release
sudo systemctl restart drust
curl -sI http://127.0.0.1:47826/health | grep -i x-drust
```

`/health` returns `ok` from the **old** binary too, and the version string is baked in at
compile time — so a build without a restart, or a restart without a build, both look
healthy while serving stale code. The version header is the only honest deploy check
(`DRUST_HIDE_VERSION=1` omits it).

Grep `x-drust`, not `x-drust-version`: a second header, **`x-drust-boot-degraded: <n>`**,
appears only when best-effort boot maintenance missed on some tenant (STRICT rebuild held
a table back, egress backfill failed). Those tenants serve normally and the work retries
next boot, so it is not an outage — but nothing else surfaces it, and that is how one
tenant's STRICT rebuild failed on 18 consecutive boots unnoticed. Absent means clean.

Building needs `clang` + `libclang`: the rusqlite `preupdate_hook` feature forces
`libsqlite3-sys` into buildtime bindgen. A missing libclang fails with a misleading
`stdarg.h not found`.

## Tests

> [!TIP]
> Cost here is COMPILE, not run. Every test binary statically links the drust lib +
> wasmtime, so a bare `cargo test <name>` still compiles **all** of them — **only
> `--test <name>` limits what compiles.** #925 merged 253 binaries into 38: 24 group
> harnesses `tests/g_<group>.rs`, each `#[path]`-including its member files unchanged,
> plus 14 targets that must keep a process to themselves. `make test-lib` (fast inner
> loop), `make test-<group>` (= `cargo test --lib --test g_<group>`; `make groups` lists
> the groups with live member counts), `make test-all` (full gate). Per-task agents run `make
> test-lib` plus the relevant group; only the final review runs `make test-all`.

Group membership is declared in the harness, not inferred from the filename, and
`autotests = false` means an unregistered `tests/*.rs` would compile into nothing at all —
so a new test file either joins its group harness with `#[path = "<file>.rs"] mod <file>;`
or gets its own `[[test]]` entry, and build.rs's ninth gate
(`build_support/test_targets_gate.rs`) fails the build on a file that is neither, or one
registered twice. The group list, the 14 standalone targets and the collision rule are in
[`.claude/rules/build-deploy.md`](.claude/rules/build-deploy.md) §Tests; per-file
membership is the harnesses themselves.

Never `cargo test --release` — LTO plus `codegen-units = 1` makes it take 40+ minutes. The
one exception is the argon2 timing test. The authoritative pre-release gate is
`CARGO_PROFILE_DEV_DEBUG=0 cargo test --no-fail-fast`, read by its real exit code and never
killed mid-run. `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings`
are **not** part of `make test-all`, and fmt is CI's first gate.

## Architecture at a glance

Three SQLite files, three lifetimes:

| File | Holds | Notes |
|---|---|---|
| `meta.sqlite` | admins, sessions, tenants, bearer tokens, admin PATs | tokens stored hashed **and** plaintext, so `whoami` and the admin UI can echo the key |
| `tenants/<id>/data.sqlite` | one per tenant: user collections + `_system_*` tables | reads via `SQLITE_OPEN_READONLY` connections under `sqlite3_set_authorizer`; writes serialize on a per-tenant writer mutex (`pool.with_writer`) |
| `meta_logs.sqlite` | the host-wide audit log | written by a single batching task; lossy under backpressure by design |

Collections are `STRICT`. Schema metadata (caps, `owner_field`, RLS policies, indexes,
descriptions, audit flag) lives per-collection in `_system_collection_meta`, cached in
`pool.schema_cache`, and is surfaced identically over MCP, REST and the admin UI.

## Surface index

Who may call what. Bodies, field lists and error catalogues are in the code and in
`.claude/rules/`; this table exists so you can tell at a glance whether a surface is
reachable by an untrusted caller.

| Surface | Callable by |
|---|---|
| `/t/<id>/records/*`, `/list`, `/search`, `/aggregate` | service, user, anon — subject to `user_caps` / `anon_caps`, `owner_field`, RLS |
| `/t/<id>/records/<c>?filter=&sort=` (legacy raw params) | **service only** — interpolated, not `?`-bound. Deprecated, Sunset 2027-01-01 |
| `/t/<id>/query`, `/query/explain` | **service only** |
| `/t/<id>/records:batch`, `records:upsert` | **service only** on both REST and MCP |
| `/t/<id>/collections/<c>/subscribe` (SSE) | anon, gated on `realtime_enabled` AND `anon_caps[select]` AND any select policy |
| `/t/<id>/realtime` (WS rooms) | subscribe: anyone with a tenant token. publish: service, unless the per-tenant publish flags are on |
| `/t/<id>/files/*` (Mode A) and `/t/<id>/uploads/*` (tus) | per-verb cap-gated via `file_caps_layer` **AND** per-file gated by the prefix policy registry (`authorize_file` on read/delete, `build_file_list_filter` on list) — the two AND; `sign` and set-visibility stay service-only |
| `/t/<id>/file-policies` (PUT / GET / DELETE) | **service only** on every verb, list included — the registry IS the tenant's file-access map |
| `/t/<id>/rpc/<name>` (`kind='sql'`) | service; anon/user only when `anon_callable` and the collection is not row-access-restricted |
| `/t/<id>/rpc/<name>` (`kind='query'`) | service; anon/user when `anon_callable` — runs a stored `FilterAst` template through the `/list` pipeline under the **caller's** identity, so owner-scope + RLS policy apply by construction (the structured camp; `RPC_ANON_OWNER_SCOPED` does not apply) |
| `/t/<id>/functions/<name>/invoke` | service always; anon/user only when the per-function invoke ACL allows it |
| `/t/<id>/mcp` | **service only** — anon `WRITE_DENIED`, user `MCP_USER_DENIED` |
| `create_fts_index`, `drop_fts_index`, `list_fts_indexes` (MCP tools) | **service only** — full-text index lifecycle, reachable only through `/t/<id>/mcp` |
| `/t/<id>/openapi.json`, `types.ts`, `zod.ts` | service and anon (different shapes; `X-Drust-Schema-Source` records which) |
| `/admin/*` | admin session cookie **or** a `drust_pat_*` bearer |
| `/public/*` | unauthenticated — served by Caddy straight from Garage, never through drust |

Configuration surfaces (caps, policies, egress allowlist, cron, invoke ACL, file caps,
file prefix policies, audit toggle) are **service-only** on every face. Storage tier and per-member tenant cap are
**admin-plane only** — a tenant's own key must never raise its own limits.

## Invariants

> [!WARNING]
> **Bearer tokens are the sole authorization boundary for data-plane access.** A leaked
> token grants full read plus structured write on its tenant until revoked. Never share
> tokens across tenants; never commit `.env`. `src/query/authorizer.rs` is the in-SQL
> cross-tenant guarantee — if you loosen it, re-prove that (a) ATTACH stays denied,
> (b) `sqlite_master` reads stay denied, (c) all write actions stay denied on read
> connections, and (d) the `$fts` search allowance lives in a SEPARATE
> `attach_search_readonly_authorizer` used only on drust-built SQL — the caller-SQL sites
> (`validate_rpc_sql`, `execute_read_query_with_named`) keep the strict arm, and every
> writer open carries `SQLITE_DBCONFIG_DEFENSIVE`.

> [!CAUTION]
> **`header_up Host "127.0.0.1:47826"` is mandatory on the Caddy block** for
> `/drust/t/<tenant>/mcp` — rmcp's DNS-rebinding guard rejects a non-loopback Host with a
> 403/421 that looks like a WAF block. Garage's `/public/*` is the same family in reverse:
> it routes *by* Host, so that block must send `Host: public.web.local`.

> [!CAUTION]
> **The systemd unit deliberately OMITS `MemoryDenyWriteExecute`.** wasmtime's Cranelift JIT
> must `mmap(PROT_EXEC)`; re-adding W^X makes every edge-function upload and invoke fail
> with `unable to make memory executable` — and **the test suite stays green**, because
> tests do not run under systemd. Only a live smoke catches it. The guest sandbox is
> enforced inside wasmtime, not by process-wide W^X. If W^X must return, move functions to
> an AOT or out-of-process model; do not just re-add the directive. The top-level
> `tool/CLAUDE.md` "never skip the sandbox directives" WARNING does **not** apply to this
> one line.

> [!CAUTION]
> **Backup snapshots contain live plaintext credentials.** `backups/*.tar.zst` carries
> `tokens.plaintext` and `_admin_tokens.plaintext` verbatim, so a snapshot grants full
> data-plane access to every tenant and cross-tenant admin access until those tokens are
> rerolled. Same filesystem perms as `.env`; never copy off-host unencrypted.

The following are enforced by **enumeration across parallel sites**, not by one abstraction.
That is what makes them fragile: a new code path that forgets one is a real hole and will
look locally correct. Do not loosen any of them without re-reasoning from scratch.

1. **`run_migrations` runs on every boot, so every step must be idempotent.** Never
   unconditionally revoke, mint, or delete a credential there. A step that did exactly that
   rerolled every admin PAT on every restart for weeks.

2. **Every growth path calls `check_tenant_quota` before the growth, for all caller roles** —
   REST and MCP and edge writes, every `run_write_rpc` caller including cron, Mode-A and tus
   uploads, edge `put-file`. Deletes, reads, and the visibility bucket-move are deliberately
   exempt: a shrink or recovery write must never be blocked. An UPDATE is checked only when
   it BOTH grows the tenant AND leaves it over the cap (`quota::check_update_growth`, called
   at all three update sites: REST `update_handler`, MCP/edge `update_record_checked`, and
   the upsert conflict branch in `upsert_row_in_tx`) — the old blanket exemption justified
   "never block a shrink" but was also permitting unbounded growth by repeated overwrite.
   **That gate is the LAST thing in the write tx, after `record_history::capture`**, because
   the history row carries the full old AND new images and is on by default: measured before
   capture it misses ~2× the payload, and a same-length overwrite moves no data pages at all,
   so the pre-capture reading is `after == before` while the tx commits unbounded growth.
   Tier is admin-plane-only config.

3. **Every path that mutates tenant data-collection rows captures record history in the same
   transaction.** Three shapes: `record_history::capture()` for structured writes,
   `capture_owner_cascade` **before** the DELETE for bulk owner-cascades (both parallel
   `delete_user` sites), and the scoped preupdate hook for raw write-RPC SQL. `_system_*`
   tables are excluded by design at every site.

4. **Every write that changes auth state evicts the auth cache after commit.** That means any
   path setting `revoked_at`, changing a tenant's `deleted_at` or id, deleting
   `_system_sessions` rows, cascade-deleting `_admin_tokens`, mutating a publish flag,
   changing an admin's `role`, or changing a tenant's `owner_admin_id` or `quota_tier`. A
   10 s per-entry safety TTL bounds a missed hook but is not a substitute for one.

5. **Every write that reduces anon read access to a realtime collection calls
   `bus.evict_collection`,** after `schema_cache.invalidate` and never before. The subscribe
   handler captures caps and the select policy **once at connect**, so invalidating the
   cache alone only affects the *next* connect and leaves in-flight subscribers reading
   revoked data. Applies to realtime-disable, `anon_caps` revoke, policy attach or clear,
   `set_owner_field`, and **token reroll** (`reroll_token_json` revokes the old bearer, so
   in-flight SSE/rooms subscribers holding it must be dropped — a tenant-wide `evict_tenant`,
   not `evict_collection`, since the revoked identity spans all collections).
   (`user_caps` paths do not evict — user tokens cannot subscribe to SSE.)
   When a select policy is active for an anon subscriber, `Deleted{id}` events are dropped —
   an id-only event cannot be policy-evaluated against the gone row, and passing it leaks
   deletion id and timing for policy-hidden rows.

6. **Every host-outbound HTTP path passes BOTH `check_egress` AND `PinnedPublicResolver`,
   per attempt, fail-closed.** They are orthogonal — the first enforces the tenant's
   deny-all-default origin allowlist, the second blocks private, loopback and link-local
   addresses at resolve time — and dropping either reopens SSRF. Unknown system or empty
   allowlist means deny.

7. **Tenant visibility is decided by `tenant_authz::tenant_access_for`, and role questions by
   `sees_all_tenants` / `can_manage_members` / `can_manage_privileged` — never by a bare
   `is_owner`.** Seven sites share the predicate: list filtering, the `tenant_ownership_layer`
   route guard, the `ensure_tenant_visible` handler choke point, the data-plane PAT deny in
   the bearer CTE, creator-becomes-owner on create, FK orphaning on `remove_admin`, and the
   id-recycle branch of `make_tenant_inner` — which hard-DELETEs a soft-deleted tenant's row
   and tokens, sits on a route with no `{id}`, and therefore inherits nothing from the route
   guard. The management plane answers **404** for a non-visible tenant, never 403, so it is
   not an existence oracle; the data-plane PAT deny is **403 `PAT_TENANT_DENIED`**. A new
   tenant-scoped admin route joins a guarded sub-router or calls the choke point.

8. **A new host-wide admin surface with no `{id}` in its path must join
   `require_owner_layer`.** The ownership guard keys on `{id}` and therefore cannot see
   these. Backups, host audit, host metrics, quota review and host files are owner-only for
   this reason — `/admin/files*` was missed until an audit precisely because it had no `{id}`.

9. **`/query` and `/query/explain` are service-only; `/mcp` rejects user and anon.** drust
   does not rewrite the raw SQL these accept, so no row-access control can be enforced on
   them — user gets `QUERY_USER_DENIED`, anon gets `QUERY_ANON_DENIED`. For per-user reads of
   owner-scoped data use a stored RPC with `:user_id`, or `/search` / `/list` / `/aggregate`,
   where drust builds the SQL.

10. **Any new endpoint that accepts user input which lands in SQL must explicitly pick a
    camp.** Structured input (`FilterAst` compiled with `?` binds) is enforceable by
    construction and may accept anon and user; raw input cannot be rewritten and is
    service-only. The legacy `GET /records/<c>?filter=` params are the raw camp and are
    service-only for exactly this reason (`RAW_FILTER_DENIED`). A **`kind='query'` stored RPC**
    is the structured camp reached through a stored template: caller args are scalar-only
    (`RPC_PARAM_NOT_SCALAR` — the AST-injection gate) and substitute into `FilterAst` operands
    at the JSON level *before* parse, never through the string-tolerant `parse_filter_value`;
    it runs the `/list` core under an `RpcGrant` cap-mode that skips ONLY caps backed by an
    independent row gate — the `read_scope="all"` / owner-scoped arms keep their cap because
    there the cap IS the row gate.

11. **`SELECT *` on a pooled reader uses plain `prepare`, never `prepare_cached`.** rusqlite
    keys its per-connection statement cache by SQL **text**, which is stable across
    `add_field` / `drop_field`, so a cached `SELECT *` — whose `column_names()` is read
    before stepping — serves a **stale column set** on a long-lived reader. DDL flushes the
    schema cache and the SSE bus but never the reader's statement cache. Only an explicit
    schema-derived projection (whose SQL text changes on DDL, so the cache self-heals) or
    `COUNT(*)` may be `prepare_cached`. The `RETURNING *` read-back equals the committed row
    only because the only AFTER trigger that MODIFIES THE PARENT ROW is the convergent
    `updated_at` one (the fts5 sync triggers write only the shadow, never the parent) and
    tenants cannot create triggers.

12. **Explicit RLS policies AND-compose with the unchanged owner clause.** The two evaluators
    — `compile_policy_using` (SQL) and `eval_policy` (in-memory) — must stay in lockstep, and
    any grammar change updates both plus the `tests/policy_expression.rs` corpus. Policy
    input stays structured, never raw SQL. The two cap-gate sites (`has_dml_cap` and the
    `records_list.rs` matrix) must also stay in lockstep, including the rule that a User READ
    on a `read_scope="all"` owner-scoped collection is gated by `user_caps[select]`. Writes
    are always owner-scoped for the User role regardless of `read_scope`. A **SELECT policy
    with no `using` clause DENIES all reads** (`select_read_access` → `0=1` in SQL, `false`
    in-memory — one classifier both evaluators route through): "a select policy row exists"
    must mean "reads are restricted", never fail open. `validate_policy` rejects a new
    clause-less SELECT policy (`POLICY_SELECT_REQUIRES_USING`); the read-path deny covers any
    legacy row. This closed a latent fail-open that `RpcGrant` (which skips caps) turned into
    a cross-tenant leak.

13. **Every `DrustMcp` construction site decides `functions:` consciously.** The executor's
    host state is built with `functions: None` (`HostStateSeed::build_mcp`); restoring a
    dispatcher there reintroduces unbounded recursion. `CallerCtx` has no `Default` and no
    fallthrough to `Privileged` — that absence is the privilege-escalation guard.

14. **Every byte responder calls `insert_content_type_headers`.** Tenant bytes are served
    from the same origin as the admin UI, so a caller-supplied markup content type rendered
    inline would execute script in the admin plane's origin. `SANDBOX_CSP` must **never**
    gain `allow-same-origin` or `allow-scripts` — either one defeats the protection
    completely, and a codified test pins the exact string. The classifier is structural
    (every `*/*+xml` essence), not an enumeration; the first version of this fix was broken
    by `application/rss+xml`.

15. **All browser-facing URL prefixes route through `crate::base_path`.** `DRUST_BASE_PATH`
    (default `/drust`; the Docker image ships `""`) is the external mount the proxy strips
    before axum, so every outbound string must re-add it — `.rs` uses
    `crate::base_path::base()` for URLs and `cookie_path()` for `Set-Cookie`, templates use
    `{{ crate::base_path::base_path() }}`. Never hardcode `/drust` in a redirect `Location`,
    cookie `Path`, OAuth `redirect_uri`, or admin `href` / `action` / `fetch`. Default mode
    is byte-identical, so the suite will not catch a regression; `tests/base_path_root.rs`
    proves empty mode.

16. **Mode B keeps every HTTP request small by design.** tus chunking exists precisely so
    each request stays under the ingress limit — never raise a body limit to accommodate a
    large upload.

17. **There are three parallel deployment targets, and a release is not done until all three
    were re-checked.** Bare-metal systemd (this host), Docker Compose, and the k3s Helm chart
    under `deploy/helm/drust/`. They share the binary and nothing else: unit files, timers,
    volume paths, env, ingress and the operational sidecars are written three times. A change
    that lands in one silently diverges from the other two, and no test sees it — the suite
    does not run under systemd, does not build the image, and does not render the chart.
    v1.58 is the worked example: `_trash` expiry lived only in `deploy/drust-janitor.timer`,
    so for every Docker and k3s user nothing swept `_trash` at all, and that was found by a
    code reviewer reading an unrelated fix rather than by any release step. The per-release
    checklist is in `.claude/rules/build-deploy.md` §Three deployment targets.

18. **A search-index shadow head is writable only via its own sync triggers; its module
    internals only via the module.** An fts5 index HEAD (`_system_search_fts$<coll>$<name>`)
    accepts INSERT/UPDATE/DELETE only when the authorizer `accessor` is one of its
    `_system_search_`-prefixed sync triggers — top-level SQL (accessor `None`) is denied, so
    no caller can poison an index by hand; the module's shadow internals are allowed by name
    but only because `SQLITE_DBCONFIG_DEFENSIVE` (on every writer open) refuses direct SQL on
    them. Head-vs-internal is decided by `pragma_table_list.type` (`virtual` vs `shadow`),
    never by name suffix.

19. **Publishing is never SILENT, and every after-the-fact door into the `public` bucket
    stays service-only.** A public object is served by Caddy straight out of Garage and never
    reaches drust, so publishing is a permanent escape from every per-file gate. The three
    stations with a caller identity share one decision (`files::enforce_upload_visibility` —
    Mode-A multipart, tus `create`, and edge `put-file` via `enforced_put_file`); the fourth,
    host-admin `/admin/files/upload`, is owner-only management plane. What the shared decision
    enforces since v1.64 (#974) is **two gates on an explicit publish**: the tenant-wide
    `upload` file cap (outer, unchanged) AND a per-prefix `public_upload_roles` grant on the
    LONGEST `_system_file_policy` rule matching the upload's declared `path` (inner) — the
    same `longest_match` the read side uses, so "which rule governs this file" has one answer.
    A **non-service caller that says nothing gets `private`**, never the station default, and
    one asking for `public` without a grant is REFUSED with `FILE_PUBLIC_UPLOAD_DENIED`,
    never silently downgraded. Deny-by-default in all four directions (no matching rule, no
    grant on the matching rule, an unreadable registry, an unfiled upload with no root grant),
    which is why the release ships a one-time grandfather grant on each existing tenant's root
    rule. The edge station declares no `path`, so only the ROOT rule can ever grant it. Two
    earlier shapes were replaced and neither shipped: v1.63.0's blanket refusal
    (`FILE_VISIBILITY_SERVICE_ONLY`, deleted — it put publishing behind the god-mode service
    key) and v1.63.1's "explicit is always honored" (no lever between "may upload" and "may
    publish"). Service short-circuits before the registry is read, so a broken registry never
    blocks the recovery path. The two after-the-fact doors,
    `PATCH` set-visibility and `sign`, remain **service-only** — `sign` because a signed URL
    is redeemed with no caller at all (`signed_bytes.rs`), so authorization can only happen at
    mint. The per-station service DEFAULT deliberately differs — Mode-A `public`, tus
    `private` — and "unifying" them would publish every existing tus upload that omits the
    field; a test pins each direction.

20. **File reads are gated twice, and the two file evaluators stay in lockstep.** Outer gate
    = `file_caps_layer`'s per-verb cap; inner gate = the `_system_file_policy` prefix
    registry, where a "folder" is a prefix of `_system_files.path` and the LONGEST match
    wins. `authorize_file` (single file: `get_one`, bytes, `delete_one`, edge `get-file`)
    and `build_file_list_filter` (the `list` SQL) must admit exactly the same rows — the
    invariant-12 rule, second pair — pinned by the `tests/file_policy_expression.rs` corpus.
    Four things fail CLOSED and must stay that way: no matching prefix ⇒ owner-scoped
    (`uploader == $auth`); a clause-less row (`owner_scoped=0`, no select clause,
    `public_read=0`) DENIES rather than meaning "unrestricted"; an unreadable registry or an
    unserializable row refuses; and a hidden file answers **404**, never 403. Prefix
    matching is a **binary byte range** (`path >= ?p AND path < ?p⁺`) — never `substr`
    (SQLite counts characters, Rust counts bytes, and a CJK prefix then fails OPEN) and
    never `LIKE` (`%`/`_` are ordinary path characters and `LIKE` is case-insensitive) — and
    the root/default arm must spell out `path IS NULL OR …`, because `NOT (NULL >= ?)` is
    NULL, not TRUE. **Gate polarity**: the three dual-mounted verbs (upload / stream /
    delete) are split into an admin twin (`admin_tfiles_*`, explicit bypass) over a shared
    `_inner`, and a data-plane handler taking `RequiredAuthCtx` that refuses with
    `AUTH_CTX_MISSING`. "Extension absent ⇒ treat as service" is permitted **only** for
    uploader stamping, never for a read or delete gate. Policy reads ride the connection the
    handler already opened (REST `tenant_db::open_read`, MCP/edge the pooled reader) — never
    a second open, never `get_or_create` on a read path, and never under the read-only
    authorizer, which would deny its own `_system_*` read.

## Where the rest lives

Mechanism moved into path-scoped rule files. Each loads automatically when you read a file
matching its `paths:` glob, and costs nothing otherwise. If you suspect a rule exists before
the glob fires, just read the file.

| File | Fires on | Covers |
|---|---|---|
| `.claude/rules/build-deploy.md` | `Dockerfile`, `Makefile`, `Cargo.*`, `.github/workflows/**`, `deploy/**` | build toolchain, test-group harnesses + the coverage gate, systemd sandbox, Caddy duties, version/lockfile sync, release gates |
| `.claude/rules/migrations-boot.md` | `src/db/**`, `src/main.rs`, `src/storage/meta.rs` | migration idempotency, one-shot backfills, STRICT rebuild, boot scans |
| `.claude/rules/auth-tenancy.md` | `src/auth/**`, `src/oauth/**`, `src/mgmt/{tenant_authz,admin_team,cli_device,oauth_login,quota_admin,tenant_cap}.rs`, `src/mgmt/tenants/**`, `src/tenant/{auth_cache,oauth_routes,admin_user_routes}.rs` | bearer CTE layout, auth cache, roles, end-user auth, OAuth, CLI device flow, quota tier and tenant cap |
| `.claude/rules/write-path.md` | `src/tenant/records*.rs`, `src/mcp/tools/**`, `src/storage/{record_history,quota,schema}.rs`, `src/query/**`, `src/functions/enforce.rs` | caps matrix, owner/RLS mechanics, batch and upsert, record-history internals, quota measurement, CHECK constraints |
| `.claude/rules/mcp-surface.md` | `src/mcp/{handler,resources,prompts,http_registry,server}.rs` | tool/resource/prompt surface, URI parser hardening, why credential-bearing reads stay behind tools |
| `.claude/rules/storage-files.md` | `src/storage/{files,visibility,garage,file_policy,file_path}.rs`, `src/tenant/{uploads/**,file_caps.rs,file_policy_routes.rs,mod.rs}`, `src/mgmt/{public_files,tenant_files}.rs` | Garage integration, upload/delete ordering, file caps, tus, Files RLS (prefix registry, the two file evaluators, the publish decision), the stored-XSS defense |
| `.claude/rules/background-jobs.md` | `src/{functions,cron,rpc,safety}/**`, `src/tenant/{webhook*,egress,rooms}` | edge functions, cron semantics, stored-RPC guards, webhooks, egress, audit writer, SSE |
| `.claude/rules/admin-ui.md` | `src/mgmt/**`, `build.rs`, `build_support/**`, `locales/**`, `themes/**` | 頁面解剖學 (the six `_ui.html` macros and the **eight `build.rs` gates that will fail your build**), `script_json`, i18n, theming |

## Directory map

See [`docs/architecture.md`](docs/architecture.md) — an auto-generated per-file index of what
each `.rs` declares, imports, and is imported by. Rebuild with `bash docs/gen-architecture.sh`.

---
paths:
  - "src/functions/**"
  - "src/cron/**"
  - "src/rpc/**"
  - "src/safety/**"
  - "src/tenant/webhook_dispatcher.rs"
  - "src/tenant/webhook_resolver.rs"
  - "src/tenant/egress.rs"
  - "src/tenant/rooms/**"
---

# Background work: functions, cron, RPC execution, webhooks, egress, audit writer, realtime

Fires on work that runs *outside* a request handler, or that makes an outbound connection on the host's behalf.

## Edge functions (`src/functions/`)

Per-tenant user-uploaded `.wasm` (wasm32-wasip2 component) run in-process via wasmtime. Host API = the existing transport-agnostic `mcp/tools/{write,read}.rs` fns (`insert/update/delete-record`, `query-list`, `put-file`, `get-file-bytes`), so a function write fans out to SSE + webhooks for free — plus an 8th WIT host import `http-fetch`, **the ONLY host op that reaches the public network**, gated by the per-tenant egress allowlist (`system=function`) + `PinnedPublicResolver` + a safety envelope (method allowlist, no auto-redirect, timeout / size / rate caps). WIT is the SoT (`sdk/edge-function-template/wit/world.wit`).

Isolation is **capability absence** + per-tenant `DrustMcp` + depth=1 (`functions: None`) + epoch & memory caps — not process-wide W^X. **The executor's host state is built with `functions: None` (`HostStateSeed::build_mcp`)** — restoring a dispatcher there reintroduces unbounded recursion; any new `DrustMcp` construction site must decide this field consciously.

> [!CAUTION]
> **The epoch budget is a CPU budget that must YIELD, and the memory cap is per-Store, not per-memory (v1.61, #932).** `arm_epoch_budget` arms a 1-tick deadline whose callback `Yield`s the Tokio worker every 100 ms tick and `Interrupt`s only when `timeout_secs × 10` ticks are spent — a single absolute deadline let a compute-only guest (no await points) pin its worker for the whole budget, starving every other future on this 2-core host. Expiry still raises `Trap::Interrupt`, so the Timeout classification is unchanged; the helper is **async-entrypoint-only** (`Yield` hard-errors on a sync wasm call). `MemLimiter` tracks ONE per-Store byte budget across all linear memories (a component holds one memory per core instance, so the old per-memory `desired > cap` multiplied the cap by N), a 1 M-element table budget, and caps instances/tables/memories at 64 (wasmtime defaults 10 000); `wasm_multi_memory` is off. A guest exceeding the entity caps fails at **instantiation**, not as a limiter denial — triage won't obviously point here.

Accepted losses: no retry; queue-full drops; loss-on-crash accepted; bad artifact → `422` at create. **No upload tool by design — REST multipart is the only ingest.**

### Caller-identity invoke (`{caller,enforce,invoke_gate}.rs`)

Execution identity is `CallerCtx` (`Privileged` | `Anon` | `User{user_id}`). `Privileged` (service invoke, event triggers, cron) keeps **god-mode on every authorization decision** — caps, `owner_field` filtering, RLS and file caps are all bypassed, and its host-op arms call the `mcp::tools` writers directly rather than going through `enforce.rs`. It is **not** exempt from row *validation*: quota, unknown-field, CHECK and — since v1.58 — `OWNER_FIELD_REQUIRED` all bind it, because that direct call lands in `insert_row_in_tx` where those checks live. Concretely, **a cron- or event-triggered function inserting into an owner-scoped collection MUST supply the owner field** (the host op neither supplies nor stamps it); before v1.58 such an insert silently minted an owner-less orphan row that no user could ever read. `Anon`/`User` run **capability-gated through the reusable enforcement core** (`enforce.rs`) on EVERY host op — caps + `owner_field` stamp/filter by `read_scope` + RLS USING/CHECK + per-verb file caps, the SAME decisions REST makes. Architectural debt: `enforce.rs` is a PARALLEL implementation reusing REST primitives; the REST handlers were deliberately not refactored onto it and remain the regression oracle.

**No god-mode leak:** `CallerCtx` has **no `Default`** and no fallthrough to `Privileged` — anon/user invoke must construct a non-`Privileged` ctx. DiD ≥ 2: (1) the HTTP per-identity gate `invoke_gate_layer`, on the `/invoke` route only; (2) the executor re-asserts the flag against the freshly-read row before running (a flag flipped off between gate and run still fails closed).

## Cron (`src/cron/`)

5-field cron expressions (**UTC** — no seconds, no `@aliases`; croner-validated at create). Targets run at **`Privileged`/service identity**: functions via the synchronous `Executor::run_one` path (**NOT the event queue**), RPCs via the existing read/write executors. An RPC declaring `:user_id` is refused at create AND at fire (`CRON_RPC_USER_ID`).

Scheduler = in-process minute tick over an invalidate-on-write in-memory index (`CronIndex` — every config mutation reloads after commit; the boot scan repopulates via the reader lane, **never creating tables**). Each fire **re-asserts the fresh job row** (gone / inactive / schedule-changed → silent skip, fail closed) and **overlapping fires of the same job skip** with a `skipped_overlap` run row; missed minutes (downtime) are skipped, never replayed. `DRUST_CRON_CONCURRENCY` is acquired **after** the overlap gate so skips never wait.

## Stored RPC execution (`src/rpc/`)

`mode='read'` (default) is SELECT-only, validated at create time under the read-only authorizer. `mode='write'` bodies run multi-statement INSERT/UPDATE/DELETE through `exec_write::run_write_rpc` (SAVEPOINT + `attach_writable_authorizer` — DDL, transactions, and `_system_*` writes denied). `call_rpc` stays on the read-only executor regardless of mode, so REST, the admin playground, and cron are the only write-RPC execution surfaces.

**A stored RPC's SQL is tenant config, and an `anon_callable` RPC returns its execution errors to an UNAUTHENTICATED caller — so never stringify a rusqlite error with `to_string()` on this path.** rusqlite reports a `conn.prepare` failure as `SqlInputError`, whose `Display` is `"{msg} in {sql} at offset {n}"` — the whole statement, literals included. Schema drift (`drop_field` on a collection an older RPC still names) turns that into a 400 that hands anon the RPC body, the exact text `redact_rpc_obj` / `redact_cron` strip from the `rpcs` + `cron` resources for a *service* caller. **Both** `classify`s — read (`src/query/executor.rs`) and write (`src/rpc/exec_write.rs`) — go through `crate::error::sqlite_error_without_sql`, which keeps `msg` + `offset` and drops the SQL; they also *classify* on that redacted text, so a plain SQL error can no longer be promoted to `Forbidden` by its own statement text mentioning `sqlite_master`. Authorizer denials are untouched (`SQLITE_AUTH` → `SqliteFailure`, never `SqlInputError`).

**Guard `RPC_ANON_OWNER_SCOPED` (`src/rpc/prepare.rs`)** refuses an `anon_callable=true` RPC over a **row-access-restricted** collection — drust does not rewrite stored-RPC SQL, so the body would otherwise return/mutate every user's rows (owner_field) or the policy-hidden rows (RLS) for an anon caller. Two restriction shapes: an **owner-scoped** collection is refused unless the RPC declares `:user_id`; a **policy-protected** collection (any `*_policy_json`, even with `owner_field=NULL`) is refused unconditionally — `:user_id` does NOT exempt the policy case, since a policy need not key on the caller. Enforced at **config time** across four parallel sites (defense-in-depth): create, update (effective-value merge), `set_owner_field`, and the policy-attach guard; a startup migration neutralizes pre-guard legacy rows fail-closed. **The runtime `call_rpc` path is NOT re-checked — config-time is the enforcement boundary.** (A review found a real `update_rpc` bypass here; that is why the parallel sites exist.)

## Webhooks + SSRF

`tokio::spawn` per delivery, HMAC-SHA256-signed POST, 4 attempts (+0/+1/+5/+30s, 10s each). 4xx terminal, 5xx/network retryable. No outbox; events lost on mid-POST crash (accepted). Secret returned plaintext exactly once; PATCH cannot rotate (rotate = delete + create).

**Fan-out is bounded on both axes (v1.61, #932).** A process-wide delivery `Semaphore` (`delivery_permits()`, `DRUST_WEBHOOK_MAX_CONCURRENCY`, default 64) caps deliveries in flight — the permit is `acquire_owned().await`ed **inside** the spawned task, NEVER in the fan-out loop, because the loop must stay await-free between the egress snapshot and the spawn (see the SSRF window note above). Bounding delays, never drops. A per-tenant registration cap (`DRUST_WEBHOOK_MAX_PER_TENANT`, default 32) is enforced by the shared `webhook_routes::check_registration_cap`, called inside the writer closure of **all three** create faces — REST `create_handler`, MCP `create_webhook`, admin-UI `tenant_webhook_create_form` — each of which has its own duplicated INSERT into `_system_webhooks` (the first cut capped only MCP; a cap on one INSERT site is no cap at all). REST maps the sentinel to `409 WEBHOOK_LIMIT_EXCEEDED`.

> [!WARNING]
> **Every host-outbound HTTP path MUST pass BOTH `check_egress` AND `PinnedPublicResolver`, per attempt, fail-closed — they are orthogonal and dropping either reopens SSRF.** `check_egress(allowlist_json, system, origin)` is pure: dispatch-on-system, EXACT-origin match (no subdomain / scheme confusion), unknown system or empty allowlist → deny. `PinnedPublicResolver` filters RFC1918 / loopback / link-local **at every dispatch attempt**; the register-time `check_url` gate is retained (defense in depth — drop either and pre-patch rows re-open the hole). Loopback targets are opt-in (`DRUST_WEBHOOK_ALLOW_LOOPBACK` or a debug build). Parser-differential lesson: the origin actually dialled must be the RE-EMITTED normalized origin, and the hand-written normalizer must never be LOOSER than the URL crate that dials.

The webhook egress gate reaches "per attempt" through **two** reads, and only one of them is live. The retry loop in `deliver_inner` re-reads the allowlist before **attempts 2..n**; a denial there is TERMINAL (`DeliveryError::EgressRevoked`, recorded with the same `egress_not_allowlisted: <url>` reason the fan-out gate writes). Before v1.58 that read did not exist, so an origin removed mid-flight kept receiving POSTs for the rest of the ~36 s schedule. **Attempt 1 is gated by `dispatch_many`'s fan-out SNAPSHOT, not by a live read** — a deliberate trade: a per-delivery read would cost one meta open per ROW of a batch, which is the exact cost the per-batch read exists to avoid (`tests/batch_webhook_fanout.rs` pins the count). So attempt 1 carries a residual window — snapshot → spawn → `resolve_public` → POST — that is bounded only by DNS latency. It is bought back where it is free: the fan-out defers denied subscriptions' `record_failure` writes until after every delivery is spawned, so a writer mutex held by a concurrent batch cannot sit inside that window. Anything that adds an attempt must stay inside the retry loop or re-check for itself, and anything that adds an `.await` between the snapshot and the spawn widens a real hole.

Two reads that both fail closed are still not interchangeable: `egress::read_egress_allowlist` collapses every failure into deny-all `'[]'` and is for config/boot surfaces (the one-time backfill needs it to see soft-deleted rows), while `egress::try_read_live_egress_allowlist` — what the dispatch gate uses — is three-way. It filters `deleted_at IS NULL` (a soft-delete leaves `egress_allowlist_json` intact, so a reader without the predicate keeps authorizing a deleted tenant's egress) and distinguishes *unreadable meta* from *denied*. An unreadable meta must never end a retry chain: it fails closed for that attempt only, because a terminal `EgressRevoked` there would lose the event permanently and write `egress_not_allowlisted` against an origin that IS allowlisted.

## Audit writer (`src/safety/audit_db.rs`)

`AuditWriter` (`OnceLock`). Writer task drains a `mpsc::channel(1000)`, batches INSERTs every 100ms or 100 rows. Channel-full drops + counter + sampled `tracing::warn!`.

> [!WARNING]
> **The retention pass runs inside the writer task and must never stop it draining.** Until v1.58 the DELETE and the monthly VACUUM ran to completion inside the same `select!` arm that owns `rx.recv()`, so the bounded channel filled and inbound rows were dropped — 962 measured in two days on the live host, and the rows lost are exactly the ones worth keeping (denials, SSRF blocks, admin mutations). Now: the DELETE is chunked at `RETENTION_DELETE_CHUNK` rows with a `try_recv` drain and a `yield_now` between chunks, and the VACUUM — which cannot be chunked — is offloaded to `spawn_blocking` while the loop keeps receiving into the in-memory buffer. Anything added to that pass must preserve both properties.

Commands arriving mid-pass are parked by `stash_cmd`: `Insert` buffers in memory, and **`SetMeta` is deferred, not dropped** — the retention task sends `last_vacuum_ts` immediately behind the retention command, so losing it silently downgrades the monthly VACUUM to a daily one. **The stash is bounded at `STASH_MAX_ENTRIES` (50k) and only the VACUUM phase uses it**: between DELETE chunks the writer still owns a live, idle connection, so what it drains is flushed straight through and the DELETE phase costs no resident memory. Overflow drops the entry, counts it in `STASH_DROPPED`, and surfaces through the same `dropped_total()` and `drust_audit_drops_total` as a channel-full drop — inbound volume is caller-driven, so an unbounded stash would trade the old bounded loss for an OOM. The offloaded VACUUM owns the connection for its duration; the writer holds a throwaway in-memory placeholder and reopens from `Connection::path()` if the blocking task never hands the real one back. The write connection caps `journal_size_limit` at 64 MiB, because SQLite never shrinks a WAL grown by a full-database rewrite.

`DRUST_AUDIT_LOG_RETENTION_DAYS` (LOG = access log, host-wide) and `DRUST_AUDIT_HISTORY_RETENTION_DAYS` (HISTORY = record snapshots, per-tenant) are **deliberately independent windows** — do not collapse them.

## Realtime

**WS rooms** (`src/tenant/rooms/`): subscribe is open to anon / user / service. Publish is service-only unless the opt-in tenant flags `allow_user_publish` / `allow_anon_publish` are set, gated through the shared `check_publish_allowed` (`rooms/policy.rs`). MCP `broadcast` stays service-only by MCP dispatch **regardless of these flags** — defense in depth ≥ 2.

> [!CAUTION]
> **Anon SSE access requires `realtime_enabled AND anon_caps[select]`** (and any select policy) — opening one without the other is a side-channel leak. The `subscribe` handler captures caps + the select-policy ONCE at connect, so **revoking any of them must `bus.evict_collection` to drop in-flight subscribers**, not merely invalidate the schema cache (which only affects the next connect). Order is always `schema_cache.invalidate` BEFORE `bus.evict_collection`. ANY new write path that reduces anon read access to a realtime collection MUST evict. When a select policy is active for an anon subscriber, `Deleted{id}` events are **dropped** (id-only, can't be policy-evaluated against the gone row) — passing them leaks deletion id/timing for policy-hidden rows.

## Provenance

Extracted from CLAUDE.md "Background work", the edge-function / cron / stored-RPC bullets of "Tools & endpoints", the `meta_logs.sqlite` bullet, and the SSE / `functions: None` invariants, during the 2026-08-02 restructure.

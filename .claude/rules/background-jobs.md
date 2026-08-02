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

Accepted losses: no retry; queue-full drops; loss-on-crash accepted; bad artifact → `422` at create. **No upload tool by design — REST multipart is the only ingest.**

### Caller-identity invoke (`{caller,enforce,invoke_gate}.rs`)

Execution identity is `CallerCtx` (`Privileged` | `Anon` | `User{user_id}`). `Privileged` (service invoke, event triggers, cron) keeps **god-mode, byte-for-byte unchanged**; `Anon`/`User` run **capability-gated through the reusable enforcement core** (`enforce.rs`) on EVERY host op — caps + `owner_field` stamp/filter by `read_scope` + RLS USING/CHECK + per-verb file caps, the SAME decisions REST makes. Architectural debt: `enforce.rs` is a PARALLEL implementation reusing REST primitives; the REST handlers were deliberately not refactored onto it and remain the regression oracle.

**No god-mode leak:** `CallerCtx` has **no `Default`** and no fallthrough to `Privileged` — anon/user invoke must construct a non-`Privileged` ctx. DiD ≥ 2: (1) the HTTP per-identity gate `invoke_gate_layer`, on the `/invoke` route only; (2) the executor re-asserts the flag against the freshly-read row before running (a flag flipped off between gate and run still fails closed).

## Cron (`src/cron/`)

5-field cron expressions (**UTC** — no seconds, no `@aliases`; croner-validated at create). Targets run at **`Privileged`/service identity**: functions via the synchronous `Executor::run_one` path (**NOT the event queue**), RPCs via the existing read/write executors. An RPC declaring `:user_id` is refused at create AND at fire (`CRON_RPC_USER_ID`).

Scheduler = in-process minute tick over an invalidate-on-write in-memory index (`CronIndex` — every config mutation reloads after commit; the boot scan repopulates via the reader lane, **never creating tables**). Each fire **re-asserts the fresh job row** (gone / inactive / schedule-changed → silent skip, fail closed) and **overlapping fires of the same job skip** with a `skipped_overlap` run row; missed minutes (downtime) are skipped, never replayed. `DRUST_CRON_CONCURRENCY` is acquired **after** the overlap gate so skips never wait.

## Stored RPC execution (`src/rpc/`)

`mode='read'` (default) is SELECT-only, validated at create time under the read-only authorizer. `mode='write'` bodies run multi-statement INSERT/UPDATE/DELETE through `exec_write::run_write_rpc` (SAVEPOINT + `attach_writable_authorizer` — DDL, transactions, and `_system_*` writes denied). `call_rpc` stays on the read-only executor regardless of mode, so REST, the admin playground, and cron are the only write-RPC execution surfaces.

**Guard `RPC_ANON_OWNER_SCOPED` (`src/rpc/prepare.rs`)** refuses an `anon_callable=true` RPC over a **row-access-restricted** collection — drust does not rewrite stored-RPC SQL, so the body would otherwise return/mutate every user's rows (owner_field) or the policy-hidden rows (RLS) for an anon caller. Two restriction shapes: an **owner-scoped** collection is refused unless the RPC declares `:user_id`; a **policy-protected** collection (any `*_policy_json`, even with `owner_field=NULL`) is refused unconditionally — `:user_id` does NOT exempt the policy case, since a policy need not key on the caller. Enforced at **config time** across four parallel sites (defense-in-depth): create, update (effective-value merge), `set_owner_field`, and the policy-attach guard; a startup migration neutralizes pre-guard legacy rows fail-closed. **The runtime `call_rpc` path is NOT re-checked — config-time is the enforcement boundary.** (A review found a real `update_rpc` bypass here; that is why the parallel sites exist.)

## Webhooks + SSRF

`tokio::spawn` per delivery, HMAC-SHA256-signed POST, 4 attempts (+0/+1/+5/+30s, 10s each). 4xx terminal, 5xx/network retryable. No outbox; events lost on mid-POST crash (accepted). Secret returned plaintext exactly once; PATCH cannot rotate (rotate = delete + create).

> [!WARNING]
> **Every host-outbound HTTP path MUST pass BOTH `check_egress` AND `PinnedPublicResolver`, per attempt, fail-closed — they are orthogonal and dropping either reopens SSRF.** `check_egress(allowlist_json, system, origin)` is pure: dispatch-on-system, EXACT-origin match (no subdomain / scheme confusion), unknown system or empty allowlist → deny. `PinnedPublicResolver` filters RFC1918 / loopback / link-local **at every dispatch attempt**; the register-time `check_url` gate is retained (defense in depth — drop either and pre-patch rows re-open the hole). Loopback targets are opt-in (`DRUST_WEBHOOK_ALLOW_LOOPBACK` or a debug build). Parser-differential lesson: the origin actually dialled must be the RE-EMITTED normalized origin, and the hand-written normalizer must never be LOOSER than the URL crate that dials.

Known gap, fixed in v1.58: the webhook egress check runs once per **event**, not per **attempt**, so 3 retries continue after an origin is removed from the allowlist.

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

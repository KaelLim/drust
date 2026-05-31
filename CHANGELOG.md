## v1.32.2 — 2026-05-31

### Performance

- **D8: WS publish serialize-once.** Pre-v1.32.2 each WS subscriber
  received broadcast frames via `(*rmsg.payload).clone() +
  serde_json::to_string(&ServerMessage)` — N subscribers × K-byte
  payload meant N × (deep-clone + serialize) per publish. The whole
  point of `Arc<Value>` on `RoomMessage` was defeated by the per-recv
  envelope rebuild. Now `publish_into_bus` pre-serializes the full
  `ServerMessage::Message` envelope into `bytes::Bytes` once at
  publish time; `ws.rs::send_json`'s Message branch forwards bytes
  verbatim. Lagged branch unchanged (per-room per-subscriber error
  envelope can't be pre-serialized; it needs the room name).

  Wire byte-identical to subscribers: serialization goes through the
  same `ServerMessage` Serialize impl that the pre-D8 `send_json` was
  invoking — pinned by a new unit test
  (`tests/bench_ws_publish.rs` and
  `src/tenant/rooms/rest.rs::tests::d8_frame_bytes_is_byte_identical_to_legacy_send_json`).

  Synthetic bench numbers (subs × payload KB, µs/publish):

  | subs × KB | baseline | D8     | improvement |
  |-----------|----------|--------|-------------|
  | 10 × 1    | 1,310    | 289    | −77.9%      |
  | 10 × 16   | 13,738   | 2,140  | −84.4%      |
  | 10 × 64   | 43,276   | 5,945  | −86.3%      |
  | 100 × 1   | 10,422   | 1,196  | −88.5%      |
  | 100 × 16  | 103,316  | 2,964  | −97.1%      |
  | 100 × 64  | 316,784  | 6,528  | −97.9%      |
  | 1000 × 1  | 71,475   | 4,948  | −93.1%      |
  | 1000 × 16 | 793,202  | 6,520  | −99.2%      |

  Post-D8 per-publish time is roughly O(1) in N — exactly as expected
  when receivers do no per-message serialize work. 1000×64KB omitted
  from the bench (~64MB per-iter alloc pushed allocator into useless
  regime; 1000×16KB + 100×64KB give the same signal).

### Notes

- Bench (`tests/bench_ws_publish.rs`) is `#[ignore]`'d so does not
  run on regular `cargo test`. Run with
  `cargo test --test bench_ws_publish -- --ignored --nocapture`.
  WS-level bench is impossible because `tests/rooms_ws.rs` is all
  `#[ignore]`'d due to tokio-rs/tokio#2374 (per-test runtime
  starvation at <10 concurrent clients); synthetic at the bus +
  send-equivalent layer measures the exact work D8 eliminates.
- Tests: 444 lib pass (+1 D8 wire-identity), 4 rooms_policy pass,
  34 tenant::rooms lib pass. 41 pre-existing integration failures
  unchanged (deferred to v1.32.5).

---

## v1.32.1 — 2026-05-31

### Changed

- **D1: JSONL audit dual-write retired.** `bearer_auth_layer` no
  longer routes through `AuditLog::append` (which was running
  `write_all + flush().await` per tenant request to daily `.jsonl`
  files). Direct path is now `audit_db::try_send` — the documented
  SoT since v1.25.2 has been adopted everywhere. `AuditLog`,
  `AuditWriterHandle`, the JSONL writer task, `TenantAuthState.audit`
  field, and `audit_handle.join()` in `main.rs` all deleted.
  Pre-existing `audit-YYYY-MM-DD.jsonl` files left on disk; operator
  may delete manually. 10 test files adapted to read from
  `meta_logs.sqlite` via dedicated-thread `AuditWriter` init pattern
  (see `tests/common/oauth_helpers.rs::TEST_AUDIT_DB`).

- **D2: RoomBus / EventBus key types → `Arc<str>` (nested DashMap).**
  Prior shape allocated `(String, String)` per publish call (tenant +
  collection/room) for DashMap lookup. `publish()` is the per-event
  hot path; alloc × 2 per event was wasted on every record CRUD +
  every broadcast publish. Switched to
  `DashMap<Arc<str>, DashMap<Arc<str>, Sender>>`: reads use `&str`
  directly, writes alloc `Arc` only on first insert. F7
  entry-guard-across-subscribe invariant preserved on both buses
  (both outer + inner guards held across `.subscribe()`). Side win:
  `tenant_channel_count` / `tenant_subscriber_count` dropped from
  O(N_total_channels) → O(N_tenant_channels).

- **D3: Stats sampler uses TenantRegistry reader pool + batched meta
  UPDATEs.** `sample_one` previously opened a fresh `Connection` per
  tenant per cycle (~1-3 ms cold open × N tenants); now uses the
  existing reader pool (PRAGMA already applied). `sample_all` batches
  all N `UPDATE meta.sqlite` statements in one
  `BEGIN IMMEDIATE / COMMIT` transaction — meta-lock acquisitions
  per cycle from N+1 to 2. Per-tenant sampling errors logged + skipped,
  batch commits what succeeded.

- **D4: `list_handler` drops redundant `collection_exists` reader.**
  `require_dml_cap` already loads the schema (via cache); successful
  return implies the collection exists. The separate `collection_exists`
  reader hit + an inner `COLLECTION_NOT_FOUND` 404 branch (already dead
  — outer 404 covered all cases) both removed. Same 200/404 outcomes
  + bodies.

- **D5: `bearer_auth_layer` lazy audit field capture.** `path`,
  `tenant`, and `hint` String allocs deferred to the audit-emit
  branch; `Method` and `Uri` clones stay pre-`next.run` (both cheap —
  `Uri` is internally Arc-shared). Naming split (`*_captured` vs
  `*_for_audit`) makes the borrow-lifecycle constraint explicit. Win
  is borrow-clarity + savings on test paths where `WRITER.get()` is
  unset; production alloc count unchanged in current emit-always
  paths.

- **D6: Session cookies respect `DRUST_DEV_NO_SECURE_COOKIES`.**
  Consistency with theme / locale + per-tenant OAuth cookies, which
  already honor this env var for HTTP-only dev runs. Both
  `build_session_cookie` AND `clear_session_cookie` fixed (the latter
  would have prevented logout in dev otherwise — set with
  non-`Secure`, browser rejects `Secure` clear over HTTP). Prod
  unaffected (env unset → `Secure` flag stays).

### Fixed

- **D7: Per-tenant OAuth multi-tab redirect_uri confusion.** Prior
  shape round-tripped frontend `redirect_uri` via a separate cookie
  (`drust_t_oauth_redirect_uri`). Two parallel OAuth starts in
  different tabs (each for a different allowlisted frontend) had the
  later cookie write clobbering the earlier — the first callback then
  redirected to the wrong frontend (still allowlisted, so no token
  leak, just wrong destination). New `TenantOauthStateToken` embeds
  `redirect_uri` + HMAC-SHA256 envelope
  (`[16B nonce][2B u16 len][N B uri][32B HMAC]`, base64url encoded;
  constant-time HMAC compare via `subtle::ConstantTimeEq`). Callback
  decodes → verifies HMAC → re-checks against per-tenant allowlist
  (TOCTOU-safe; defense in depth — 4 gates total: cookie match, PKCE,
  HMAC, URI allowlist). Admin OAuth (`src/mgmt/oauth_login.rs`)
  untouched — added a separate type rather than mutating
  `OauthStateToken`. Per-process secret (32 bytes random at boot,
  matching `url_sign_secret` pattern); restart invalidates in-flight
  flows (acceptable given 5-min PKCE TTL).

### Notes

- Wire-identical across REST, MCP, audit-DB consumers. No DB
  migration, no env var addition, no admin UI change.
- `cargo test --lib` 434 → 443 (+9 D7 unit tests).
- Pre-existing 41 integration test failures unchanged; v1.32.1
  introduced 0 new failures, fixed 0 (test-harness rot deferred to
  v1.32.5 / v1.33 — see task #722).

---

## v1.32.0 — 2026-05-31

### Security

- **A1: RPC `:user_id` user-token spoofing closed (CRITICAL).** Prior
  to this release, any User-token caller could supply
  `{"user_id":"<victim>"}` in an RPC body and the auto-bind would
  honor it (condition `!body_map.contains_key("user_id")` skipped
  overwrite). This let any user impersonate any other user on any
  RPC declaring a `:user_id` param. Now the auto-bind always
  overwrites for User tokens — both read and write arms. The Anon
  arm was also tightened: if an RPC declares `:user_id`, Anon
  callers are rejected categorically (previously body-supplied
  user_id could thread into SQL). Service tokens unchanged. Four
  regression tests in `tests/rpc_user_id_spoof.rs` cover read/write
  × User/Anon spoof attempts.

- **A2: OAuth id_token iss/aud/exp validation.** The Google id_token
  decode path skipped signature verification per OIDC §3.1.3.7
  (confidential client + TLS-trusted token endpoint), but the same
  section also requires iss/aud/exp claim checks — which were
  missing. Added: `iss ∈ {accounts.google.com,
  https://accounts.google.com}`, `aud == client_id`, `exp > now`.
  4 unit tests in `src/oauth/google.rs::tests`. Closes the
  hijack path where a misconfigured `token_endpoint` or attacker
  with a Google project + allowlisted email could log in as any
  drust admin.

- **A3: webhook resolver IPv6 + CGNAT private-range close.** Added
  `100.64.0.0/10` (RFC 6598 CGNAT shared address space), `::/128`
  (IPv6 unspecified), `::ffff:0:0/96` (IPv4-mapped wildcard via
  recursion into IPv4 private check), and `2001:db8::/32` (RFC 3849
  docs prefix) to `is_private_ip`. Applied by `PinnedPublicResolver`
  at every webhook dispatch attempt. 2 unit tests.

- **A4: EventBus subscribe race close (F7 mirror).** `EventBus::
  subscribe` now holds the DashMap entry guard across `tx.
  subscribe()`, mirroring the v1.31.2 F7 fix already applied to
  `RoomBus`. Latent — no user report; structural fix prevents
  parallel `evict_collection` from orphaning a freshly-subscribed
  receiver. 50-subscriber × 200ms stress test mirrors the bus.rs
  F7 test shape.

### Cleanup

- **B1: Fix 5 cargo warnings.** Deleted `CollectionsPage.tenant_id`
  + `WebhookFailureRow.id` (unused fields), dropped 2 redundant
  `mut` in `admin_team.rs`, raised `DryRunQuery` + `DryRunQs`
  visibility to `pub` (fixes `private_interfaces`). `cargo check`
  is now warning-free for Rust code (i18n build.rs orphan warnings
  retained as soft signal).

- **B2: Drop tokio-test dev dep.** Single call site in
  `src/tenant/mod.rs` converted from `tokio_test::block_on` to
  `#[tokio::test]`. Cargo.toml `[dev-dependencies]` no longer
  lists `tokio-test`.

- **B3: Backup restore audit row.** Restore handler now emits an
  `admin.backup.restore` audit row with archive filename + restore
  destination — closes the LOW-severity audit gap for the most
  destructive admin op. Mirrors the v1.31.3 F15 admin_rooms.rs
  audit pattern.

### Observability

- **C1: `/admin/_metrics` Prometheus endpoint.** Admin-session-gated
  GET endpoint exposing 5 metrics:
  - `drust_audit_drops_total` (counter — audit channel-full drops)
  - `drust_bearer_denied_total{role,status}` (counter)
  - `drust_webhook_attempts_total{result}` (counter)
  - `drust_ws_connections_active` (gauge — RAII guard)
  - `drust_tenant_db_bytes{tenant_id}` (gauge — refreshed at scrape)

  `prometheus = 0.13` with `default-features = false` (no process
  metrics / protobuf baggage). Closes ISO/IEC 27001 A.8.16
  (Monitoring) gap surfaced in the v1.31.9 review.

- **C2: GitHub Actions CI workflow.** `.github/workflows/ci.yml`
  runs `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --lib`, and `cargo audit` on every push to main + on
  manual dispatch. NEVER `--release` (LTO + codegen-units=1 hangs
  40+ min). Closes ISO/IEC 27001 A.8.8 (Vulnerability mgmt) gap.
  Passive — push not blocked on red.

### Tests (harness rot fixed incidentally)

- **admin_oauth integration suite restored.** v1.31.9 baseline had
  5 admin_oauth happy-path tests failing — root cause was
  `sessions.token_hash` column added in v1.29.5 but the test
  bootstrap didn't call `run_migrations`. INSERT failed at runtime,
  mapped to `oauth_provider_error` redirect (masked the real
  cause). Test harness now calls `run_migrations` in setup.
- **Audit polling in tests now reads SQLite, not JSONL.** v1.25.2
  retired JSONL writes but `poll_for_audit_row` still scanned for
  `audit-*.jsonl` files. Test harness now initializes a global
  audit writer + queries the SQLite DB.
- **Fake Google `aud` mirrors request client_id.** Previously
  hardcoded `"test-client-id"`, broke any test using a different
  client_id once A2 added `aud` validation. Now matches real OIDC
  behavior.

Pre-existing test-harness rot in 10 other suites (admin_index_routes,
admin_oauth_provider_handlers, admin_webhook_handlers, audit_ui_routes,
auth_admin_ui, mgmt_login, session, session_middleware, tenants_api,
tokens_api — 41 failing tests total) remains; production code
unaffected, scheduled for a dedicated harness-cleanup release.

### Notes

- No DB migration, no env var addition, no admin UI change visible
  to operators, no MCP tool signature change. Wire shape preserved
  across REST, MCP, admin UI, audit-DB.
- Spec: docs/superpowers/specs/2026-05-30-drust-v132-post-review-hardening-design.md

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
- CORS support on tenant routes. New `DRUST_CORS_ORIGINS` (comma-separated allow-list, empty = layer disabled). Applied OUTSIDE `bearer_auth_layer` so OPTIONS preflight is intercepted before auth. Subdomain wildcards (single `*`) supported — `https://*.tzuchi.org`, `http://localhost:*`; multi-`*` rejected at parse.
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

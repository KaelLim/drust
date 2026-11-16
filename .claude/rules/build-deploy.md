---
paths:
  - "Dockerfile"
  - "Makefile"
  - "Cargo.toml"
  - "Cargo.lock"
  - ".github/workflows/**"
  - "deploy/**"
  - "docker-compose*.yml"
---

# drust — build, test & deploy landmines

Fires on the build, packaging, CI, and deploy surface. Each item is a failure a green local build does NOT catch.

## Build

Building requires `clang` + `libclang`: the rusqlite `preupdate_hook` feature forces `libsqlite3-sys` into buildtime bindgen, which needs `libclang.so` and clang's builtin headers. The Dockerfile builder and CI install `clang libclang-dev` explicitly — a missing libclang fails the build with a misleading `stdarg.h not found`.

Bumping `Cargo.toml`'s version requires updating **and staging `Cargo.lock` in the same commit**: local builds silently fix a stale lock, so local stays green while Docker's `cargo build --locked` exits 101. Reproduce without compiling via `cargo metadata --locked`.

## Tests

Cost here is COMPILE, not run: every test binary statically links the drust lib + wasmtime, so a bare `cargo test <name>` compiles all of them and only filters what *runs* — the classic trap. Only `--test <name>` limits what compiles. #925 (spec `docs/superpowers/specs/2026-08-13-test-binary-consolidation-design.md`) cut that from 253 binaries to **38**: 24 merged group harnesses plus 14 targets that must keep a process to themselves. Measured on the mcp group, 20 binaries → 1 was 189s → 15s of build and 3.20 GB → 244 MB of `target/debug`, running the same 137 tests.

A group harness is `tests/g_<group>.rs` and contains nothing but `#[path = "<member>.rs"] mod <member>;` lines, one per former standalone file. **Member files are neither moved nor edited** — `#[path]` keeps their own `#[path = "helpers.rs"] mod helpers;` resolving exactly as before, which is why physically relocating them was rejected. Run a group with `make test-<group>` (= `cargo test --lib --test g_<group>`); `make groups` lists the harnesses with live member counts and the standalone count; `make test-lib` and `make test-all` are unchanged. Per-task workflow agents run `make test-lib` + the relevant group; only the final review runs `make test-all`.

The 24 groups are admin, audit, auth, batch, cli, collection, cron, egress, file, fts, functions, mcp, member, misc, policy, record, rooms, rpc, schema, storage, tenant, user, vector, webhook. **Membership is declared in the harness, never inferred from the filename** — the old `tests/<group>_*.rs` convention no longer decides anything, and four groups hold members that glob would miss (`audit` holds `audit3_*`, `file` holds `files_rls_*`, `record` holds `records_*`, `webhook` holds `webhooks.rs` and `webhooks_migration.rs`), while `misc` is the tail bucket for every prefix with fewer than three files. **Per-file membership is authoritative in the harnesses themselves** — one `#[path]` line per member in `tests/g_<group>.rs`, with `make groups` reporting the live counts and build.rs's ninth gate failing the build on anything unregistered. The plan `docs/superpowers/plans/2026-08-13-test-consolidation-925.md` holds the original table but is local-only provenance (`.gitignore` excludes `docs/superpowers/plans/`), so it is not present in a fresh clone and is not the operational reference.

Every harness carries `#![allow(clippy::duplicate_mod)]`. Its N members each `#[path]`-include `helpers.rs`, and inside one crate clippy reads that as N duplicate modules, so `cargo clippy --all-targets -- -D warnings` goes red without it. Deduplicating instead would mean editing member files, which is exactly what the consolidation forbids. Where members use the shared `common/` or `webhooks_common/` directories, the harness declares `mod common;` / `mod webhooks_common;` once for the whole crate and those members say `use crate::common;` instead of `mod common;` — that mechanical rewrite (7 files) is the *only* in-file edit #925 permitted (spec 鐵律 2).

These 14 keep their own binary and are run by name, `cargo test --test <name>`; no `make test-<group>` covers them:

| Standalone target | Why it is not merged |
|---|---|
| `admin_theme`, `cli_device_approval`, `config`, `deploy4_login_version`, `fts_deadline`, `query_executor`, `webhook_concurrency` | mutate process-global env via `std::env::set_var` / `remove_var` |
| `base_path_root` | the base path is a first-write-wins `OnceLock` |
| `admin_pat_bearer`, `admin_pat_reroll`, `tenant_quota_requests`, `audit_retention_no_drop`, `egress_http_fetch`, `rpc_v2_mutation` | merge collisions, backed out rather than edited (below) |

**A merge collision is resolved by backing the file out of its harness, never by touching the test.** No serialization, no rewritten assert, no reordered setup — the file gets its own `[[test]]` entry back and the commit message records why (spec 鐵律 1). All six backouts so far are one failure mode, and it is race-dependent rather than deterministic: `safety::audit_db::init_globals` installs the global audit `WRITER` into a first-write-wins `OnceLock`, so when two members of a binary each install their own audit SQLite file and then assert on rows in it, only the race winner's file ever receives anything while the loser polls an empty DB and panics. A file that asserts on audit-row *contents* cannot share a binary with a second installer; one that merely needs *a* writer to exist (`admin_oauth` / `tenant_oauth`, via `common::oauth_helpers::ensure_test_audit_writer`) can. Expect any future collision to be some other process-global of the same shape.

`[package] autotests = false` is what makes the explicit target list possible, and it removes cargo's `tests/*.rs` discovery: an unregistered file is then never compiled and never run, with no error, no warning and no missing-suite line — a failure mode that did not exist before #925. build.rs's **ninth gate** (`build_support/test_targets_gate.rs`, pure functions unit-tested through `src/lib.rs` under `cfg(test)`, same arrangement as `ui_gates.rs`) restores fail-loud: it walks the `#[path]` include graph out from the `[[test]]` roots across every top-level `tests/*.rs` and fails the build on `unregistered-test-file` (reachable from nothing), `double-registered-test-file` (a `[[test]]` target that is also a harness member) and `multi-harness-member` (one file included by two harnesses) — the last two both meaning the file's tests compile and run twice. Reachability is transitive, and an unregistered harness therefore cannot launder its members. The scan is comment- and string-literal-aware because a member commented out with `/* … */` once read as a live include. Its allowlist holds exactly one entry, `helpers.rs` (42 KB of shared harness, zero `#[test]` fns, previously linked as a binary for nothing); **growing that list is how a suite goes dark.**

So a new integration test has exactly two legal homes, and the build tells you when you picked neither: add `#[path = "my_test.rs"] mod my_test;` to the matching `tests/g_<group>.rs`, or give it its own `[[test]]` entry (`name` + `path`) in Cargo.toml. Take the second route only when the test needs its own process — env mutation, or a global `OnceLock` whose contents it asserts on.

Never `cargo test --release` — LTO + `codegen-units = 1` takes 40+ minutes. Sole exception: the argon2 timing test.

Two CI gates live **outside** `make test-all`: `cargo fmt --all --check` (CI's first gate) and `cargo clippy --all-targets -- -D warnings`.

The chart's `deploy/helm/drust/tests/render_test.sh` also reads files outside the chart: `deploy/compose-rustfs/{init.sh,public-read.json,drust-objects.json}`, which the chart's `files/rustfs-init/` must equal byte for byte, `deploy/compose.Caddyfile`, whose `/public/*` block the chart's proxy copies (the rest of `compose.Caddyfile` is not compared), and `Cargo.toml`, whose version must equal `Chart.yaml`'s `appVersion`. **While the chart is on hold (§Deployment targets) its test runs only when `deploy/helm/**` or `.github/workflows/helm-chart.yml` changes, or by hand** (`helm-chart.yml`, not `ci.yml`), so a version bump or an edit to those Compose files does not fail CI — and must NOT be followed into the chart. Edit the Compose side alone; any later run of the chart test fails on that drift by design. The chart's own "edit both together" instructions (the `files/public-proxy.Caddyfile` header, the `templates/rustfs-init-configmap.yaml` header, and `render_test.sh`'s "— edit both" FAIL text) predate the hold and stay only because the chart is frozen; while the hold lasts they do not apply. The chart mentions inside `deploy/compose-rustfs/init.sh` describe the frozen chart and stay because the whole file is compared.

`make test-shell` (part of `make test-all`) and a CI step each run the deploy-script fixture tests, which `cargo test` cannot see: `deploy/tests/backup_retention_test.sh`, `deploy/tests/compose_storage_test.sh` (the bundled Compose object store: overlay, `rustfs-init`, key generator; its Docker parse checks skip themselves without docker), `deploy/tests/compose_public_route_test.sh` (the Compose `/public/*` block) and `deploy/tests/janitor_no_hardcoded_trash_mtime_test.sh`.

## systemd

> [!CAUTION]
> **drust's systemd unit deliberately OMITS `MemoryDenyWriteExecute`.** wasmtime's Cranelift JIT must `mmap(PROT_EXEC)` to run guest wasm; re-adding W^X makes EVERY edge-function upload/invoke fail the compile gate with `WASM_COMPILE_FAILED: unable to make memory executable` (EPERM) — and the unsandboxed `cargo test` suite stays green, so ONLY a live smoke against the running service catches it. The guest sandbox is enforced inside wasmtime (epoch deadline + `ResourceLimiter` + empty `WasiCtx` + WIT import-absence), not by process-wide W^X — a conscious posture trade-off. Rationale is inline in `deploy/drust.service`; the top-level `tool/CLAUDE.md` "never skip the sandbox directives" WARNING does **not** apply to this one line. If W^X must return, move functions to an AOT/out-of-process model — do not just re-add the directive.

## Caddy

> [!WARNING]
> **`header_up Host "127.0.0.1:47826"` is mandatory on the Caddy block** for `/drust/t/<tenant>/mcp` — rmcp's DNS-rebinding guard rejects non-loopback Hosts with a 403/421 that looks like a WAF. The bare-metal Garage `/public/*` is the same family but routes by `Host: <bucket>.web.local`, so it needs `header_up Host "public.web.local"`, never `127.0.0.1:<port>`. The Compose `/public/*` block talks to an S3 API path-style and keeps `Host {upstream_hostport}`. A vhost Host sent to RustFS with `RUSTFS_SERVER_DOMAINS` unset is parsed as path-style and 403s.

The `/public/*` block's `handle_response` matcher (CSP-sandboxing script-executing content types served straight out of the object store) has three traps:

- **`copy_response` is mandatory inside that `handle_response` block** — entering `handle_response` replaces the default passthrough, so a block with only a `header` directive silently discards the entire upstream body (caught live against a real 2.6 MB object before shipping: 200 OK with a 0-byte body). `caddy adapt` validates such a block happily.
- Caddy 2.6.2's response-matcher allowlist has **no regex or case-insensitive option**, only a plain glob on `header`. The matcher's exact shape, and the fact that it must stay in lockstep with `storage::files::is_unsafe_inline_type`, are documented once in `.claude/rules/storage-files.md` — read that before editing the `@markup` matcher.
- **An S3-API upstream needs the query string dropped** (`rewrite * /public{path}?`). RustFS honours `?response-content-type=` on anonymous GETs, and a case-variant type slips past the case-sensitive matcher. Garage's website endpoint is not an S3 API, but the strip costs nothing there.

**Do not log the `Location` of `/oauth/consent/approve` responses** in a proxy access log:
it carries a one-time MCP authorization code (compensated by PKCE, a 300-second lifetime
and single use, but a log is not where it belongs). Default Caddy access logs do not record
response headers; keep it that way for that path.

**The RFC 8414 root rule for a path-mounted issuer is not configured on bare metal yet.**
The host's `/drust/*` block serves the MCP OAuth AS metadata at
`/drust/.well-known/oauth-authorization-server`; the root location
`/.well-known/oauth-authorization-server/drust` has no proxy rule, so the metadata is
reachable only under the base path (Compose serves drust at the root and needs no rule).
To check whether the AS is enabled on a host: the boot log has one line beginning
`MCP OAuth AS enabled` or `MCP OAuth AS disabled`, and `GET <DRUST_PUBLIC_URL><base
path>/.well-known/oauth-authorization-server` answers 200 only when it is enabled (404
otherwise).

The bare-metal block's authoritative snippet is **`../garage/deploy/Caddyfile`**, not `drust/deploy/` — `/public/*` is Garage's route there; verified 2026-08-02 as byte-identical to the live `/etc/caddy/Caddyfile` apart from one space. The Compose block is `deploy/compose.Caddyfile`, a second lockstep partner pinned by `deploy/tests/compose_public_route_test.sh`. The on-hold k3s chart's `deploy/helm/drust/files/public-proxy.Caddyfile` carries a byte copy of the Compose `handle_path /public/*` block as of the chart's freeze; while the hold lasts it is not a lockstep partner, so edit the Compose block alone (§Tests). Per-service `deploy/Caddyfile` files are snippets pasted into the single `/etc/caddy/Caddyfile`; after editing it, `sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy`.

## Deployment targets

The binary is shared; **everything around it is written once per target** and nothing in the
test suite compares them. **Two targets are active: bare-metal systemd (this host) and Docker
(the image plus Docker Compose).** A release is not done until both were re-checked, and every
env knob, path, route and recurring job is checked on both. The suite does not run under
systemd and does not build the image, so divergence between them is invisible until a user
hits it.

**The k3s Helm chart (`deploy/helm/drust/`) is on hold.** It is frozen at chart 0.2.0 /
`appVersion` 1.67.0, the state last verified live on a k3s cluster with drust 1.67.0, and a
default install of it pulls drust 1.67.0. It is not developed, not kept in step with the
active targets and not re-checked per release: do not edit it to follow a Docker or
bare-metal change. Drift between the chart and the other two is expected while the hold lasts
and is not a defect. Its column below still describes the frozen chart; bringing it back is
*Resuming k3s* at the end of this section.

| | Bare-metal (this host) | Docker Compose | k3s (on hold, frozen at chart 0.2.0) |
|---|---|---|---|
| Process supervision | `deploy/drust.service` | `docker-compose.yml` | `deploy/helm/drust/templates/drust-statefulset.yaml` |
| Reverse proxy | `/etc/caddy/Caddyfile` (+ `deploy/Caddyfile`, `../garage/deploy/Caddyfile`) | `deploy/compose.Caddyfile` (`/` → drust, `/public/*` → object store) | chart Ingress (`/` → drust, `/public` → `public-proxy` Caddy) |
| Object store | host Garage | RustFS via `docker-compose.storage.yml` + `rustfs-init` (off until `deploy/compose-storage-env.sh`) | RustFS StatefulSet + `rustfs-init` hook (the Compose `init.sh`) |
| Scheduled work | `drust-backup.timer`, `drust-janitor.timer` | **nothing** | chart CronJobs **+ the `maintenance` sidecar** (default on, opt-out) |
| Base path | `/drust` | `""` | `""` |
| Trusted proxies (`DRUST_TRUSTED_PROXIES`) | 2 (default, nginx + Caddy) | 1 (`docker-compose.yml`; image default 0) | `ingress.trustedProxies` (default 1) |

> [!CAUTION]
> **Anything scheduled outside the drust process is a per-target coin flip.** `deploy/drust-janitor.sh` and `deploy/drust-backup.sh` are systemd timers with **no Compose equivalent at all**; the chart re-implements *some* of that work in its `maintenance` sidecar, so k3s coverage depends on which half you look at. `deploy/drust-janitor.sh` does two jobs — `_trash` expiry and `drust_session_janitor` — and each was fixed in a different release, for the same reason, a release apart: v1.58 moved trash in-process, and only the follow-up caught that sessions were still swept nowhere on Compose. **Enumerate every job a timer performs, not the timer.** When adding recurring maintenance, put it in-process and treat both the timer and the sidecar as accelerators, not the mechanism. As of v1.59 (#935) the hardcoded `find … _trash … -mtime +7` was removed from `deploy/drust-janitor.sh` **and** the k3s `maintenance` sidecar — it capped any longer `DRUST_TRASH_RETENTION_DAYS` and defeated `0` (keep-forever), the exact v1.58.0 regression. `_trash` retention is now in-process only on all three targets; never re-add a time-based trash `find`. Guarded by `deploy/tests/janitor_no_hardcoded_trash_mtime_test.sh` and, for the frozen chart, `render_test.sh` (`assert_absent full.yaml "-mtime"`).

Per-release checklist — run it before tagging, not after. It covers the two active targets; the chart is not part of a release (no `appVersion` bump, no render test, no k3s install):

1. New env knob this release? It must appear on both: `deploy/drust.service` `Environment=`/`EnvironmentFile` and `docker-compose.yml` `environment:`, plus the `Dockerfile` `ENV` when the image needs its own default (as `DRUST_BASE_PATH` and `DRUST_TRUSTED_PROXIES` do). A knob with a default only in Rust works everywhere but is undiscoverable on a target that does not list it. A Caddy-container variable or a variable of `docker-compose.storage.yml` counts too.
2. New on-disk path, volume, or directory? Compose needs it mounted — a path drust creates at boot lands on ephemeral container storage otherwise — and on bare metal the unit's `ProtectSystem=strict` sandbox must allow writes to it (`ReadWritePaths=`).
3. New recurring job? See the CAUTION above.
4. New route or route prefix? Check `deploy/compose.Caddyfile`, not just the host Caddyfile.
5. Migration or first-boot behaviour change? It runs on every boot on both targets, and containers restart far more often than this host does.
6. Storage or `/public/*` change? Run the smoke on both stores: `deploy/smoke/up.sh` (RustFS) and `SMOKE_STORE=garage deploy/smoke/up.sh` (the host's store).
7. MCP OAuth enabled anywhere? Re-fetch `https://claude.ai/oauth/claude-code-client-metadata`
   and compare it with `KNOWN_CLIENTS` in `src/mgmt/mcp_oauth/clients.rs`. On any difference
   in `client_id` or `redirect_uris`, update the pinned copy and `pinned_on` in the same
   release. Claude Code has changed its redirect host before, and a stale pin shows up only as
   users stuck on the authorize error page.

Resuming k3s — the chart-side work the hold skips, all of it, before the chart counts as a target again:

1. Resync the chart's copies from Compose: `files/rustfs-init/{init.sh,public-read.json,drust-objects.json}` from `deploy/compose-rustfs/`, and the `handle_path /public/*` block of `files/public-proxy.Caddyfile` from `deploy/compose.Caddyfile`.
2. Bump `Chart.yaml`'s `appVersion` to the current release and its `version` for the chart. **`appVersion` is the image tag `helm install` pulls**: `values.yaml` ships `image.tag: ""` and both drust containers fall back to it, which is why the frozen chart still installs 1.67.0. `render_test.sh` asserts `appVersion == Cargo.toml version`; before it did, `appVersion` read `1.49.4` for nine releases while `image.tag` carried a second, equally stale hardcoded version, so default installs shipped a binary missing two intra-tenant fixes and the stored-XSS sandbox.
3. Walk every release since 1.67.0 through the chart: each new env knob into `values.yaml` + ConfigMap, each new on-disk path into the StatefulSet `volumeClaimTemplates`, each new route into the chart's Ingress, each recurring job against the `maintenance` sidecar and the CronJobs, each migration or first-boot change, and any change to `DRUST_SHUTDOWN_GRACE_SECS` against Kubernetes' 30s `terminationGracePeriodSeconds`.
4. Re-pin the chart's images: the RustFS image to the digest `docker-compose.storage.yml` uses at that point, and every other digest-pinned image in `values.yaml` (Caddy, rclone, kubectl, Litestream) checked as still pullable — chart 0.2.0 exists partly because two pinned images vanished while nobody looked.
5. `deploy/helm/drust/tests/render_test.sh` green (offline `helm template` + `kubeconform`, both needed on PATH locally).
6. Install the chart on a real k3s cluster, **and `helm upgrade` a populated 0.2.0 release to it**, and exercise uploads and `/public/*` through the Ingress: `render_test.sh` renders manifests and cannot see a running store, its hook Job, a NetworkPolicy or a migration.
7. Put the chart job back on the every-push gate: move `helm-chart` from `.github/workflows/helm-chart.yml` back into `ci.yml`.
8. Restore the three-target wording here (this section, §Tests, §Caddy), in CLAUDE.md invariants 14 and 17, in `.claude/rules/storage-files.md` (the `/public/*` proxy-block paragraph and the `is_unsafe_inline_type` WARNING), in AGENTS.md (remove the adjudicated verdict on the hold), in the `DRUST_PUBLIC_BASE_URL` row of `README.md` and `README.zh.md`, and in the comments of `deploy/compose.Caddyfile`, `deploy/drust.service` and `ci.yml` (the pointer where the moved job stood); drop the on-hold notice at the top of the chart README. Record the resume in the root `CHANGELOG.md` and the chart's own `CHANGELOG.md`.

`deploy/helm/**` is engineer-owned: read it, do not stage it in an automated commit. It is also on hold, so its divergence from the active targets is expected and is neither reported as a defect nor fixed; until the chart is resumed (above), nothing edits it to follow the other two.

## Deploy check

`curl -sI http://127.0.0.1:47826/health | grep -i x-drust` after `cargo build --release && sudo systemctl restart drust`. Plain `/health` returns `ok` from the OLD binary too, so it proves nothing about which build is live; the version string is baked at compile time, so rebuild **and** restart before trusting the header. `DRUST_HIDE_VERSION=1` omits it.

Grep the `x-drust` prefix, not `x-drust-version`. **`x-drust-boot-degraded: <n>`** is emitted only when best-effort boot maintenance missed on some tenant — a STRICT rebuild that held a table back, an egress backfill that failed. Those tenants serve normally and the job retries next boot, so this is not an outage and never fails a probe; it is deliberately a header and not part of the `/health` body, which is a liveness contract for k8s and Compose. Absent means clean. It exists because a per-tenant `tracing::error!` is not a signal anyone receives: one tenant's STRICT rebuild failed on 18 consecutive boots and was found by accident.

> [!CAUTION]
> **Shutdown grace is bounded in-process, and the bound must stay under the tightest supervisor's.** `axum::serve(..).with_graceful_shutdown(..)` waits for every in-flight connection, and MCP Streamable HTTP sessions, `/subscribe` SSE and WS rooms never close on their own — so before v1.58.3 SIGTERM hung until `TimeoutStopSec` fired and SIGKILLed the process (8 of 10 stops on this host took exactly 90s). The damage was not the wait: SIGKILL skips the post-`serve()` `drain_writer()`, so the audit buffer that the graceful path exists to flush was lost on precisely the restarts it was written to protect. `DRUST_SHUTDOWN_GRACE_SECS` (default 10) now caps the drain. Raising it above the tightest supervisor deadline — Compose `stop_grace_period` 10s, k8s `terminationGracePeriodSeconds` 30s, systemd `TimeoutStopSec` 90s — silently restores the old bug on that target.

## Provenance

Extracted from CLAUDE.md "Build & restart", "Tests", the W^X + Caddy Host invariants, and the Caddy `handle_response` notes in the per-tenant files section, during the 2026-08-02 restructure.

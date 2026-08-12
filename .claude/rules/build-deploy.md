---
paths:
  - "Dockerfile"
  - "Makefile"
  - "Cargo.toml"
  - "Cargo.lock"
  - ".github/workflows/**"
  - "deploy/**"
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

## systemd

> [!CAUTION]
> **drust's systemd unit deliberately OMITS `MemoryDenyWriteExecute`.** wasmtime's Cranelift JIT must `mmap(PROT_EXEC)` to run guest wasm; re-adding W^X makes EVERY edge-function upload/invoke fail the compile gate with `WASM_COMPILE_FAILED: unable to make memory executable` (EPERM) — and the unsandboxed `cargo test` suite stays green, so ONLY a live smoke against the running service catches it. The guest sandbox is enforced inside wasmtime (epoch deadline + `ResourceLimiter` + empty `WasiCtx` + WIT import-absence), not by process-wide W^X — a conscious posture trade-off. Rationale is inline in `deploy/drust.service`; the top-level `tool/CLAUDE.md` "never skip the sandbox directives" WARNING does **not** apply to this one line. If W^X must return, move functions to an AOT/out-of-process model — do not just re-add the directive.

## Caddy

> [!WARNING]
> **`header_up Host "127.0.0.1:47826"` is mandatory on the Caddy block** for `/drust/t/<tenant>/mcp` — rmcp's DNS-rebinding guard rejects non-loopback Hosts with a 403/421 that looks like a WAF. Garage `/public/*` is the same family but routes by `Host: <bucket>.web.local`, so it needs `header_up Host "public.web.local"`, never `127.0.0.1:<port>`.

The `/public/*` block's `handle_response` matcher (CSP-sandboxing script-executing content types served straight out of Garage) has two traps:

- **`copy_response` is mandatory inside that `handle_response` block** — entering `handle_response` replaces the default passthrough, so a block with only a `header` directive silently discards the entire upstream body (caught live against a real 2.6 MB object before shipping: 200 OK with a 0-byte body). `caddy adapt` validates such a block happily.
- Caddy 2.6.2's response-matcher allowlist has **no regex or case-insensitive option**, only a plain glob on `header`. The matcher's exact shape, and the fact that it must stay in lockstep with `storage::files::is_unsafe_inline_type`, are documented once in `.claude/rules/storage-files.md` — read that before editing the `@markup` matcher.

The authoritative snippet for this block lives in `../garage/deploy/Caddyfile`, not in `drust/deploy/` — `/public/*` is Garage's route. Verified 2026-08-02 as byte-identical to the live `/etc/caddy/Caddyfile` apart from one space.

That block's authoritative snippet is **`../garage/deploy/Caddyfile`**, not `drust/deploy/`. Per-service `deploy/Caddyfile` files are snippets pasted into the single `/etc/caddy/Caddyfile`; after editing it, `sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy`.

## Three deployment targets

The binary is shared; **everything around it is written three times** and nothing in the test
suite compares them. The suite does not run under systemd, does not build the image, and does
not render the chart, so divergence is invisible until a user hits it.

| | Bare-metal (this host) | Docker Compose | k3s |
|---|---|---|---|
| Process supervision | `deploy/drust.service` | `docker-compose.yml` | `deploy/helm/drust/templates/drust-statefulset.yaml` |
| Reverse proxy | `/etc/caddy/Caddyfile` (+ `deploy/Caddyfile`, `../garage/deploy/Caddyfile`) | `deploy/compose.Caddyfile` | chart Ingress |
| Object store | host Garage | compose service | MinIO StatefulSet |
| Scheduled work | `drust-backup.timer`, `drust-janitor.timer` | **nothing** | chart CronJobs **+ the `maintenance` sidecar** (default on, opt-out) |
| Base path | `/drust` | `""` | `""` |

> [!CAUTION]
> **Anything scheduled outside the drust process is a per-target coin flip.** `deploy/drust-janitor.sh` and `deploy/drust-backup.sh` are systemd timers with **no Compose equivalent at all**; the chart re-implements *some* of that work in its `maintenance` sidecar, so k3s coverage depends on which half you look at. `deploy/drust-janitor.sh` does two jobs — `_trash` expiry and `drust_session_janitor` — and each was fixed in a different release, for the same reason, a release apart: v1.58 moved trash in-process, and only the follow-up caught that sessions were still swept nowhere on Compose. **Enumerate every job a timer performs, not the timer.** When adding recurring maintenance, put it in-process and treat both the timer and the sidecar as accelerators, not the mechanism. As of v1.59 (#935) the hardcoded `find … _trash … -mtime +7` was removed from `deploy/drust-janitor.sh` **and** the k3s `maintenance` sidecar — it capped any longer `DRUST_TRASH_RETENTION_DAYS` and defeated `0` (keep-forever), the exact v1.58.0 regression. `_trash` retention is now in-process only on all three targets; never re-add a time-based trash `find`. Guarded by `render_test.sh` (`assert_absent full.yaml "-mtime"`) and `deploy/tests/janitor_no_hardcoded_trash_mtime_test.sh`.

Per-release checklist — run it before tagging, not after:

1. `deploy/helm/drust/Chart.yaml` — bump `appVersion` to the release version, and `version` if the chart's own templates changed. **`appVersion` is the image tag `helm install` pulls**: `values.yaml` ships `image.tag: ""` and both drust containers fall back to it. This item is now mechanized — `render_test.sh` asserts `appVersion == Cargo.toml version` and CI's `helm-chart` job runs it, so a skipped bump is a red build rather than a silent gap. It was not always: `appVersion` read `1.49.4` for nine releases while `image.tag` carried a second, equally stale hardcoded version, so default installs shipped a binary missing two intra-tenant fixes and the stored-XSS sandbox.
2. New env knob this release? It must appear in all three: `deploy/drust.service` `Environment=`/`EnvironmentFile`, `docker-compose.yml` `environment:`, and the chart's `values.yaml` + ConfigMap. A knob with a default only in Rust works everywhere but is undiscoverable in two of the three.
3. New on-disk path, volume, or directory? Compose and the chart both need it mounted, and the chart needs it in the StatefulSet `volumeClaimTemplates` — a path drust creates at boot lands on ephemeral container storage otherwise.
4. New recurring job? See the CAUTION above.
5. New route or route prefix? Check the chart's Ingress and `deploy/compose.Caddyfile`, not just the host Caddyfile.
6. Migration or first-boot behaviour change? It runs on every boot in all three, and containers restart far more often than this host does.
7. `deploy/helm/drust/tests/render_test.sh` still passes (offline `helm template` + `kubeconform`). CI's `helm-chart` job runs it on every push to main, so this is a pre-push convenience rather than the only line of defence — but it needs `helm` + `kubeconform` on PATH locally.

`deploy/helm/**` is engineer-owned: read it, report divergence, do not stage it in an automated commit.

## Deploy check

`curl -sI http://127.0.0.1:47826/health | grep -i x-drust` after `cargo build --release && sudo systemctl restart drust`. Plain `/health` returns `ok` from the OLD binary too, so it proves nothing about which build is live; the version string is baked at compile time, so rebuild **and** restart before trusting the header. `DRUST_HIDE_VERSION=1` omits it.

Grep the `x-drust` prefix, not `x-drust-version`. **`x-drust-boot-degraded: <n>`** is emitted only when best-effort boot maintenance missed on some tenant — a STRICT rebuild that held a table back, an egress backfill that failed. Those tenants serve normally and the job retries next boot, so this is not an outage and never fails a probe; it is deliberately a header and not part of the `/health` body, which is a liveness contract for k8s and Compose. Absent means clean. It exists because a per-tenant `tracing::error!` is not a signal anyone receives: one tenant's STRICT rebuild failed on 18 consecutive boots and was found by accident.

> [!CAUTION]
> **Shutdown grace is bounded in-process, and the bound must stay under the tightest supervisor's.** `axum::serve(..).with_graceful_shutdown(..)` waits for every in-flight connection, and MCP Streamable HTTP sessions, `/subscribe` SSE and WS rooms never close on their own — so before v1.58.3 SIGTERM hung until `TimeoutStopSec` fired and SIGKILLed the process (8 of 10 stops on this host took exactly 90s). The damage was not the wait: SIGKILL skips the post-`serve()` `drain_writer()`, so the audit buffer that the graceful path exists to flush was lost on precisely the restarts it was written to protect. `DRUST_SHUTDOWN_GRACE_SECS` (default 10) now caps the drain. Raising it above the tightest supervisor deadline — Compose `stop_grace_period` 10s, k8s `terminationGracePeriodSeconds` 30s, systemd `TimeoutStopSec` 90s — silently restores the old bug on that target.

## Provenance

Extracted from CLAUDE.md "Build & restart", "Tests", the W^X + Caddy Host invariants, and the Caddy `handle_response` notes in the per-tenant files section, during the 2026-08-02 restructure.

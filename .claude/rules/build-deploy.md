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

Cost here is COMPILE, not run: each `tests/*.rs` is its own binary statically linking the drust lib + wasmtime, so a bare `cargo test <name>` still compiles all of them — only `--test <name>` limits what compiles. The `Makefile` groups by the `tests/<prefix>_*.rs` convention: `make test-lib` (fast inner loop), `make test-functions` / `make test-auth` / any prefix (`make groups` lists them), `make test-all` (full gate). Glob-based, so new test files need no edits. Per-task workflow agents should run `make test-lib` + the relevant group; only the final review runs `make test-all`. (The Makefile header's "~142 binaries" at lines 5 and 18 is stale — 226 today; the advice stands.)

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

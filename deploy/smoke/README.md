# Local smoke stack

A throwaway drust deployment on your own machine (Docker Desktop or any Docker
host) for checking a build the way a client would see it, before it goes
anywhere real. It is the **Compose deployment target itself** — the repo's
`docker-compose.yml`, unmodified — with one override file that moves the
published ports and turns the version header back on, plus an object store:
RustFS from the repo's own `docker-compose.storage.yml` by default, or Garage with
`SMOKE_STORE=garage` (what the bare-metal host runs).

It exists because three things cannot be learned from `cargo test`:

- whether the **built image** boots and serves (the suite never builds it);
- whether edge functions really compile and run in the deployed process
  (wasmtime's JIT), and whether file features work against a **real** S3
  endpoint rather than the in-memory store the tests use;
- whether the integration suite and the deploy scripts pass on **Linux** — CI
  runs `cargo test --lib` only, and a macOS workstation cannot run
  `make test-shell` or `tests/backup_roundtrip.rs` (they need GNU bash and GNU
  find).

It does **not** stand in for the bare-metal host: nothing here runs under
systemd, so the unit's sandbox directives are not exercised. A live check on
that host after deploying is still required (see `CLAUDE.md`, the
`MemoryDenyWriteExecute` caution).

## Use

```bash
deploy/smoke/up.sh              # build the image, start (RustFS), mint an admin PAT
SMOKE_STORE=garage deploy/smoke/up.sh   # the same with Garage, bootstrapped by up.sh
deploy/smoke/run-all.sh         # run every check in checks/
deploy/smoke/run-all.sh 10 20   # only checks/10-*.sh and checks/20-*.sh
deploy/smoke/test-linux.sh      # make test-shell + cargo test --no-fail-fast, in a Linux container
deploy/smoke/down.sh            # stop;  --wipe also deletes the volumes and the secrets
```

`up.sh --no-build` reuses the image that is already built. After a code change,
plain `up.sh` rebuilds (the cargo cache is a BuildKit cache mount, so only the
first build is slow).

`up.sh` remembers the store in `deploy/smoke/.env` (`SMOKE_STORE`), so a later plain
`up.sh`, `run-all.sh` and `down.sh` stay on it; switching stores removes the other
store's container (`--remove-orphans`), and `down.sh --wipe` deletes every volume of
the project, both stores' included. `run-all.sh` records the store it checked in
`.last-run/store.txt`. Every public-object check goes through the stack's own
`/public/*` route, so the assertions are the same on either store.

Before a release that touches storage, run the checks on **both** stores. RustFS is the
Compose default, and Garage is what the bare-metal host serves from.

On Docker Desktop all host traffic reaches Caddy from one VM gateway address, so
the per-IP rate limits (logins, register, anon uploads and invokes) are still
shared by every check during a local run — the scripts back off on
`RATE_LIMITED_IP`. That is the environment, not drust: the stack keys on the
client address Caddy sees (`DRUST_TRUSTED_PROXIES: "1"` in
`docker-compose.yml`), and on Linux with external clients Docker keeps the
source address.

| What | Where |
|---|---|
| Admin UI (through Caddy) | <http://localhost:48080/login> |
| drust directly, no proxy | `http://127.0.0.1:48826` |
| Object store | RustFS has no host port (checks go through Caddy's `/public/*`). Garage mode has S3 / website / admin on `127.0.0.1:48900` / `48902` / `48903` |
| Admin username, password, PAT, object-store keys, `SMOKE_STORE` | `deploy/smoke/.env` (generated, mode 600, gitignored) |

Everything binds to loopback, and the ports are chosen not to collide with a
drust (47826) or Garage (47830–47832) already running on the host. Override
them with `SMOKE_HTTP_PORT`, `SMOKE_DRUST_PORT`, `SMOKE_GARAGE_*_PORT`. The compose
project is `drust-smoke`. If you rename it with `SMOKE_COMPOSE_PROJECT`, set the same
value for `up.sh`, `run-all.sh` and `down.sh` alike — the checks that read container logs
or peek into drust use it too. Renaming it does **not** let a second stack run beside the
first from the same checkout: `deploy/smoke/.env` holds per-stack state (the admin PAT that
`up.sh` re-mints when the stored one does not authenticate, `SMOKE_STORE`, the generated
keys, and `down.sh --wipe` deletes it), so a concurrent second stack needs its own checkout.

## Signing in

There is deliberately **no "skip the login" switch** in drust, not even for
development: the binary that runs here is the binary that ships, and a flag
that disables admin authentication is a flag that can be left on. Instead
`up.sh` generates the admin password once and mints a personal access token,
so the check scripts never need a human and you sign in to the browser once
(let it remember the password).

To choose the password yourself, set `SMOKE_ADMIN_PASSWORD` before the *first*
`up.sh` (or after `down.sh --wipe`); it is only read on first boot.

## Checks that fail today

None. `run-all.sh` exits zero at this commit: all 1425 assertions pass, on RustFS and on
Garage (`SMOKE_STORE=garage`). The stack's first run, before the v1.67.0 fixes, passed 1356
and failed 22, each on a confirmed defect; all of those are fixed.

When a check fails on a confirmed defect that is not fixed yet, add a line to this table,
and remove it in the same commit that fixes the defect. An assertion states the intended
behaviour, so it turns green when the defect is fixed.

| Script | Failing | Defect |
|---|---|---|

## Writing a check

Each `checks/NN-name.sh` sources `checks/lib.sh`, creates its own throwaway
tenant with `new_tenant`, and ends with `finish`. Tenants are deleted when the
script exits. `checks/00-boot.sh` is the smallest complete example.

Rules the existing checks follow:

- A check asserts the **intended** behaviour (from the source, `CHANGELOG.md`
  or an invariant in `CLAUDE.md`), with an exact status or error code — not
  "whatever came back".
- No secret is ever printed.
- bash 3.2, `curl` and `python3` only, so it runs on a stock Mac.
- Never reroll or revoke the shared admin PAT inside a check; create a second
  admin if a test needs to revoke one.

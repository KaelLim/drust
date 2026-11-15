# Local smoke stack

A throwaway drust deployment on your own machine (Docker Desktop or any Docker
host) for checking a build the way a client would see it, before it goes
anywhere real. It is the **Compose deployment target itself** — the repo's
`docker-compose.yml`, unmodified — with one override file that adds a real
Garage, moves the published ports, and turns the version header back on.

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
deploy/smoke/up.sh              # build the image, start, bootstrap Garage, mint an admin PAT
deploy/smoke/run-all.sh         # run every check in checks/
deploy/smoke/run-all.sh 10 20   # only checks/10-*.sh and checks/20-*.sh
deploy/smoke/test-linux.sh      # make test-shell + cargo test --no-fail-fast, in a Linux container
deploy/smoke/down.sh            # stop;  --wipe also deletes the volumes and the secrets
```

`up.sh --no-build` reuses the image that is already built. After a code change,
plain `up.sh` rebuilds (the cargo cache is a BuildKit cache mount, so only the
first build is slow).

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
| Garage S3 / website / admin | `127.0.0.1:48900` / `48902` / `48903` |
| Admin username, password, PAT, Garage keys | `deploy/smoke/.env` (generated, mode 600, gitignored) |

Everything binds to loopback, and the ports are chosen not to collide with a
drust (47826) or Garage (47830–47832) already running on the host. Override
them with `SMOKE_HTTP_PORT`, `SMOKE_DRUST_PORT`, `SMOKE_GARAGE_*_PORT`.

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

`run-all.sh` exits non-zero at this commit: 1356 assertions pass and 22 fail. Each
failure is a confirmed defect that has not been fixed yet. The assertion states the
intended behaviour, so it turns green when the defect is fixed. Remove a line from this
table in the same commit that fixes it.

| Script | Failing | Defect |
|---|---|---|
| `20-files`, `50-mcp` | 5 | `docker-compose.yml` does not set `DRUST_PUBLIC_BASE_URL`, so file, signed and MCP-advertised URLs point at `http://localhost:8793` |
| `20-files`, `30-uploads-tus` | 2 | `deploy/compose.Caddyfile` has no `/public/*` route, so the public URL drust returns answers 400 |
| `20-files` | 2 | a public file whose extension has a non-ASCII character or `~` is stored under a different key than the returned URL |
| `50-mcp` | 2 | a missing or wrongly typed tool argument answers plain-text `isError` (rmcp 1.8) instead of one of drust's two error shapes |
| `50-mcp` | 1 | `query`'s write refusal carries prose in `data.error_code` instead of an `UPPER_SNAKE` code |
| `70-admin` | 3 | tenant create, tenant key reroll and tenant soft-delete write no host audit row |
| `70-admin` | 1 | creating a tenant id that already exists answers 500 instead of 400 |
| `80-rpc-cron-webhooks` | 2 | the egress allowlist cannot match an IPv6-literal origin without a port |

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

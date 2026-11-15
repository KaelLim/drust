#!/usr/bin/env bash
# Static and fixture tests for the bundled Compose object store:
# docker-compose.storage.yml, deploy/compose-rustfs/* and the one-step
# generator deploy/compose-storage-env.sh.
#
# Compose and RustFS cannot run under `cargo test`, and a live smoke run is the
# only end-to-end proof. What this pins is the part a careless edit breaks
# silently: a published store port, the console back on, a credential with a
# default instead of a refusal, drust handed the root key, an anonymous policy
# that also lists the bucket, an init that skips re-adding drust's key, and a
# generator that rotates or prints a secret or dies on a fresh clone.
#
# bash 3.2 (macOS) and GNU bash alike; needs python3 and openssl. The Docker
# part (item 6) is skipped with a note when `docker` is not on PATH.
#
# Usage: bash deploy/tests/compose_storage_test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OVERLAY="$ROOT/docker-compose.storage.yml"
INIT_DIR="$ROOT/deploy/compose-rustfs"
GEN="$ROOT/deploy/compose-storage-env.sh"
FAILURES=0
CASES=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/compose-storage-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
ok()   { echo "ok: $*"; }
check() { # NAME COMMAND... — passes when the command succeeds
  local name="$1"; shift
  CASES=$((CASES + 1))
  if "$@"; then ok "$name"; else fail "$name"; fi
}

# Non-comment lines of a file (full-line comments only; YAML/sh both use '#').
code_lines() { grep -v '^[[:space:]]*#' "$1"; }
# The block of one top-level service: from "  <name>:" to the next two-space key.
service_block() { # FILE NAME
  awk -v n="  $2:" '
    $0 == n { on = 1; print; next }
    on && /^  [A-Za-z0-9_-]+:/ { exit }
    on && /^[A-Za-z]/ { exit }
    on { print }
  ' "$1"
}

for f in "$OVERLAY" "$INIT_DIR/init.sh" "$INIT_DIR/public-read.json" \
         "$INIT_DIR/drust-objects.json" "$GEN"; do
  [ -f "$f" ] || { echo "FAIL: $f not found" >&2; exit 1; }
done

# ---- 1. docker-compose.storage.yml -------------------------------------------
img_rustfs="$(service_block "$OVERLAY" rustfs | sed -n 's/^    image: *//p')"
img_init="$(service_block "$OVERLAY" rustfs-init | sed -n 's/^    image: *//p')"
check "rustfs image is pinned by tag AND digest" \
  sh -c 'printf "%s" "$1" | grep -Eq "^rustfs/rustfs:[0-9.]+@sha256:[0-9a-f]{64}$"' _ "$img_rustfs"
check "rustfs-init runs the same image as rustfs" test -n "$img_init" -a "$img_init" = "$img_rustfs"
check "no ports: key anywhere in the overlay (store and console stay off the host)" \
  sh -c '! grep -v "^[[:space:]]*#" "$1" | grep -Eq "^[[:space:]]*ports:"' _ "$OVERLAY"
check "the RustFS web console is disabled" grep -q '^      RUSTFS_CONSOLE_ENABLE: "false"$' "$OVERLAY"
check "RustFS logs to stdout (RUSTFS_OBS_LOG_DIRECTORY empty)" \
  grep -q '^      RUSTFS_OBS_LOG_DIRECTORY: ""$' "$OVERLAY"
check "RUSTFS_SERVER_DOMAINS is never set (path-style only)" \
  sh -c '! grep -v "^[[:space:]]*#" "$1" | grep -q "RUSTFS_SERVER_DOMAINS:"' _ "$OVERLAY"
cred_lines="$(code_lines "$OVERLAY" | grep -E '^[[:space:]]+(RUSTFS|GARAGE_S3)_(ACCESS|SECRET)_KEY:')"
cred_total="$(printf '%s\n' "$cred_lines" | grep -c .)"
cred_strict="$(printf '%s\n' "$cred_lines" | grep -cE ': \$\{[A-Z0-9_]+:\?')"
check "every credential line refuses to start without a value (\${…:?}, $cred_total lines)" \
  test "$cred_total" -ge 8 -a "$cred_total" = "$cred_strict"
drust_block="$(service_block "$OVERLAY" drust)"
check "drust's GARAGE_S3_ACCESS_KEY is its own key, not the RustFS root key" \
  sh -c 'printf "%s\n" "$1" | grep -q "GARAGE_S3_ACCESS_KEY: \${GARAGE_S3_ACCESS_KEY:?" &&
         printf "%s\n" "$1" | grep -q "GARAGE_S3_SECRET_KEY: \${GARAGE_S3_SECRET_KEY:?" &&
         ! printf "%s\n" "$1" | grep -q "RUSTFS_"' _ "$drust_block"
check "drust waits for rustfs-init to complete" \
  sh -c 'printf "%s\n" "$1" | grep -q "condition: service_completed_successfully"' _ "$drust_block"
check "rustfs-init mounts tmpfs on /data (no anonymous volume per run)" \
  sh -c 'printf "%s\n" "$1" | grep -v "^[[:space:]]*#" | grep -A1 "^    tmpfs:" | grep -Eq "^      - /data$"' \
  _ "$(service_block "$OVERLAY" rustfs-init)"

# ---- 2. public-read.json: anonymous GetObject on public/* and nothing else -----
check "public-read.json grants exactly s3:GetObject on arn:aws:s3:::public/*" \
  python3 -I -c '
import json, sys
p = json.load(open(sys.argv[1]))
st = p["Statement"]
assert len(st) == 1, st
s = st[0]
assert s["Effect"] == "Allow", s
assert s["Action"] == ["s3:GetObject"], s["Action"]
assert s["Resource"] == ["arn:aws:s3:::public/*"], s["Resource"]
raw = open(sys.argv[1]).read()
assert "ListBucket" not in raw and "private" not in raw, raw
' "$INIT_DIR/public-read.json"

# ---- 3. drust-objects.json: drust's key cannot manage buckets or policy --------
check "drust-objects.json has no wildcard, bucket-policy, create-bucket or admin action" \
  python3 -I -c '
import json, sys
p = json.load(open(sys.argv[1]))
acts = [a for s in p["Statement"] for a in s["Action"]]
res = [r for s in p["Statement"] for r in s["Resource"]]
for a in acts:
    assert a != "s3:*" and not a.startswith("admin:"), a
    assert "BucketPolicy" not in a and a != "s3:CreateBucket" and a != "s3:DeleteBucket", a
for r in res:
    assert r.split(":::")[1].split("/")[0] in ("public", "private"), r
assert "s3:PutObject" in acts and "s3:ListBucket" in acts, acts
' "$INIT_DIR/drust-objects.json"

# ---- 4. init.sh -----------------------------------------------------------------
check "init.sh sets the public policy from the GetObject-only JSON (set-json)" \
  grep -q 'rc bucket anonymous set-json /init/public-read.json s3/public' "$INIT_DIR/init.sh"
check "init.sh never uses the canned download policy (it also lists)" \
  sh -c '! grep -v "^[[:space:]]*#" "$1" | grep -q "anonymous set download"' _ "$INIT_DIR/init.sh"
check "init.sh always re-adds drust's user (no 'admin user info' guard)" \
  sh -c '! grep -q "admin user info" "$1"' _ "$INIT_DIR/init.sh"

# A stub `rc` records every call; the script runs under plain sh.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/rc" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "$RC_STUB_LOG"
exit 0
STUB
chmod 755 "$WORK/bin/rc"
k() { openssl rand -hex "$1"; }
ROOT_AK="$(k 10)"; ROOT_SK="$(k 20)"; DR_AK="$(k 10)"; DR_SK="$(k 20)"
run_init() { # RUSTFS_ACCESS_KEY RUSTFS_SECRET_KEY GARAGE_S3_ACCESS_KEY GARAGE_S3_SECRET_KEY
  : > "$WORK/rc.log"
  env -i PATH="$WORK/bin:/usr/bin:/bin" RC_STUB_LOG="$WORK/rc.log" \
    RUSTFS_ACCESS_KEY="$1" RUSTFS_SECRET_KEY="$2" \
    GARAGE_S3_ACCESS_KEY="$3" GARAGE_S3_SECRET_KEY="$4" \
    sh "$INIT_DIR/init.sh" > "$WORK/init.out" 2>&1
}
expect_refused() { # NAME ARGS...
  local name="$1"; shift
  CASES=$((CASES + 1))
  run_init "$@"; local rc=$?
  if [ "$rc" = 1 ] && [ ! -s "$WORK/rc.log" ]; then
    ok "init.sh refuses $name before any rc call"
  else
    fail "init.sh with $name: exit $rc, rc calls: $(wc -l < "$WORK/rc.log" | tr -d ' ')"
  fi
}
expect_refused "RUSTFS_ACCESS_KEY=rustfsadmin" rustfsadmin "$ROOT_SK" "$DR_AK" "$DR_SK"
expect_refused "RUSTFS_SECRET_KEY=rustfsadmin" "$ROOT_AK" rustfsadmin "$DR_AK" "$DR_SK"
expect_refused "drust's key equal to the root key" "$ROOT_AK" "$ROOT_SK" "$ROOT_AK" "$DR_SK"
expect_refused "an empty GARAGE_S3_SECRET_KEY" "$ROOT_AK" "$ROOT_SK" "$DR_AK" ""
expect_refused "an empty RUSTFS_ACCESS_KEY" "" "$ROOT_SK" "$DR_AK" "$DR_SK"

CASES=$((CASES + 1))
run_init "$ROOT_AK" "$ROOT_SK" "$DR_AK" "$DR_SK"; rc=$?
last2="$(tail -n 2 "$WORK/rc.log" | cut -d' ' -f1-3 | tr '\n' '|')"
if [ "$rc" = 0 ] && [ "$last2" = "admin user add|admin policy attach|" ]; then
  ok "init.sh with valid keys ends in 'admin user add' then 'admin policy attach'"
else
  fail "init.sh with valid keys: exit $rc, last calls [$last2]"
fi
leak=no
for v in "$ROOT_AK" "$ROOT_SK" "$DR_AK" "$DR_SK"; do
  grep -qF -- "$v" "$WORK/init.out" && leak=yes
done
check "init.sh prints no key (stdout and stderr)" test "$leak" = no
check "init.sh's buckets are exactly public and private" \
  sh -c 'grep -c "^bucket create s3/" "$1" | grep -qx 2 &&
         grep -q "^bucket create s3/public " "$1" && grep -q "^bucket create s3/private " "$1"' _ "$WORK/rc.log"

# ---- 5. the generator -------------------------------------------------------------
# A copy under <tmp>/deploy/ so the script's own `root` resolves to <tmp>.
G="$WORK/gen"
mkdir -p "$G/deploy"
cp "$GEN" "$G/deploy/compose-storage-env.sh"
gen() { # [ENV_FILE_CONTENT] — runs the generator in $G; output in $G/out
  ( cd "$G" && COMPOSE_PROJECT_NAME=drust-compose-storage-test \
      bash deploy/compose-storage-env.sh ) > "$G/out" 2>&1
}
val() { sed -n "s/^$1=//p" "$G/.env" | tail -n 1; }
mode_of() { ls -l "$1" | cut -c1-10; }

rm -f "$G/.env"
gen; rc=$?
check "generator on a fresh clone (no .env at all) exits 0" test "$rc" = 0
check "generator creates .env with mode 600" test "$(mode_of "$G/.env")" = "-rw-------"
check "generator writes COMPOSE_FILE with the storage overlay" \
  test "$(val COMPOSE_FILE)" = "docker-compose.yml:docker-compose.storage.yml"
for key in RUSTFS_ACCESS_KEY GARAGE_S3_ACCESS_KEY; do
  v="$(val "$key")"
  check "generator writes a 20-character $key" test "${#v}" = 20
done
for key in RUSTFS_SECRET_KEY GARAGE_S3_SECRET_KEY; do
  v="$(val "$key")"
  check "generator writes a 40-character $key" test "${#v}" = 40
done
check "generator never writes RustFS's published default" \
  sh -c '! grep -q "=rustfsadmin$" "$1"' _ "$G/.env"
check "generated drust key differs from the root key" \
  test "$(val GARAGE_S3_ACCESS_KEY)" != "$(val RUSTFS_ACCESS_KEY)"
leak=no
for key in RUSTFS_ACCESS_KEY RUSTFS_SECRET_KEY GARAGE_S3_ACCESS_KEY GARAGE_S3_SECRET_KEY; do
  grep -qF -- "$(val "$key")" "$G/out" && leak=yes
done
check "generator output contains no generated value" test "$leak" = no
check "generator names each key it added" test "$(grep -c '^  added ' "$G/out")" = 5

cp "$G/.env" "$G/env.before"
gen; rc=$?
check "a second run exits 0, adds nothing and changes no value" \
  sh -c 'test "$1" = 0 && cmp -s "$2/env.before" "$2/.env" && ! grep -q "^  added " "$2/out"' _ "$rc" "$G"

printf 'GARAGE_S3_ENDPOINT=http://127.0.0.1:47830\nGARAGE_S3_ACCESS_KEY=x\n' > "$G/.env"
cp "$G/.env" "$G/env.before"
gen; rc=$?
check "a .env pointing at another store makes it exit 1 and stay byte-identical" \
  sh -c 'test "$1" = 1 && cmp -s "$2/env.before" "$2/.env"' _ "$rc" "$G"

printf 'GARAGE_S3_ENDPOINT=\nGARAGE_S3_ACCESS_KEY=\nGARAGE_S3_SECRET_KEY=\nKEEP_ME=1\n' > "$G/.env"
gen; rc=$?
v="$(val GARAGE_S3_ACCESS_KEY)"
check "the .env.example shape (empty GARAGE_S3_*) is accepted and the empty keys replaced" \
  sh -c 'test "$1" = 0 && test "${#2}" = 20 && grep -qx "KEEP_ME=1" "$3/.env" &&
         test "$(grep -c "^GARAGE_S3_ACCESS_KEY=" "$3/.env")" = 1' _ "$rc" "$v" "$G"

printf 'COMPOSE_FILE=docker-compose.yml:my-own.yml\n' > "$G/.env"
cp "$G/.env" "$G/env.before"
gen; rc=$?
check "a foreign COMPOSE_FILE makes it exit 1 and stay byte-identical" \
  sh -c 'test "$1" = 1 && cmp -s "$2/env.before" "$2/.env"' _ "$rc" "$G"

printf 'RUSTFS_SECRET_KEY=keep-this-one-0123456789\n' > "$G/.env"
gen; rc=$?
check "an existing non-empty key is never changed" \
  sh -c 'test "$1" = 0 && test "$(sed -n "s/^RUSTFS_SECRET_KEY=//p" "$2/.env")" = keep-this-one-0123456789' _ "$rc" "$G"

# ---- 6. Compose itself (skipped without docker) -----------------------------------
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  : > "$WORK/empty.env"
  dc() { # run docker compose from the repo with an EMPTY environment file
    env -i PATH="$PATH" HOME="$HOME" ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} \
      docker compose --project-directory "$ROOT" --env-file "$WORK/empty.env" "$@"
  }
  services="$(dc -f "$ROOT/docker-compose.yml" config --services 2>"$WORK/dc.err" | sort | tr '\n' ' ')"
  check "docker-compose.yml alone, empty env: exactly caddy and drust" test "$services" = "caddy drust "
  dc -f "$ROOT/docker-compose.yml" -f "$OVERLAY" config -q > "$WORK/dc.out" 2>&1; rc=$?
  check "the storage overlay without keys refuses to parse, naming the generator" \
    sh -c 'test "$1" != 0 && grep -q "run deploy/compose-storage-env.sh" "$2"' _ "$rc" "$WORK/dc.out"
  printf 'RUSTFS_ACCESS_KEY=a\nRUSTFS_SECRET_KEY=b\nGARAGE_S3_ACCESS_KEY=c\nGARAGE_S3_SECRET_KEY=d\n' > "$WORK/dummy.env"
  services="$(env -i PATH="$PATH" HOME="$HOME" ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} \
    docker compose --project-directory "$ROOT" --env-file "$WORK/dummy.env" \
    -f "$ROOT/docker-compose.yml" -f "$OVERLAY" config --services 2>/dev/null | sort | tr '\n' ' ')"
  check "with the overlay and keys: caddy, drust, rustfs, rustfs-init" \
    test "$services" = "caddy drust rustfs rustfs-init "
else
  echo "note: docker not on PATH — skipped the Compose parse checks (item 6)"
fi

echo
if [ "$FAILURES" -gt 0 ]; then
  echo "compose_storage_test: $FAILURES of $CASES checks FAILED" >&2
  exit 1
fi
echo "compose_storage_test: all $CASES checks passed"

#!/usr/bin/env bash
# Static pins for the Compose /public/* route in deploy/compose.Caddyfile and
# the caddy / drust wiring in docker-compose.yml.
#
# /public/* serves tenant bytes from the admin UI's origin straight out of the
# object store, never through drust (CLAUDE.md invariants 14 and 19). Every
# line of that block is load-bearing, and `caddy adapt` / `caddy validate`
# accept a block that has lost any of them: a dropped copy_response serves
# 200 with 0 bytes, a dropped "?" lets an S3 API's ?response-content-type=
# re-serve a public object as unsandboxed HTML, a `handle` instead of
# `handle_path` lets the raw path steer the bucket. The live proof is the
# smoke stack (deploy/smoke/checks/20-files.sh); this catches the edit first.
#
# Pure bash + grep/awk/sed; bash 3.2 (macOS) and GNU bash alike.
#
# Usage: bash deploy/tests/compose_public_route_test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CADDY="$ROOT/deploy/compose.Caddyfile"
COMPOSE="$ROOT/docker-compose.yml"
FILES_RS="$ROOT/src/storage/files.rs"
FAILURES=0
CASES=0

fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
ok()   { echo "ok: $*"; }
check() { # NAME COMMAND...
  local name="$1"; shift
  CASES=$((CASES + 1))
  if "$@"; then ok "$name"; else fail "$name"; fi
}

for f in "$CADDY" "$COMPOSE" "$FILES_RS"; do
  [ -f "$f" ] || { echo "FAIL: $f not found" >&2; exit 1; }
done

# Active (non-comment) text of a Caddyfile: drop full-line comments and the
# trailing " # ..." part of a line. (No Caddyfile token here contains " #".)
active() { sed -e 's/^[[:space:]]*#.*$//' -e 's/[[:space:]]#.*$//' "$1"; }

# The /public block: from the line opening it to its matching closing brace.
public_block="$(active "$CADDY" | awk '
  !on && /^[[:space:]]*handle(_path)?[[:space:]]+\/public\/\*[[:space:]]*\{/ { on = 1 }
  on {
    print
    n = gsub(/\{/, "{"); m = gsub(/\}/, "}")
    depth += n - m
    if (depth == 0) exit
  }')"
# The handle_response @markup block inside it.
markup_resp="$(printf '%s\n' "$public_block" | awk '
  !on && /handle_response[[:space:]]+@markup[[:space:]]*\{/ { on = 1 }
  on {
    print
    n = gsub(/\{/, "{"); m = gsub(/\}/, "}")
    depth += n - m
    if (depth == 0) exit
  }')"
has() { printf '%s\n' "$public_block" | grep -qF -- "$1"; }
count_in_block() { printf '%s\n' "$public_block" | grep -cE -- "$1"; }

check "the /public block exists" test -n "$public_block"

# 1. Every UNSAFE_INLINE_CONTENT_TYPES essence, exact and with params.
essences="$(awk '
  /pub const UNSAFE_INLINE_CONTENT_TYPES/ { on = 1; next }
  on && /^\];/ { exit }
  on { line = $0; sub(/\/\/.*/, "", line); while (match(line, /"[^"]*"/)) {
         print substr(line, RSTART + 1, RLENGTH - 2); line = substr(line, RSTART + RLENGTH) } }
' "$FILES_RS")"
check "UNSAFE_INLINE_CONTENT_TYPES was read from files.rs ($(printf '%s\n' "$essences" | grep -c .) essences)" \
  test "$(printf '%s\n' "$essences" | grep -c .)" -ge 4
for e in $essences; do
  check "@markup matches $e exactly" sh -c 'printf "%s\n" "$1" | grep -qE "^[[:space:]]*header Content-Type $2\$"' _ "$public_block" "$e"
  check "@markup matches $e;*" sh -c 'printf "%s\n" "$1" | grep -qF "header Content-Type $2;*"' _ "$public_block" "$e"
done
# 2. The structural +xml pair.
check "@markup matches *+xml" sh -c 'printf "%s\n" "$1" | grep -qE "^[[:space:]]*header Content-Type \*\+xml\$"' _ "$public_block"
check "@markup matches *+xml;*" has 'header Content-Type *+xml;*'

# 3. The CSP value is SANDBOX_CSP verbatim.
sandbox_csp="$(sed -n 's/^pub const SANDBOX_CSP: &str = "\(.*\)";$/\1/p' "$FILES_RS")"
check "SANDBOX_CSP was read from files.rs" test -n "$sandbox_csp"
check "the CSP header is SANDBOX_CSP verbatim" \
  sh -c 'printf "%s\n" "$1" | grep -qF "header Content-Security-Policy \"$2\""' _ "$markup_resp" "$sandbox_csp"
# 4. copy_response inside handle_response @markup.
check "copy_response sits inside handle_response @markup" \
  sh -c 'printf "%s\n" "$1" | grep -qE "^[[:space:]]*copy_response[[:space:]]*$"' _ "$markup_resp"

# 5. handle_path, not handle.
check "the block opens with handle_path /public/* (not handle)" \
  sh -c 'printf "%s\n" "$1" | head -n 1 | grep -qE "^[[:space:]]*handle_path[[:space:]]+/public/\*"' _ "$public_block"
# 6. Exactly one active rewrite, pinning the bucket and dropping the query.
check "exactly one active rewrite in the block" test "$(count_in_block '^[[:space:]]*rewrite[[:space:]]')" = 1
check "that rewrite is 'rewrite * /public{path}?' (bucket pinned, query dropped)" \
  sh -c 'printf "%s\n" "$1" | grep -E "^[[:space:]]*rewrite[[:space:]]" | sed "s/[[:space:]]*$//" | grep -qE "^[[:space:]]*rewrite \* /public\{path\}\?$"' _ "$public_block"
# 7. GET/HEAD only.
check "@write not method GET HEAD" has '@write not method GET HEAD'
check "respond @write 405" has 'respond @write 405'
# 8. Header removals and nosniff.
check "header_up -Authorization" has 'header_up -Authorization'
check "header_up -Cookie" has 'header_up -Cookie'
check 'header_down X-Content-Type-Options "nosniff"' has 'header_down X-Content-Type-Options "nosniff"'
check "header_down -Set-Cookie (the store never sets a cookie on the admin origin)" has 'header_down -Set-Cookie'
# 9. Upstream from PUBLIC_OBJECTS_UPSTREAM; the only Host line is upstream_hostport.
check "upstream is {\$PUBLIC_OBJECTS_UPSTREAM:rustfs:9000}" \
  sh -c 'printf "%s\n" "$1" | grep -qE "^[[:space:]]*reverse_proxy \{\\\$PUBLIC_OBJECTS_UPSTREAM:rustfs:9000\} \{"' _ "$public_block"
check "the only active Host line in the block is header_up Host {upstream_hostport}" \
  sh -c 'test "$(printf "%s\n" "$1" | grep -cE "header_up[[:space:]]+Host[[:space:]]")" = 1 &&
         printf "%s\n" "$1" | grep -qE "header_up Host \{upstream_hostport\}[[:space:]]*$"' _ "$public_block"
# 10. The STORE-SHAPE comments carry the Garage forms; MinIO is marked untested.
check "STORE-SHAPE comment carries the Garage rewrite form" \
  grep -qF 'rewrite * /public{path}? # STORE-SHAPE. Garage s3_web form: rewrite * {path}?' "$CADDY"
check "STORE-SHAPE comment carries the Garage Host form" \
  grep -qF 'header_up Host {upstream_hostport} # STORE-SHAPE. Garage s3_web form: header_up Host "public.web.local"' "$CADDY"
check "the header's minio:9000 row says untested in this release" \
  sh -c 'grep -A1 "^#   minio:9000" "$1" | grep -q "untested in this release"' _ "$CADDY"
# 11. The drust block keeps the rmcp Host.
check 'the drust block keeps header_up Host "127.0.0.1:47826"' \
  sh -c 'active() { sed -e "s/^[[:space:]]*#.*$//" -e "s/[[:space:]]#.*$//" "$1"; }
         active "$1" | grep -qF "header_up Host \"127.0.0.1:47826\""' _ "$CADDY"
# 12. docker-compose.yml wiring.
check "docker-compose.yml sets DRUST_PUBLIC_BASE_URL with an overridable default" \
  grep -qE '^      DRUST_PUBLIC_BASE_URL: \$\{DRUST_PUBLIC_BASE_URL:-' "$COMPOSE"
check "docker-compose.yml sets PUBLIC_OBJECTS_UPSTREAM (default rustfs:9000)" \
  grep -qF 'PUBLIC_OBJECTS_UPSTREAM: ${PUBLIC_OBJECTS_UPSTREAM:-rustfs:9000}' "$COMPOSE"
check "docker-compose.yml declares no minio service" \
  sh -c '! grep -qE "^  minio:" "$1"' _ "$COMPOSE"

echo
if [ "$FAILURES" -gt 0 ]; then
  echo "compose_public_route_test: $FAILURES of $CASES checks FAILED" >&2
  exit 1
fi
echo "compose_public_route_test: all $CASES checks passed"

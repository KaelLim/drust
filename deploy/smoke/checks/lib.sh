# Shared helpers for deploy/smoke/checks/*.sh. Source it; do not execute it.
#
#   . "$(dirname "$0")/lib.sh"
#   new_tenant "my-check"                 # sets TENANT_ID SERVICE_KEY ANON_KEY
#   req GET "$BASE/t/$TENANT_ID/collections" -H "Authorization: Bearer $SERVICE_KEY"
#   check_eq "list collections answers 200" 200 "$STATUS"
#   finish
#
# Needs bash 3.2+, curl and python3 — nothing else, so it runs on a stock Mac.
# Every check talks to the stack that deploy/smoke/up.sh started and reads its
# secrets from deploy/smoke/.env. Nothing here prints a secret.
#
# MCP checks go to the account-level endpoint ($BASE/mcp) with an OAuth access
# token in SMOKE_MCP_TOKEN: run-all.sh mints one per run, and mcp_token mints
# one on demand when a script runs on its own (revoked again on exit). A failed
# mint is not retried within the run, so a broken sign-in cannot use up the
# admin login rate limit. mcp_call takes the tenant from
# $T, never from TENANT_ID, because several scripts switch tenants by setting
# T alone. Each MCP call takes at least 0.2 s (mcp_client.py MIN_CALL_SECS) so
# a run stays far below the endpoint's 600 requests per minute per grant.
#
# MCP_OFF is 1 when up.sh started the stack with SMOKE_DRUST_MCP=off (it records
# that in .env): then no token is minted, and the scripts that know the off
# state (00, 50) check it instead.

set -u

_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMOKE_DIR="$(cd "$_lib_dir/.." && pwd)"
REPO_ROOT="$(cd "$SMOKE_DIR/../.." && pwd)"

if [ ! -f "$SMOKE_DIR/.env" ]; then
  echo "deploy/smoke/.env is missing — run deploy/smoke/up.sh first" >&2
  exit 2
fi
set -a
# shellcheck disable=SC1091
. "$SMOKE_DIR/.env"
set +a

# BASE goes through Caddy, which is what a real client sees (and what the MCP
# endpoint needs: Caddy rewrites Host for the endpoint's Host check).
# DIRECT bypasses Caddy; use it only to compare against BASE.
BASE="http://127.0.0.1:${SMOKE_HTTP_PORT:-48080}"
DIRECT="http://127.0.0.1:${SMOKE_DRUST_PORT:-48826}"
# The account-level MCP endpoint, and the public URL the stack runs with (the
# DRUST_PUBLIC_URL of docker-compose.smoke.yml): the OAuth resource is $PUBLIC_URL/mcp.
MCP_URL="$BASE/mcp"
PUBLIC_URL="http://localhost:${SMOKE_HTTP_PORT:-48080}"
# PUBLIC is this deployment's own /public/* route through Caddy, i.e. what a client
# fetches. It is the same URL on either store, so every public-object assertion
# means the same thing on RustFS and Garage.
PUBLIC="$BASE/public"
SMOKE_STORE="${SMOKE_STORE:-rustfs}"
SMOKE_COMPOSE_PROJECT="${SMOKE_COMPOSE_PROJECT:-drust-smoke}"
ADMIN_PAT="${SMOKE_ADMIN_PAT:?deploy/smoke/.env has no SMOKE_ADMIN_PAT — re-run deploy/smoke/up.sh}"
MCP_OFF=0
[ "${SMOKE_DRUST_MCP:-on}" = off ] && MCP_OFF=1

TMP="$(mktemp -d "${TMPDIR:-/tmp}/drust-smoke.XXXXXX")"
PASS=0
FAIL=0
_tenants=""
# MCP token state of this script: whether it re-minted after a 401 already,
# whether it minted the token it holds (and so revokes it on exit), and whether
# it already noted that no token is available.
_mcp_reminted=0
_mcp_minted_here=0
_mcp_token_noted=0

# On exit: revoke the token this script minted, delete its tenants, remove
# $TMP. A revoke that cannot be shown to have worked fails the script; the exit
# status is otherwise left alone (a script's own EXIT trap calls this last).
_cleanup() {
  local id revoke_ok=1
  _mcp_revoke_own || revoke_ok=0
  for id in $_tenants; do
    curl -sS -o /dev/null -X DELETE "$BASE/admin/api/tenants/$id" \
      -H "Authorization: Bearer $ADMIN_PAT" || true
  done
  rm -rf "$TMP"
  [ "$revoke_ok" = 1 ] || exit 1
}
trap _cleanup EXIT

ok()  { PASS=$((PASS + 1)); printf 'ok    %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '      %s\n' "$2"; return 0; }
note() { printf '      %s\n' "$1"; }

# req METHOD URL [curl args...] — sets STATUS (HTTP code, 000 on transport
# failure), BODY (response body) and HEADERS (response headers, CRLF stripped).
# Call it as a plain statement, never inside $(...) or a pipe.
req() {
  local method="$1" url="$2"
  shift 2
  STATUS="$(curl -sS -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' \
    --max-time "${REQ_TIMEOUT:-30}" -X "$method" "$url" "$@" 2>"$TMP/curl.err")" || STATUS=000
  BODY="$(cat "$TMP/body" 2>/dev/null || true)"
  HEADERS="$(tr -d '\r' < "$TMP/headers" 2>/dev/null || true)"
}

# json PATH — read JSON on stdin, print the value at a dotted path
# ("tenant.id", "items.0.name"). Prints nothing and returns 1 when absent.
json() {
  python3 -c '
import json, sys
try:
    v = json.load(sys.stdin)
    for k in sys.argv[1].split("."):
        if k == "":
            continue
        v = v[int(k)] if isinstance(v, list) else v[k]
except Exception:
    sys.exit(1)
if isinstance(v, (dict, list)):
    print(json.dumps(v, ensure_ascii=False))
elif v is None:
    print("null")
elif isinstance(v, bool):
    print("true" if v else "false")
else:
    print(v)
' "$1"
}

# body PATH — json PATH applied to the last response body.
body() { printf '%s' "$BODY" | json "$1"; }

# header NAME — value of a response header from the last req (case-insensitive).
header() {
  printf '%s\n' "$HEADERS" | awk -v n="$1" -F': ' 'tolower($1) == tolower(n) { sub(/^[^:]*: /, ""); print; exit }'
}

check_eq() { # NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2], got [$3]"; fi
}

check_ne() { # NAME UNEXPECTED ACTUAL
  if [ "$2" != "$3" ]; then ok "$1"; else bad "$1" "did not expect [$2]"; fi
}

check_contains() { # NAME NEEDLE HAYSTACK
  case "$3" in
    *"$2"*) ok "$1" ;;
    *) bad "$1" "expected to find [$2] in: $(printf '%s' "$3" | head -c 300)" ;;
  esac
}

check_not_contains() { # NAME NEEDLE HAYSTACK
  case "$3" in
    *"$2"*) bad "$1" "did not expect [$2] in: $(printf '%s' "$3" | head -c 300)" ;;
    *) ok "$1" ;;
  esac
}

# admin METHOD PATH [JSON] — management-plane call with the admin PAT.
admin() {
  local method="$1" path="$2"
  if [ -n "${3:-}" ]; then
    req "$method" "$BASE$path" -H "Authorization: Bearer $ADMIN_PAT" \
      -H 'Content-Type: application/json' --data "$3"
  else
    req "$method" "$BASE$path" -H "Authorization: Bearer $ADMIN_PAT"
  fi
}

# new_tenant NAME — create a throwaway tenant, deleted again when the script
# exits. Sets TENANT_ID, SERVICE_KEY, ANON_KEY and T (= $BASE/t/$TENANT_ID).
new_tenant() {
  admin POST /admin/api/tenants "{\"name\":\"smoke-$1-$$\"}"
  if [ "$STATUS" != "201" ]; then
    echo "new_tenant: create answered $STATUS: $BODY" >&2
    exit 2
  fi
  TENANT_ID="$(body tenant.id)"
  SERVICE_KEY="$(body initial_tokens.service)"
  ANON_KEY="$(body initial_tokens.anon)"
  T="$BASE/t/$TENANT_ID"
  _tenants="$_tenants $TENANT_ID"
}

# svc / anon METHOD PATH [JSON] — data-plane call on the current tenant.
svc()  { _tenant_call "$SERVICE_KEY" "$@"; }
anon() { _tenant_call "$ANON_KEY" "$@"; }
_tenant_call() {
  local key="$1" method="$2" path="$3"
  if [ -n "${4:-}" ]; then
    req "$method" "$T$path" -H "Authorization: Bearer $key" \
      -H 'Content-Type: application/json' --data "$4"
  else
    req "$method" "$T$path" -H "Authorization: Bearer $key"
  fi
}

# mcp_token — make sure SMOKE_MCP_TOKEN holds an access token for the account
# endpoint. Uses the one run-all.sh passed in, else mints one (and remembers that
# this script minted it). A failed mint is remembered in SMOKE_MCP_TOKEN_FAILED
# and noted once; later calls fail at once without signing in again.
mcp_token() {
  [ -n "${SMOKE_MCP_TOKEN:-}" ] && return 0
  if [ "$MCP_OFF" = 1 ] && [ "$_mcp_token_noted" = 0 ]; then
    note "mcp token unavailable: the stack runs with DRUST_MCP=off (SMOKE_DRUST_MCP=off in .env)"
    _mcp_token_noted=1
  fi
  [ "$MCP_OFF" = 1 ] && return 1
  if [ "${SMOKE_MCP_TOKEN_FAILED:-0}" = 1 ]; then
    if [ "$_mcp_token_noted" = 0 ]; then
      note "mcp token unavailable (an earlier attempt in this run failed; see mcp token above)"
      _mcp_token_noted=1
    fi
    return 1
  fi
  local minted
  minted="$(python3 "$_lib_dir/mcp_client.py" token "$BASE" "$PUBLIC_URL/mcp" 2>"$TMP/mcp-token.err")" || minted=""
  if [ -n "$minted" ]; then
    SMOKE_MCP_TOKEN="$minted"
    export SMOKE_MCP_TOKEN
    _mcp_minted_here=1
    return 0
  fi
  SMOKE_MCP_TOKEN=""
  SMOKE_MCP_TOKEN_FAILED=1
  _mcp_token_noted=1
  # The client's last stderr line names the step, the status and the error code only.
  note "mcp token unavailable: $(tail -n 1 "$TMP/mcp-token.err")"
  return 1
}

# _mcp_revoke_own — revoke the token this script minted itself; a token passed
# in by run-all.sh is left to run-all.sh. The client proves the revoke (the
# token's next call answers 401 MCP_OAUTH_REQUIRED); when it cannot, this
# records a failure whose detail names the cause and how to revoke by hand,
# and returns 1.
_mcp_revoke_own() {
  local rc=0
  if [ "$_mcp_minted_here" = 1 ] && [ -n "${SMOKE_MCP_TOKEN:-}" ]; then
    if ! python3 "$_lib_dir/mcp_client.py" revoke "$BASE" >/dev/null 2>"$TMP/mcp-revoke.err"; then
      bad "the MCP grant this script minted is revoked" "$(tail -n 1 "$TMP/mcp-revoke.err")"
      rc=1
    fi
  fi
  _mcp_minted_here=0
  return "$rc"
}

# _mcp_tenant — the tenant id of $T ($BASE/t/<id>); nothing when T names none.
_mcp_tenant() {
  case "${T:-}" in
    */t/*) printf '%s' "${T##*/t/}" ;;
  esac
}

# _mcp_send ARGS... — run mcp_client.py ARGS with the run's token; sets STATUS
# (the client's exit code) and BODY (its stdout). A 401 MCP_OAUTH_REQUIRED (an
# expired or revoked token) mints a new token once per script and re-sends.
# BODY never goes to a file: it can carry an anon key or an upload ticket.
_mcp_send() {
  if ! mcp_token; then
    STATUS=1
    BODY='{"http_status": 0, "body": "no MCP access token"}'
    return 0
  fi
  BODY="$(python3 "$_lib_dir/mcp_client.py" "$@" 2>"$TMP/mcp.err")"
  STATUS=$?
  if [ "$STATUS" -ne 0 ] && [ "$_mcp_reminted" = 0 ] &&
    [ "$(printf '%s' "$BODY" | python3 "$_lib_dir/mcp_client.py" field remint)" = yes ]; then
    _mcp_reminted=1
    _mcp_revoke_own || true
    SMOKE_MCP_TOKEN=""
    if mcp_token; then
      BODY="$(python3 "$_lib_dir/mcp_client.py" "$@" 2>"$TMP/mcp.err")"
      STATUS=$?
    fi
  fi
  return 0
}

# mcp_call TOOL [JSON_ARGS] — one tools/call on the account endpoint, for the
# tenant of $T. Sets BODY (the JSON-RPC message, or {"http_status","body"} on an
# HTTP failure), STATUS, MCP_IS_ERROR ("false" only for a real result that is
# not isError), MCP_TEXT (the result text, or the error message) and MCP_CODE
# (the error_code of a failure, empty otherwise).
mcp_call() {
  local args="${2:-}"
  [ -n "$args" ] || args='{}'
  _mcp_send tool "$MCP_URL" "$1" "$args" "$(_mcp_tenant)"
  MCP_IS_ERROR="$(printf '%s' "$BODY" | python3 "$_lib_dir/mcp_client.py" field is_error)"
  MCP_TEXT="$(printf '%s' "$BODY" | python3 "$_lib_dir/mcp_client.py" field text)"
  MCP_CODE="$(printf '%s' "$BODY" | python3 "$_lib_dir/mcp_client.py" field code)"
}

# mcp_rpc JSON — send one JSON-RPC message to the account endpoint and put the
# response with the same id in BODY (STATUS 0), or the HTTP failure (STATUS 1).
mcp_rpc() {
  _mcp_send call "$MCP_URL" "$1"
}

# check_mcp_disabled — with MCP off, the account endpoint answers 404
# MCP_DISABLED with its fixed message (route_layer.rs DISABLED) and no-store.
check_mcp_disabled() {
  req POST "$MCP_URL" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
  check_eq "with MCP off, POST /mcp answers 404 MCP_DISABLED" "404 MCP_DISABLED" "$STATUS $(body error_code)"
  check_eq "... with the disabled message" \
    "MCP is disabled on this server; ask the operator (see boot log)" "$(body message)"
  check_eq "... and Cache-Control: no-store" no-store "$(header cache-control)"
}

finish() {
  printf '\n%s: %d passed, %d failed\n' "$(basename "$0")" "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ]
}

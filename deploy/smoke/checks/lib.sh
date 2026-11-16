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
# endpoint needs: Caddy rewrites Host for rmcp's DNS-rebinding guard).
# DIRECT bypasses Caddy; use it only to compare against BASE.
BASE="http://127.0.0.1:${SMOKE_HTTP_PORT:-48080}"
DIRECT="http://127.0.0.1:${SMOKE_DRUST_PORT:-48826}"
# PUBLIC is this deployment's own /public/* route through Caddy, i.e. what a client
# fetches. It is the same URL on either store, so every public-object assertion
# means the same thing on RustFS and Garage.
PUBLIC="$BASE/public"
SMOKE_STORE="${SMOKE_STORE:-rustfs}"
SMOKE_COMPOSE_PROJECT="${SMOKE_COMPOSE_PROJECT:-drust-smoke}"
ADMIN_PAT="${SMOKE_ADMIN_PAT:?deploy/smoke/.env has no SMOKE_ADMIN_PAT — re-run deploy/smoke/up.sh}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/drust-smoke.XXXXXX")"
PASS=0
FAIL=0
_tenants=""

_cleanup() {
  local id
  for id in $_tenants; do
    curl -sS -o /dev/null -X DELETE "$BASE/admin/api/tenants/$id" \
      -H "Authorization: Bearer $ADMIN_PAT" || true
  done
  rm -rf "$TMP"
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

# mcp_call TOOL JSON_ARGS — one stateless MCP tools/call as the service key.
# Sets MCP_TEXT (the first text content block), MCP_IS_ERROR ("true"/"false")
# and leaves the raw JSON-RPC result in BODY.
mcp_call() {
  local payload
  payload="$(python3 -c '
import json, sys
print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": sys.argv[1], "arguments": json.loads(sys.argv[2])}}))
' "$1" "${2:-{\}}")"
  mcp_rpc "$payload"
  MCP_IS_ERROR="$(printf '%s' "$BODY" | json result.isError 2>/dev/null || echo false)"
  MCP_TEXT="$(printf '%s' "$BODY" | json result.content.0.text 2>/dev/null || true)"
}

# mcp_rpc JSON — send one JSON-RPC message to the tenant's MCP endpoint after
# an initialize handshake, and put the matching JSON-RPC response in BODY.
mcp_rpc() {
  python3 "$_lib_dir/mcp_client.py" "$T/mcp" "$SERVICE_KEY" "$1" > "$TMP/mcp.out" 2> "$TMP/mcp.err"
  STATUS=$?
  BODY="$(cat "$TMP/mcp.out")"
}

finish() {
  printf '\n%s: %d passed, %d failed\n' "$(basename "$0")" "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ]
}

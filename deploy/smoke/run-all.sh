#!/usr/bin/env bash
# Run every check in deploy/smoke/checks/ against the running smoke stack.
#
#   deploy/smoke/run-all.sh            # all checks, in filename order
#   deploy/smoke/run-all.sh 10 40      # only the checks whose name starts with 10- or 40-
#
# Exit status is non-zero when any check script failed. Each script's full
# output is kept under deploy/smoke/.last-run/ for reading afterwards, with the
# store that ran in store.txt and whether the run got an MCP access token in
# mcp-token.txt (never the token). Set SMOKE_COMPOSE_PROJECT as for up.sh.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/.last-run"
rm -rf "$out"
mkdir -p "$out"

# Which object store this run checked (up.sh records SMOKE_STORE in .env).
store="$(sed -n 's/^SMOKE_STORE=//p' "$here/.env" 2>/dev/null | tail -n 1)"
echo "store: ${store:-unknown}" | tee "$out/store.txt"

# One OAuth access token for the whole run (the account-level MCP endpoint).
# It lives only in this environment, never in a file, and is revoked on exit.
# Its stderr (step, status and error code only) goes to mcp-token.err, so a
# login back-off message cannot interleave with this script's own output.
SMOKE_MCP_TOKEN="$( set -a; . "$here/.env"; set +a
  python3 "$here/checks/mcp_client.py" token "http://127.0.0.1:${SMOKE_HTTP_PORT:-48080}" \
    "http://localhost:${SMOKE_HTTP_PORT:-48080}/mcp" 2>"$out/mcp-token.err" )" || SMOKE_MCP_TOKEN=""
SMOKE_MCP_TOKEN_FAILED=1
[ -n "$SMOKE_MCP_TOKEN" ] && SMOKE_MCP_TOKEN_FAILED=0
export SMOKE_MCP_TOKEN SMOKE_MCP_TOKEN_FAILED
if [ "$SMOKE_MCP_TOKEN_FAILED" = 0 ]; then
  echo "mcp token: ok" | tee "$out/mcp-token.txt"
else
  echo "mcp token: unavailable ($(tail -n 1 "$out/mcp-token.err" 2>/dev/null))" | tee "$out/mcp-token.txt"
fi
port="$(sed -n 's/^SMOKE_HTTP_PORT=//p' "$here/.env" 2>/dev/null | tail -n 1)"
_revoke() { [ -n "$SMOKE_MCP_TOKEN" ] && python3 "$here/checks/mcp_client.py" revoke "http://127.0.0.1:${port:-${SMOKE_HTTP_PORT:-48080}}" >/dev/null 2>&1; return 0; }
trap _revoke EXIT

failed=""
total=0
for script in "$here"/checks/[0-9]*.sh; do
  name="$(basename "$script" .sh)"
  if [ "$#" -gt 0 ]; then
    want=no
    for prefix in "$@"; do
      case "$name" in "$prefix"-*) want=yes ;; esac
    done
    [ "$want" = yes ] || continue
  fi
  total=$((total + 1))
  start=$(date +%s)
  if bash "$script" > "$out/$name.log" 2>&1; then
    verdict=ok
  else
    verdict=FAIL
    failed="$failed $name"
  fi
  printf '%-5s %-28s %s  (%ss)\n' "$verdict" "$name" \
    "$(tail -n 1 "$out/$name.log")" "$(( $(date +%s) - start ))"
done

echo
if [ -n "$failed" ]; then
  echo "failed:$failed"
  echo "details: $out/<name>.log   (grep '^FAIL' to see the failing checks)"
  exit 1
fi
echo "all $total check scripts passed"

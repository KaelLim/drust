#!/usr/bin/env bash
# Run every check in deploy/smoke/checks/ against the running smoke stack.
#
#   deploy/smoke/run-all.sh            # all checks, in filename order
#   deploy/smoke/run-all.sh 10 40      # only the checks whose name starts with 10- or 40-
#
# Exit status is non-zero when any check script failed or the run's MCP grant
# could not be shown revoked at the end. Each script's full output is kept
# under deploy/smoke/.last-run/ for reading afterwards, with the store that ran
# in store.txt and what became of the run's MCP access token in mcp-token.txt
# (never the token). Set SMOKE_COMPOSE_PROJECT as for up.sh.
#
# A stack that up.sh started with SMOKE_DRUST_MCP=off (recorded in .env) runs
# in off mode: no token is minted, 00 and 50 check the off-state answers
# instead, and every other script is refused (it needs MCP), so the off round
# is "run-all.sh 00 50".
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/.last-run"
rm -rf "$out"
mkdir -p "$out"

# Which object store this run checked (up.sh records SMOKE_STORE in .env).
store="$(sed -n 's/^SMOKE_STORE=//p' "$here/.env" 2>/dev/null | tail -n 1)"
echo "store: ${store:-unknown}" | tee "$out/store.txt"

# Whether up.sh started the stack with MCP off (it records SMOKE_DRUST_MCP).
mcp_mode="$(sed -n 's/^SMOKE_DRUST_MCP=//p' "$here/.env" 2>/dev/null | tail -n 1)"
[ "$mcp_mode" = off ] || mcp_mode=on
# Scripts that check the off state themselves; in off mode the rest are refused.
off_mode_scripts="00-boot 50-mcp"

# One OAuth access token for the whole run (the account-level MCP endpoint).
# It lives only in this environment, never in a file. On exit its grant is
# revoked, and the revoke is proven: the token's next call must answer 401
# MCP_OAUTH_REQUIRED, or the run fails with a line naming the cause. The trap
# goes in before the mint. The mint's stderr (step, status and error code only)
# goes to mcp-token.err, so a login back-off message cannot interleave with this
# script's own output.
port="$(sed -n 's/^SMOKE_HTTP_PORT=//p' "$here/.env" 2>/dev/null | tail -n 1)"
SMOKE_MCP_TOKEN=""
_revoke() {
  [ -n "$SMOKE_MCP_TOKEN" ] || return 0
  if python3 "$here/checks/mcp_client.py" revoke "http://127.0.0.1:${port:-${SMOKE_HTTP_PORT:-48080}}" \
    >/dev/null 2>"$out/mcp-revoke.err"; then
    SMOKE_MCP_TOKEN=""
    echo "mcp token: revoked (its next call answered 401 MCP_OAUTH_REQUIRED)" | tee -a "$out/mcp-token.txt"
    return 0
  fi
  SMOKE_MCP_TOKEN=""
  echo "mcp token: NOT REVOKED ($(tail -n 1 "$out/mcp-revoke.err" 2>/dev/null))" | tee -a "$out/mcp-token.txt"
  return 1
}
_on_exit() { _revoke || exit 1; }
trap _on_exit EXIT

if [ "$mcp_mode" = off ]; then
  SMOKE_MCP_TOKEN_FAILED=1
  echo "mcp token: not minted (the stack runs with DRUST_MCP=off; 00 and 50 check the off state)" \
    | tee "$out/mcp-token.txt"
else
  SMOKE_MCP_TOKEN="$( set -a; . "$here/.env"; set +a
    python3 "$here/checks/mcp_client.py" token "http://127.0.0.1:${SMOKE_HTTP_PORT:-48080}" \
      "http://localhost:${SMOKE_HTTP_PORT:-48080}/mcp" 2>"$out/mcp-token.err" )" || SMOKE_MCP_TOKEN=""
  SMOKE_MCP_TOKEN_FAILED=1
  [ -n "$SMOKE_MCP_TOKEN" ] && SMOKE_MCP_TOKEN_FAILED=0
  if [ "$SMOKE_MCP_TOKEN_FAILED" = 0 ]; then
    echo "mcp token: ok" | tee "$out/mcp-token.txt"
  else
    echo "mcp token: unavailable ($(tail -n 1 "$out/mcp-token.err" 2>/dev/null))" | tee "$out/mcp-token.txt"
  fi
fi
export SMOKE_MCP_TOKEN SMOKE_MCP_TOKEN_FAILED

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
  if [ "$mcp_mode" = off ]; then
    case " $off_mode_scripts " in
      *" $name "*) ;;
      *)
        failed="$failed $name"
        printf '%-5s %-28s %s\n' REFUSED "$name" "needs MCP; the stack runs with DRUST_MCP=off"
        continue ;;
    esac
  fi
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
# Revoke now, while the summary below can still say so; the EXIT trap only
# covers a run that stops early.
_revoke || failed="$failed mcp-revoke"
if [ -n "$failed" ]; then
  echo "failed:$failed"
  echo "details: $out/<name>.log   (grep '^FAIL' to see the failing checks)"
  exit 1
fi
echo "all $total check scripts passed"

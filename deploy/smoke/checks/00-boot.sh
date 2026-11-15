#!/usr/bin/env bash
# Boot sanity: the build that answers is the one we think it is, both through
# Caddy and directly, and the three planes (admin, data, MCP) all respond.
. "$(dirname "$0")/lib.sh"

want="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)"

req GET "$BASE/health"
check_eq "health through Caddy answers 200" 200 "$STATUS"
check_eq "x-drust-version through Caddy matches Cargo.toml" "$want" "$(header x-drust-version)"
check_eq "no x-drust-boot-degraded header" "" "$(header x-drust-boot-degraded)"

req GET "$DIRECT/health"
check_eq "x-drust-version direct matches Cargo.toml" "$want" "$(header x-drust-version)"

req GET "$BASE/"
check_eq "bare root redirects to /login (root base path, no /drust prefix)" "/login" "$(header location)"

admin GET /admin/api/tenants
check_eq "admin PAT lists tenants" 200 "$STATUS"

req GET "$BASE/admin/api/tenants"
check_ne "admin API refuses a request with no credential" 200 "$STATUS"

new_tenant boot
svc GET /collections
check_eq "service key lists collections" 200 "$STATUS"
anon GET /collections
check_eq "anon key lists collections" 200 "$STATUS"

mcp_rpc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
check_eq "MCP tools/list through Caddy returns a result" 0 "$STATUS"
tools="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["result"]["tools"]))' 2>/dev/null || echo 0)"
if [ "$tools" -gt 0 ]; then ok "MCP exposes $tools tools"; else bad "MCP exposes tools" "$BODY"; fi

mcp_call list_collections '{}'
check_eq "MCP list_collections is not an error" false "$MCP_IS_ERROR"

finish

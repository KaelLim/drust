#!/usr/bin/env bash
# Management plane (admin) on the Compose target, root base path (DRUST_BASE_PATH=""):
#   /health + version header; /login form flow with a cookie session (303 target,
#   cookie attributes, wrong-password page, 401/303 content negotiation), logout
#   revokes the session server-side; every nav page and the tenant sidebar pages
#   render 200 with no hardcoded "/drust/" (invariant 15); CHANGELOG viewer shows
#   the running version; tenant lifecycle via /admin/api/tenants (explicit id,
#   list, tokens, duplicate/invalid id, soft-delete refusals on REST + MCP +
#   self-register (E3), id recycle drops the old incarnation's data on REST and
#   MCP (E5) and its keys (invariant 4)); token reroll evicts the old key at once;
#   admin team invite/remove of a throwaway member; owner-only host surfaces answer
#   the owner; backups list/download guards; settings locale/theme round-trip;
#   CLI device flow (start / poll / approval page / CSRF / deny, never approve);
#   whoami; (opt-in, SMOKE_70_PAT_FENCE=1) CLI refresh/logout fence the UI PAT;
#   host audit entries for the above.
# Uses ONE explicit tenant id (created twice: original + recycle), one throwaway
# member admin, at most 3 admin login attempts (1 good, 2 wrong) per run.
. "$(dirname "$0")/lib.sh"

SCRATCH="$TMP/admin70"
mkdir -p "$SCRATCH"
RUN="$$"
TID="smoke-70-adm-$RUN"
MEMBER_EMAIL="smoke-70admin-$RUN@example.com"
MEMBER_ID=""
SESS=""
START_ISO="$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"))')"
want="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)"

_admin70_cleanup() {
  if [ -n "$MEMBER_ID" ]; then
    curl -sS -o /dev/null --max-time 30 -X DELETE "$BASE/admin/team/$MEMBER_ID" \
      -H "Authorization: Bearer $ADMIN_PAT" || true
  fi
  if [ -n "$SESS" ]; then
    curl -sS -o /dev/null --max-time 30 -X POST "$BASE/logout" \
      -H "Cookie: drust_session=$SESS" || true
  fi
  _cleanup
}
trap _admin70_cleanup EXIT

# sreq METHOD PATH [curl args] — management-plane call with the cookie session.
sreq() {
  local method="$1" path="$2"
  shift 2
  req "$method" "$BASE$path" -H "Cookie: drust_session=$SESS" "$@"
}

# py SCRIPT — run python on $BODY (stdin) with extra argv.
py() { local code="$1"; shift; printf '%s' "$BODY" | python3 -c "$code" "$@"; }

# Links (href/src, root-relative, comments stripped, de-duplicated).
LINKS_PY='
import re, sys, html
s = re.sub(r"<!--.*?-->", "", sys.stdin.read(), flags=re.S)
out = set()
for m in re.finditer(r"""(?:href|src)\s*=\s*["\x27]([^"\x27]*)["\x27]""", s):
    v = html.unescape(m.group(1)).split("#")[0]
    if v.startswith("/") and not v.startswith("//"):
        out.add(v)
for v in sorted(out):
    print(v)
'
# Any quoted string literal (attribute value, JS string, fetch arg) starting
# with "/drust/" or equal to "/drust" — comments stripped. Prints count|context.
DRUST_PY='
import re, sys
s = re.sub(r"<!--.*?-->", "", sys.stdin.read(), flags=re.S)
hits = [m.start() for m in re.finditer(r"""["\x27`(]/drust(?:/|["\x27`])""", s)]
ctx = s[max(0, hits[0] - 60):hits[0] + 60].replace("\n", " ") if hits else ""
print("%d|%s" % (len(hits), ctx))
'
drust_refs() { py "$DRUST_PY"; }

# mcp_result_ok NAME — the last mcp_call produced a real JSON-RPC `result`
# with isError != true. lib.sh's MCP_IS_ERROR defaults to "false" when the
# body has no `result` at all (JSON-RPC error, HTTP/transport failure), so a
# bare `check_eq ... false "$MCP_IS_ERROR"` cannot fail; this one can.
mcp_result_ok() {
  local r
  r="$(printf '%s' "$BODY" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); r=d["result"]
    print("ok" if r.get("isError") is not True else "isError")
except Exception:
    print("no-result")' 2>/dev/null)"
  check_eq "$1" ok "$r"
}

# login USER PASS — POST /login form; one bounded back-off if the shared
# per-IP limiter answers 429 (all agents share one IP).
login() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
    req POST "$BASE/login" --data-urlencode "username=$1" --data-urlencode "password=$2"
    [ "$STATUS" != "429" ] && return 0
    [ "$i" = 1 ] && note "login answered 429 (shared IP bucket) — backing off up to ~70s"
    sleep 5
  done
}

# ============================================================== health/version
req GET "$BASE/health"
check_eq "GET /health through Caddy answers 200" 200 "$STATUS"
check_eq "/health body is 'ok'" "ok" "$BODY"
check_eq "x-drust-version matches Cargo.toml (smoke resets DRUST_HIDE_VERSION)" "$want" "$(header x-drust-version)"
req GET "$DIRECT/health"
check_eq "x-drust-version on the direct port matches Cargo.toml" "$want" "$(header x-drust-version)"
if grep -q '^ *DRUST_HIDE_VERSION: "1"' "$REPO_ROOT/docker-compose.yml"; then
  ok "shipped docker-compose.yml sets DRUST_HIDE_VERSION=\"1\" (public image hides the header)"
else
  bad "shipped docker-compose.yml sets DRUST_HIDE_VERSION=\"1\" (public image hides the header)"
fi

req GET "$DIRECT/"
check_eq "drust root / answers 303 to /admin/tenants (no /drust prefix)" "303 /admin/tenants" "$STATUS $(header location)"
req GET "$BASE/admin/public-files"
check_eq "legacy /admin/public-files answers 301" 301 "$STATUS"
check_eq "legacy redirect Location carries the root base path" "/admin/files" "$(header location)"

# ===================================================================== login
req GET "$BASE/login"
check_eq "GET /login renders 200" 200 "$STATUS"
check_contains "login form posts to /login (root base path)" 'action="/login"' "$BODY"
check_contains "login page shows the running version when DRUST_HIDE_VERSION is unset" "v$want" "$BODY"
r="$(drust_refs)"
check_eq "login page has no hardcoded /drust/ reference" 0 "${r%%|*}"
check_eq "login page sends X-Frame-Options DENY (frame guard)" "DENY" "$(header x-frame-options)"

req GET "$BASE/admin/tenants" -H 'Accept: text/html'
check_eq "no-credential browser request to /admin/tenants answers 303" 303 "$STATUS"
check_eq "... and redirects to /login (no /drust prefix)" "/login" "$(header location)"
req GET "$BASE/admin/tenants" -H 'Accept: application/json'
check_eq "no-credential JSON request answers 401" 401 "$STATUS"
check_eq "... with error_code HTTP_401" "HTTP_401" "$(body error_code)"
req GET "$BASE/admin/api/tenants" -H 'Authorization: Bearer drust_pat_not-a-real-token'
check_eq "an invalid admin PAT answers 401 ADMIN_PAT_INVALID (never a redirect)" "401 ADMIN_PAT_INVALID" "$STATUS $(body error_code)"

login "$SMOKE_ADMIN_USERNAME" "smoke-wrong-password-$RUN"
check_eq "wrong password answers 401" 401 "$STATUS"
check_contains "wrong password re-renders the login page with the error banner" "Wrong username or password." "$BODY"
check_eq "wrong password sets no session cookie" "" "$(printf '%s\n' "$HEADERS" | grep -i '^set-cookie: drust_session=' || true)"
login "smoke-no-such-admin-$RUN" "smoke-wrong-password-$RUN"
check_eq "unknown username answers the same 401 (no username oracle)" 401 "$STATUS"

login "$SMOKE_ADMIN_USERNAME" "$SMOKE_ADMIN_PASSWORD"
check_eq "correct password answers 303" 303 "$STATUS"
check_eq "login redirects to /admin/tenants (no /drust prefix)" "/admin/tenants" "$(header location)"
cookie_line="$(printf '%s\n' "$HEADERS" | grep -i '^set-cookie: drust_session=' | head -1)"
SESS="$(printf '%s' "$cookie_line" | sed -n 's/^[Ss]et-[Cc]ookie: drust_session=\([^;]*\);.*/\1/p')"
attrs="$(printf '%s' "$cookie_line" | sed 's/drust_session=[^;]*/drust_session=<v>/')"
if [ -z "$SESS" ]; then
  bad "login issues a drust_session cookie"
  echo "cannot continue without a session" >&2
  finish
  exit 1
fi
ok "login issues a drust_session cookie"
check_contains "session cookie Path=/ (root base path)" "Path=/;" "$attrs"
check_contains "session cookie is HttpOnly" "HttpOnly" "$attrs"
check_contains "session cookie is SameSite=Lax" "SameSite=Lax" "$attrs"
check_contains "session cookie is Secure (DRUST_DEV_NO_SECURE_COOKIES unset)" "Secure" "$attrs"
check_contains "session cookie Max-Age is DRUST_SESSION_TTL_DAYS (default 7d)" "Max-Age=604800" "$attrs"

# ======================================================= tenant create / list
admin POST /admin/api/tenants "{\"id\":\"$TID\",\"name\":\"smoke admin70\"}"
check_eq "create tenant with an explicit id answers 201" 201 "$STATUS"
check_eq "created tenant carries the requested id" "$TID" "$(body tenant.id)"
SERVICE_KEY="$(body initial_tokens.service)"
ANON_KEY="$(body initial_tokens.anon)"
T="$BASE/t/$TID"
_tenants="$_tenants $TID"
same="$(py 'import json,sys; d=json.load(sys.stdin); print("yes" if d["initial_token"]==d["initial_tokens"]["service"] and d["initial_tokens"]["service"]!=d["initial_tokens"]["anon"] else "no")')"
check_eq "create returns distinct service+anon keys; initial_token == service key" yes "$same"

admin POST /admin/api/tenants "{\"id\":\"$TID\",\"name\":\"dup\"}"
check_eq "creating a live tenant id again is a client error (400), not a 500" 400 "$STATUS"
admin POST /admin/api/tenants '{"id":"Smoke_Bad_ID","name":"bad"}'
check_eq "an invalid tenant id (uppercase/underscore) answers 400" 400 "$STATUS"

admin GET /admin/api/tenants
check_eq "GET /admin/api/tenants answers 200" 200 "$STATUS"
listed="$(py 'import json,sys; print("yes" if any(t.get("id")==sys.argv[1] and t.get("name")=="smoke admin70" for t in json.load(sys.stdin)) else "no")' "$TID")"
check_eq "tenant list includes the new tenant with its name" yes "$listed"
admin GET "/admin/tenants/$TID"
check_eq "GET /admin/tenants/<id> answers 303" 303 "$STATUS"
check_eq "... to the tenant overview (root base path)" "/admin/tenants/$TID/_overview" "$(header location)"
admin GET "/admin/api/tenants/$TID/tokens"
check_eq "GET tokens JSON answers 200" 200 "$STATUS"
tk="$(py 'import json,sys; d=json.load(sys.stdin); print("yes" if d["service"]["plaintext"]==sys.argv[1] and d["anon"]["plaintext"]==sys.argv[2] else "no")' "$SERVICE_KEY" "$ANON_KEY")"
check_eq "tokens JSON echoes the issued service+anon keys" yes "$tk"
admin GET "/admin/tenants/smoke-70-no-such-tenant-$RUN/_overview"
check_eq "overview of a nonexistent tenant answers 404" 404 "$STATUS"

# ============================================================ admin UI crawl
crawl_page() { # PATH
  sreq GET "$1"
  case "$STATUS" in
    301|302|303|307|308)
      # Legacy alias / detail redirect: must stay inside the root base path.
      case "$(header location)" in
        /admin/*) ok "link $1 redirects ($STATUS) within the root base path to $(header location)" ;;
        *) bad "link $1 redirects within the root base path" "$STATUS -> $(header location)" ;;
      esac
      return 0 ;;
  esac
  check_eq "page $1 renders 200 with the session cookie" 200 "$STATUS"
  local r
  r="$(drust_refs)"
  if [ "${r%%|*}" = "0" ]; then
    ok "page $1 has no hardcoded /drust/ href/src/action/fetch"
  else
    bad "page $1 has no hardcoded /drust/ href/src/action/fetch" "${r%%|*} hit(s): ${r#*|}"
  fi
}

sreq GET /admin/tenants
check_eq "/admin/tenants renders 200 with the session cookie" 200 "$STATUS"
r="$(drust_refs)"
check_eq "/admin/tenants has no hardcoded /drust/ reference" 0 "${r%%|*}"
py "$LINKS_PY" > "$SCRATCH/nav.txt"
sreq GET "/admin/tenants/$TID/_overview"
check_eq "tenant overview renders 200" 200 "$STATUS"
py "$LINKS_PY" > "$SCRATCH/tenant.txt"
# Nav pages + this tenant's sidebar; other tenants' pages belong to other agents.
cat "$SCRATCH/nav.txt" "$SCRATCH/tenant.txt" | sort -u | while IFS= read -r p; do
  case "$p" in
    /admin/tenants/"$TID"|/admin/tenants/"$TID"/*) echo "$p" ;;
    /admin/tenants/new) : ;;
    /admin/tenants/*) : ;;
    /admin/*|/auth/*) echo "$p" ;;
    *) echo "EXTERNAL $p" ;;
  esac
done > "$SCRATCH/crawl.txt"
n_pages="$(grep -vc '^EXTERNAL ' "$SCRATCH/crawl.txt" || true)"
if [ "${n_pages:-0}" -ge 15 ]; then ok "crawl found $n_pages admin pages one level deep"; else bad "crawl found >= 15 admin pages" "found ${n_pages:-0}"; fi
while IFS= read -r p; do
  case "$p" in
    "EXTERNAL "*) bad "every root-relative link on admin pages stays under /admin or /auth" "${p#EXTERNAL }" ;;
    /admin/tenants) : ;;
    /admin/_docs/changelog) : ;;  # asserted on its own below (one defect, not two FAILs)
    *) crawl_page "$p" ;;
  esac
done < "$SCRATCH/crawl.txt"
note "admin UI is self-contained: no stylesheet/script/image URL outside data: URIs on the crawled pages"

sreq GET /admin/_docs/changelog
check_eq "CHANGELOG viewer (sidebar link on every page) renders 200 in the image" 200 "$STATUS"
check_contains "CHANGELOG viewer shows the v$want section" "v$want" "$BODY"
sreq GET /admin/_metrics
check_eq "owner reads /admin/_metrics (owner-only host surface)" 200 "$STATUS"
check_contains "metrics exposition carries drust_ series" "drust_" "$BODY"
for p in /admin/backups /admin/audit /admin/quota-requests /admin/tenant-cap-requests /admin/files; do
  sreq GET "$p"
  check_eq "owner reads owner-only host surface $p" 200 "$STATUS"
done

# ================================================================== settings
sreq GET /admin/settings
check_eq "settings page renders 200" 200 "$STATUS"
orig_theme="$(py '
import re, sys
s = sys.stdin.read()
m = re.search(r"<select name=\"theme\".*?</select>", s, re.S)
o = re.search(r"<option value=\"([^\"]+)\"\s*selected", m.group(0)) if m else None
print(o.group(1) if o else "system")')"
new_theme="soft-light"; [ "$orig_theme" = "soft-light" ] && new_theme="cozy-dark"
sreq POST /admin/settings/theme --data-urlencode "theme=$new_theme"
check_eq "theme save answers 303" 303 "$STATUS"
check_eq "theme save redirects to /admin/settings" "/admin/settings" "$(header location)"
tc="$(printf '%s\n' "$HEADERS" | grep -i '^set-cookie: drust_theme=' | head -1)"
check_contains "theme cookie mirrors the saved theme with Path=/" "drust_theme=$new_theme; Path=/;" "$tc"
sreq GET /admin/settings
sel="$(py 'import re,sys; s=sys.stdin.read(); m=re.search(r"<select name=\"theme\".*?</select>", s, re.S); o=re.search(r"<option value=\"([^\"]+)\"\s*selected", m.group(0)) if m else None; print(o.group(1) if o else "")')"
check_eq "saved theme is read back from admins.theme (no theme cookie sent)" "$new_theme" "$sel"
sreq POST /admin/settings/theme --data-urlencode "theme=$orig_theme"
check_eq "theme restored to '$orig_theme'" 303 "$STATUS"
sreq POST /admin/settings/theme --data-urlencode "theme=no-such-theme"
check_eq "unknown theme answers 400" 400 "$STATUS"

sreq POST /admin/settings/locale --data-urlencode "locale=zh-TW"
check_eq "locale save answers 303" 303 "$STATUS"
lc="$(printf '%s\n' "$HEADERS" | grep -i '^set-cookie: drust_locale=' | head -1)"
check_contains "locale cookie mirrors zh-TW with Path=/" "drust_locale=zh-TW; Path=/;" "$lc"
sreq GET /admin/settings -H "Cookie: drust_locale=zh-TW"
check_contains "page renders in zh-TW with the locale cookie" '<html lang="zh-TW">' "$BODY"
sreq POST /admin/settings/locale --data-urlencode "locale=en"
check_eq "locale restored to en" 303 "$STATUS"
sreq POST /admin/settings/locale --data-urlencode "locale=xx-YY"
check_eq "unsupported locale answers 400" 400 "$STATUS"

# ============================================== reroll + auth-cache eviction
svc GET /collections
svc GET /collections
check_eq "service key works before reroll (cache warmed)" 200 "$STATUS"
OLD_SERVICE="$SERVICE_KEY"
admin POST "/admin/api/tenants/$TID/tokens/service/reroll"
check_eq "service reroll answers 201" 201 "$STATUS"
check_eq "reroll response names the role" service "$(body role)"
NEW_SERVICE="$(body token)"
diff="$(python3 -c 'import sys; print("yes" if sys.argv[1] and sys.argv[1]!=sys.argv[2] else "no")' "$NEW_SERVICE" "$OLD_SERVICE")"
check_eq "reroll returns a new, different service key" yes "$diff"
svc GET /collections
check_eq "old service key is refused immediately after reroll (cache evicted)" "401 UNAUTHENTICATED" "$STATUS $(body error_code)"
SERVICE_KEY="$NEW_SERVICE"
svc GET /collections
check_eq "new service key works" 200 "$STATUS"
anon GET /collections
check_eq "anon key is untouched by a service reroll" 200 "$STATUS"
admin POST "/admin/api/tenants/$TID/tokens/admin/reroll"
check_eq "reroll of an unknown role answers 400 TYPE_MISMATCH" "400 TYPE_MISMATCH" "$STATUS $(body error_code)"
admin POST "/admin/api/tenants/smoke-70-no-such-tenant-$RUN/tokens/service/reroll"
check_eq "reroll on a nonexistent tenant answers 404" 404 "$STATUS"

# ================================ first incarnation data (REST + MCP cache warm)
mcp_call create_collection '{"name":"probe_old","fields":[{"name":"x","sql_type":"text"}]}'
mcp_result_ok "MCP create_collection probe_old in the first incarnation returns a result"
svc POST /records/probe_old '{"data":{"x":"first-incarnation"}}'
check_eq "insert a row into probe_old" 201 "$STATUS"
mcp_call list_collections '{}'
check_contains "MCP sees probe_old in the first incarnation (MCP cache now holds its pool)" "probe_old" "$MCP_TEXT"
admin POST "/admin/tenants/$TID/allow-self-register" '{"enabled":true}'
check_eq "self-registration toggled on" true "$(body enabled)"

# ======================================================= soft-delete refusals
admin DELETE "/admin/api/tenants/$TID"
check_eq "soft-delete answers 204" 204 "$STATUS"
svc GET /collections
check_eq "data plane refuses the deleted tenant's service key: 404 TENANT_NOT_FOUND" "404 TENANT_NOT_FOUND" "$STATUS $(body error_code)"
anon GET /collections
check_eq "data plane refuses the deleted tenant's anon key: 404 TENANT_NOT_FOUND" "404 TENANT_NOT_FOUND" "$STATUS $(body error_code)"
mcp_rpc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
check_eq "MCP on the deleted tenant answers HTTP 404" 404 "$(body http_status)"
reg_body="{\"email\":\"smoke70-$RUN@example.com\",\"password\":\"smoke-pass-$RUN-long\"}"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
  req POST "$T/auth/register" -H 'Content-Type: application/json' --data "$reg_body"
  [ "$STATUS" != "429" ] && break
  [ "$i" = 1 ] && note "register answered 429 (shared IP bucket) — backing off up to ~70s"
  sleep 5
done
check_eq "self-register on a soft-deleted tenant answers 403 SELF_REGISTER_DISABLED (E3)" "403 SELF_REGISTER_DISABLED" "$STATUS $(body error_code)"
admin GET "/admin/api/tenants/$TID/tokens"
check_eq "tokens JSON for the deleted tenant answers 404" 404 "$STATUS"
admin GET /admin/api/tenants
gone="$(py 'import json,sys; print("no" if any(t.get("id")==sys.argv[1] for t in json.load(sys.stdin)) else "yes")' "$TID")"
check_eq "tenant list no longer shows the deleted tenant" yes "$gone"
sreq GET "/admin/tenants/$TID/_overview"
check_eq "overview of the deleted tenant answers 404" 404 "$STATUS"
admin DELETE "/admin/api/tenants/$TID"
check_eq "deleting it again answers 404" 404 "$STATUS"

# ================================================================ id recycle
OLD_SERVICE="$SERVICE_KEY"
admin POST /admin/api/tenants "{\"id\":\"$TID\",\"name\":\"smoke admin70 recycled\"}"
check_eq "re-creating the soft-deleted id (recycle) answers 201" 201 "$STATUS"
NEW_SERVICE="$(body initial_tokens.service)"
ANON_KEY="$(body initial_tokens.anon)"
svc GET /collections
check_eq "previous incarnation's service key is refused after recycle (401)" "401 UNAUTHENTICATED" "$STATUS $(body error_code)"
SERVICE_KEY="$NEW_SERVICE"
svc GET /collections
check_eq "recycled tenant's new service key works" 200 "$STATUS"
check_not_contains "REST on the recycled tenant does not see the old incarnation's collection" "probe_old" "$BODY"
svc GET /records/probe_old
check_eq "the old incarnation's collection does not exist on the recycled tenant" 404 "$STATUS"
# Positive control first: MCP must answer on the recycled tenant AND see a
# collection made in THIS incarnation, so the "no probe_old" check below cannot
# pass on an empty/failed MCP answer.
mcp_call create_collection '{"name":"probe_new","fields":[{"name":"x","sql_type":"text"}]}'
mcp_result_ok "MCP create_collection probe_new on the recycled tenant returns a result"
mcp_call list_collections '{}'
mcp_result_ok "MCP list_collections on the recycled tenant returns a result"
check_contains "MCP on the recycled tenant lists this incarnation's probe_new" "probe_new" "$MCP_TEXT"
check_not_contains "MCP on the recycled tenant does not serve the old incarnation's pool (E5)" "probe_old" "$MCP_TEXT"
admin GET /admin/api/tenants
renamed="$(py 'import json,sys; print(next((t.get("name") for t in json.load(sys.stdin) if t.get("id")==sys.argv[1]), ""))' "$TID")"
check_eq "tenant list shows the recycled tenant's new name" "smoke admin70 recycled" "$renamed"

# ================================================================ admin team
admin GET /admin/team -H 'Accept: application/json'
check_eq "team roster JSON answers 200 to the owner" 200 "$STATUS"
admin POST /admin/team "{\"email\":\"$MEMBER_EMAIL\",\"role\":\"member\"}"
check_eq "invite a member admin answers 201" 201 "$STATUS"
MEMBER_ID="$(body id)"
check_eq "invited admin has role member" member "$(body role)"
admin GET /admin/team -H 'Accept: application/json'
mrole="$(py 'import json,sys; d=json.load(sys.stdin); print(next((a["role"] for a in d["admins"] if str(a["id"])==sys.argv[1]), ""))' "$MEMBER_ID")"
check_eq "roster lists the member with role member" member "$mrole"
admin POST /admin/team "{\"email\":\"$MEMBER_EMAIL\",\"role\":\"member\"}"
check_eq "inviting the same email again answers 409 ADMIN_EMAIL_TAKEN" "409 ADMIN_EMAIL_TAKEN" "$STATUS $(body error_code)"
admin POST /admin/team '{"email":"not-an-email","role":"member"}'
check_eq "an invalid email answers 400 INVALID_EMAIL" "400 INVALID_EMAIL" "$STATUS $(body error_code)"
admin POST /admin/team "{\"email\":\"x-$MEMBER_EMAIL\",\"role\":\"superuser\"}"
check_eq "an unknown role answers 400 INVALID_ROLE" "400 INVALID_ROLE" "$STATUS $(body error_code)"
admin PATCH "/admin/team/$MEMBER_ID/role" '{"role":"superuser"}'
check_eq "role change to an unknown role answers 400" 400 "$STATUS"
if [ -n "$MEMBER_ID" ]; then
  admin DELETE "/admin/team/$MEMBER_ID"
  check_eq "remove the member admin answers 200 {removed:true}" "200 true" "$STATUS $(body removed)"
  removed_id="$MEMBER_ID"
  admin DELETE "/admin/team/$MEMBER_ID"
  check_eq "removing it again answers 404 ADMIN_NOT_FOUND" "404 ADMIN_NOT_FOUND" "$STATUS $(body error_code)"
  MEMBER_ID=""
else
  removed_id=""
fi

# =================================================== CLI device + PAT lifecycle
req POST "$BASE/auth/cli/device/start" -H 'Content-Type: application/json' --data '{"client_name":"smoke-70"}'
check_eq "device/start answers 200" 200 "$STATUS"
DEVICE_CODE="$(body device_code)"
USER_CODE="$(body user_code)"
check_eq "verification_uri is DRUST_PUBLIC_URL + /auth/cli/device (no /drust)" "http://localhost:${SMOKE_HTTP_PORT:-48080}/auth/cli/device" "$(body verification_uri)"
check_eq "poll interval is advertised" 5 "$(body interval)"
dc="$(printf '{"device_code":"%s"}' "$DEVICE_CODE")"
req POST "$BASE/auth/cli/device/poll" -H 'Content-Type: application/json' --data "$dc"
check_eq "first poll of a fresh code answers 200 pending" "200 pending" "$STATUS $(body status)"
req POST "$BASE/auth/cli/device/poll" -H 'Content-Type: application/json' --data "$dc"
check_eq "an immediate second poll answers slow_down" "200 slow_down" "$STATUS $(body status)"
req POST "$BASE/auth/cli/device/poll" -H 'Content-Type: application/json' --data '{"device_code":"smoke-unknown-device-code"}'
check_eq "an unknown device_code polls as expired (no enumeration)" "200 expired" "$STATUS $(body status)"
req GET "$BASE/auth/cli/device?user_code=$USER_CODE" -H 'Accept: text/html'
check_eq "approval page without a session redirects to /login" "303 /login" "$STATUS $(header location)"
sreq GET "/auth/cli/device?user_code=$USER_CODE"
check_eq "approval page renders 200 with the session" 200 "$STATUS"
check_contains "approval page shows the user code" "$USER_CODE" "$BODY"
check_contains "approval page posts deny to /auth/cli/device/deny (root base path)" 'action="/auth/cli/device/deny"' "$BODY"
csrf_line="$(printf '%s\n' "$HEADERS" | grep -i '^set-cookie: drust_cli_csrf=' | head -1)"
CSRF="$(printf '%s' "$csrf_line" | sed -n 's/^[Ss]et-[Cc]ookie: drust_cli_csrf=\([^;]*\);.*/\1/p')"
check_contains "CSRF cookie is Path=/ HttpOnly SameSite=Lax" "Path=/; HttpOnly; SameSite=Lax" "$(printf '%s' "$csrf_line" | sed 's/drust_cli_csrf=[^;]*/drust_cli_csrf=<v>/')"
formcsrf="$(py 'import re,sys; m=re.search(r"name=\"csrf\" value=\"([^\"]+)\"", sys.stdin.read()); print(m.group(1) if m else "")')"
eqc="$(python3 -c 'import sys; print("yes" if sys.argv[1] and sys.argv[1]==sys.argv[2] else "no")' "$CSRF" "$formcsrf")"
check_eq "CSRF cookie equals the hidden form field (double submit)" yes "$eqc"
sreq POST /auth/cli/device/deny --data-urlencode "user_code=$USER_CODE" --data-urlencode "csrf=forged-$RUN" -H "Cookie: drust_cli_csrf=forged-$RUN"
check_eq "deny with a forged CSRF pair answers 403 CSRF_MISMATCH" "403 CSRF_MISMATCH" "$STATUS $(body error_code)"
req POST "$BASE/auth/cli/device/deny" -H "Cookie: drust_session=$SESS; drust_cli_csrf=$CSRF" \
  --data-urlencode "user_code=$USER_CODE" --data-urlencode "csrf=$formcsrf"
check_eq "deny with the issued CSRF pair answers 200" 200 "$STATUS"
for i in 1 2 3 4 5 6 7; do
  req POST "$BASE/auth/cli/device/poll" -H 'Content-Type: application/json' --data "$dc"
  [ "$(body status)" != "slow_down" ] && break
  sleep 1
done
check_eq "poll after deny answers denied" "200 denied" "$STATUS $(body status)"

req GET "$BASE/auth/cli/whoami" -H "Authorization: Bearer $ADMIN_PAT"
check_eq "whoami with the admin UI PAT answers 200" 200 "$STATUS"
check_eq "whoami tenants_endpoint is /admin/api/cmdk/tenants" "/admin/api/cmdk/tenants" "$(body tenants_endpoint)"
check_eq "whoami console host is DRUST_PUBLIC_URL" "http://localhost:${SMOKE_HTTP_PORT:-48080}" "$(body consoles.0.host)"
req GET "$BASE/auth/cli/whoami"
check_eq "whoami without a PAT answers 401 CLI_AUTH_REQUIRED (JSON, not a redirect)" "401 CLI_AUTH_REQUIRED" "$STATUS $(body error_code)"
# The two fence checks below present the SHARED admin PAT to endpoints whose job
# is to rotate / revoke the presented token. Today's source fences the UI PAT
# twice (admin_pat.rs cli_token_refresh `label.is_none()` -> 403, and
# cli_token_logout's `label IS NOT NULL` predicate), but if a future build
# regressed, running this script would revoke the PAT every concurrent smoke
# agent shares. So they are opt-in: SMOKE_70_PAT_FENCE=1 on a stack you own.
if [ "${SMOKE_70_PAT_FENCE:-0}" = 1 ]; then
  req POST "$BASE/auth/cli/token/refresh" -H "Authorization: Bearer $ADMIN_PAT"
  check_eq "refresh refuses the unlabeled UI PAT: 403 NOT_A_CLI_TOKEN" "403 NOT_A_CLI_TOKEN" "$STATUS $(body error_code)"
  req DELETE "$BASE/auth/cli/token" -H "Authorization: Bearer $ADMIN_PAT"
  check_eq "CLI logout with the UI PAT revokes nothing" "200 false" "$STATUS $(body revoked)"
  admin GET /admin/api/tenants
  check_eq "shared admin PAT still works after the CLI lifecycle calls" 200 "$STATUS"
else
  note "UI-PAT refresh/logout fence not exercised (shared PAT); set SMOKE_70_PAT_FENCE=1 to run it"
fi

# =================================================================== backups
admin GET /admin/api/backups
check_eq "backups JSON answers 200 to the owner" 200 "$STATUS"
nb="$(py 'import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else -1)')"
if [ "${nb:-x}" -ge 0 ] 2>/dev/null; then ok "backups JSON is an array ($nb snapshot(s))"; else bad "backups JSON is an array" "$(printf '%s' "$BODY" | head -c 200)"; fi
if [ "${nb:-0}" -gt 0 ]; then
  fname="$(body 0.filename)"; fsize="$(body 0.size_bytes)"
  REQ_TIMEOUT=120 req GET "$BASE/admin/backups/$fname/download" -H "Authorization: Bearer $ADMIN_PAT" -o /dev/null
  check_eq "download of $fname answers 200" 200 "$STATUS"
  check_eq "download Content-Length equals the listed size" "$fsize" "$(header content-length)"
else
  note "no snapshot exists: nothing on the Compose target produces one (see report)"
fi
admin GET "/admin/backups/drust-1999-01-01-000000.tar.zst/download"
check_eq "download of a missing snapshot answers 404" 404 "$STATUS"
admin GET "/admin/backups/meta.sqlite/download"
check_eq "download of a non-snapshot filename answers 400" 400 "$STATUS"
admin GET "/admin/api/backups/drust-1999-01-01-000000.tar.zst/inspect"
check_eq "inspect of a missing snapshot answers 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"

# ===================================================================== audit
# AUDIT_FIND SCOPE_TENANT KIND [ARG] — search /admin/api/audit browse entries
# since START_ISO. Prints yes/no.
AUDIT_PY='
import json, sys
d = json.load(sys.stdin)
since, kind, arg, tid = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
# Admin-plane entry: an "admin.*"/"tenant.*"-style op name, or an HTTP-shaped op
# on an /admin path. Data-plane ops ("GET /collections", ...) never count.
def admin_op(e):
    op = e.get("op") or ""
    parts = op.split(" ", 1)
    if len(parts) == 2 and parts[0] in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        return parts[1].startswith("/admin")
    return True
hit = False
for e in d.get("entries", []):
    if (e.get("ts") or "") < since:
        continue
    op = e.get("op") or ""
    blob = json.dumps(e)
    if kind == "login_ok":
        hit = op == "POST /login" and e.get("status") == "ok"
    elif kind == "login_fail":
        hit = op == "POST /login" and e.get("error_code") == "HTTP_401"
    elif kind == "invite":
        hit = op == "admin.team.invite" and arg in blob
    elif kind == "remove":
        # admins.id has no AUTOINCREMENT, so ids recur across runs: match the
        # run-unique email the entry carries, not the id.
        hit = op == "admin.team.remove" and (e.get("extra") or {}).get("removed_email") == arg
    elif kind == "deny":
        hit = op == "POST /auth/cli/device/deny" and arg in blob
    elif kind in ("create", "delete", "reroll"):
        words = {"create": ("create", "post /admin/api/tenants", "/admin/tenants/new"),
                 "delete": ("delete", "soft"),
                 "reroll": ("reroll", "rotate", "token")}[kind]
        hit = tid in blob and admin_op(e) and any(w in op.lower() for w in words)
    if hit:
        break
print("yes" if hit else "no")
'
audit_find() { # TENANT_SCOPE KIND ARG
  local i res=no
  for i in 1 2 3 4 5 6 7 8; do
    admin GET "/admin/api/audit?tab=browse&window=1h&tenant=$1"
    res="$(py "$AUDIT_PY" "$START_ISO" "$2" "${3:-}" "$TID" 2>/dev/null || echo no)"
    [ "$res" = yes ] && break
    sleep 1
  done
  echo "$res"
}
admin GET "/admin/api/audit?tab=browse&window=1h"
check_eq "host audit JSON answers 200 to the owner" 200 "$STATUS"
# POST /login entries carry no username (extra = {admin_id, auth_kind}), and every
# agent logs in as the shared admin, so these two can only assert "an entry
# appeared since this run started" — not that it is this run's own.
check_eq "host audit records a successful admin password login (since run start)" yes "$(audit_find - login_ok)"
check_eq "host audit records failed admin logins as HTTP_401 (since run start)" yes "$(audit_find - login_fail)"
check_eq "host audit records admin.team.invite for the member" yes "$(audit_find - invite "$MEMBER_EMAIL")"
if [ -n "$removed_id" ]; then
  check_eq "host audit records admin.team.remove for the member" yes "$(audit_find - remove "$MEMBER_EMAIL")"
fi
check_eq "host audit records the CLI device deny" yes "$(audit_find - deny "$USER_CODE")"
admin GET "/admin/api/audit?tab=browse&window=1h&tenant=$TID"
check_contains "host audit records data-plane calls on the tenant" "GET /collections" "$BODY"
# Admin-plane tenant lifecycle + credential rotation (convention: every admin
# mutation gets an admin.<area>.<verb> audit entry — CHANGELOG v1.31.x F15).
c="$(audit_find - create)"; [ "$c" = no ] && c="$(audit_find "$TID" create)"
check_eq "host audit records the admin-plane tenant create (admin.<area>.<verb> convention)" yes "$c"
c="$(audit_find - reroll)"; [ "$c" = no ] && c="$(audit_find "$TID" reroll)"
check_eq "host audit records the tenant service-key reroll (credential rotation)" yes "$c"
c="$(audit_find - delete)"; [ "$c" = no ] && c="$(audit_find "$TID" delete)"
check_eq "host audit records the tenant soft-delete" yes "$c"

# ==================================================================== logout
OLD_SESS="$SESS"
req POST "$BASE/logout" -H "Cookie: drust_session=$OLD_SESS"
check_eq "logout answers 303" 303 "$STATUS"
check_eq "logout redirects to /login (no /drust prefix)" "/login" "$(header location)"
clr="$(printf '%s\n' "$HEADERS" | grep -i '^set-cookie: drust_session=' | head -1)"
check_contains "logout clears the session cookie on Path=/" "drust_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" "$clr"
SESS=""
req GET "$BASE/admin/tenants" -H "Cookie: drust_session=$OLD_SESS" -H 'Accept: text/html'
check_eq "the logged-out session cookie no longer authenticates (303 /login)" "303 /login" "$STATUS $(header location)"
OLD_SESS=""

finish

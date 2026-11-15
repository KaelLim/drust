#!/usr/bin/env bash
# Jobs surface: stored RPC (kind='sql' read/write, kind='query'), anon_callable
# semantics + RPC_ANON_OWNER_SCOPED config-time guard, validate_rpc_sql
# refusals, write-RPC record history via the preupdate hook (rusqlite 0.42),
# the read query deadline (progress handler, rusqlite 0.42), cron (a real
# minute fire of a write RPC + limits/error codes), webhooks + egress allowlist
# (deny-all default, register-time private-IP refusal even when allowlisted,
# dispatch-time egress denial recorded on the subscription, registration cap).
# Uses 3 throwaway tenants; never makes an outbound connection to a third party
# (the only allowlisted origin is the TEST-NET-1 literal 192.0.2.10, and it is
# removed from the allowlist before any write that could fan out to it).
. "$(dirname "$0")/lib.sh"

SCRIPT_START=$(date +%s)

# ── helpers local to this script ────────────────────────────────────────────

# req with bounded back-off on 429 (per-token rate limit is 60 / 10 s and the
# same budget also counts MCP round-trips). Overrides lib.sh's req in this
# script only.
eval "_lib_req() $(declare -f req | sed '1d')"
req() {
  local i=0
  while :; do
    _lib_req "$@"
    if [ "$STATUS" != "429" ] || [ "$i" -ge 8 ]; then return 0; fi
    local ra
    ra="$(header retry-after)"
    case "$ra" in ''|*[!0-9]*) ra=2 ;; esac
    [ "$ra" -gt 10 ] && ra=10
    sleep "$ra"
    i=$((i + 1))
  done
}

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

# pyj EXPR — evaluate a python expression over the JSON on stdin (bound to d);
# prints the result (json-encoded for containers), or __ERR__ on any failure.
pyj() {
  python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read() or "null")
    r = eval(sys.argv[1], {"d": d, "json": json})
    if isinstance(r, bool):
        print("true" if r else "false")
    elif isinstance(r, (dict, list)):
        print(json.dumps(r, ensure_ascii=False, sort_keys=True))
    elif r is None:
        print("null")
    else:
        print(r)
except Exception:
    print("__ERR__")
' "$1"
}
bodyj() { printf '%s' "$BODY" | pyj "$1"; }

# Session-reusing MCP client: one initialize per tenant per run, then one HTTP
# request per tool call (lib.sh's mcp_call does 3 per call, which burns the
# per-token rate budget). Retries 429 with Retry-After; re-initializes when the
# server forgets the session.
cat > "$TMP/mcpc.py" <<'PY'
import json, os, sys, time, urllib.error, urllib.request
url, bearer, sidfile, message = sys.argv[1], sys.argv[2], sys.argv[3], json.loads(sys.argv[4])
PV = "2025-06-18"
def post(msg, sid=None, proto=None):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
         "Authorization": "Bearer " + bearer}
    if sid: h["Mcp-Session-Id"] = sid
    if proto: h["MCP-Protocol-Version"] = proto
    for attempt in range(10):
        req = urllib.request.Request(url, data=json.dumps(msg).encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return r.status, r.headers, r.headers.get("Content-Type", ""), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 9:
                ra = e.headers.get("Retry-After", "2")
                time.sleep(min(10, int(ra) if ra.isdigit() else 2))
                continue
            return e.code, e.headers, e.headers.get("Content-Type", ""), e.read().decode("utf-8", "replace")
def pick(ctype, raw, want):
    msgs = []
    if "text/event-stream" in ctype:
        for line in raw.splitlines():
            if line.startswith("data:") and line[5:].strip():
                try: msgs.append(json.loads(line[5:].strip()))
                except ValueError: pass
    elif raw.strip():
        try:
            p = json.loads(raw); msgs = p if isinstance(p, list) else [p]
        except ValueError: pass
    for m in msgs:
        if isinstance(m, dict) and m.get("id") == want: return m
    return None
def init():
    st, hd, ct, raw = post({"jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": PV, "capabilities": {}, "clientInfo": {"name": "drust-smoke-80", "version": "1"}}})
    m = pick(ct, raw, 0)
    if st != 200 or m is None: return None, None
    sid = hd.get("Mcp-Session-Id"); proto = m.get("result", {}).get("protocolVersion", PV)
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, proto)
    with open(sidfile, "w") as f: f.write(json.dumps({"sid": sid, "proto": proto}))
    return sid, proto
sid = proto = None
if os.path.exists(sidfile):
    try:
        s = json.load(open(sidfile)); sid, proto = s["sid"], s["proto"]
    except Exception: pass
if not sid:
    sid, proto = init()
for _ in range(2):
    st, hd, ct, raw = post(message, sid, proto)
    ans = pick(ct, raw, message.get("id"))
    if ans is not None:
        print(json.dumps(ans, ensure_ascii=False)); sys.exit(0)
    if st in (400, 404, 410):
        sid, proto = init(); continue
    break
print(json.dumps({"http_status": st, "body": raw[:2000]})); sys.exit(1)
PY

# mcp TOOL JSON_ARGS — service-key tools/call on the current tenant. Sets
# MCP_OK (true when a result that is not isError), MCP_TEXT (result text or the
# error message), MCP_CODE (data.error_code when present), BODY (raw).
_mcp_id=1
mcp() {
  _mcp_id=$((_mcp_id + 1))
  local payload
  payload="$(python3 -c '
import json, sys
print(json.dumps({"jsonrpc": "2.0", "id": int(sys.argv[3]), "method": "tools/call",
                  "params": {"name": sys.argv[1], "arguments": json.loads(sys.argv[2])}}))
' "$1" "$2" "$_mcp_id")"
  python3 "$TMP/mcpc.py" "$T/mcp" "$SERVICE_KEY" "$TMP/mcp-$TENANT_ID.sid" "$payload" > "$TMP/mcp.out" 2>"$TMP/mcp.err" || true
  BODY="$(cat "$TMP/mcp.out")"
  MCP_OK="$(bodyj '("result" in d) and not d["result"].get("isError", False)')"
  MCP_TEXT="$(bodyj 'd["result"]["content"][0]["text"] if "result" in d else d["error"]["message"]')"
  MCP_CODE="$(bodyj '(d.get("error", {}).get("data") or {}).get("error_code", "")')"
}

# Remember / switch between this run's tenants (lib.sh's helpers use globals).
save_tenant() { eval "TID_$1=\$TENANT_ID; SVC_$1=\$SERVICE_KEY; ANON_$1=\$ANON_KEY"; }
use_tenant() {
  eval "TENANT_ID=\$TID_$1; SERVICE_KEY=\$SVC_$1; ANON_KEY=\$ANON_$1"
  T="$BASE/t/$TENANT_ID"
}

setup_ok() { # NAME — a setup step must succeed or the dependent checks are meaningless
  if [ "$MCP_OK" = "true" ]; then ok "$1"; else bad "$1" "$(printf '%s' "$MCP_TEXT" | head -c 300)"; fi
}

# ═══════════════════════════════════════════════════════════════════════════
# Tenant B (cron) first, so its minute fire happens while A and C run.
# ═══════════════════════════════════════════════════════════════════════════
new_tenant jobs-cron
save_tenant B

mcp create_collection '{"name":"items","fields":[{"name":"title","sql_type":"text"},{"name":"n","sql_type":"integer"}]}'
setup_ok "cron tenant: create_collection items"
mcp create_rpc '{"name":"w_ins","mode":"write","sql":"INSERT INTO items(title, n) VALUES(:t, 7)","params":[{"name":"t","type":"text"}]}'
setup_ok "cron tenant: create write RPC w_ins"
mcp create_rpc '{"name":"q_items","kind":"query","query":{"collection":"items"},"params":[]}'
setup_ok "cron tenant: create kind=query RPC q_items"
mcp create_rpc '{"name":"r_uid","sql":"SELECT id FROM items WHERE title = :user_id","params":[{"name":"user_id","type":"text"}]}'
setup_ok "cron tenant: create read RPC r_uid declaring :user_id"

# A per-run unique marker, so a re-run never mistakes an old row for this fire.
CRON_MARK="cron-fire-$$-$SCRIPT_START"
svc POST /cron "{\"name\":\"tick\",\"schedule\":\"* * * * *\",\"target_kind\":\"rpc\",\"target_name\":\"w_ins\",\"payload_json\":\"{\\\"t\\\":\\\"$CRON_MARK\\\"}\"}"
check_eq "cron: every-minute job targeting a write RPC is created (201)" 201 "$STATUS"
check_ne "cron: created job reports a next_fire" "" "$(body next_fire)"
CRON_CREATED=$(date +%s)

svc POST /cron '{"name":"six","schedule":"*/5 * * * * *","target_kind":"rpc","target_name":"w_ins"}'
check_eq "cron: a 6-field (seconds) schedule is refused 400" 400 "$STATUS"
check_eq "cron: 6-field schedule error code is CRON_INVALID_SCHEDULE" CRON_INVALID_SCHEDULE "$(body error_code)"
svc POST /cron '{"name":"alias","schedule":"@hourly","target_kind":"rpc","target_name":"w_ins"}'
check_eq "cron: an @alias schedule is refused with CRON_INVALID_SCHEDULE" "400 CRON_INVALID_SCHEDULE" "$STATUS $(body error_code)"
svc POST /cron '{"name":"qkind","schedule":"* * * * *","target_kind":"rpc","target_name":"q_items"}'
check_eq "cron: a kind=query RPC target is refused 409 CRON_RPC_QUERY_KIND" "409 CRON_RPC_QUERY_KIND" "$STATUS $(body error_code)"
svc POST /cron '{"name":"uid","schedule":"* * * * *","target_kind":"rpc","target_name":"r_uid"}'
check_eq "cron: an RPC declaring :user_id is refused 409 CRON_RPC_USER_ID" "409 CRON_RPC_USER_ID" "$STATUS $(body error_code)"
svc POST /cron '{"name":"ghost","schedule":"* * * * *","target_kind":"rpc","target_name":"no_such_rpc"}'
check_eq "cron: a missing RPC target is refused 404 CRON_TARGET_NOT_FOUND" "404 CRON_TARGET_NOT_FOUND" "$STATUS $(body error_code)"
svc POST /cron '{"name":"tick","schedule":"* * * * *","target_kind":"rpc","target_name":"w_ins","active":false}'
check_eq "cron: a duplicate job name is refused 409 CRON_DUPLICATE" "409 CRON_DUPLICATE" "$STATUS $(body error_code)"
svc POST /cron '{"name":"Bad Name","schedule":"* * * * *","target_kind":"rpc","target_name":"w_ins","active":false}'
check_eq "cron: an invalid job name is refused 400 CRON_INVALID_NAME" "400 CRON_INVALID_NAME" "$STATUS $(body error_code)"
anon GET /cron
check_eq "cron: the anon key cannot read the cron config (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"
anon POST /cron '{"name":"anon","schedule":"* * * * *","target_kind":"rpc","target_name":"w_ins"}'
check_eq "cron: the anon key cannot create a cron job (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"
mcp create_cron_job '{"name":"mcpbad","schedule":"nope","target_kind":"rpc","target_name":"w_ins"}'
check_eq "cron: MCP create_cron_job carries error_code CRON_INVALID_SCHEDULE" CRON_INVALID_SCHEDULE "$MCP_CODE"

# DRUST_CRON_MAX_JOBS_PER_TENANT (default 10; the smoke stack does not set it).
# 'tick' is job 1; inactive jobs 2..10 fill the cap, job 11 must be refused.
lim_ok=0
i=2
while [ "$i" -le 10 ]; do
  svc POST /cron "{\"name\":\"lim$i\",\"schedule\":\"0 0 1 1 *\",\"target_kind\":\"rpc\",\"target_name\":\"w_ins\",\"active\":false}"
  [ "$STATUS" = "201" ] && lim_ok=$((lim_ok + 1))
  i=$((i + 1))
done
check_eq "cron: jobs 2..10 are accepted up to the default per-tenant cap of 10" 9 "$lim_ok"
svc POST /cron '{"name":"lim11","schedule":"0 0 1 1 *","target_kind":"rpc","target_name":"w_ins","active":false}'
check_eq "cron: the 11th job is refused 409 CRON_JOB_LIMIT" "409 CRON_JOB_LIMIT" "$STATUS $(body error_code)"
del_ok=0
i=2
while [ "$i" -le 10 ]; do
  svc DELETE "/cron/lim$i"
  [ "$STATUS" = "204" ] && del_ok=$((del_ok + 1))
  i=$((i + 1))
done
check_eq "cron: the 9 filler jobs delete with 204" 9 "$del_ok"

# ═══════════════════════════════════════════════════════════════════════════
# Tenant A — stored RPC, record history, deadline.
# ═══════════════════════════════════════════════════════════════════════════
new_tenant jobs-rpc
save_tenant A

mcp create_collection '{"name":"items","fields":[{"name":"title","sql_type":"text"},{"name":"n","sql_type":"integer"}]}'
setup_ok "rpc tenant: create_collection items"
mcp create_collection '{"name":"owned","fields":[{"name":"title","sql_type":"text"},{"name":"owner","sql_type":"text","foreign_key":"_system_users"}]}'
setup_ok "rpc tenant: create_collection owned (owner FK to _system_users)"
mcp set_owner_field '{"collection":"owned","field":"owner"}'
setup_ok "rpc tenant: set_owner_field owned.owner"
mcp create_collection '{"name":"posts","fields":[{"name":"title","sql_type":"text"},{"name":"status","sql_type":"text"}]}'
setup_ok "rpc tenant: create_collection posts"
mcp set_policy '{"collection":"posts","op":"select","using":{"status":"published"}}'
setup_ok "rpc tenant: attach select policy status=published on posts"
mcp create_collection '{"name":"drift","fields":[{"name":"a","sql_type":"text"},{"name":"b","sql_type":"text"}]}'
setup_ok "rpc tenant: create_collection drift"

seed_ok=0
for t in i1 i2 i3; do svc POST /records/items "{\"data\":{\"title\":\"$t\",\"n\":1}}"; [ "$STATUS" = "201" ] && seed_ok=$((seed_ok + 1)); done
check_eq "rpc tenant: seed 3 items rows (each 201)" 3 "$seed_ok"
svc POST /records/posts '{"data":{"title":"pub1","status":"published"}}'
svc POST /records/posts '{"data":{"title":"draft1","status":"draft"}}'
check_eq "rpc tenant: seed posts rows" 201 "$STATUS"
svc POST /admin/users "{\"email\":\"smoke80-$$@example.invalid\",\"password\":\"Smoke-80-pw-$$-x\"}"
OWNER_UID="$(body user_id)"
check_ne "rpc tenant: create an end user to own a row" "" "$OWNER_UID"
svc POST /records/owned "{\"data\":{\"title\":\"secret-row\",\"owner\":\"$OWNER_UID\"}}"
check_eq "rpc tenant: seed one owner-scoped row" 201 "$STATUS"
svc POST /records/drift '{"data":{"a":"x","b":"y"}}'

# ── kind='sql' read RPC ─────────────────────────────────────────────────────
mcp create_rpc '{"name":"r_items","sql":"SELECT id, title FROM items WHERE n >= :min ORDER BY id","params":[{"name":"min","type":"integer"}]}'
setup_ok "rpc: create read RPC r_items"
svc POST /rpc/r_items '{"min":0}'
check_eq "rpc: service REST call of a read RPC answers 200" 200 "$STATUS"
check_eq "rpc: read RPC returns the 3 seeded rows" 3 "$(body row_count)"
check_eq "rpc: read RPC column_names are the projection" '["id", "title"]' "$(bodyj 'd["column_names"]')"
svc POST /rpc/r_items '{"min":"x"}'
check_eq "rpc: a wrongly typed param is refused 400 PARAM_TYPE_MISMATCH" "400 PARAM_TYPE_MISMATCH" "$STATUS $(body error_code)"
svc POST /rpc/r_items '{}'
check_eq "rpc: a missing required param is refused 400 PARAM_MISSING" "400 PARAM_MISSING" "$STATUS $(body error_code)"
svc POST /rpc/r_items '{"min":0,"zzz":1}'
check_eq "rpc: an undeclared param is refused 400 PARAM_UNKNOWN" "400 PARAM_UNKNOWN" "$STATUS $(body error_code)"
svc POST /rpc/no_such_rpc '{}'
check_eq "rpc: calling a missing RPC answers 404 RPC_NOT_FOUND" "404 RPC_NOT_FOUND" "$STATUS $(body error_code)"
mcp call_rpc '{"name":"r_items","body":{"min":0}}'
check_eq "rpc: MCP call_rpc of the read RPC returns the same 3 rows" 3 "$(printf '%s' "$MCP_TEXT" | pyj 'd["row_count"]')"
anon POST /rpc/r_items '{"min":0}'
check_eq "rpc: anon cannot call a read RPC that is not anon_callable (403 ANON_DENIED)" "403 ANON_DENIED" "$STATUS $(body error_code)"

mcp create_rpc '{"name":"r_items_pub","sql":"SELECT id, title FROM items ORDER BY id","params":[],"anon_callable":true}'
setup_ok "rpc: create anon_callable read RPC over an unrestricted collection"
anon POST /rpc/r_items_pub '{}'
check_eq "rpc: anon may call an anon_callable RPC over an unrestricted collection (200, 3 rows)" "200 3" "$STATUS $(body row_count)"

# ── RPC_ANON_OWNER_SCOPED, the four config-time sites ──────────────────────
mcp create_rpc '{"name":"bad_owned","sql":"SELECT id, title FROM owned","params":[],"anon_callable":true}'
check_eq "rpc guard (create): anon_callable RPC over an owner-scoped collection without :user_id is refused" false "$MCP_OK"
check_contains "rpc guard (create): refusal names RPC_ANON_OWNER_SCOPED" RPC_ANON_OWNER_SCOPED "$MCP_TEXT"
mcp create_rpc '{"name":"bad_owned2","sql":"SELECT id, title FROM owned WHERE :user_id IS NOT NULL","params":[{"name":"user_id","type":"text"}],"anon_callable":true}'
check_contains "rpc guard (create): declaring :user_id without constraining the owner column is refused" RPC_ANON_OWNER_SCOPED "$MCP_TEXT"
mcp create_rpc '{"name":"bad_policy","sql":"SELECT id, title FROM posts WHERE title = :user_id","params":[{"name":"user_id","type":"text"}],"anon_callable":true}'
check_contains "rpc guard (create): anon_callable RPC over a policy-protected collection is refused even with :user_id" RPC_ANON_OWNER_SCOPED "$MCP_TEXT"
mcp create_rpc '{"name":"r_owned_uid","sql":"SELECT id, title FROM owned WHERE owner = :user_id","params":[{"name":"user_id","type":"text"}],"anon_callable":true}'
setup_ok "rpc guard: anon_callable RPC over owned that binds owner = :user_id is accepted"
anon POST /rpc/r_owned_uid "{\"user_id\":\"$OWNER_UID\"}"
check_eq "rpc: anon calling an RPC that declares :user_id is refused 403 USER_ID_BINDING_REQUIRED (no spoofing)" "403 USER_ID_BINDING_REQUIRED" "$STATUS $(body error_code)"

mcp create_rpc '{"name":"r_owned_svc","sql":"SELECT id, title FROM owned","params":[]}'
setup_ok "rpc: create service-only RPC over owned"
mcp update_rpc '{"name":"r_owned_svc","anon_callable":true}'
check_contains "rpc guard (update): flipping anon_callable on an RPC over owned is refused" RPC_ANON_OWNER_SCOPED "$MCP_TEXT"
anon POST /rpc/r_owned_svc '{}'
check_eq "rpc guard (update): after the refused flip anon still gets 403 ANON_DENIED" "403 ANON_DENIED" "$STATUS $(body error_code)"
mcp create_collection '{"name":"pubtab","fields":[{"name":"title","sql_type":"text"},{"name":"owner","sql_type":"text","foreign_key":"_system_users"}]}'
setup_ok "rpc tenant: create_collection pubtab"
mcp create_rpc '{"name":"r_pubtab","sql":"SELECT id, title FROM pubtab","params":[],"anon_callable":true}'
setup_ok "rpc: create anon_callable RPC over pubtab (not yet restricted)"
mcp set_owner_field '{"collection":"pubtab","field":"owner"}'
check_contains "rpc guard (set_owner_field): making a collection owner-scoped under an anon_callable RPC is refused" RPC_ANON_OWNER_SCOPED "$MCP_TEXT"
mcp set_policy '{"collection":"pubtab","op":"select","using":{"title":"x"}}'
check_contains "rpc guard (policy attach): attaching an RLS policy under an anon_callable RPC is refused" RPC_ANON_OWNER_SCOPED "$MCP_TEXT"

# ── validate_rpc_sql refusals (create-time, mode-matched authorizer) ───────
# Every PrepareError carries the "prepare-time validation" prefix — a syntax
# error or "no such table" too — so assert the authorizer's own wording
# ("not authorized" / "access to <t>.<c> is prohibited") as well.
check_authz_refusal() { # NAME
  case "$MCP_OK:$MCP_TEXT" in
    false:*"prepare-time validation: not authorized"*|false:*"prepare-time validation: access to "*" is prohibited"*) ok "$1" ;;
    *) bad "$1" "expected an authorizer refusal, got: $(printf '%s' "$MCP_TEXT" | head -c 300)" ;;
  esac
}
mcp create_rpc '{"name":"bad_attach","sql":"ATTACH DATABASE '"'"'/tmp/smoke80.db'"'"' AS x","params":[]}'
check_authz_refusal "rpc validate: ATTACH in a read RPC is refused at create by the authorizer"
mcp create_rpc '{"name":"bad_master","sql":"SELECT name FROM sqlite_master","params":[]}'
check_authz_refusal "rpc validate: a sqlite_master read is refused at create by the authorizer"
mcp create_rpc '{"name":"bad_sysread","sql":"SELECT * FROM _system_users","params":[]}'
check_authz_refusal "rpc validate: a _system_* read is refused at create by the authorizer"
mcp create_rpc '{"name":"bad_rw","sql":"INSERT INTO items(title) VALUES('"'"'x'"'"')","params":[]}'
check_authz_refusal "rpc validate: an INSERT in a read-mode RPC is refused at create by the authorizer"
mcp create_rpc '{"name":"bad_ddl","mode":"write","sql":"DROP TABLE items","params":[]}'
check_authz_refusal "rpc validate: DDL in a write-mode RPC is refused at create by the authorizer"
mcp create_rpc '{"name":"bad_tx","mode":"write","sql":"BEGIN; UPDATE items SET n = 2; COMMIT","params":[]}'
check_authz_refusal "rpc validate: transaction control in a write-mode RPC is refused at create by the authorizer"
mcp create_rpc '{"name":"bad_syswrite","mode":"write","sql":"DELETE FROM _system_webhooks","params":[]}'
check_authz_refusal "rpc validate: a _system_* write in a write-mode RPC is refused at create by the authorizer"
mcp create_rpc '{"name":"bad_seq","mode":"write","sql":"UPDATE sqlite_sequence SET seq = 9223372036854775807","params":[]}'
check_authz_refusal "rpc validate: a sqlite_sequence write in a write-mode RPC is refused at create by the authorizer"
mcp list_rpc '{}'
stored_bad="$(printf '%s' "$MCP_TEXT" | pyj 'sorted(r["name"] for r in d if r["name"].startswith("bad_"))')"
check_eq "rpc validate/guard: none of the refused RPCs was stored" "[]" "$stored_bad"
note "MCP create_rpc refusals arrive as JSON-RPC -32603 with no data.error_code (see report)"

# ── runtime errors never echo the stored SQL (sqlite_error_without_sql) ────
mcp create_rpc '{"name":"r_drift","sql":"SELECT a, b FROM drift WHERE a = '"'"'LITERAL_MARKER'"'"' OR 1","params":[],"anon_callable":true}'
setup_ok "rpc: create anon_callable RPC over drift"
mcp drop_field '{"collection":"drift","field":"b"}'
setup_ok "rpc: drop_field drift.b (schema drift under the RPC)"
anon POST /rpc/r_drift '{}'
check_eq "rpc: a drifted RPC answers 400 SQL_ERROR to anon" "400 SQL_ERROR" "$STATUS $(body error_code)"
check_not_contains "rpc: the drift error does not hand anon the RPC body (literal)" LITERAL_MARKER "$BODY"
check_not_contains "rpc: the drift error does not hand anon the RPC body (SELECT)" "SELECT a" "$BODY"

# ── MCP call_rpc stays on the read-only executor for a write RPC ───────────
mcp create_rpc '{"name":"w_mcp","mode":"write","sql":"INSERT INTO items(title, n) VALUES('"'"'via-mcp'"'"', 9)","params":[]}'
setup_ok "rpc: create write RPC w_mcp"
mcp call_rpc '{"name":"w_mcp"}'
check_eq "rpc: MCP call_rpc of a write RPC is refused (read-only executor)" false "$MCP_OK"
svc POST /collections/items/list '{"filter":{"title":"via-mcp"}}'
check_eq "rpc: the refused MCP call_rpc wrote nothing" 0 "$(body total)"

# ── write RPC + record history (preupdate hook, rusqlite 0.42) ─────────────
mcp create_rpc '{"name":"w_upd","mode":"write","sql":"UPDATE items SET title = :t WHERE id = :id","params":[{"name":"t","type":"text"},{"name":"id","type":"integer"}]}'
setup_ok "rpc: create write RPC w_upd"
mcp create_rpc '{"name":"w_ins","mode":"write","sql":"INSERT INTO items(title, n) VALUES(:t, :n)","params":[{"name":"t","type":"text"},{"name":"n","type":"integer"}]}'
setup_ok "rpc: create write RPC w_ins"
mcp create_rpc '{"name":"w_del","mode":"write","sql":"DELETE FROM items WHERE id = :id","params":[{"name":"id","type":"integer"}]}'
setup_ok "rpc: create write RPC w_del"
mcp create_rpc '{"name":"w_two","mode":"write","sql":"UPDATE items SET title = '"'"'should-roll-back'"'"' WHERE id = :id; INSERT INTO items(id, title) VALUES(:id, '"'"'dup'"'"')","params":[{"name":"id","type":"integer"}]}'
setup_ok "rpc: create two-statement write RPC w_two (second statement conflicts)"

anon POST /rpc/w_upd '{"t":"anon","id":1}'
check_eq "rpc: anon cannot call a write RPC that is not anon_callable (403 RPC_DENIED)" "403 RPC_DENIED" "$STATUS $(body error_code)"

svc POST /rpc/w_upd '{"t":"i1-renamed","id":1}'
check_eq "rpc write: UPDATE via write RPC answers 200 with affected_rows 1" "200 1" "$STATUS $(body affected_rows)"
svc GET /records/items/1
REC_UPDATED_AT="$(body record.updated_at)"
[ -z "$REC_UPDATED_AT" ] && REC_UPDATED_AT="$(body updated_at)"
check_eq "rpc write: the row really changed" i1-renamed "$( (body record.title || body title) 2>/dev/null)"
mcp get_record_history '{"collection":"items","record_id":1}'
H="$MCP_TEXT"
check_eq "rpc history: exactly one update row for the RPC UPDATE (trigger change merged, no double capture)" 1 "$(printf '%s' "$H" | pyj 'len([r for r in d["rows"] if r["op"]=="update"])')"
check_eq "rpc history: update old image carries the pre-update title" i1 "$(printf '%s' "$H" | pyj '[r for r in d["rows"] if r["op"]=="update"][0]["old"]["title"]')"
check_eq "rpc history: update new image carries the post-update title" i1-renamed "$(printf '%s' "$H" | pyj '[r for r in d["rows"] if r["op"]=="update"][0]["new"]["title"]')"
check_eq "rpc history: update new image updated_at equals the committed row's updated_at" "$REC_UPDATED_AT" "$(printf '%s' "$H" | pyj '[r for r in d["rows"] if r["op"]=="update"][0]["new"]["updated_at"]')"
check_eq "rpc history: write-RPC history is attributed to the service actor" service "$(printf '%s' "$H" | pyj '[r for r in d["rows"] if r["op"]=="update"][0]["actor_kind"]')"

svc POST /rpc/w_ins '{"t":"rpc-inserted","n":5}'
NEW_ID="$(body last_insert_rowid)"
check_eq "rpc write: INSERT via write RPC answers 200 with affected_rows 1" "200 1" "$STATUS $(body affected_rows)"
mcp get_record_history "{\"collection\":\"items\",\"record_id\":${NEW_ID:-0}}"
check_eq "rpc history: INSERT captured as op=insert with old=null and the new title" "insert null rpc-inserted" "$(printf '%s' "$MCP_TEXT" | pyj '"%s %s %s" % (d["rows"][0]["op"], json.dumps(d["rows"][0]["old"]), d["rows"][0]["new"]["title"])')"

svc POST /rpc/w_del "{\"id\":${NEW_ID:-0}}"
check_eq "rpc write: DELETE via write RPC answers 200 with affected_rows 1" "200 1" "$STATUS $(body affected_rows)"
mcp get_record_history "{\"collection\":\"items\",\"record_id\":${NEW_ID:-0}}"
check_eq "rpc history: DELETE captured as op=delete with the old image and new=null" "delete rpc-inserted null" "$(printf '%s' "$MCP_TEXT" | pyj '"%s %s %s" % (d["rows"][0]["op"], d["rows"][0]["old"]["title"], json.dumps(d["rows"][0]["new"]))')"

mcp create_rpc '{"name":"w_anon","mode":"write","sql":"UPDATE items SET n = n + 1 WHERE id = :id","params":[{"name":"id","type":"integer"}],"anon_callable":true}'
setup_ok "rpc: create anon_callable write RPC over unrestricted items"
anon POST /rpc/w_anon '{"id":3}'
check_eq "rpc write: anon may call an anon_callable write RPC over an unrestricted collection (200, 1 row)" "200 1" "$STATUS $(body affected_rows)"
mcp get_record_history '{"collection":"items","record_id":3}'
check_eq "rpc history: an anon write-RPC change is captured with actor_kind anon and n 1 -> 2" "update anon 1 2" "$(printf '%s' "$MCP_TEXT" | pyj '"%s %s %s %s" % (d["rows"][0]["op"], d["rows"][0]["actor_kind"], d["rows"][0]["old"]["n"], d["rows"][0]["new"]["n"])')"

mcp get_record_history '{"collection":"items","record_id":2}'
H2_BEFORE="$(printf '%s' "$MCP_TEXT" | pyj 'd["total"]')"
case "$H2_BEFORE" in ''|*[!0-9]*|0) bad "rpc history: record 2 has a readable history baseline (its insert)" "total=[$H2_BEFORE]" ;;
  *) ok "rpc history: record 2 has a readable history baseline (its insert)" ;; esac
svc POST '/rpc/w_upd?dry_run=true' '{"t":"dry","id":2}'
check_eq "rpc write: dry_run answers 200 with dry_run=true and would_commit=true" "200 true true" "$STATUS $(body dry_run) $(body would_commit)"
svc POST /rpc/w_two '{"id":2}'
check_eq "rpc write: a failing second statement answers 400 RPC_STATEMENT_FAILED at (1-based) statement_index 2" "400 RPC_STATEMENT_FAILED 2" "$STATUS $(body error_code) $(body statement_index)"
svc GET /records/items/2
check_eq "rpc write: dry_run and the failed multi-statement RPC both left the row untouched" i2 "$( (body record.title || body title) 2>/dev/null)"
mcp get_record_history '{"collection":"items","record_id":2}'
check_eq "rpc history: no history row from the dry_run or the rolled-back RPC" "$H2_BEFORE" "$(printf '%s' "$MCP_TEXT" | pyj 'd["total"]')"

# ── kind='query' RPC: caller identity, policy, scalar-only args ────────────
mcp create_rpc '{"name":"q_posts","kind":"query","query":{"collection":"posts","sort":{"field":"id","dir":"asc"}},"params":[],"anon_callable":true}'
setup_ok "rpc query: create anon_callable kind=query RPC over policy-protected posts"
anon POST /rpc/q_posts '{}'
check_eq "rpc query: anon call answers 200" 200 "$STATUS"
check_eq "rpc query: anon sees only the policy-visible row (select policy applied under the caller identity)" '["pub1"]' "$(bodyj '[r["title"] for r in d["records"]]')"
svc POST /rpc/q_posts '{}'
check_eq "rpc query: service caller sees every row (service bypasses RLS)" '["draft1", "pub1"]' "$(bodyj 'sorted(r["title"] for r in d["records"])')"
mcp call_rpc '{"name":"q_posts"}'
check_eq "rpc query: MCP call_rpc returns the /list envelope under the service identity" 2 "$(printf '%s' "$MCP_TEXT" | pyj 'd["total"]')"

mcp create_rpc '{"name":"q_title","kind":"query","query":{"collection":"posts","filter":{"title":{"$param":"who"}}},"params":[{"name":"who","type":"text"}],"anon_callable":true}'
setup_ok "rpc query: create parameterised kind=query RPC q_title"
anon POST /rpc/q_title '{"who":"pub1"}'
check_eq "rpc query: a scalar arg naming a policy-visible row returns that row to anon" "200 1 pub1" "$STATUS $(body total) $(body records.0.title)"
anon POST /rpc/q_title '{"who":"draft1"}'
check_eq "rpc query: a scalar arg naming a policy-hidden row returns nothing to anon" "200 0" "$STATUS $(body total)"
svc POST /rpc/q_title '{"who":{"$ne":"zzz"}}'
check_eq "rpc query: an object arg is refused 400 RPC_PARAM_NOT_SCALAR (AST-injection gate)" "400 RPC_PARAM_NOT_SCALAR" "$STATUS $(body error_code)"
anon POST /rpc/q_title '{"who":["pub1","draft1"]}'
check_eq "rpc query: an array arg is refused 400 RPC_PARAM_NOT_SCALAR" "400 RPC_PARAM_NOT_SCALAR" "$STATUS $(body error_code)"
mcp create_rpc '{"name":"q_uid","kind":"query","query":{"collection":"posts","filter":{"title":{"$param":"user_id"}}},"params":[{"name":"user_id","type":"text"}]}'
check_contains "rpc query: a kind=query RPC declaring user_id is refused RPC_KIND_INVALID" RPC_KIND_INVALID "$MCP_TEXT"
mcp create_rpc '{"name":"q_sys","kind":"query","query":{"collection":"_system_users"},"params":[]}'
check_contains "rpc query: a kind=query RPC over a _system_* collection is refused PROTECTED_COLLECTION" PROTECTED_COLLECTION "$MCP_OK $MCP_TEXT"
check_eq "rpc query: the _system_* template refusal is an error, not a result" false "$MCP_OK"
mcp create_rpc '{"name":"q_owned","kind":"query","query":{"collection":"owned"},"params":[],"anon_callable":true}'
setup_ok "rpc query: create anon_callable kind=query RPC over owner-scoped owned"
anon POST /rpc/q_owned '{}'
check_eq "rpc query: anon on an owner-scoped template is denied 403 ANON_FORBIDDEN_OWNER_SCOPED" "403 ANON_FORBIDDEN_OWNER_SCOPED" "$STATUS $(body error_code)"
check_not_contains "rpc query: the owner-scoped row never reaches anon" secret-row "$BODY"
mcp create_rpc '{"name":"q_svc","kind":"query","query":{"collection":"items"},"params":[]}'
setup_ok "rpc query: create service-only kind=query RPC q_svc"
anon POST /rpc/q_svc '{}'
check_eq "rpc query: anon calling a non-anon_callable query RPC gets 403 ANON_DENIED" "403 ANON_DENIED" "$STATUS $(body error_code)"
svc POST '/rpc/q_svc?per_page=0' '{}'
check_eq "rpc query: an out-of-range per_page is a typed 422 PAGE_RANGE_INVALID" "422 PAGE_RANGE_INVALID" "$STATUS $(body error_code)"

# ── query deadline (DRUST_QUERY_DEADLINE_MS, default 5000; unset on the stack) ──
mcp create_rpc '{"name":"r_slow","sql":"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c","params":[]}'
setup_ok "rpc deadline: create an unbounded recursive-CTE read RPC"
t0=$(now_ms)
REQ_TIMEOUT=90 svc POST /rpc/r_slow '{}'
t1=$(now_ms)
el=$((t1 - t0))
check_eq "rpc deadline: an unbounded read RPC is interrupted with 408 QUERY_TIMEOUT" "408 QUERY_TIMEOUT" "$STATUS $(body error_code)"
if [ "$el" -ge 4500 ] && [ "$el" -lt 20000 ]; then ok "rpc deadline: interrupted near the 5000 ms deadline (${el} ms), not at the HTTP timeout"
else bad "rpc deadline: interrupted near the 5000 ms deadline" "elapsed ${el} ms"; fi
fast_ok=0
for i in 1 2 3 4 5 6; do svc POST /rpc/r_items '{"min":0}'; [ "$STATUS" = "200" ] && fast_ok=$((fast_ok + 1)); done
check_eq "rpc deadline: pooled readers serve fast RPCs after the interrupt (progress handler removed)" 6 "$fast_ok"

# Measurement only (no check): does a WRITE RPC carry the same deadline? The
# source arms DeadlineGuard only on the read executor; this records what the
# deployed binary does with a bounded CTE calibrated to run ~7 s.
mcp create_rpc '{"name":"w_slow","mode":"write","sql":"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < :n) INSERT INTO items(title, n) SELECT '"'"'never'"'"', x FROM c WHERE x < 0","params":[{"name":"n","type":"integer"}]}'
t0=$(now_ms); svc POST /rpc/w_slow '{"n":3000000}'; t1=$(now_ms)
cal=$((t1 - t0)); [ "$cal" -lt 50 ] && cal=50
N2=$(python3 -c "print(min(400000000, int(3000000 * 7500 / $cal)))")
t0=$(now_ms); REQ_TIMEOUT=60 svc POST /rpc/w_slow "{\"n\":$N2}"; t1=$(now_ms)
note "measurement: write RPC calibrated to ~7.5 s (n=$N2; 3M rows took ${cal} ms) answered $STATUS $(body error_code 2>/dev/null) after $((t1 - t0)) ms"

# ═══════════════════════════════════════════════════════════════════════════
# Tenant C — webhooks + egress allowlist.
# ═══════════════════════════════════════════════════════════════════════════
new_tenant jobs-hook
save_tenant C

svc GET /egress-allowlist
check_eq "egress: a fresh tenant's allowlist is empty (deny-all default)" "200 []" "$STATUS $(bodyj 'd["entries"]')"
mcp get_egress_allowlist '{}'
check_eq "egress: MCP get_egress_allowlist agrees (empty)" "[]" "$(printf '%s' "$MCP_TEXT" | pyj 'd["entries"]')"
anon GET /egress-allowlist
check_eq "egress: the anon key cannot read the allowlist (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"

svc POST /admin/webhooks '{"collection":"items","events":["created"],"url":"https://192.0.2.10/hook"}'
check_eq "webhook: registering a non-allowlisted origin is refused 400 EGRESS_NOT_ALLOWLISTED" "400 EGRESS_NOT_ALLOWLISTED" "$STATUS $(body error_code)"
mcp create_webhook '{"collection":"items","events":["created"],"url":"https://192.0.2.10/hook"}'
check_eq "webhook: MCP create_webhook to a non-allowlisted origin carries EGRESS_NOT_ALLOWLISTED" EGRESS_NOT_ALLOWLISTED "$MCP_CODE"

svc PUT /egress-allowlist '{"entries":[{"system":"function","uri":"http://169.254.169.254"}]}'
check_eq "egress: a function origin that is a private-IP literal is refused 400 EGRESS_BAD_ORIGIN" "400 EGRESS_BAD_ORIGIN" "$STATUS $(body error_code)"
svc PUT /egress-allowlist '{"entries":[{"system":"function","uri":"http://2130706433"}]}'
check_eq "egress: a function origin in alternate IPv4 encoding of loopback is refused EGRESS_BAD_ORIGIN" "400 EGRESS_BAD_ORIGIN" "$STATUS $(body error_code)"
svc PUT /egress-allowlist '{"entries":[{"system":"smtp","uri":"https://192.0.2.10"}]}'
check_eq "egress: an unknown system is refused 400 EGRESS_BAD_SYSTEM" "400 EGRESS_BAD_SYSTEM" "$STATUS $(body error_code)"
svc PUT /egress-allowlist '{"entries":[{"system":"webhook","uri":"ftp://192.0.2.10"}]}'
check_eq "egress: a non-http(s) origin is refused 400 EGRESS_BAD_ORIGIN" "400 EGRESS_BAD_ORIGIN" "$STATUS $(body error_code)"
mcp set_egress_allowlist '{"entries":[{"system":"smtp","uri":"https://192.0.2.10"}]}'
check_contains "egress: MCP set_egress_allowlist refuses an unknown system" EGRESS_BAD_SYSTEM "$MCP_TEXT"

# Allowlist the private targets on purpose: invariant 6 says the private-IP
# block is orthogonal to the allowlist, so allowlisting must not open them.
PRIV_URLS="https://127.0.0.1/h https://10.0.0.5/h https://172.16.0.9/h https://192.168.1.1/h https://169.254.169.254/h https://100.64.0.1/h https://0.0.0.0/h https://2852039166/h https://0x7f000001/h https://localhost/h http://127.0.0.1:9/h"
# Private IPv6 targets are checked without an allowlist entry: check_url refuses
# them at registration before the egress gate is consulted.
PRIV6_URLS="https://[::1]/h https://[::ffff:127.0.0.1]/h https://[fe80::1]/h https://[fd00::1]/h"
# A bracketed IPv6 origin is storable (normalize_origin parses the literal and
# stores its canonical text) and a stored entry matches across default-port
# and spelling differences (check_egress doc). No outbound connection: the hook
# goes on a collection nothing writes and is deleted at once if it registers.
svc PUT /egress-allowlist '{"entries":[{"system":"webhook","uri":"https://[2606:4700:4700::1111]"}]}'
check_eq "egress: a public IPv6-literal webhook origin without a port is accepted by the allowlist (200)" 200 "$STATUS"
svc PUT /egress-allowlist '{"entries":[{"system":"webhook","uri":"https://[2606:4700:4700::1111]:443"}]}'
check_eq "egress: the same IPv6 origin written with :443 is stored with the default port dropped" '200 ["https://[2606:4700:4700::1111]"]' "$STATUS $(bodyj '[e["uri"] for e in d["entries"]]')"
svc POST /admin/webhooks '{"collection":"never_written","events":["created"],"url":"https://[2606:4700:4700::1111]/h"}'
check_eq "webhook: a target on an allowlisted IPv6 origin registers (201), not EGRESS_NOT_ALLOWLISTED" 201 "$STATUS"
[ "$STATUS" = "201" ] && { V6_ID="$(body id)"; svc DELETE "/admin/webhooks/$V6_ID"; }
svc PUT /egress-allowlist '{"entries":[]}'
check_eq "egress: allowlist cleared after the IPv6 probe" 200 "$STATUS"
entries="$(python3 -c '
import json, sys
urls = sys.argv[1].split() + ["https://HTTPS-CASE.invalid:443/", "https://192.0.2.10"]
out = []
for u in urls:
    o = u.split("/h")[0] if u.endswith("/h") else u
    out.append({"system": "webhook", "uri": o})
print(json.dumps({"entries": out}))
' "$PRIV_URLS")"
svc PUT /egress-allowlist "$entries"
check_eq "egress: webhook origins are accepted and stored (normalized)" 200 "$STATUS"
check_contains "egress: origins are normalized (lower-cased host, default port dropped)" '"https://https-case.invalid"' "$BODY"
for u in $PRIV_URLS; do
  svc POST /admin/webhooks "{\"collection\":\"items\",\"events\":[\"created\"],\"url\":\"$u\"}"
  check_eq "webhook: private/loopback/link-local target $u is refused 422 INVALID_URL even when allowlisted" "422 INVALID_URL" "$STATUS $(body error_code)"
done
for u in $PRIV6_URLS; do
  svc POST /admin/webhooks "{\"collection\":\"items\",\"events\":[\"created\"],\"url\":\"$u\"}"
  check_eq "webhook: private IPv6 target $u is refused 422 INVALID_URL" "422 INVALID_URL" "$STATUS $(body error_code)"
done
mcp create_webhook '{"collection":"items","events":["created"],"url":"https://169.254.169.254/latest"}'
check_eq "webhook: MCP create_webhook to link-local metadata is refused INVALID_URL even when allowlisted" INVALID_URL "$MCP_CODE"

svc POST /admin/webhooks '{"collection":"items","events":["created","updated"],"url":"https://192.0.2.10/hook"}'
check_eq "webhook: an allowlisted public-literal target registers (201)" 201 "$STATUS"
WH_ID="$(body id)"
check_eq "webhook: the secret is returned once as 64 hex chars" 64 "$(bodyj 'len(d["secret"]) if all(c in "0123456789abcdef" for c in d["secret"]) else -1')"
svc GET /admin/webhooks
check_eq "webhook: list redacts the secret" "●●●●" "$(bodyj 'd["webhooks"][0]["secret"]')"
svc PATCH "/admin/webhooks/$WH_ID" '{"secret":"0000"}'
check_eq "webhook: PATCH cannot rotate the secret (422 INVALID_PATCH)" "422 INVALID_PATCH" "$STATUS $(body error_code)"
svc PATCH "/admin/webhooks/$WH_ID" '{"url":"https://192.0.2.11/other"}'
check_eq "webhook: PATCH to a non-allowlisted origin is refused 400 EGRESS_NOT_ALLOWLISTED" "400 EGRESS_NOT_ALLOWLISTED" "$STATUS $(body error_code)"
svc PATCH "/admin/webhooks/$WH_ID" '{"url":"https://10.0.0.5/h"}'
check_eq "webhook: PATCH to an allowlisted private target is refused 422 INVALID_URL" "422 INVALID_URL" "$STATUS $(body error_code)"
svc POST /admin/webhooks '{"collection":"items","events":["exploded"],"url":"https://192.0.2.10/hook"}'
check_eq "webhook: an unknown event name is refused 422 INVALID_EVENTS" "422 INVALID_EVENTS" "$STATUS $(body error_code)"
anon GET /admin/webhooks
check_eq "webhook: the anon key cannot list webhooks (403 SERVICE_ONLY)" "403 SERVICE_ONLY" "$STATUS $(body error_code)"

# Dispatch-time egress gate: revoke the origin, then write. The fan-out must
# deny (no connection) and record the reason on the subscription.
svc PUT /egress-allowlist '{"entries":[]}'
revoked="$STATUS $(bodyj 'd["entries"]')"
check_eq "egress: clearing the allowlist answers 200 with no entries" "200 []" "$revoked"
mcp create_collection '{"name":"items","fields":[{"name":"title","sql_type":"text"}]}'
setup_ok "webhook tenant: create_collection items"
if [ "$revoked" = "200 []" ]; then
  svc POST /records/items '{"data":{"title":"fan-out-probe"}}'
  check_eq "webhook: a write on the subscribed collection still succeeds (201)" 201 "$STATUS"
  reason=""
  i=0
  while [ "$i" -lt 20 ]; do
    svc GET "/admin/webhooks/$WH_ID"
    reason="$(body last_failure_reason)"
    [ -n "$reason" ] && [ "$reason" != "null" ] && break
    sleep 1; i=$((i + 1))
  done
  check_eq "webhook: dispatch to a de-allowlisted origin is denied and recorded on the subscription" "egress_not_allowlisted: https://192.0.2.10/hook" "$reason"
  check_eq "webhook: the denial carries an RFC 3339 last_failure_at" true "$(bodyj 'isinstance(d.get("last_failure_at"), str) and d["last_failure_at"][:2] == "20" and "T" in d["last_failure_at"]')"
else
  bad "webhook: dispatch-time egress denial" "allowlist could not be cleared; write skipped so nothing is dialled"
fi

# Registration cap: DRUST_WEBHOOK_MAX_PER_TENANT (default 32; not set on the
# stack). Fill to 32 on a collection nothing writes, then expect the refusal.
svc PUT /egress-allowlist '{"entries":[{"system":"webhook","uri":"https://192.0.2.10"}]}'
cap_ok=0
i=2
while [ "$i" -le 32 ]; do
  svc POST /admin/webhooks '{"collection":"never_written","events":["created"],"url":"https://192.0.2.10/cap"}'
  [ "$STATUS" = "201" ] && cap_ok=$((cap_ok + 1))
  i=$((i + 1))
done
check_eq "webhook cap: subscriptions 2..32 are accepted" 31 "$cap_ok"
svc POST /admin/webhooks '{"collection":"never_written","events":["created"],"url":"https://192.0.2.10/cap"}'
check_eq "webhook cap: the 33rd subscription is refused 409 WEBHOOK_LIMIT_EXCEEDED (REST)" "409 WEBHOOK_LIMIT_EXCEEDED" "$STATUS $(body error_code)"
mcp create_webhook '{"collection":"never_written","events":["created"],"url":"https://192.0.2.10/cap"}'
check_eq "webhook cap: MCP create_webhook is capped too (WEBHOOK_LIMIT_EXCEEDED)" WEBHOOK_LIMIT_EXCEEDED "$MCP_CODE"
svc PUT /egress-allowlist '{"entries":[]}'
check_eq "egress: allowlist cleared again after the cap test" 200 "$STATUS"
svc DELETE "/admin/webhooks/$WH_ID"
check_eq "webhook: DELETE answers 204" 204 "$STATUS"
svc DELETE "/admin/webhooks/$WH_ID"
check_eq "webhook: a second DELETE answers 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"

# ═══════════════════════════════════════════════════════════════════════════
# Back to tenant B: wait (bounded) for the cron fire.
# ═══════════════════════════════════════════════════════════════════════════
use_tenant B
runs_status=""
while :; do
  svc GET /cron/tick/runs
  runs_status="$(bodyj 'd["runs"][0]["status"] if d["runs"] else ""')"
  [ -n "$runs_status" ] && break
  [ $(( $(date +%s) - CRON_CREATED )) -ge 130 ] && break
  sleep 5
done
check_eq "cron: the every-minute job fired within 130 s and recorded an ok run" ok "$runs_status"
check_eq "cron: the run row carries no error" null "$(bodyj 'd["runs"][0]["error"] if d["runs"] else "missing"')"
svc GET /cron/tick
check_eq "cron: the job row's last_status is ok" ok "$(body last_status)"
svc POST /collections/items/list "{\"filter\":{\"title\":\"$CRON_MARK\"}}"
check_eq "cron: the fired write RPC really inserted its row (payload title, RPC body n=7)" true "$(bodyj 'd["total"] >= 1 and all(r["n"] == 7 for r in d["records"])')"
CRON_ROW="$(bodyj 'd["records"][0]["id"] if d["records"] else 0')"
mcp get_record_history "{\"collection\":\"items\",\"record_id\":${CRON_ROW:-0}}"
check_eq "cron: the cron-fired write RPC insert is captured in record history as the service actor" "insert $CRON_MARK service" "$(printf '%s' "$MCP_TEXT" | pyj '"%s %s %s" % (d["rows"][-1]["op"], d["rows"][-1]["new"]["title"], d["rows"][-1]["actor_kind"])')"
svc DELETE /cron/tick
check_eq "cron: the job deletes with 204" 204 "$STATUS"
svc GET /cron/tick
check_eq "cron: a deleted job answers 404 CRON_NOT_FOUND" "404 CRON_NOT_FOUND" "$STATUS $(body error_code)"

note "elapsed $(( $(date +%s) - SCRIPT_START )) s"
finish

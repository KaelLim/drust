#!/usr/bin/env bash
# Edge functions (wasmtime 50 / Cranelift JIT) on the live stack:
#  - upload compile gate for the three committed fixtures (happy / loop / membomb),
#    for junk bytes, and for hand-built components using the three proposals drust
#    turns off (GC, function-references, wide-arithmetic) plus an MVP control;
#  - service invoke of happy: returned payload, guest log, host insert-record effect,
#    record-history capture (actor service / anon / user);
#  - loop.wasm stopped by the epoch deadline ("timeout"), and another tenant's
#    function still runs while it spins; membomb.wasm stopped by the memory cap ("oom");
#  - per-function invoke ACL (anon/user denied by default, no existence oracle,
#    granted -> capability-gated run, revoke -> denied again, one-sided PATCH);
#  - CRUD: list / get / patch (active, description, triggers) / delete / 404s / 422s,
#    re-upload replace, FN_LIMIT, artifact GC on disk (read-only docker exec);
#  - logs endpoint; record-trigger dispatch with depth=1 (no recursion);
#  - MCP function tools (list / set_active / set_invoke_acl / invoke / logs / delete)
#    and their annotations.
# Not covered (no fixture reaches them): http-fetch egress, file host ops,
# the edge SYSTEM_FIELD_READONLY id guard.
. "$(dirname "$0")/lib.sh"

FX="$REPO_ROOT/tests/fixtures/functions"
FN_TIMEOUT_SECS=30 # DRUST_FN_TIMEOUT_SECS default; docker-compose.yml does not override it

# ---------------------------------------------------------------- helpers

# The per-token limiter (DRUST_RATE_LIMIT_PER_TOKEN, default 60 per 10 s) is
# easy to hit with one service key driving a long script. Shadow lib.sh's req
# so a per-TOKEN 429 (error_code RATE_LIMITED) is waited out and retried a
# bounded number of times. Per-IP 429s (RATE_LIMITED_IP — login and the
# anon/user invoke limiter) are NOT retried: those are behaviour under test.
# MCP calls go to the account endpoint and are not charged to this key.
eval "_lib_$(declare -f req)"
req() {
  local tries=0 ra
  while :; do
    _lib_req "$@"
    [ "$STATUS" = 429 ] || return 0
    case "$BODY" in *'"RATE_LIMITED"'*) ;; *) return 0 ;; esac
    tries=$((tries + 1))
    [ "$tries" -le 8 ] || return 0
    ra="$(header retry-after)"
    case "$ra" in '' | *[!0-9]*) ra=2 ;; esac
    [ "$ra" -le 10 ] || ra=10
    sleep "$ra"
  done
}

# upload NAME FILE [TRIGGERS] — multipart create on the current tenant.
upload() {
  REQ_TIMEOUT=90 req POST "$T/functions" -H "Authorization: Bearer $SERVICE_KEY" \
    --form-string "name=$1" -F "wasm=@$2;type=application/wasm" \
    --form-string "triggers=${3:-[]}" --form-string "description=smoke"
}

# user_call TOKEN METHOD PATH [JSON]
user_call() { _tenant_call "$@"; }

# mcp_ok NAME — the last mcp_call produced a real tools/call RESULT with
# isError false (lib.sh's MCP_IS_ERROR is "true" for anything else); on failure
# the detail names what came back instead.
mcp_ok() {
  local got
  got="$(printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)["result"]
except Exception:
    print("no-result"); sys.exit()
print("isError=%s" % ("true" if r.get("isError") else "false"))' 2>/dev/null)"
  check_eq "$1" "isError=false" "$got"
}

sha_of() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }

# mkwasm KIND OUT [TAG] — build a tiny component byte-wise (no toolchain): a
# component whose only content is one nested core module. TAG adds a component
# custom section so otherwise-identical bytes get a distinct sha.
mkwasm() {
  python3 - "$1" "$2" "${3:-}" <<'PY'
import sys
def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        if n: out.append(b | 0x80)
        else: out.append(b); return bytes(out)
def sec(i, c): return bytes([i]) + leb(len(c)) + c
def body(ops):
    b = b'\x00' + ops + b'\x0b'
    return leb(len(b)) + b
def core(types, funcs=None, code=None):
    m = b'\x00asm\x01\x00\x00\x00' + sec(1, types)
    if funcs: m += sec(3, funcs)
    if code: m += sec(10, code)
    return m
kind, out, tag = sys.argv[1], sys.argv[2], sys.argv[3]
void = b'\x01\x60\x00\x00'
if kind == 'mvp':        # i64.const 0; i64.const 0; i64.add; drop
    m = core(void, b'\x01\x00', b'\x01' + body(b'\x42\x00\x42\x00\x7c\x1a'))
elif kind == 'gc':       # (type (struct))
    m = core(b'\x01\x5f\x00')
elif kind == 'funcref':  # (type (func (param (ref func))))
    m = core(b'\x01\x60\x01\x64\x70\x00')
elif kind == 'wide':     # 4x i64.const 0; i64.add128; drop; drop
    m = core(void, b'\x01\x00', b'\x01' + body(b'\x42\x00' * 4 + b'\xfc\x13\x1a\x1a'))
elif kind == 'junk':
    open(out, 'wb').write(b'this is not a wasm component'); sys.exit()
c = b'\x00asm\x0d\x00\x01\x00' + sec(1, m)
if tag:
    name = b'smoke'
    c += sec(0, leb(len(name)) + name + tag.encode())
open(out, 'wb').write(c)
PY
}

# fn_dir_has TENANT SHA — "yes"/"no"/"skip": does the artifact exist on disk?
# Read-only `ls` inside the drust container; "skip" when docker is unavailable.
fn_dir_has() {
  local cid out
  command -v docker >/dev/null 2>&1 || { echo skip; return; }
  cid="$(docker compose -p "$SMOKE_COMPOSE_PROJECT" ps -q drust 2>/dev/null | head -1)"
  [ -n "$cid" ] || { echo skip; return; }
  out="$(docker exec "$cid" ls "/data/tenants/$1/_functions" 2>/dev/null || true)"
  case "$out" in *"$2.wasm"*) echo yes ;; *) echo no ;; esac
}

check_disk() { # NAME TENANT SHA EXPECT(yes|no)
  local got
  got="$(fn_dir_has "$2" "$3")"
  if [ "$got" = skip ]; then note "skipped (docker not reachable): $1"; return; fi
  check_eq "$1" "$4" "$got"
}

# count_rows COLLECTION — total rows via service REST.
count_rows() {
  svc GET "/records/$1?perPage=1"
  ROWS="$(body total || echo -1)"
}

# log_count NAME [TRIGGER] — number of log rows (optionally of one trigger).
log_count() {
  svc GET "/functions/$1/logs?limit=200"
  LOGS="$(printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    rows = json.load(sys.stdin)["logs"]
except Exception:
    print(-1); sys.exit()
t = sys.argv[1]
print(len([r for r in rows if not t or r.get("trigger") == t]))' "${2:-}")"
}

# poll_until DESCRIPTION MAX_TRIES CMD... — run CMD (a shell function that
# returns 0 when the condition holds) up to MAX_TRIES times, 1 s apart.
poll_until() {
  local n="$2" i=0
  shift 2
  while [ "$i" -lt "$n" ]; do
    if "$@"; then return 0; fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

W="$TMP/wasm"
mkdir -p "$W"
for k in mvp gc funcref wide junk; do mkwasm "$k" "$W/$k.wasm"; done
mkwasm mvp "$W/swap_old.wasm" "swap-$$"
HAPPY_SHA="$(sha_of "$FX/happy.wasm")"
HAPPY_SIZE="$(wc -c < "$FX/happy.wasm" | tr -d ' ')"

# ======================================================= tenant A: main surface
new_tenant fn-a
A_ID="$TENANT_ID"; A_SVC="$SERVICE_KEY"; A_ANON="$ANON_KEY"; A_T="$T"

mcp_call create_collection '{"name":"fn_out","fields":[{"name":"payload","sql_type":"text"}]}'
mcp_ok "MCP create_collection fn_out (happy.wasm's target) succeeds"
mcp_call create_collection '{"name":"src","fields":[{"name":"x","sql_type":"text"}]}'
mcp_ok "MCP create_collection src (trigger source) succeeds"

# --- compile gate: real fixtures ----------------------------------------------
upload happy "$FX/happy.wasm"
check_eq "upload happy.wasm compiles under Cranelift (201, not WASM_COMPILE_FAILED)" 201 "$STATUS"
check_eq "created row carries the uploaded bytes' sha256" "$HAPPY_SHA" "$(body wasm_sha256)"
check_eq "created row carries the uploaded byte size" "$HAPPY_SIZE" "$(body size_bytes)"
check_eq "new function is active by default" true "$(body active)"
check_eq "new function: invoke_anon defaults to false" false "$(body invoke_anon)"
check_eq "new function: invoke_user defaults to false" false "$(body invoke_user)"
check_disk "happy artifact {sha}.wasm is stored under tenants/<id>/_functions" "$A_ID" "$HAPPY_SHA" yes

upload mem "$FX/membomb.wasm"
check_eq "upload membomb.wasm compiles (201)" 201 "$STATUS"

# --- compile gate: refused inputs ---------------------------------------------
upload junk "$W/junk.wasm"
check_eq "non-wasm bytes are refused at upload (422)" 422 "$STATUS"
check_eq "non-wasm bytes are refused with WASM_COMPILE_FAILED" WASM_COMPILE_FAILED "$(body error_code)"

upload pmvp "$W/mvp.wasm"
check_eq "hand-built MVP component (control for the proposal checks) is accepted (201)" 201 "$STATUS"
for k in gc funcref wide; do
  upload "p$k" "$W/$k.wasm"
  check_eq "component using the $k proposal (off in drust's engine) is refused (422)" 422 "$STATUS"
  check_eq "component using the $k proposal is refused with WASM_COMPILE_FAILED" WASM_COMPILE_FAILED "$(body error_code)"
done
upload pgc "$W/gc.wasm"
check_contains "GC refusal names the disabled gc feature" "gc feature" "$(body message)"
upload pwide "$W/wide.wasm"
check_contains "wide-arithmetic refusal names the disabled feature" "wide arithmetic support is not enabled" "$(body message)"
svc GET /functions/pgc
check_eq "a refused upload leaves no function row (GET 404 FN_NOT_FOUND)" "404 FN_NOT_FOUND" "$STATUS $(body error_code)"

# --- input validation ----------------------------------------------------------
upload "Bad.Name" "$W/mvp.wasm"
check_eq "uppercase/dot function name is refused with 422 FN_NAME_INVALID" "422 FN_NAME_INVALID" "$STATUS $(body error_code)"
upload badtrig "$W/mvp.wasm" '[{"collection":"src","events":["exploded"]}]'
check_eq "unknown trigger event is refused (422)" 422 "$STATUS"
check_eq "unknown trigger event is refused with FN_TRIGGERS_INVALID" FN_TRIGGERS_INVALID "$(body error_code)"
REQ_TIMEOUT=60 req POST "$T/functions" -H "Authorization: Bearer $SERVICE_KEY" --form-string "name=nowasm"
check_eq "multipart create without a wasm part is refused with 422 INVALID_PARAMS" "422 INVALID_PARAMS" "$STATUS $(body error_code)"

# --- service invoke of happy -----------------------------------------------------
REQ_TIMEOUT=90 svc POST /functions/happy/invoke '{"event":{"smoke":"svc-1"}}'
check_eq "service invoke of happy answers 200" 200 "$STATUS"
check_eq "service invoke of happy reports status ok" ok "$(body status)"
check_eq "happy returns its documented payload {\"done\":true}" '{"done":true}' "$(body result)"
check_contains "invoke response carries the guest's host::log line" "happy fixture running" "$(body logs)"
svc GET "/records/fn_out?perPage=50"
check_eq "happy's insert-record host op landed exactly one row in fn_out" 1 "$(body total)"
check_eq "the inserted row's payload is the event JSON the function received" '{"smoke":"svc-1"}' "$(body records.0.payload)"
SVC_ROW_ID="$(body records.0.id)"
mcp_call get_record_history "{\"collection\":\"fn_out\",\"record_id\":${SVC_ROW_ID:-0}}"
check_eq "record history captured the function's insert (op insert)" insert "$(printf '%s' "$MCP_TEXT" | json rows.0.op)"
check_eq "history actor of a service-invoked function write is service" service "$(printf '%s' "$MCP_TEXT" | json rows.0.actor_kind)"
check_eq "history new-image payload matches the inserted row" '{"smoke":"svc-1"}' "$(printf '%s' "$MCP_TEXT" | json rows.0.new.payload)"

# --- membomb: memory cap -----------------------------------------------------------
REQ_TIMEOUT=150 svc POST /functions/mem/invoke '{"event":{}}'
check_eq "membomb invoke answers 200 (the run fails, the request does not)" 200 "$STATUS"
check_eq "membomb is stopped by the per-Store memory cap with status oom" oom "$(body status)"
check_contains "membomb's result is the guest trap after the failed grow" "wasm trap" "$(body result)"
req GET "$BASE/health"
check_eq "drust is still healthy after the memory-cap run" 200 "$STATUS"

# --- logs endpoint -------------------------------------------------------------------
svc GET "/functions/happy/logs?limit=10"
check_eq "logs endpoint answers 200" 200 "$STATUS"
check_eq "logs: newest row is the manual invoke" manual "$(body logs.0.trigger)"
check_eq "logs: newest row status ok" ok "$(body logs.0.status)"
check_contains "logs: captured guest log text is stored" "happy fixture running" "$(body logs.0.log_text)"
check_eq "logs: result_json stores the returned payload" '{"done":true}' "$(body logs.0.result_json)"
svc GET "/functions/mem/logs?limit=1"
check_eq "logs: membomb's run is logged as oom" oom "$(body logs.0.status)"
svc GET "/functions/mem/logs?limit=1"
check_eq "logs?limit=1 returns exactly one row" 1 "$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["logs"]))' 2>/dev/null)"

# --- list / get ----------------------------------------------------------------------
svc GET /functions
check_eq "list functions answers 200" 200 "$STATUS"
names="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(",".join(sorted(f["name"] for f in json.load(sys.stdin)["functions"])))' 2>/dev/null)"
check_eq "list shows exactly the accepted uploads" "happy,mem,pmvp" "$names"
svc GET /functions/happy
check_eq "get one function answers 200 with its name" happy "$(body name)"
svc GET /functions/ghost
check_eq "get a missing function answers 404" 404 "$STATUS"
check_eq "get a missing function answers FN_NOT_FOUND" FN_NOT_FOUND "$(body error_code)"

# --- config routes are service-only ----------------------------------------------------
anon GET /functions
check_eq "anon key cannot list functions (403)" 403 "$STATUS"
check_eq "anon list is refused with WRITE_DENIED" WRITE_DENIED "$(body error_code)"
anon PATCH /functions/happy '{"invoke_anon":true}'
check_eq "anon key cannot grant itself invoke (PATCH 403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"
anon GET /functions/happy/logs
check_eq "anon key cannot read function logs (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"
REQ_TIMEOUT=60 req POST "$T/functions" -H "Authorization: Bearer $ANON_KEY" \
  --form-string name=anonup -F "wasm=@$W/mvp.wasm"
check_eq "anon key cannot upload a function (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"
svc GET /functions/happy
check_eq "the refused anon PATCH changed nothing (invoke_anon still false)" false "$(body invoke_anon)"

# --- invoke ACL: anon -------------------------------------------------------------------
anon POST /functions/happy/invoke '{"event":{}}'
check_eq "anon invoke is denied by default (403)" 403 "$STATUS"
check_eq "anon invoke is denied with FN_INVOKE_ANON_DENIED" FN_INVOKE_ANON_DENIED "$(body error_code)"
anon POST /functions/ghost/invoke '{"event":{}}'
check_eq "anon invoke of a missing function gives the same 403 (no existence oracle)" "403 FN_INVOKE_ANON_DENIED" "$STATUS $(body error_code)"
svc POST /functions/ghost/invoke '{"event":{}}'
check_eq "service invoke of a missing function answers 404 FN_NOT_FOUND" "404 FN_NOT_FOUND" "$STATUS $(body error_code)"

svc PATCH /functions/happy '{"invoke_anon":true}'
check_eq "service grants invoke_anon (PATCH 200)" 200 "$STATUS"
check_eq "PATCH response shows invoke_anon true" true "$(body invoke_anon)"
count_rows fn_out; before="$ROWS"
REQ_TIMEOUT=90 anon POST /functions/happy/invoke '{"event":{"smoke":"anon-nocap"}}'
check_eq "granted anon invoke is admitted by the gate (200)" 200 "$STATUS"
check_eq "anon-run host insert without anon_caps[insert] fails (status error)" error "$(body status)"
check_contains "anon-run host insert is refused with ANON_CAP_DENIED" "ANON_CAP_DENIED" "$(body result)"
count_rows fn_out
check_eq "the cap-denied anon run wrote no row" "$before" "$ROWS"

mcp_call set_anon_caps '{"collection":"fn_out","caps":["select","insert"]}'
mcp_ok "MCP set_anon_caps fn_out [select,insert] succeeds"
REQ_TIMEOUT=90 anon POST /functions/happy/invoke '{"event":{"smoke":"anon-ok"}}'
check_eq "anon invoke with insert cap runs ok" ok "$(body status)"
svc GET "/records/fn_out?perPage=100"
anon_row="$(printf '%s' "$BODY" | python3 -c '
import json,sys
for r in json.load(sys.stdin)["records"]:
    if r["payload"] == "{\"smoke\":\"anon-ok\"}": print(r["id"]); break' 2>/dev/null)"
check_ne "anon-run insert landed in fn_out" "" "$anon_row"
mcp_call get_record_history "{\"collection\":\"fn_out\",\"record_id\":${anon_row:-0}}"
check_eq "history actor of an anon-invoked function write is anon (not god-mode)" anon "$(printf '%s' "$MCP_TEXT" | json rows.0.actor_kind)"

svc PATCH /functions/happy '{"invoke_user":true}'
check_eq "one-sided PATCH of invoke_user keeps invoke_anon (still true)" true "$(body invoke_anon)"
svc PATCH /functions/happy '{"invoke_anon":false}'
check_eq "one-sided PATCH revoking invoke_anon keeps invoke_user (still true)" true "$(body invoke_user)"
anon POST /functions/happy/invoke '{"event":{}}'
check_eq "anon invoke is denied again after revoke" "403 FN_INVOKE_ANON_DENIED" "$STATUS $(body error_code)"
svc PATCH /functions/happy '{"invoke_user":false}'
check_eq "service revokes invoke_user" false "$(body invoke_user)"

# --- invoke ACL: user ----------------------------------------------------------------------
UPW="$(python3 -c 'import secrets; print("Sm0ke-" + secrets.token_urlsafe(18))')"
UEMAIL="smoke-fn-$$@example.invalid"
svc POST /admin/users "{\"email\":\"$UEMAIL\",\"password\":\"$UPW\",\"verified\":true}"
check_eq "service REST create_user succeeds" 201 "$STATUS"
# The end-user login limiter is per IP (5 per 60 s) and every smoke agent
# shares this host's IP, so a 429 here is usually someone else's logins. Back
# off and retry at most twice (bounded: <= ~50 s extra) before skipping.
_login_try=0
while :; do
  req POST "$T/auth/login" -H 'Content-Type: application/json' \
    --data "{\"email\":\"$UEMAIL\",\"password\":\"$UPW\"}"
  [ "$STATUS" = 429 ] || break
  _login_try=$((_login_try + 1))
  [ "$_login_try" -le 2 ] || break
  _ra="$(header retry-after)"
  case "$_ra" in '' | *[!0-9]*) _ra=25 ;; esac
  [ "$_ra" -le 30 ] || _ra=30
  sleep "$_ra"
done
if [ "$STATUS" = 429 ]; then
  note "user login rate-limited (shared IP) — user invoke checks skipped this run"
else
  check_eq "end-user password login answers 200" 200 "$STATUS"
  UTOK="$(body token || true)"
  UID_="$(body user_id || true)"
  user_call "$UTOK" POST /functions/happy/invoke '{"event":{}}'
  check_eq "user invoke is denied by default" "403 FN_INVOKE_USER_DENIED" "$STATUS $(body error_code)"
  user_call "$UTOK" GET /functions
  check_eq "user token cannot list functions (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"
  svc PATCH /functions/happy '{"invoke_user":true}'
  check_eq "service grants invoke_user" true "$(body invoke_user)"
  mcp_call set_user_caps '{"collection":"fn_out","caps":["select","insert"]}'
  mcp_ok "MCP set_user_caps fn_out [select,insert] succeeds"
  REQ_TIMEOUT=90 user_call "$UTOK" POST /functions/happy/invoke '{"event":{"smoke":"user-ok"}}'
  check_eq "granted user invoke runs ok" "200 ok" "$STATUS $(body status)"
  svc GET "/records/fn_out?perPage=100"
  user_row="$(printf '%s' "$BODY" | python3 -c '
import json,sys
for r in json.load(sys.stdin)["records"]:
    if r["payload"] == "{\"smoke\":\"user-ok\"}": print(r["id"]); break' 2>/dev/null)"
  check_ne "user-run insert landed in fn_out" "" "$user_row"
  mcp_call get_record_history "{\"collection\":\"fn_out\",\"record_id\":${user_row:-0}}"
  check_eq "history actor of a user-invoked function write is user" user "$(printf '%s' "$MCP_TEXT" | json rows.0.actor_kind)"
  check_eq "history actor id is the invoking user's id" "$UID_" "$(printf '%s' "$MCP_TEXT" | json rows.0.actor_id)"
  svc PATCH /functions/happy '{"invoke_user":false}'
  user_call "$UTOK" POST /functions/happy/invoke '{"event":{}}'
  check_eq "user invoke is denied again after revoke" "403 FN_INVOKE_USER_DENIED" "$STATUS $(body error_code)"
fi

# --- PATCH: active / description / triggers ---------------------------------------------
svc PATCH /functions/happy '{"active":false,"description":"paused by smoke"}'
check_eq "PATCH active=false + description answers 200" "200 false" "$STATUS $(body active)"
check_eq "PATCH stored the new description" "paused by smoke" "$(body description)"
count_rows fn_out; before="$ROWS"
REQ_TIMEOUT=90 svc POST /functions/happy/invoke '{"event":{"smoke":"inactive"}}'
check_eq "invoking a deactivated function reports status error" error "$(body status)"
check_eq "deactivated run says why" "function deactivated before run" "$(body result)"
count_rows fn_out
check_eq "a deactivated function did not run (no new row)" "$before" "$ROWS"
svc PATCH /functions/happy '{"active":true}'
check_eq "PATCH active=true re-enables" true "$(body active)"
svc PATCH /functions/happy '{"triggers":[{"collection":"src","events":["nope"]}]}'
check_eq "PATCH with an invalid trigger is refused with FN_TRIGGERS_INVALID" "422 FN_TRIGGERS_INVALID" "$STATUS $(body error_code)"
svc PATCH /functions/ghost '{"active":false}'
check_eq "PATCH a missing function answers 404 FN_NOT_FOUND" "404 FN_NOT_FOUND" "$STATUS $(body error_code)"

# --- record trigger dispatch + depth=1 ---------------------------------------------------
# onsrc = happy's bytes, triggered by src.created AND fn_out.created. Its own
# insert into fn_out must NOT re-trigger it (functions: None on the executor's
# host state — invariant 13), so one src insert ⇒ exactly one run.
upload onsrc "$FX/happy.wasm" '[{"collection":"src","events":["created"]},{"collection":"fn_out","events":["created"]}]'
check_eq "upload a record-triggered function (same bytes as happy) answers 201" 201 "$STATUS"
check_eq "same bytes ⇒ same content-addressed sha" "$HAPPY_SHA" "$(body wasm_sha256)"
count_rows fn_out; before="$ROWS"
svc POST /records/src '{"data":{"x":"fire"}}'
check_eq "service insert into src (trigger source) answers 201" 201 "$STATUS"
_trig_done() { log_count onsrc "record.created:src"; [ "$LOGS" -ge 1 ]; }
if poll_until "onsrc ran" 60 _trig_done; then ok "record.created:src fan-out ran onsrc (log row trigger=record.created:src)"; else bad "record.created:src fan-out ran onsrc" "no log row after 60 s"; fi
svc GET "/functions/onsrc/logs?limit=5"
check_eq "triggered run finished ok" ok "$(body logs.0.status)"
svc GET "/records/fn_out?perPage=100"
trig_payload="$(printf '%s' "$BODY" | python3 -c '
import json,sys
for r in json.load(sys.stdin)["records"]:
    if "record.created" in (r.get("payload") or ""): print(r["payload"]); break' 2>/dev/null)"
check_contains "triggered run received the record.created event JSON" '"trigger":"record.created"' "$trig_payload"
check_contains "the event names the source collection" '"collection":"src"' "$trig_payload"
# Give a recursive re-trigger a bounded chance to show up before asserting it did not.
_recursed() { log_count onsrc "record.created:fn_out"; [ "$LOGS" -ge 1 ]; }
if poll_until "onsrc recursed" 4 _recursed; then
  bad "a function's own write does not re-trigger functions (depth=1)" "found a record.created:fn_out run"
else
  ok "a function's own write does not re-trigger functions (depth=1)"
fi
count_rows fn_out
check_eq "one trigger event produced exactly one function-written row" "$((before + 1))" "$ROWS"
# Positive control for the depth=1 check above: the fn_out binding IS live, so
# a REST insert into fn_out fires onsrc exactly once — and onsrc's own write
# from that run again does not re-trigger it. Without this, "no fn_out run"
# would also pass if the second trigger entry were simply never bound.
svc POST /records/fn_out '{"data":{"payload":"rest-direct"}}'
check_eq "service insert into fn_out answers 201" 201 "$STATUS"
if poll_until "onsrc ran on fn_out" 60 _recursed; then
  ok "a REST insert into fn_out fires the fn_out.created binding (control for depth=1)"
else
  bad "a REST insert into fn_out fires the fn_out.created binding (control for depth=1)" "no record.created:fn_out log row after 60 s"
fi
_fnout_runs_gt1() { log_count onsrc "record.created:fn_out"; [ "$LOGS" -gt 1 ]; }
if poll_until "onsrc re-triggered" 4 _fnout_runs_gt1; then
  bad "the fn_out-triggered run's own fn_out write does not re-trigger (exactly one fn_out run)" "log rows: $LOGS"
else
  check_eq "the fn_out-triggered run's own fn_out write does not re-trigger (exactly one fn_out run)" 1 "$LOGS"
fi
svc PATCH /functions/onsrc '{"triggers":[]}'
check_eq "PATCH triggers=[] unbinds the function" "200 []" "$STATUS $(body triggers_json)"

# --- re-upload replaces in place ------------------------------------------------------------
SWAP_OLD_SHA="$(sha_of "$W/swap_old.wasm")"
upload swap "$W/swap_old.wasm"
check_eq "upload swap (v1, hand-built component) answers 201" 201 "$STATUS"
swap_id="$(body id)"
check_disk "swap v1 artifact is on disk" "$A_ID" "$SWAP_OLD_SHA" yes
REQ_TIMEOUT=90 svc POST /functions/swap/invoke '{"event":{}}'
check_eq "swap v1 (no handle export) fails at instantiation with status trap" trap "$(body status)"
check_contains "swap v1's failure names the missing handle export" 'no export `handle`' "$(body result)"
upload swap "$FX/happy.wasm"
check_eq "re-upload under the same name replaces (201)" 201 "$STATUS"
check_eq "replace keeps the same row id (upsert in place)" "$swap_id" "$(body id)"
check_eq "replace switches the row to the new sha" "$HAPPY_SHA" "$(body wasm_sha256)"
REQ_TIMEOUT=90 svc POST /functions/swap/invoke '{"event":{"smoke":"swapped"}}'
check_eq "the replaced function now runs the new code (status ok, done payload)" 'ok {"done":true}' "$(body status) $(body result)"
check_disk "replace GCs the displaced v1 artifact" "$A_ID" "$SWAP_OLD_SHA" no

# --- MCP function tools ---------------------------------------------------------------------
mcp_rpc '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
ann="$(printf '%s' "$BODY" | python3 -c '
import json,sys
want = ["list_functions","get_function_logs","set_function_active","set_function_invoke_acl","delete_function","invoke_function"]
tools = {t["name"]: t.get("annotations") or {} for t in json.load(sys.stdin)["result"]["tools"]}
out = []
for n in want:
    a = tools.get(n)
    out.append("%s:%s" % (n, "missing" if a is None else "ro=%s,de=%s,ow=%s" % (a.get("readOnlyHint"), a.get("destructiveHint"), a.get("openWorldHint"))))
print(" ".join(out))' 2>/dev/null)"
check_eq "MCP exposes the six function tools with the documented hints (only invoke_function open-world; delete/invoke destructive)" \
  "list_functions:ro=True,de=None,ow=False get_function_logs:ro=True,de=None,ow=False set_function_active:ro=False,de=False,ow=False set_function_invoke_acl:ro=False,de=False,ow=False delete_function:ro=False,de=True,ow=False invoke_function:ro=False,de=True,ow=True" "$ann"
check_not_contains "there is no MCP upload tool (REST multipart is the only ingest)" "upload_function" "$BODY"

mcp_call list_functions '{}'
mcp_ok "MCP list_functions is not an error"
check_eq "MCP list_functions lists the same five functions as REST" "happy,mem,onsrc,pmvp,swap" \
  "$(printf '%s' "$MCP_TEXT" | python3 -c 'import json,sys; print(",".join(sorted(f["name"] for f in json.load(sys.stdin)["functions"])))' 2>/dev/null)"
mcp_call set_function_active '{"name":"pmvp","active":false}'
check_eq "MCP set_function_active false" false "$(printf '%s' "$MCP_TEXT" | json active)"
svc GET /functions/pmvp
check_eq "MCP set_function_active is visible over REST" false "$(body active)"
mcp_call set_function_active '{"name":"ghost","active":true}'
check_eq "MCP set_function_active on a missing name reports FN_NOT_FOUND" FN_NOT_FOUND "$MCP_CODE"
mcp_call set_function_invoke_acl '{"name":"swap","anon":true,"user":false}'
check_eq "MCP set_function_invoke_acl answers the new flags" true "$(printf '%s' "$MCP_TEXT" | json invoke_anon)"
svc GET /functions/swap
check_eq "MCP-granted invoke_anon is visible over REST" true "$(body invoke_anon)"
REQ_TIMEOUT=90 anon POST /functions/swap/invoke '{"event":{"smoke":"mcp-acl"}}'
check_eq "MCP-granted anon invoke runs (anon has fn_out insert cap)" "200 ok" "$STATUS $(body status)"
mcp_call set_function_invoke_acl '{"name":"swap","anon":false,"user":false}'
anon POST /functions/swap/invoke '{"event":{}}'
check_eq "MCP revoke of invoke_anon denies anon again" "403 FN_INVOKE_ANON_DENIED" "$STATUS $(body error_code)"

log_count happy manual; before_manual="$LOGS"
mcp_call invoke_function '{"name":"happy","event":{"smoke":"mcp-async"}}'
check_eq "MCP invoke_function enqueues (ack names the function)" happy "$(printf '%s' "$MCP_TEXT" | json enqueued)"
_mcp_ran() { log_count happy manual; [ "$LOGS" -gt "$before_manual" ]; }
if poll_until "mcp invoke ran" 60 _mcp_ran; then ok "MCP-enqueued invoke ran (new manual log row)"; else bad "MCP-enqueued invoke ran" "no new manual log row after 60 s"; fi
mcp_call get_function_logs '{"name":"happy","limit":1}'
check_eq "MCP get_function_logs shows the async run ok" ok "$(printf '%s' "$MCP_TEXT" | json logs.0.status)"
mcp_call invoke_function '{"name":"ghost","event":{}}'
check_eq "MCP invoke_function on a missing name reports FN_NOT_FOUND" FN_NOT_FOUND "$MCP_CODE"

# --- delete + artifact GC -----------------------------------------------------------------------
svc DELETE /functions/happy
check_eq "REST delete answers 204" 204 "$STATUS"
svc GET /functions/happy
check_eq "deleted function is gone (404)" 404 "$STATUS"
svc DELETE /functions/happy
check_eq "second delete answers 404 FN_NOT_FOUND" "404 FN_NOT_FOUND" "$STATUS $(body error_code)"
check_disk "artifact survives while onsrc/swap still reference the sha" "$A_ID" "$HAPPY_SHA" yes
mcp_call delete_function '{"name":"onsrc"}'
check_eq "MCP delete_function answers the deleted name" onsrc "$(printf '%s' "$MCP_TEXT" | json deleted)"
svc DELETE /functions/swap
check_eq "REST delete swap answers 204" 204 "$STATUS"
check_disk "artifact is GC'd once no row references the sha" "$A_ID" "$HAPPY_SHA" no

# ======================================================= tenant B: loop + isolation
new_tenant fn-b
B_ID="$TENANT_ID"; B_T="$T"; B_SVC="$SERVICE_KEY"
upload spin "$FX/loop.wasm"
check_eq "upload loop.wasm compiles (201)" 201 "$STATUS"

# Start the loop in the background; while it spins, tenant A's function must still run.
curl -sS -o "$TMP/loop.body" -w '%{http_code}' --max-time 180 -X POST "$B_T/functions/spin/invoke" \
  -H "Authorization: Bearer $B_SVC" -H 'Content-Type: application/json' \
  --data '{"event":{}}' > "$TMP/loop.status" 2>/dev/null &
loop_pid=$!

T="$A_T"; SERVICE_KEY="$A_SVC"; ANON_KEY="$A_ANON"
upload side "$FX/happy.wasm"
check_eq "upload a function in tenant A while B's loop spins (201)" 201 "$STATUS"
t0="$(python3 -c 'import time; print(time.time())')"
REQ_TIMEOUT=90 svc POST /functions/side/invoke '{"event":{"smoke":"while-loop"}}'
dt="$(python3 -c 'import sys,time; print(int(time.time()-float(sys.argv[1])))' "$t0")"
check_eq "tenant A's function runs ok while tenant B's loop spins" ok "$(body status)"
# Overlap proof: B's loop request must still be in flight when A's invoke
# returned, otherwise the two checks around this one prove nothing about
# isolation (they would pass just as well run one after the other).
if kill -0 "$loop_pid" 2>/dev/null; then
  ok "B's loop invoke was still in flight when A's invoke returned (the runs overlapped)"
else
  bad "B's loop invoke was still in flight when A's invoke returned (the runs overlapped)" "loop request had already finished"
fi
if [ "$dt" -lt "$FN_TIMEOUT_SECS" ]; then
  ok "tenant A's invoke finished before B's loop deadline (${dt}s < ${FN_TIMEOUT_SECS}s)"
else
  bad "tenant A's invoke finished before B's loop deadline" "took ${dt}s"
fi
svc DELETE /functions/side

wait "$loop_pid" || true
T="$B_T"; SERVICE_KEY="$B_SVC"; TENANT_ID="$B_ID"
STATUS="$(cat "$TMP/loop.status" 2>/dev/null || echo 000)"
BODY="$(cat "$TMP/loop.body" 2>/dev/null || true)"
check_eq "loop invoke answers 200 (the run fails, the request does not)" 200 "$STATUS"
check_eq "loop.wasm is stopped by the epoch deadline with status timeout" timeout "$(body status)"
check_contains "timeout result is the wasmtime interrupt trap" "interrupt" "$(body result)"
dur="$(body duration_ms || echo 0)"
if [ "${dur:-0}" -ge $(( (FN_TIMEOUT_SECS - 1) * 1000 )) ] && [ "${dur:-0}" -le 120000 ]; then
  ok "loop ran for about the configured ${FN_TIMEOUT_SECS}s budget (${dur} ms), not forever"
else
  bad "loop ran for about the configured ${FN_TIMEOUT_SECS}s budget" "duration_ms=${dur}"
fi
svc GET "/functions/spin/logs?limit=1"
check_eq "logs: the loop run is logged as timeout" timeout "$(body logs.0.status)"

# --- FN_LIMIT (default 10 per tenant) + no orphan blob on rejection --------------------------
i=1
while [ "$i" -le 9 ]; do
  mkwasm mvp "$W/lim$i.wasm" "lim-$i-$$"
  upload "lim$i" "$W/lim$i.wasm"
  [ "$STATUS" = 201 ] || bad "upload lim$i for the cap test" "status $STATUS: $BODY"
  i=$((i + 1))
done
svc GET /functions
check_eq "tenant B now holds 10 functions" 10 "$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["functions"]))' 2>/dev/null)"
check_disk "tenant B's accepted lim9 artifact is on disk (control for the orphan check)" "$B_ID" "$(sha_of "$W/lim9.wasm")" yes
mkwasm mvp "$W/over.wasm" "over-$$"
OVER_SHA="$(sha_of "$W/over.wasm")"
upload over "$W/over.wasm"
check_eq "the 11th function is refused with 409 FN_LIMIT" "409 FN_LIMIT" "$STATUS $(body error_code)"
check_disk "a FN_LIMIT rejection leaves no orphan artifact on disk" "$B_ID" "$OVER_SHA" no
upload lim1 "$FX/happy.wasm"
check_eq "replacing an existing name at the cap is still allowed (201)" 201 "$STATUS"

finish

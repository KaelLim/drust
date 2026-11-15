#!/usr/bin/env bash
# Records / schema / query surface against the live stack (rusqlite 0.42 +
# bundled SQLite 3.54.1, plus the v1.67.0 E-track fixes):
#   - create_collection / add_field for every field type via MCP, D1 (rowid /
#     _rowid_ / oid add_field refused), drop_field warnings (E6')
#   - REST CRUD as service, STRICT typing, CHECK / UNIQUE constraint codes,
#     datetime / json / boolean round-trips
#   - /list, /aggregate, /search (vector) with filters and sorts
#   - records:batch (atomic) and records:upsert, service-only
#   - /query and /query/explain service-only, read-only authorizer on /query
#   - legacy ?filter= / ?sort= service-only (RAW_FILTER_DENIED)
#   - anon_caps / user_caps matrix, end-user register/login, owner_field
#     scoping, RLS select policy (POLICY_SELECT_REQUIRES_USING)
#   - E1' (SYSTEM_FIELD_READONLY), E8 (describe of _system_* / sqlite_*),
#     E9 (id-only PATCH response)
#   - record history for insert / update / delete
#   - FTS5 index lifecycle (create, $fts on /list + /aggregate, sync triggers,
#     FTS_QUERY_INVALID, drop)
#   - openapi.json / types.ts / zod.ts for service and anon
#   - quota tier admin API validation (a tiny quota is not settable: min tier 1)
#   - client-IP derivation behind the Compose Caddy (DRUST_TRUSTED_PROXIES=1):
#     the login's ip_at_login, no fallback warning, the boot line
# One tenant per run (deleted on exit by lib.sh), one end-user login per run.
. "$(dirname "$0")/lib.sh"

# UTC start of this script, for `docker compose logs --since`.
START_ISO="$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"

# ── local helpers ──────────────────────────────────────────────────────────

# pyq EXPR — evaluate a python expression over the last response body (bound
# to `d`); prints the result (JSON for containers), empty on any error.
pyq() {
  printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    v = eval(sys.argv[1])
except Exception:
    sys.exit(0)
if isinstance(v, (dict, list)):
    print(json.dumps(v, ensure_ascii=False, sort_keys=True))
elif isinstance(v, bool):
    print("true" if v else "false")
elif v is None:
    print("null")
else:
    print(v)
' "$1"
}

# mcp_text_q EXPR — like pyq, over the parsed text of the last MCP tool result.
mcp_text_q() {
  printf '%s' "$MCP_TEXT" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    v = eval(sys.argv[1])
except Exception:
    sys.exit(0)
if isinstance(v, (dict, list)):
    print(json.dumps(v, ensure_ascii=False, sort_keys=True))
elif isinstance(v, bool):
    print("true" if v else "false")
elif v is None:
    print("null")
else:
    print(v)
' "$1"
}

# mcp_outcome — after mcp_call: "ok" for a successful tool result, "tool_error"
# for isError:true, "rpc_error" for a JSON-RPC error, "transport" otherwise.
mcp_outcome() {
  printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
except Exception:
    print("transport"); sys.exit(0)
if "error" in d:
    print("rpc_error")
elif "result" in d:
    print("tool_error" if d["result"].get("isError") else "ok")
else:
    print("transport")
'
}

# mcp_err_code — the error_code of the last MCP failure, from either face
# (JSON-RPC error.data.error_code, or the isError text body's error_code).
mcp_err_code() {
  printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    if "error" in d:
        print((d["error"].get("data") or {}).get("error_code", ""))
    elif d.get("result", {}).get("isError"):
        print(json.loads(d["result"]["content"][0]["text"]).get("error_code", ""))
except Exception:
    pass
'
}

# mcp_err_msg — the human message of the last MCP failure (no secrets in it).
mcp_err_msg() {
  printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    if "error" in d:
        print(d["error"].get("message", ""))
    elif d.get("result", {}).get("isError"):
        print(json.loads(d["result"]["content"][0]["text"]).get("message", ""))
except Exception:
    pass
'
}

USER_TOKEN=""
user() { _tenant_call "$USER_TOKEN" "$@"; }

# The data plane rate-limits each bearer to DRUST_RATE_LIMIT_PER_TOKEN (60) per
# DRUST_RATE_LIMIT_WINDOW_SECS (10 s), and every mcp_call is three requests on
# the service key. A 429 here is that limiter, not the behaviour under test,
# so both request paths back off on Retry-After (bounded) and retry. The lib's
# versions are wrapped, not edited.
eval "_lib_req() $(declare -f req | sed '1d')"
req() {
  local n=0 wait
  while :; do
    _lib_req "$@"
    [ "$STATUS" != 429 ] && return 0
    n=$((n + 1)); [ $n -ge 15 ] && return 0
    wait="$(header retry-after)"; case "$wait" in ''|*[!0-9]*) wait=1 ;; esac
    [ "$wait" -gt 5 ] && wait=5
    sleep "$wait"
  done
}
eval "_lib_mcp_rpc() $(declare -f mcp_rpc | sed '1d')"
mcp_rpc() {
  local n=0
  while :; do
    _lib_mcp_rpc "$1"
    case "$BODY" in *'"http_status": 429'*) ;; *) return 0 ;; esac
    n=$((n + 1)); [ $n -ge 15 ] && return 0
    sleep 1
  done
}

new_tenant records
C=items

# ── 1. schema DDL via MCP: every field type ────────────────────────────────

mcp_call create_collection '{"name":"items","fields":[
  {"name":"title","sql_type":"text","nullable":false},
  {"name":"qty","sql_type":"integer","min":0,"max":100},
  {"name":"price","sql_type":"real"},
  {"name":"done","sql_type":"boolean","default_value":false},
  {"name":"due","sql_type":"datetime"},
  {"name":"meta","sql_type":"json"},
  {"name":"sku","sql_type":"text","unique":true},
  {"name":"color","sql_type":"text","enum_values":["red","blue"]},
  {"name":"emb","sql_type":"vector","dim":3}]}'
check_eq "create_collection with text/integer/real/boolean/datetime/json/vector fields succeeds" ok "$(mcp_outcome)"
check_eq "create_collection maps the logical types onto STRICT storage classes" \
  '["INTEGER", "TEXT", "INTEGER", "REAL", "INTEGER", "TEXT", "TEXT", "TEXT", "TEXT", "BLOB", "TEXT", "TEXT"]' \
  "$(mcp_text_q '[f["sql_type"] for f in d["fields"]]')"
check_eq "vector field is registered with its dim" '[{"dim": 3, "name": "emb"}]' "$(mcp_text_q 'd["vector_fields"]')"

mcp_call add_field '{"collection":"items","field":{"name":"note","sql_type":"text","max_length":5}}'
check_eq "add_field of an ordinary text column succeeds" ok "$(mcp_outcome)"
for f in integer real boolean datetime json; do
  mcp_call add_field "{\"collection\":\"items\",\"field\":{\"name\":\"extra_$f\",\"sql_type\":\"$f\"}}"
  check_eq "add_field with sql_type=$f succeeds" ok "$(mcp_outcome)"
done
mcp_call add_field '{"collection":"items","field":{"name":"extra_vec","sql_type":"vector","dim":2}}'
check_eq "add_field with sql_type=vector succeeds" ok "$(mcp_outcome)"
mcp_call add_field '{"collection":"items","field":{"name":"bad","sql_type":"TEXT"}}'
check_eq "add_field refuses an upper-case sql_type (must be lowercase): JSON-RPC error" rpc_error "$(mcp_outcome)"
check_contains "add_field upper-case sql_type error says 'unsupported sql_type'" "unsupported sql_type" "$(mcp_err_msg)"

# D1 — SQLite 3.54 refuses ALTER TABLE ADD COLUMN for a rowid alias name.
for alias in rowid _rowid_ oid; do
  mcp_call add_field "{\"collection\":\"items\",\"field\":{\"name\":\"$alias\",\"sql_type\":\"text\"}}"
  check_eq "D1: add_field named $alias is refused (SQLite 3.54)" rpc_error "$(mcp_outcome)"
  check_contains "D1: add_field $alias error carries SQLite's 'cannot add rowid alias' text" \
    "cannot add rowid alias" "$(mcp_err_msg)"
done
note "D1 surface: JSON-RPC error, data.error_code=[$(mcp_err_code)] message=[$(mcp_err_msg)]"
mcp_call describe_collection '{"collection":"items"}'
check_eq "D1: describe still lists the table's columns and no rowid-alias column was added" true \
  "$(mcp_text_q '"title" in [f["name"] for f in d["fields"]] and not any(f["name"] in ("rowid","_rowid_","oid") for f in d["fields"])')"

# drop_field (E6'): an unreferenced drop answers with no warnings key.
mcp_call drop_field '{"collection":"items","field":"extra_real"}'
check_eq "drop_field of an unreferenced column succeeds" ok "$(mcp_outcome)"
check_eq "E6': unreferenced drop_field has no warnings key" false "$(mcp_text_q '"warnings" in d')"
mcp_call drop_field '{"collection":"items","field":"id"}'
check_eq "drop_field refuses the system id column (JSON-RPC error)" rpc_error "$(mcp_outcome)"
check_contains "drop_field id refusal says 'cannot drop system column'" "cannot drop system column" "$(mcp_err_msg)"

# ── 2. REST CRUD as service, types and constraints ─────────────────────────

req POST "$T/query" -H "Authorization: Bearer $SERVICE_KEY" -H 'Content-Type: application/json' \
  --data '{"sql":"select sqlite_version() as v"}'
check_eq "service /query answers 200" 200 "$STATUS"
check_eq "bundled SQLite is 3.54.1 (rusqlite 0.42 deployed)" 3.54.1 "$(pyq 'd["rows"][0][0]')"

svc POST /records/items '{"data":{"title":"alpha","qty":5,"price":1.5,"done":true,"due":"2026-01-02T03:04:05Z","meta":{"k":[1,2],"s":"x"},"sku":"s1","color":"red","emb":[1,0,0]}}'
check_eq "service insert answers 201" 201 "$STATUS"
ID1="$(body id)"
check_eq "insert response carries an integer id equal to the persisted record's id" true \
  "$(pyq 'isinstance(d["id"], int) and d["record"]["id"] == d["id"]')"
check_eq "insert response hides the vector column" false "$(pyq '"emb" in d["record"]')"
check_eq "boolean true is stored as 1" 1 "$(body record.done)"
check_ne "created_at is maintained by drust" "" "$(body record.created_at)"

svc GET "/records/items/$ID1"
check_eq "service GET by id answers 200" 200 "$STATUS"
check_eq "datetime field round-trips byte-identical" "2026-01-02T03:04:05Z" "$(body record.due)"
check_eq "json field round-trips to an equal JSON value" '{"k": [1, 2], "s": "x"}' \
  "$(pyq 'json.loads(d["record"]["meta"])')"
check_eq "real field round-trips" 1.5 "$(body record.price)"

svc POST /records/items '{"data":{"title":"beta","qty":20,"sku":"s2","color":"blue","due":"2026-03-01T00:00:00Z","emb":[0,1,0]}}'
ID2="$(body id)"; S2="$STATUS"
svc POST /records/items '{"data":{"title":"gamma","qty":50,"sku":"s3","due":"2025-12-31T23:59:59Z","emb":[0,0,1]}}'
ID3="$(body id)"
check_eq "two more service inserts each answer 201" "201 201" "$S2 $STATUS"

svc POST /records/items '{"data":{"title":"x","qty":500}}'
check_eq "integer max CHECK answers 400" 400 "$STATUS"
check_eq "integer max CHECK answers CHECK_CONSTRAINT_FAILED" CHECK_CONSTRAINT_FAILED "$(body error_code)"
svc POST /records/items '{"data":{"title":"x","color":"green"}}'
check_eq "enum CHECK answers CHECK_CONSTRAINT_FAILED" CHECK_CONSTRAINT_FAILED "$(body error_code)"
svc POST /records/items '{"data":{"title":"x","note":"toolongvalue"}}'
check_eq "max_length CHECK answers CHECK_CONSTRAINT_FAILED" CHECK_CONSTRAINT_FAILED "$(body error_code)"
svc POST /records/items '{"data":{"title":"dup","sku":"s1"}}'
check_eq "UNIQUE violation on insert is refused with 400" 400 "$STATUS"
check_contains "UNIQUE violation names the column" "UNIQUE constraint failed: items.sku" "$BODY"
note "UNIQUE surface: content-type=[$(header content-type)] error_code=[$(body error_code 2>/dev/null)]"
svc POST /records/items '{"data":{"title":"x","qty":"not-a-number"}}'
check_eq "STRICT table refuses TEXT in an INTEGER column with 400" 400 "$STATUS"
check_contains "STRICT refusal carries SQLite's STRICT message" "cannot store TEXT value in INTEGER column items.qty" "$BODY"
svc POST /records/items '{"data":{"title":"x","nope":1}}'
check_eq "unknown field on insert answers 400 FIELD_NOT_FOUND" "400 FIELD_NOT_FOUND" "$STATUS $(body error_code)"
note "unknown-field insert surface: body=[$(printf '%s' "$BODY" | head -c 120)]"
svc POST /records/items '{"data":{"qty":1}}'
check_eq "NOT NULL column omitted is refused with 400" 400 "$STATUS"
check_contains "NOT NULL refusal names the column" "NOT NULL constraint failed: items.title" "$BODY"
svc POST /records/items '{"data":{"title":"v","emb":[1,2]}}'
check_eq "vector of the wrong dim answers 422 VECTOR_DIM_MISMATCH" "422 VECTOR_DIM_MISMATCH" "$STATUS $(body error_code)"

svc PATCH "/records/items/$ID2" '{"data":{"qty":21,"title":"beta2"}}'
check_eq "service PATCH answers 200" 200 "$STATUS"
check_eq "service PATCH returns the full post-image (title)" beta2 "$(body record.title)"
check_eq "service PATCH returns the full post-image (qty)" 21 "$(body record.qty)"
svc PATCH "/records/items/$ID2" '{"data":{"nope":1}}'
check_eq "unknown field on PATCH answers 400 FIELD_NOT_FOUND" "400 FIELD_NOT_FOUND" "$STATUS $(body error_code)"
svc PATCH "/records/items/999999" '{"data":{"qty":1}}'
check_eq "PATCH of a missing id answers 404" 404 "$STATUS"

req DELETE "$T/records/items/$ID3?dry_run=true" -H "Authorization: Bearer $SERVICE_KEY"
check_eq "DELETE ?dry_run=true answers 200" 200 "$STATUS"
svc GET "/records/items/$ID3"
check_eq "dry-run delete leaves the row in place" 200 "$STATUS"
svc DELETE "/records/items/$ID3"
check_eq "service DELETE answers 204" 204 "$STATUS"
svc GET "/records/items/$ID3"
check_eq "deleted row answers 404" 404 "$STATUS"
req DELETE "$T/records/ghost/1?dry_run=true" -H "Authorization: Bearer $SERVICE_KEY"
check_eq "DELETE ?dry_run=true on a missing collection answers 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"
# E7's failing-probe path needs a collection dropped between the cap check and
# the probe (a race); this only asserts readers still read sqlite_master after
# a successful and a refused dry-run.
svc GET /collections
check_eq "GET /collections (sqlite_master read) still answers 200 after dry-run deletes" "200 true" \
  "$STATUS $(pyq '"items" in [c["name"] for c in d["collections"]]')"

# Record history: insert, update, delete were captured for ID3 / ID2.
svc GET "/collections/items/history?record_id=$ID3"
check_eq "history of a deleted record is [delete, insert] newest first" '["delete", "insert"]' \
  "$(pyq '[r["op"] for r in d["rows"]]')"
check_eq "history delete row carries the old image" gamma "$(pyq '[r for r in d["rows"] if r["op"]=="delete"][0]["old"]["title"]')"
svc GET "/collections/items/history?record_id=$ID2"
check_eq "history of an updated record is [update, insert]" '["insert", "update"]' \
  "$(pyq 'sorted(r["op"] for r in d["rows"])')"
check_eq "history update row carries old and new images" "beta beta2" \
  "$(pyq '" ".join([[r for r in d["rows"] if r["op"]=="update"][0]["old"]["title"], [r for r in d["rows"] if r["op"]=="update"][0]["new"]["title"]])')"
check_eq "history actor of a service write is service" service "$(pyq 'd["rows"][0]["actor_kind"]')"
mcp_call get_record_history "{\"collection\":\"items\",\"record_id\":$ID2}"
check_eq "MCP get_record_history sees the same two entries" 2 "$(mcp_text_q 'd["total"]')"
anon GET /collections/items/history
check_eq "anon cannot read record history (403 HISTORY_READ_DENIED)" "403 HISTORY_READ_DENIED" "$STATUS $(body error_code)"

# ── 3. /list, /aggregate, /search ──────────────────────────────────────────

svc POST /collections/items/list '{"filter":{"qty":{"gte":10}},"sort":{"field":"qty","dir":"desc"}}'
check_eq "/list gte filter + desc sort" "[$ID2]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /collections/items/list '{"sort":{"field":"qty","dir":"asc"},"select":["id","qty"]}'
check_eq "/list asc sort over all rows" "[$ID1, $ID2]" "$(pyq '[r["id"] for r in d["records"]]')"
check_eq "/list select projects only the requested columns" '["id", "qty"]' "$(pyq 'sorted(d["records"][0].keys())')"
check_eq "/list total counts every match" 2 "$(body total)"
svc POST /collections/items/list '{"filter":{"or":[{"color":"blue"},{"title":{"like":"alp%"}}]},"sort":{"field":"id","dir":"asc"}}'
check_eq "/list or + like filter" "[$ID1, $ID2]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /collections/items/list '{"filter":{"not":{"color":{"in":["red"]}}}}'
check_eq "/list not + in filter" "[$ID2]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /collections/items/list '{"filter":{"due":{"gt":"2026-02-01"}}}'
check_eq "/list datetime comparison filter" "[$ID2]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /collections/items/list '{"filter":{"extra_integer":{"is_null":true}},"per_page":1,"page":2,"sort":{"field":"id","dir":"asc"}}'
check_eq "/list is_null + pagination (page 2 of 2)" "[$ID2] 2" "$(pyq '[r["id"] for r in d["records"]]') $(body total)"
svc POST /collections/items/list '{"filter":{"nope":1}}'
check_eq "/list unknown filter field answers 400 FILTER_UNKNOWN_FIELD" "400 FILTER_UNKNOWN_FIELD" "$STATUS $(body error_code)"
svc POST /collections/items/list '{"filter":{"emb":1}}'
check_eq "/list on a vector field answers 400 FILTER_VECTOR_FIELD" "400 FILTER_VECTOR_FIELD" "$STATUS $(body error_code)"

svc POST /collections/items/aggregate '{"metrics":[{"op":"count"},{"op":"sum","field":"qty"},{"op":"avg","field":"qty"},{"op":"min","field":"qty","as":"lo"},{"op":"max","field":"qty"}],"group_by":["color"],"sort":{"field":"color","dir":"asc"}}'
check_eq "/aggregate answers 200" 200 "$STATUS"
check_eq "/aggregate count/sum/avg/min/max grouped by color" \
  '[["blue", 1, 21, 21.0, 21, 21], ["red", 1, 5, 5.0, 5, 5]]' \
  "$(pyq '[[r["color"],r["count"],r["sum_qty"],r["avg_qty"],r["lo"],r["max_qty"]] for r in d["rows"]]')"
svc POST /collections/items/aggregate '{"filter":{"qty":{"lt":10}},"metrics":[{"op":"count"}]}'
check_eq "/aggregate honours the filter" 1 "$(pyq 'd["rows"][0]["count"]')"
svc POST /collections/items/aggregate '{"metrics":[{"op":"count","as":"n"},{"op":"sum","field":"qty","as":"n"}]}'
check_eq "/aggregate duplicate alias answers AGG_ALIAS_DUPLICATE" AGG_ALIAS_DUPLICATE "$(body error_code)"

svc POST /collections/items/search '{"field":"emb","vector":[0.9,0.1,0],"k":2,"metric":"cosine"}'
check_eq "/search answers 200" 200 "$STATUS"
check_eq "/search ranks the nearest vector first" "$ID1" "$(pyq 'd["rows"][0]["id"]')"
check_eq "/search injects _distance and hides the vector" "true false" \
  "$(pyq '"_distance" in d["rows"][0]') $(pyq '"emb" in d["rows"][0]')"
svc POST /collections/items/search '{"field":"emb","vector":[0.9,0.1,0],"k":5,"where":{"color":"blue"}}'
check_eq "/search where filter restricts the candidates" "[$ID2]" "$(pyq '[r["id"] for r in d["rows"]]')"
svc POST /collections/items/search '{"field":"emb","vector":[1,0],"k":1}'
check_eq "/search with a wrong-dim query vector answers 422 VECTOR_DIM_MISMATCH" "422 VECTOR_DIM_MISMATCH" "$STATUS $(body error_code)"
anon POST /collections/items/search '{"field":"emb","vector":[1,0,0],"k":1}'
check_eq "anon /search with the default select cap answers 200" 200 "$STATUS"

# ── 4. batch / upsert (service-only) ───────────────────────────────────────

svc POST /collections/items/records:batch '{"records":[{"title":"b1","sku":"b1"},{"title":"b2","sku":"b2"}]}'
check_eq "service records:batch answers 200 with count 2" "200 2" "$STATUS $(body count)"
svc POST /collections/items/records:batch '{"records":[{"title":"b3","sku":"b3"},{"nope":"x"}]}'
check_eq "records:batch with one bad row answers 400" 400 "$STATUS"
svc POST /collections/items/list '{"filter":{"sku":"b3"}}'
check_eq "records:batch is atomic: the good row of a failed batch did not land" 0 "$(body total)"
svc POST /collections/items/records:batch '{"records":[{"id":5000,"title":"imp","sku":"imp"}]}'
check_eq "E1': service records:batch may still set an explicit id" 5000 "$(pyq 'd["inserted"][0]["id"]')"
anon POST /collections/items/records:batch '{"records":[{"title":"z"}]}'
check_eq "anon records:batch answers 403 WRITE_DENIED" "403 WRITE_DENIED" "$STATUS $(body error_code)"

svc POST /collections/items/records:upsert '{"records":[{"sku":"u1","title":"one"},{"sku":"s1","title":"alpha-up"}],"on_conflict":["sku"]}'
check_eq "service records:upsert answers 200" 200 "$STATUS"
check_eq "upsert reports inserted for a new key and updated for an existing key" '["inserted", "updated"]' \
  "$(pyq '[r["op"] for r in d["results"]]')"
svc GET "/records/items/$ID1"
check_eq "upsert conflict branch updated the existing row" alpha-up "$(body record.title)"
svc POST /collections/items/records:upsert '{"records":[{"title":"t","color":"red"}],"on_conflict":["color"]}'
check_eq "upsert on a non-unique target answers 400 UPSERT_NO_UNIQUE" "400 UPSERT_NO_UNIQUE" "$STATUS $(body error_code)"
svc POST /collections/items/records:upsert '{"records":[{"title":"t"}],"on_conflict":["sku"]}'
check_eq "upsert row without the conflict key answers UPSERT_MISSING_KEY" UPSERT_MISSING_KEY "$(body error_code)"
anon POST /collections/items/records:upsert '{"records":[{"sku":"z","title":"z"}],"on_conflict":["sku"]}'
check_eq "anon records:upsert answers 403 WRITE_DENIED" "403 WRITE_DENIED" "$STATUS $(body error_code)"
svc GET "/collections/items/history?record_id=$ID1"
check_eq "upsert conflict branch captured an update history row" true "$(pyq 'any(r["op"]=="update" for r in d["rows"])')"

# Unique index over duplicates: REST answers 409 UNIQUE_VIOLATION.
svc POST /records/items '{"data":{"title":"dupcolor1","color":"blue"}}'
svc POST /collections/items/indexes '{"fields":["color"],"unique":true}'
check_eq "unique index over duplicate values answers 409 UNIQUE_VIOLATION" "409 UNIQUE_VIOLATION" "$STATUS $(body error_code)"
svc POST /collections/items/indexes '{"fields":["qty"]}'
check_eq "non-unique index creation answers 201 with ok:true" "201 true" "$STATUS $(body ok)"

# ── 5. /query, /query/explain, read-only authorizer, legacy raw params ─────

anon POST /query '{"sql":"select 1"}'
check_eq "anon /query answers 403 QUERY_ANON_DENIED" "403 QUERY_ANON_DENIED" "$STATUS $(body error_code)"
anon POST /query/explain '{"sql":"select 1"}'
check_eq "anon /query/explain answers 403 QUERY_ANON_DENIED" "403 QUERY_ANON_DENIED" "$STATUS $(body error_code)"
svc POST /query/explain '{"sql":"select * from items where qty > 1"}'
check_eq "service /query/explain answers 200 with a plan" "200 true" "$STATUS $(pyq 'len(d["plan"]) > 0')"
svc POST /query '{"sql":"select count(*) from items"}'
check_eq "service /query reads a user collection" 200 "$STATUS"
svc POST /query '{"sql":"delete from items"}'
check_eq "service /query refuses a write (403 QUERY_FORBIDDEN)" "403 QUERY_FORBIDDEN" "$STATUS $(body error_code)"
svc POST /query '{"sql":"select name from sqlite_master"}'
check_eq "service /query refuses a sqlite_master read (403 QUERY_FORBIDDEN)" "403 QUERY_FORBIDDEN" "$STATUS $(body error_code)"
svc POST /query "{\"sql\":\"attach database 'file:x?mode=memory' as x\"}"
check_eq "service /query refuses ATTACH (403 QUERY_FORBIDDEN)" "403 QUERY_FORBIDDEN" "$STATUS $(body error_code)"
svc GET "/records/items/$ID1"
check_eq "item row still present after the refused /query write" 200 "$STATUS"

anon GET "/records/items?filter=qty%3E1"
check_eq "anon legacy ?filter= answers 403 RAW_FILTER_DENIED" "403 RAW_FILTER_DENIED" "$STATUS $(body error_code)"
anon GET "/records/items?sort=qty"
check_eq "anon legacy ?sort= answers 403 RAW_FILTER_DENIED" "403 RAW_FILTER_DENIED" "$STATUS $(body error_code)"
svc GET "/records/items?filter=qty%3E10"
check_eq "service legacy ?filter= still works (200)" 200 "$STATUS"
check_eq "service legacy ?filter= result is filtered" "[$ID2]" "$(pyq 'sorted(r["id"] for r in d["records"])')"
check_eq "legacy ?filter= response advertises Deprecation + Sunset" "true|Fri, 01 Jan 2027 00:00:00 GMT" \
  "$(header deprecation)|$(header sunset)"
anon GET /records/items
check_eq "anon plain GET list (no raw params) answers 200" 200 "$STATUS"

# ── 6. E8: describe / list of _system_* and sqlite_* ───────────────────────

anon GET /collections/_system_users
check_eq "E8: anon describe of _system_users answers 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"
anon GET /collections/sqlite_sequence
check_eq "E8: anon describe of sqlite_sequence answers 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"
anon GET /collections/_SYSTEM_USERS
check_eq "E8: anon describe of a case variant answers the same 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"
anon GET /collections/_system_does_not_exist
check_eq "E8: anon describe of a missing _system_ name answers the same 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"
anon GET /collections/does_not_exist
check_eq "E8: missing ordinary name keeps its plain-text 404" "404 collection not found" "$STATUS $BODY"
svc GET /collections/_system_users
check_eq "E8: service may still describe _system_users" "200 _system_users" "$STATUS $(body name)"
svc GET /collections/sqlite_sequence
check_eq "E8: service may still describe sqlite_sequence" 200 "$STATUS"
anon GET /collections/items
check_eq "E8: ordinary collection describe unchanged for anon (row_count present)" "200 true" \
  "$STATUS $(pyq '"row_count" in d')"
svc GET /collections
check_eq "E8: service collection list answers 200, lists items, hides _system_* / sqlite_*" "200 true" \
  "$STATUS $(pyq '"items" in [c["name"] for c in d["collections"]] and not any(c["name"].startswith(("_system_","sqlite_")) for c in d["collections"])')"
anon GET /collections
check_eq "E8: anon collection list answers 200, lists items, hides _system_* / sqlite_*" "200 true" \
  "$STATUS $(pyq '"items" in [c["name"] for c in d["collections"]] and not any(c["name"].startswith(("_system_","sqlite_")) for c in d["collections"])')"
anon POST /collections/_system_users/list '{}'
check_eq "anon /list of _system_users answers 404 COLLECTION_NOT_FOUND" "404 COLLECTION_NOT_FOUND" "$STATUS $(body error_code)"
svc POST /records/_system_users '{"data":{"email":"x@y.z"}}'
check_eq "service REST write into _system_users is refused (404 NOT_FOUND)" "404 NOT_FOUND" "$STATUS $(body error_code)"

# ── 7. FTS5 lifecycle ──────────────────────────────────────────────────────

mcp_call create_collection '{"name":"docs","fields":[{"name":"title","sql_type":"text"},{"name":"body","sql_type":"text"},{"name":"score","sql_type":"integer"}]}'
svc POST /collections/docs/records:batch '{"records":[{"title":"hospital report","body":"annual","score":5},{"title":"school news","body":"weekly hospital","score":2},{"title":"慈濟醫院年度","body":"zz","score":9}]}'
check_eq "docs seed batch answers 200" 200 "$STATUS"
D1ID="$(pyq 'd["inserted"][0]["id"]')"; D2ID="$(pyq 'd["inserted"][1]["id"]')"; D3ID="$(pyq 'd["inserted"][2]["id"]')"
mcp_call create_fts_index '{"collection":"docs","name":"main","fields":["title","body"]}'
check_eq "create_fts_index (trigram) succeeds over existing rows" ok "$(mcp_outcome)"
check_eq "create_fts_index defaults to the trigram tokenizer" trigram "$(mcp_text_q 'd["tokenizer"]')"
mcp_call create_fts_index '{"collection":"docs","name":"uni","fields":["title"],"tokenizer":"unicode61"}'
check_eq "create_fts_index with unicode61 succeeds" ok "$(mcp_outcome)"
mcp_call create_fts_index '{"collection":"docs","name":"bad","fields":["score"]}'
check_eq "create_fts_index on a non-TEXT field answers FTS_FIELD_INVALID" FTS_FIELD_INVALID "$(mcp_err_code)"
mcp_call create_fts_index '{"collection":"docs","name":"x_data","fields":["title"]}'
check_eq "create_fts_index with a reserved shadow suffix answers FTS_NAME_RESERVED" FTS_NAME_RESERVED "$(mcp_err_code)"
mcp_call list_fts_indexes '{"collection":"docs"}'
check_eq "list_fts_indexes shows both indexes" '["main", "uni"]' "$(mcp_text_q 'sorted(i["name"] for i in d["fts_indexes"])')"

svc POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"hospital"}},"sort":{"field":"id","dir":"asc"}}'
check_eq "\$fts trigram query finds rows matching in either indexed column (backfilled)" "[$D1ID, $D2ID]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"醫院年度"}}}'
check_eq "\$fts trigram query matches CJK text" "[$D3ID]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"zz"}}}'
check_eq "\$fts short-term (<3 chars) LIKE fallback still matches" "[$D3ID]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"zz 醫院年度"}}}'
check_eq "\$fts short-term fallback is phrase-substring, not over-broad" 0 "$(body total)"
svc POST /collections/docs/list '{"filter":{"and":[{"$fts":{"index":"main","query":"hospital"}},{"score":{"gt":3}}]}}'
check_eq "\$fts AND-composes with an ordinary filter" "[$D1ID]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"uni","query":"foo AND ("}}}'
check_eq "malformed unicode61 MATCH answers 400 FTS_QUERY_INVALID" "400 FTS_QUERY_INVALID" "$STATUS $(body error_code)"
svc POST /collections/docs/aggregate '{"filter":{"$fts":{"index":"uni","query":"foo AND ("}},"metrics":[{"op":"count"}]}'
check_eq "malformed MATCH on /aggregate answers 400 FTS_QUERY_INVALID" "400 FTS_QUERY_INVALID" "$STATUS $(body error_code)"
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"ghost","query":"hospital"}}}'
check_eq "\$fts on an unknown index answers 400 FTS_INDEX_NOT_FOUND" "400 FTS_INDEX_NOT_FOUND" "$STATUS $(body error_code)"
svc POST /collections/docs/aggregate '{"filter":{"$fts":{"index":"main","query":"hospital"}},"metrics":[{"op":"count"}]}'
check_eq "\$fts on /aggregate counts the matches" 2 "$(pyq 'd["rows"][0]["count"]')"
anon POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"hospital"}}}'
check_eq "anon \$fts search with the select cap answers 200 with matches" "200 2" "$STATUS $(body total)"
svc PATCH "/records/docs/$D2ID" '{"data":{"body":"weekly clinic"}}'
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"hospital"}}}'
check_eq "fts update trigger: an edited row leaves the index" "[$D1ID]" "$(pyq '[r["id"] for r in d["records"]]')"
svc POST /records/docs '{"data":{"title":"new hospital wing","body":"b"}}'
D4ID="$(body id)"
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"hospital"}},"sort":{"field":"id","dir":"asc"}}'
check_eq "fts insert trigger: a new row enters the index" "[$D1ID, $D4ID]" "$(pyq '[r["id"] for r in d["records"]]')"
svc DELETE "/records/docs/$D1ID"
check_eq "deleting a pre-index row does not corrupt the index (204)" 204 "$STATUS"
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"hospital"}}}'
check_eq "fts delete trigger: a deleted row leaves the index" "[$D4ID]" "$(pyq '[r["id"] for r in d["records"]]')"
mcp_call set_policy '{"collection":"docs","op":"select","using":{"$fts":{"index":"main","query":"x"}}}'
check_contains "a policy using \$fts is refused (POLICY_OPERAND_UNSUPPORTED)" POLICY_OPERAND_UNSUPPORTED "$(mcp_err_msg)"
svc GET /collections
check_eq "fts shadow tables never appear in the collection list (docs is listed)" "200 true" \
  "$STATUS $(pyq '"docs" in [c["name"] for c in d["collections"]] and not any("search" in c["name"] for c in d["collections"])')"
mcp_call drop_fts_index '{"collection":"docs","name":"main"}'
check_eq "drop_fts_index succeeds" ok "$(mcp_outcome)"
svc POST /collections/docs/list '{"filter":{"$fts":{"index":"main","query":"hospital"}}}'
check_eq "\$fts on a dropped index answers 400 FTS_INDEX_NOT_FOUND" "400 FTS_INDEX_NOT_FOUND" "$STATUS $(body error_code)"
svc POST /records/docs '{"data":{"title":"after drop","body":"b"}}'
check_eq "writes still work after drop_fts_index (no dangling trigger)" 201 "$STATUS"

# ── 8. caps matrix, E1', E9, policy (anon) ─────────────────────────────────

mcp_call create_collection '{"name":"pub","fields":[{"name":"t","sql_type":"text"},{"name":"hidden","sql_type":"integer"},{"name":"x","sql_type":"integer"}]}'
anon POST /records/pub '{"data":{"t":"a"}}'
check_eq "anon insert without the insert cap answers 403 ANON_CAP_DENIED" "403 ANON_CAP_DENIED" "$STATUS $(body error_code)"
svc POST /records/pub '{"data":{"t":"seed","hidden":1,"x":0}}'
P1="$(body id)"
anon PATCH "/records/pub/$P1" '{"data":{"t":"b"}}'
check_eq "anon PATCH without the update cap answers 403 ANON_CAP_DENIED" "403 ANON_CAP_DENIED" "$STATUS $(body error_code)"
anon DELETE "/records/pub/$P1"
check_eq "anon DELETE without the delete cap answers 403 ANON_CAP_DENIED" "403 ANON_CAP_DENIED" "$STATUS $(body error_code)"

mcp_call set_anon_caps '{"collection":"pub","caps":["insert","update"]}'
check_eq "set_anon_caps insert+update succeeds" '["insert", "update"]' "$(mcp_text_q 'sorted(d["anon_caps"])')"
anon POST /records/pub '{"data":{"t":"anon-row","hidden":1}}'
check_eq "anon insert with the insert cap answers 201" 201 "$STATUS"
P2="$(body id)"
check_eq "insert response is NOT narrowed for anon (echoes own write)" anon-row "$(body record.t)"
anon GET "/records/pub/$P2"
check_eq "anon GET without the select cap answers 403 ANON_CAP_DENIED" "403 ANON_CAP_DENIED" "$STATUS $(body error_code)"
anon POST /records/pub '{"data":{"id":9223372036854775807,"t":"pin"}}'
check_eq "E1': anon insert with an explicit id answers 400 SYSTEM_FIELD_READONLY" "400 SYSTEM_FIELD_READONLY" "$STATUS $(body error_code)"
anon POST /records/pub '{"data":{"id":null,"t":"nullid"}}'
check_eq "E1': anon insert with id:null still auto-assigns (201)" 201 "$STATUS"
anon PATCH "/records/pub/$P2" '{"data":{"id":9223372036854775806}}'
check_eq "E1': anon PATCH changing id answers 400 SYSTEM_FIELD_READONLY" "400 SYSTEM_FIELD_READONLY" "$STATUS $(body error_code)"
anon PATCH "/records/pub/$P2" "{\"data\":{\"id\":\"$P2\",\"t\":\"same-id\"}}"
check_eq "E1': anon PATCH carrying its own id (numeric string) is accepted" 200 "$STATUS"
anon PATCH "/records/pub/$P2" "{\"data\":{\"id\":$P2}}"
check_eq "E1': anon PATCH whose body is only its own id is accepted" 200 "$STATUS"
check_eq "E9: anon PATCH without select returns only the id" "{\"record\": {\"id\": $P2}}" "$(pyq 'd')"
svc GET "/records/pub/$P2"
check_eq "E9: the narrowed PATCH still committed the write" same-id "$(body record.t)"
svc POST /records/pub '{"data":{"t":"x"}}'
check_eq "auto-id insert still works after the refused max-id attempts" 201 "$STATUS"
svc POST /records/pub '{"data":{"id":7777,"t":"svc-id"}}'
check_eq "E1': service insert may still choose the id" "201 7777" "$STATUS $(body id)"
svc PATCH /records/pub/7777 '{"data":{"id":7778}}'
check_eq "E1': service PATCH may still change the id" "200 7778" "$STATUS $(body record.id)"

mcp_call set_policy '{"collection":"pub","op":"select"}'
check_contains "set_policy select without using is refused with POLICY_SELECT_REQUIRES_USING" \
  POLICY_SELECT_REQUIRES_USING "$(mcp_err_msg)"
check_eq "clause-less select policy refusal is a tool failure" rpc_error "$(mcp_outcome)"
mcp_call set_anon_caps '{"collection":"pub","caps":["select","update"]}'
mcp_call set_policy '{"collection":"pub","op":"select","using":{"hidden":{"eq":0}}}'
check_eq "set_policy select using hidden=0 succeeds" ok "$(mcp_outcome)"
svc PATCH "/records/pub/$P1" '{"data":{"hidden":0}}'
anon POST /collections/pub/list '{"sort":{"field":"id","dir":"asc"}}'
check_eq "RLS select policy filters anon /list to visible rows" "[$P1]" "$(pyq '[r["id"] for r in d["records"]]')"
anon GET "/records/pub/$P2"
check_eq "RLS select policy hides a row from anon GET (404)" 404 "$STATUS"
anon GET "/records/pub?filter=id%3E0"
check_eq "anon raw ?filter= on a policy collection answers 403 ANON_QUERY_DENIED_ON_POLICY" \
  "403 ANON_QUERY_DENIED_ON_POLICY" "$STATUS $(body error_code)"
anon PATCH "/records/pub/$P1" '{"data":{"t":"visible"}}'
check_eq "E9: anon PATCH whose post-image passes the policy returns the full row" visible "$(body record.t)"
anon PATCH "/records/pub/$P1" '{"data":{"t":"now-hidden","hidden":1}}'
check_eq "E9: anon PATCH whose post-image the policy hides returns only the id" "{\"record\": {\"id\": $P1}}" "$(pyq 'd')"
svc PATCH "/records/pub/$P1" '{"data":{"hidden":0}}'
mcp_call set_policy '{"collection":"pub","op":"select","using":{"x":{"eq":0}}}'
mcp_call set_policy '{"collection":"pub","op":"update","check":{"x":{"is_null":false}}}'
mcp_call drop_field '{"collection":"pub","field":"x"}'
check_eq "E6': drop_field of a policy-referenced field still succeeds" ok "$(mcp_outcome)"
check_eq "E6': drop_field warns once per referencing clause" \
  '[["FIELD_REFERENCED_BY_POLICY", "select", "using", "x"], ["FIELD_REFERENCED_BY_POLICY", "update", "check", "x"]]' \
  "$(mcp_text_q 'sorted([w["code"],w["op"],w["clause"],w["field"]] for w in d["warnings"])')"
anon POST /collections/pub/list '{}'
check_eq "E6': anon /list under a policy naming a dropped field fails closed (POLICY_COMPILE_ERROR)" \
  POLICY_COMPILE_ERROR "$(body error_code)"
svc PATCH "/records/pub/$P1" '{"data":{"t":"pre"}}'
anon PATCH "/records/pub/$P1" '{"data":{"t":"after-drop"}}'
check_eq "E6'/E9: anon PATCH read-back under a policy naming a dropped field is id-only" "{\"record\": {\"id\": $P1}}" "$(pyq 'd')"
mcp_call clear_policy '{"collection":"pub","op":"select"}'
mcp_call clear_policy '{"collection":"pub","op":"update"}'

# ── 9. end-user auth, owner_field, user_caps, E8/E9 for users ──────────────

mcp_call set_self_register '{"enabled":true}'
check_eq "set_self_register true succeeds" true "$(mcp_text_q 'd["allow_self_register"]')"
UEMAIL="smoke-a-$$@records.test"
UPASS="smoke-pass-$$-$(date +%s)"
req POST "$T/auth/register" -H 'Content-Type: application/json' \
  --data "{\"email\":\"$UEMAIL\",\"password\":\"$UPASS\"}"
check_eq "self-registration answers 201" 201 "$STATUS"
UA_ID="$(body user_id)"
check_contains "registered user id is server-minted (u-<uuid>)" "u-" "$UA_ID"
USER_TOKEN=""
tries=0
while [ $tries -lt 3 ]; do
  # The client-sent X-Forwarded-For (a documentation address) must NOT become
  # the client address: Caddy rebuilds the header from its TCP peer.
  req POST "$T/auth/login" -H 'Content-Type: application/json' \
    -H 'X-Forwarded-For: 198.51.100.77' \
    --data "{\"email\":\"$UEMAIL\",\"password\":\"$UPASS\"}"
  [ "$STATUS" != 429 ] && break
  tries=$((tries + 1)); sleep 5
done
LOGIN_STATUS="$STATUS"
check_eq "tenant end-user login answers 200" 200 "$STATUS"
USER_TOKEN="$(body token 2>/dev/null || true)"
[ -n "$USER_TOKEN" ] && ok "login returned a bearer token" || bad "login returned a bearer token" "no token in the login response"

# ── 9a. client IP behind the Compose Caddy (DRUST_TRUSTED_PROXIES=1) ──────
# The login above went through Caddy ($T = $BASE). drust records the derived
# client address as the host audit entry's extra.ip_at_login.
LOGIN_IP_PY='
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for e in d.get("entries", []):
    x = e.get("extra") or {}
    if e.get("op") == "POST /auth/login" and e.get("status") == "ok" and x.get("email") == sys.argv[1]:
        print(x.get("ip_at_login") or "")
        break
'
if [ "$LOGIN_STATUS" != 200 ]; then
  note "skipped (the login was rate-limited; on Docker Desktop every smoke agent reaches Caddy from one address): client-IP checks"
else
  IP_AT_LOGIN=""
  for i in 1 2 3 4 5 6 7 8; do
    admin GET "/admin/api/audit?tab=browse&window=1h&tenant=$TENANT_ID"
    IP_AT_LOGIN="$(printf '%s' "$BODY" | python3 -c "$LOGIN_IP_PY" "$UEMAIL" 2>/dev/null || true)"
    [ -n "$IP_AT_LOGIN" ] && break
    sleep 1
  done
  if [ -z "$IP_AT_LOGIN" ]; then
    bad "the tenant login wrote a host audit row with ip_at_login" "no POST /auth/login ok entry for this run's user"
  else
    check_ne "tenant login through Caddy records the client address, not the loopback fallback" 127.0.0.1 "$IP_AT_LOGIN"
    check_ne "a client-sent X-Forwarded-For through Caddy does not become the client address" 198.51.100.77 "$IP_AT_LOGIN"
    CADDY_CID=""
    if command -v docker >/dev/null 2>&1; then
      CADDY_CID="$(docker compose -p "$SMOKE_COMPOSE_PROJECT" ps -q caddy 2>/dev/null | head -1)"
    fi
    if [ -z "$CADDY_CID" ]; then
      note "skipped (docker not reachable): client-IP checks against the Caddy address and the drust log"
    else
      CADDY_IPS="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$CADDY_CID" 2>/dev/null || true)"
      # Fails when docker-compose.yml lacks DRUST_TRUSTED_PROXIES=1 (0 keys on
      # the TCP peer = Caddy) or main never sets it (2 on a one-entry header
      # falls back to the peer = Caddy). An empty CADDY_IPS would make it pass
      # vacuously, so that case is skipped with a note instead.
      if [ -z "$(printf '%s' "$CADDY_IPS" | tr -d ' ')" ]; then
        note "skipped (docker inspect gave no Caddy address): login not keyed on the proxy's own address"
      else
        check_not_contains "tenant login through Caddy is not keyed on the proxy's own address" \
          " $IP_AT_LOGIN " " $CADDY_IPS "
      fi
      # A failing `docker compose logs` reads as 0 warnings here (pass); the
      # boot-line check below reads the same log and goes red in that case, so
      # it is what keeps this one honest — do not drop it as redundant.
      N_WARN="$(docker compose -p "$SMOKE_COMPOSE_PROJECT" logs --no-log-prefix --since "$START_ISO" drust 2>/dev/null \
        | grep -c 'client_ip: X-Forwarded-For' || true)"
      check_eq "drust logged no client_ip X-Forwarded-For fallback warning during this script" 0 "${N_WARN:-0}"
      BOOT_LINE="$(docker compose -p "$SMOKE_COMPOSE_PROJECT" logs --no-log-prefix drust 2>/dev/null \
        | grep 'client-IP derivation configured' | tail -1 || true)"
      check_contains "drust booted with trusted_proxies=1 (the boot line reads the global back)" \
        '"trusted_proxies":1' "$BOOT_LINE"
    fi
  fi
fi

# ── 9b. the real TCP peer reaches drust (main serves with connect-info) ─────
# Sent straight to drust's own port with no X-Forwarded-For: the one-entry chain
# is missing, so client_ip falls back to the TCP peer. With connect-info that is
# the Docker gateway; without it, peer_addr's loopback default, and the bare
# image (DRUST_TRUSTED_PROXIES=0) would key every client on one address. An
# absent header takes the peer without the fallback warning, so the warning
# count above is not affected by where this runs.
ALL_LOGIN_IPS_PY='
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
ips = [(e.get("extra") or {}).get("ip_at_login") or "" for e in d.get("entries", [])
       if e.get("op") == "POST /auth/login" and e.get("status") == "ok"
       and (e.get("extra") or {}).get("email") == sys.argv[1]]
print(" ".join(ips))
'
if [ "$LOGIN_STATUS" != 200 ]; then
  note "skipped (the first login was rate-limited): direct-port client-IP check"
else
  req POST "$DIRECT/t/$TENANT_ID/auth/login" -H 'Content-Type: application/json' \
    --data "{\"email\":\"$UEMAIL\",\"password\":\"$UPASS\"}"
  if [ "$STATUS" = 429 ]; then
    note "skipped (the direct login was rate-limited): direct-port client-IP check"
  else
    check_eq "a login sent straight to drust's port (no X-Forwarded-For) answers 200" 200 "$STATUS"
    LOGIN_IPS=""; N_LOGIN_IPS=0
    for i in 1 2 3 4 5 6 7 8; do
      admin GET "/admin/api/audit?tab=browse&window=1h&tenant=$TENANT_ID"
      LOGIN_IPS="$(printf '%s' "$BODY" | python3 -c "$ALL_LOGIN_IPS_PY" "$UEMAIL" 2>/dev/null || true)"
      N_LOGIN_IPS="$(printf '%s\n' $LOGIN_IPS | grep -c . || true)"
      [ "${N_LOGIN_IPS:-0}" -ge 2 ] && break
      sleep 1
    done
    check_eq "both logins wrote a host audit row with ip_at_login" 2 "${N_LOGIN_IPS:-0}"
    check_not_contains "a login with no X-Forwarded-For is keyed on the real TCP peer, not the loopback default" \
      " 127.0.0.1 " " $LOGIN_IPS "
  fi
fi
mcp_call create_user "{\"email\":\"smoke-b-$$@records.test\",\"password\":\"another-long-pass-$$\"}"
UB_ID="$(mcp_text_q 'd["user_id"]')"
check_contains "MCP create_user mints a second user" "u-" "$UB_ID"

if [ -n "$USER_TOKEN" ]; then
  mcp_call create_collection '{"name":"notes","fields":[{"name":"body","sql_type":"text"},{"name":"owner_id","sql_type":"text","foreign_key":"_system_users"}]}'
  mcp_call set_owner_field '{"collection":"notes","field":"owner_id","read_scope":"own"}'
  check_eq "set_owner_field read_scope=own succeeds" own "$(mcp_text_q 'd["read_scope"]')"
  mcp_call set_owner_field '{"collection":"pub","field":"t"}'
  check_eq "set_owner_field on a column without the _system_users FK answers OWNER_FIELD_NOT_FK" OWNER_FIELD_NOT_FK "$(mcp_err_code)"

  user POST /records/notes '{"data":{"body":"mine","owner_id":"u-forged"}}'
  check_eq "user insert on an owner-scoped collection answers 201" 201 "$STATUS"
  N1="$(body id)"
  check_eq "user insert stamps owner_id with the caller (forged value overwritten)" "$UA_ID" "$(body record.owner_id)"
  svc POST /records/notes '{"data":{"body":"svc-no-owner"}}'
  check_eq "service insert without the owner field answers 409 OWNER_FIELD_REQUIRED" "409 OWNER_FIELD_REQUIRED" "$STATUS $(body error_code)"
  svc POST /records/notes "{\"data\":{\"body\":\"theirs\",\"owner_id\":\"$UB_ID\"}}"
  N2="$(body id)"
  check_eq "service insert for user B answers 201" 201 "$STATUS"
  user POST /collections/notes/list '{}'
  check_eq "owner_field: user /list sees only own rows" "[$N1]" "$(pyq '[r["id"] for r in d["records"]]')"
  user POST /collections/notes/aggregate '{"metrics":[{"op":"count"}]}'
  check_eq "owner_field: user /aggregate counts only own rows" 1 "$(pyq 'd["rows"][0]["count"]')"
  user GET "/records/notes/$N2"
  check_eq "owner_field: user GET of another user's row answers 404" 404 "$STATUS"
  user PATCH "/records/notes/$N2" '{"data":{"body":"hijack"}}'
  check_eq "owner_field: user PATCH of another user's row answers 404" 404 "$STATUS"
  user DELETE "/records/notes/$N2"
  check_eq "owner_field: user DELETE of another user's row answers 404" 404 "$STATUS"
  svc GET "/records/notes/$N2"
  check_eq "owner_field: user B's row is untouched" theirs "$(body record.body)"
  user PATCH "/records/notes/$N1" "{\"data\":{\"owner_id\":\"$UB_ID\"}}"
  svc GET "/records/notes/$N1"
  check_eq "owner_field: user cannot re-assign their row to another owner" "$UA_ID" "$(body record.owner_id)"
  user GET "/records/notes?filter=id%3E0"
  check_eq "user raw ?filter= on own-scoped collection answers USER_FILTER_DENIED_ON_OWNER_SCOPED" \
    "400 USER_FILTER_DENIED_ON_OWNER_SCOPED" "$STATUS $(body error_code)"
  anon POST /collections/notes/list '{}'
  check_eq "anon /list on an owner-scoped collection answers 403 ANON_FORBIDDEN_OWNER_SCOPED" "403 ANON_FORBIDDEN_OWNER_SCOPED" "$STATUS $(body error_code)"
  anon POST /records/notes '{"data":{"body":"x"}}'
  check_eq "anon write to an owner-scoped collection answers 403 ANON_FORBIDDEN_OWNER_SCOPED" "403 ANON_FORBIDDEN_OWNER_SCOPED" "$STATUS $(body error_code)"
  user POST /records/notes '{"data":{"id":123456,"body":"x"}}'
  check_eq "E1': user insert with an explicit id answers 400 SYSTEM_FIELD_READONLY" "400 SYSTEM_FIELD_READONLY" "$STATUS $(body error_code)"
  user PATCH "/records/notes/$N1" '{"data":{"id":123456}}'
  check_eq "E1': user PATCH changing id answers 400 SYSTEM_FIELD_READONLY" "400 SYSTEM_FIELD_READONLY" "$STATUS $(body error_code)"
  user PATCH "/records/notes/$N1" '{"data":{"body":"edited"}}'
  check_eq "user PATCH of own readable row returns the full row" edited "$(body record.body)"
  svc GET "/collections/notes/history?record_id=$N1"
  check_eq "history attributes the user's insert to actor_kind=user" "user $UA_ID" \
    "$(pyq '[r for r in d["rows"] if r["op"]=="insert"][0]["actor_kind"]') $(pyq '[r for r in d["rows"] if r["op"]=="insert"][0]["actor_id"]')"

  # E9 for users: owner-scoped read_scope=all with user_caps lacking select.
  mcp_call set_owner_field '{"collection":"notes","field":"owner_id","read_scope":"all"}'
  mcp_call set_user_caps '{"collection":"notes","caps":["insert","update"]}'
  check_eq "set_user_caps insert+update (no select) succeeds" '["insert", "update"]' "$(mcp_text_q 'sorted(d["user_caps"])')"
  user POST /collections/notes/list '{}'
  check_eq "user read on read_scope=all without user_caps[select] answers 403 ANON_CAP_DENIED (shared code)" "403 ANON_CAP_DENIED" "$STATUS $(body error_code)"
  user PATCH "/records/notes/$N1" '{"data":{"body":"blind"}}'
  check_eq "E9: user PATCH without read access returns only the id" "{\"record\": {\"id\": $N1}}" "$(pyq 'd')"
  svc GET "/records/notes/$N1"
  check_eq "E9: the user's narrowed PATCH committed" blind "$(body record.body)"

  # user_caps on a plain (non owner-scoped) collection.
  user POST /records/docs '{"data":{"title":"u"}}'
  check_eq "user insert on a plain collection without user_caps[insert] is refused (403 ANON_CAP_DENIED, shared code)" \
    "403 ANON_CAP_DENIED" "$STATUS $(body error_code)"
  check_contains "user cap denial names user_caps in its message" "user_caps" "$(body message)"
  user POST /collections/docs/list '{}'
  check_eq "user /list on a plain collection with the default select cap answers 200" 200 "$STATUS"
  mcp_call set_user_caps '{"collection":"docs","caps":["select","insert"]}'
  user POST /records/docs '{"data":{"title":"user-row"}}'
  check_eq "user insert after granting user_caps[insert] answers 201" 201 "$STATUS"
  anon POST /records/docs '{"data":{"title":"anon"}}'
  check_eq "granting user_caps does not open anon_caps (403 ANON_CAP_DENIED)" "403 ANON_CAP_DENIED" "$STATUS $(body error_code)"

  # Service-only surfaces refuse the user token.
  user POST /query '{"sql":"select 1"}'
  check_eq "user /query answers 403 QUERY_USER_DENIED" "403 QUERY_USER_DENIED" "$STATUS $(body error_code)"
  user POST /query/explain '{"sql":"select 1"}'
  check_eq "user /query/explain answers 403 QUERY_USER_DENIED" "403 QUERY_USER_DENIED" "$STATUS $(body error_code)"
  user POST /collections/docs/records:batch '{"records":[{"title":"y"}]}'
  check_eq "user records:batch answers 403 WRITE_DENIED" "403 WRITE_DENIED" "$STATUS $(body error_code)"
  user POST /collections/items/records:upsert '{"records":[{"sku":"q","title":"q"}],"on_conflict":["sku"]}'
  check_eq "user records:upsert answers 403 WRITE_DENIED" "403 WRITE_DENIED" "$STATUS $(body error_code)"
  user GET "/records/docs?filter=id%3E0"
  check_eq "user legacy ?filter= on a plain collection answers 403 RAW_FILTER_DENIED" "403 RAW_FILTER_DENIED" "$STATUS $(body error_code)"
  user GET /collections/_system_users
  check_eq "E8: user describe of _system_users answers 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"
  user GET /collections/_system_sessions
  check_eq "E8: user describe of _system_sessions answers 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(body error_code)"
  user GET /collections/_system_users/history
  check_eq "user cannot read record history (403 HISTORY_READ_DENIED)" "403 HISTORY_READ_DENIED" "$STATUS $(body error_code)"
else
  bad "end-user checks skipped" "no user token (login status $STATUS)"
fi

# ── 10. codegen for service and anon ───────────────────────────────────────

for f in openapi.json types.ts zod.ts; do
  req GET "$T/$f" -H "Authorization: Bearer $SERVICE_KEY"
  check_eq "service GET $f answers 200 (X-Drust-Schema-Source: service)" "200 service" "$STATUS $(header x-drust-schema-source)"
  check_contains "service $f describes the items collection" Items "$BODY"
  check_not_contains "service $f emits no type for _system_users" SystemUsers "$BODY"
  req GET "$T/$f" -H "Authorization: Bearer $ANON_KEY"
  check_eq "anon GET $f answers 200 (X-Drust-Schema-Source: anon)" "200 anon" "$STATUS $(header x-drust-schema-source)"
  check_not_contains "anon $f emits no type for _system_users" SystemUsers "$BODY"
  check_not_contains "anon $f emits no type for _system_sessions" SystemSessions "$BODY"
done
for k in SERVICE_KEY ANON_KEY; do
  eval "key=\$$k"
  req GET "$T/openapi.json" -H "Authorization: Bearer $key"
  check_eq "openapi.json ($k) answers 200 with schemas and has no _system_* / sqlite_* schema or path" "200 true" \
    "$STATUS $(pyq 'len(d["components"]["schemas"]) > 0 and not any("_system_" in x or "sqlite_" in x for x in list(d["components"]["schemas"]) + list(d.get("paths", {})))')"
done
req GET "$T/openapi.json" -H "Authorization: Bearer $SERVICE_KEY"
check_eq "openapi.json is OpenAPI 3.1" 3.1.0 "$(body openapi)"

# ── 11. quota tier (admin plane only) ──────────────────────────────────────

admin PATCH "/admin/tenants/$TENANT_ID/quota" '{"tier":0}'
check_eq "quota tier 0 is refused (400 QUOTA_TIER_INVALID; 10 GiB x tier, min 1)" "400 QUOTA_TIER_INVALID" "$STATUS $(body error_code)"
req PATCH "$BASE/admin/tenants/$TENANT_ID/quota" -H "Authorization: Bearer $SERVICE_KEY" \
  -H 'Content-Type: application/json' --data '{"tier":5}'
check_eq "a tenant service key cannot raise its own quota (401 on the admin plane)" 401 "$STATUS"

finish

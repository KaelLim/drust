#!/usr/bin/env bash
# Mode B / tus 1.0 resumable uploads (/t/<id>/uploads/*) against the real object
# store (RustFS or Garage, SMOKE_STORE):
# capability discovery (OPTIONS + CORS preflight), create (Upload-Length,
# Upload-Metadata, Location without a base-path prefix, Upload-Expires), PATCH
# in several chunks of a ~20 MB random file (> the 16 MiB finalize part size, so
# the object_store multipart upload to the store carries two parts), HEAD offsets,
# the 409 wrong-offset refusal, an interrupted chunk + resume, overflow, the
# finalize (row in /files, sha256 of the bytes through drust AND through the
# deployment's own /public/* route), the tus private default (invariant 19) and the
# private bucket finalize, termination cleanup (session row + spool file),
# Upload-Length above Tus-Max-Size, the per-tenant session cap, anon/user file
# caps + per-bearer session binding + the per-prefix publish grant, and the
# disk-free guard, and per-tenant isolation of upload tokens. Uses 3 tenants;
# everything it creates is removed again.
. "$(dirname "$0")/lib.sh"

SPOOL_ROOT=/data/tenants      # DRUST_DATA_DIR=/data in the image
TUS="Tus-Resumable: 1.0.0"
OCT="Content-Type: application/offset+octet-stream"

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
hval() { header "$1"; }                       # alias for readability
sha_file() { python3 -c 'import hashlib,sys;h=hashlib.sha256();f=open(sys.argv[1],"rb")
for b in iter(lambda:f.read(1<<20),b""): h.update(b)
print(h.hexdigest())' "$1"; }
fsize() { python3 -c 'import os,sys;print(os.path.getsize(sys.argv[1]))' "$1"; }

# tus KEY METHOD URL [curl args...] — tus request with a bearer.
tus() { local k="$1" m="$2" u="$3"; shift 3; req "$m" "$u" -H "Authorization: Bearer $k" -H "$TUS" "$@"; }
tus_head() { req HEAD "$2" --head -H "Authorization: Bearer $1" -H "$TUS"; }

# A non-service upload/delete verb is per-IP rate-limited (30/60 s) and all
# smoke agents share one IP; back off on RATE_LIMITED_IP, bounded to ~70 s.
tus_rl() {
  local i=0
  while :; do
    tus "$@"
    if [ "$STATUS" = "429" ] && [ "$(body error_code 2>/dev/null)" = "RATE_LIMITED_IP" ] && [ $i -lt 14 ]; then
      i=$((i + 1)); sleep 5; continue
    fi
    break
  done
}
tus_head_rl() {
  local i=0
  while :; do
    tus_head "$@"
    if [ "$STATUS" = "429" ] && [ $i -lt 14 ]; then i=$((i + 1)); sleep 5; continue; fi
    break
  done
}

# download KEY URL OUTFILE [curl args] — sets DL_STATUS; never loads bytes into bash.
# An empty KEY sends no Authorization header at all (an empty "Bearer " is never right).
download() {
  local k="$1" u="$2" o="$3"; shift 3
  if [ -n "$k" ]; then set -- -H "Authorization: Bearer $k" "$@"; fi
  DL_STATUS="$(curl -sS -o "$o" -D "$TMP/dl.h" -w '%{http_code}' --max-time "${REQ_TIMEOUT:-120}" \
    "$u" "$@" 2>/dev/null)" || DL_STATUS=000
}

# Read-only peeks into the drust container (spool directory). Optional.
have_docker=0
if command -v docker >/dev/null 2>&1 && docker compose -p "$SMOKE_COMPOSE_PROJECT" ps drust >/dev/null 2>&1; then
  have_docker=1
fi
in_drust() { docker compose -p "$SMOKE_COMPOSE_PROJECT" exec -T drust sh -c "$1" 2>/dev/null; }
spool_size() { # TENANT TOKEN — prints byte size or "absent"
  in_drust "stat -c %s $SPOOL_ROOT/$1/_uploads/$2.part 2>/dev/null || echo absent"
}

# session_field TOKEN FIELD — from the service-only GET /uploads list.
session_field() {
  printf '%s' "$BODY" | python3 -c '
import json, sys
tok, f = sys.argv[1], sys.argv[2]
for s in json.load(sys.stdin).get("sessions", []):
    if s.get("upload_token") == tok:
        print(s.get(f)); sys.exit(0)
print("")' "$1" "$2"
}
token_of() { printf '%s' "$1" | sed -n 's#.*/uploads/##p'; }

# ============================================================================
# Tenant A — service flows against the object store
# ============================================================================
new_tenant tusa
A_ID="$TENANT_ID"; A_SVC="$SERVICE_KEY"; A_T="$T"

# ---- discovery -------------------------------------------------------------
tus "$A_SVC" OPTIONS "$A_T/uploads"
check_eq "OPTIONS /uploads (service) answers 204" 204 "$STATUS"
check_eq "OPTIONS advertises Tus-Version 1.0.0" "1.0.0" "$(hval tus-version)"
check_eq "OPTIONS advertises Tus-Resumable 1.0.0" "1.0.0" "$(hval tus-resumable)"
check_eq "OPTIONS advertises creation,termination,expiration" "creation,termination,expiration" "$(hval tus-extension)"
MAX_SIZE="$(hval tus-max-size)"
check_eq "OPTIONS advertises Tus-Max-Size = DRUST_LARGE_UPLOAD_MAX_BYTES default (2 GiB)" 2147483648 "$MAX_SIZE"

# build_cors_layer returns None when DRUST_CORS_ORIGINS is empty, so with no
# CORS configured a preflight is NOT short-circuited and meets bearer auth.
cors_cfg=""
[ $have_docker = 1 ] && cors_cfg="$(in_drust 'printf %s "${DRUST_CORS_ORIGINS:-}"')"
req OPTIONS "$A_T/uploads" -H 'Origin: http://app.example' -H 'Access-Control-Request-Method: POST'
if [ -z "$cors_cfg" ]; then
  check_eq "with DRUST_CORS_ORIGINS unset an unauthenticated preflight meets bearer auth (401)" 401 "$STATUS"
else
  check_eq "unauthenticated CORS preflight on /uploads is answered by the CORS layer (200)" 200 "$STATUS"
fi
check_eq "the OPTIONS /uploads response still carries the tus capability headers (inject_tus_capabilities)" "creation,termination,expiration" "$(hval tus-extension)"

# ---- create validation -----------------------------------------------------
tus "$A_SVC" POST "$A_T/uploads"
check_eq "create without Upload-Length answers 400" 400 "$STATUS"
check_eq "create without Upload-Length is UPLOAD_LENGTH_REQUIRED" UPLOAD_LENGTH_REQUIRED "$(body error_code)"

over=$(( ${MAX_SIZE:-2147483648} + 1 ))
tus "$A_SVC" POST "$A_T/uploads" -H "Upload-Length: $over"
check_eq "create with Upload-Length = Tus-Max-Size+1 answers 413" 413 "$STATUS"
check_eq "create above the limit is UPLOAD_TOO_LARGE" UPLOAD_TOO_LARGE "$(body error_code)"

tus "$A_SVC" POST "$A_T/uploads" -H "Upload-Length: 10" -H "Upload-Metadata: filename $(b64 x.bin),path $(b64 '../etc/x')"
check_eq "create with a traversal path in Upload-Metadata answers 400 FILE_PATH_INVALID" "400 FILE_PATH_INVALID" "$STATUS $(body error_code)"

# ---- disk guard (decision must match statvfs of the data dir) --------------
if [ $have_docker = 1 ]; then
  df_line="$(in_drust 'df -P /data | tail -1')"
  min_pct="$(in_drust 'printf %s "${DRUST_DISK_MIN_FREE_PCT:-20}"')"
  free_pct="$(printf '%s' "$df_line" | awk '{ if ($2 > 0) printf "%d", ($4 / $2) * 100; else print 0 }')"
  note "data dir free: ${free_pct}% (guard threshold ${min_pct:-20}%)"
fi

# ---- the big multi-chunk public upload ------------------------------------
BIG="$TMP/big.bin"
head -c 20000000 /dev/urandom > "$BIG"
dd if="$BIG" of="$TMP/c1" bs=1000000 skip=0  count=7 2>/dev/null
dd if="$BIG" of="$TMP/c2" bs=1000000 skip=7  count=7 2>/dev/null
dd if="$BIG" of="$TMP/c3" bs=1000000 skip=14 count=6 2>/dev/null
cp "$TMP/c3" "$TMP/c3plus"; printf 'X' >> "$TMP/c3plus"
BIG_SHA="$(sha_file "$BIG")"

md="filename $(b64 big.bin),filetype $(b64 application/octet-stream),visibility $(b64 public),path $(b64 smoke/big.bin)"
tus "$A_SVC" POST "$A_T/uploads" -H "Upload-Length: 20000000" -H "Upload-Metadata: $md"
check_eq "create a 20 MB public upload answers 201" 201 "$STATUS"
if [ $have_docker = 1 ] && [ -n "${free_pct:-}" ]; then
  if [ "$free_pct" -ge "${min_pct:-20}" ]; then
    check_eq "disk guard does not trip with ${free_pct}% free (>= ${min_pct:-20}%): create is 201, not 507 DISK_FULL" "201 " "$STATUS $(body error_code 2>/dev/null)"
  else
    check_eq "disk guard trips with ${free_pct}% free (< ${min_pct:-20}%): 507 DISK_FULL" "507 DISK_FULL" "$STATUS $(body error_code 2>/dev/null)"
  fi
fi
LOC="$(hval location)"
TOK="$(token_of "$LOC")"
case "$LOC" in
  "/t/$A_ID/uploads/"*) ok "Location is /t/<id>/uploads/<token> with no /drust prefix (DRUST_BASE_PATH=\"\")" ;;
  *) bad "Location is /t/<id>/uploads/<token> with no /drust prefix" "got [$LOC]" ;;
esac
check_eq "create answers Tus-Resumable 1.0.0" "1.0.0" "$(hval tus-resumable)"
exp="$(hval upload-expires)"
hrs="$(python3 -c '
import sys, datetime
s = sys.argv[1]
try:
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac, tz = rest[:rest.find("+")], rest[rest.find("+"):]
        s = head + "." + frac[:6] + tz
    d = datetime.datetime.fromisoformat(s)
    print(round((d - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 3600))
except Exception:
    print("bad")' "$exp")"
check_eq "Upload-Expires is ~24 h ahead (DRUST_LARGE_UPLOAD_SESSION_TTL_SECS default)" 24 "$hrs"
URL="$BASE$LOC"

tus_head "$A_SVC" "$URL"
check_eq "HEAD on a fresh session answers 200" 200 "$STATUS"
check_eq "HEAD on a fresh session reports Upload-Offset 0" 0 "$(hval upload-offset)"
check_eq "HEAD reports the declared Upload-Length" 20000000 "$(hval upload-length)"
check_eq "HEAD is Cache-Control: no-store" no-store "$(hval cache-control)"

REQ_TIMEOUT=120 tus "$A_SVC" PATCH "$URL" -H "$OCT" -H "Upload-Offset: 0" --data-binary @"$TMP/c1"
check_eq "PATCH chunk 1 (7 MB) answers 204" 204 "$STATUS"
check_eq "PATCH chunk 1 returns Upload-Offset 7000000" 7000000 "$(hval upload-offset)"
tus_head "$A_SVC" "$URL"
check_eq "HEAD after chunk 1 reports Upload-Offset 7000000" 7000000 "$(hval upload-offset)"
if [ $have_docker = 1 ]; then
  check_eq "spool file size equals the reported offset (filesystem is the offset source of truth)" 7000000 "$(spool_size "$A_ID" "$TOK")"
fi

# Interrupted chunk: announce 7 MB, send 3 MB, drop the connection.
sent="$(AUTHZ="$A_SVC" python3 - "$URL" "$TMP/c2" <<'PY' 2>/dev/null || true
import http.client, os, sys, urllib.parse
u = urllib.parse.urlparse(sys.argv[1])
data = open(sys.argv[2], "rb").read()
c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
c.putrequest("PATCH", u.path)
c.putheader("Authorization", "Bearer " + os.environ["AUTHZ"])
c.putheader("Tus-Resumable", "1.0.0")
c.putheader("Upload-Offset", "7000000")
c.putheader("Content-Type", "application/offset+octet-stream")
c.putheader("Content-Length", str(len(data)))
c.endheaders()
c.send(data[:3000000])
c.sock.close()
print(3000000)
PY
)"
# Precondition: the truncated chunk really went out — otherwise the next check
# would pass without testing anything.
check_eq "the interrupted PATCH actually sent 3 MB of its announced 7 MB before dropping" 3000000 "$sent"
prev=""; off=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  tus_head "$A_SVC" "$URL"; off="$(hval upload-offset)"
  [ -n "$prev" ] && [ "$off" = "$prev" ] && break
  prev="$off"; sleep 1
done
check_eq "an interrupted chunk appends nothing: HEAD still reports 7000000" 7000000 "$off"

REQ_TIMEOUT=120 tus "$A_SVC" PATCH "$URL" -H "$OCT" -H "Upload-Offset: $off" --data-binary @"$TMP/c2"
check_eq "resume: PATCH chunk 2 from the HEAD offset answers 204" 204 "$STATUS"
check_eq "resume: Upload-Offset is now 14000000" 14000000 "$(hval upload-offset)"

printf 'abc' > "$TMP/tiny"
tus "$A_SVC" PATCH "$URL" -H "$OCT" -H "Upload-Offset: 0" --data-binary @"$TMP/tiny"
check_eq "PATCH with a stale Upload-Offset is refused 409" 409 "$STATUS"
check_eq "the 409 carries the server's real Upload-Offset" 14000000 "$(hval upload-offset)"
tus "$A_SVC" PATCH "$URL" -H "$OCT" --data-binary @"$TMP/tiny"
check_eq "PATCH without Upload-Offset is refused 409" 409 "$STATUS"

REQ_TIMEOUT=120 tus "$A_SVC" PATCH "$URL" -H "$OCT" -H "Upload-Offset: 14000000" --data-binary @"$TMP/c3plus"
check_eq "a chunk overrunning Upload-Length is 400 UPLOAD_OVERFLOW" "400 UPLOAD_OVERFLOW" "$STATUS $(body error_code)"
tus_head "$A_SVC" "$URL"
check_eq "the refused overflow chunk appended nothing" 14000000 "$(hval upload-offset)"

tus "$A_SVC" GET "$A_T/uploads"
check_eq "service lists in-flight sessions (200)" 200 "$STATUS"
BIG_KEY="$(session_field "$TOK" key)"
check_eq "the session list shows the declared total_length" 20000000 "$(session_field "$TOK" total_length)"
case "$BIG_KEY" in *.bin) ok "server-minted key keeps the .bin extension" ;; *) bad "server-minted key keeps the .bin extension" "key [$BIG_KEY]" ;; esac

REQ_TIMEOUT=180 tus "$A_SVC" PATCH "$URL" -H "$OCT" -H "Upload-Offset: 14000000" --data-binary @"$TMP/c3"
check_eq "final PATCH finalizes the 2-part multipart upload to the object store (204)" 204 "$STATUS"
[ "$STATUS" = 204 ] || note "final PATCH body: $(printf '%s' "$BODY" | head -c 200)"
check_eq "final PATCH returns Upload-Offset 20000000" 20000000 "$(hval upload-offset)"

tus_head "$A_SVC" "$URL"
check_eq "after finalize the session is gone (HEAD 404)" 404 "$STATUS"
tus "$A_SVC" GET "$A_T/uploads"
check_eq "after finalize the session is no longer listed (list answers 200 without it)" "200 " "$STATUS $(session_field "$TOK" key)"
if [ $have_docker = 1 ]; then
  check_eq "after finalize the spool file is deleted" absent "$(spool_size "$A_ID" "$TOK")"
fi

svc GET "/files/$BIG_KEY"
check_eq "the finalized file is in /files (200)" 200 "$STATUS"
check_eq "/files row has size_bytes 20000000" 20000000 "$(body size_bytes)"
check_eq "/files row is visibility public (explicit service request honoured)" public "$(body visibility)"
check_eq "/files row carries the path declared at create" smoke/big.bin "$(body path)"
check_eq "/files row uploader is service" service "$(body uploader)"
check_eq "/files row keeps the declared filetype" application/octet-stream "$(body content_type)"
check_eq "/files row original_name is the declared filename" big.bin "$(body original_name)"

download "$A_SVC" "$A_T/files/$BIG_KEY/bytes" "$TMP/dl1"
check_eq "GET /files/<key>/bytes answers 200" 200 "$DL_STATUS"
check_eq "bytes streamed back through drust have the same sha256" "$BIG_SHA" "$(sha_file "$TMP/dl1" 2>/dev/null)"

download "" "$PUBLIC/$A_ID/$BIG_KEY" "$TMP/dl2"
check_eq "public object is served by the public route (200)" 200 "$DL_STATUS"
check_eq "public route bytes have the same sha256" "$BIG_SHA" "$(sha_file "$TMP/dl2" 2>/dev/null)"
etag="$(tr -d '\r' < "$TMP/dl.h" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '"')"
case "$etag" in
  *-2) ok "public route ETag shows a 2-part multipart object (16 MiB part size)" ;;
  *) bad "public route ETag shows a 2-part multipart object (16 MiB part size)" "etag [$etag]" ;;
esac
gct="$(tr -d '\r' < "$TMP/dl.h" | awk -F': ' 'tolower($1)=="content-type"{print $2}')"
check_eq "the public route serves the declared Content-Type" application/octet-stream "$gct"

svc POST "/files/$BIG_KEY/sign" '{}'
check_eq "sign on a public file answers 200" 200 "$STATUS"
PUB_URL="$(body url)"
case "$PUB_URL" in
  */public/"$A_ID/$BIG_KEY") ok "advertised public URL is <public_base>/public/<tenant>/<key>" ;;
  *) bad "advertised public URL is <public_base>/public/<tenant>/<key>" "url [$PUB_URL]" ;;
esac
pub_path="/${PUB_URL#*://*/}"
download "" "$BASE$pub_path" "$TMP/dl3"
check_eq "the public URL drust advertises (<DRUST_PUBLIC_BASE_URL>/public/<tenant>/<key>) serves the object through the Compose proxy deploy/compose.Caddyfile (200)" 200 "$DL_STATUS"
[ "$DL_STATUS" = 200 ] || note "the advertised public URL answered: $(head -c 80 "$TMP/dl3")"

svc DELETE "/files/$BIG_KEY"
check_eq "deleting the finalized file answers 204" 204 "$STATUS"
download "" "$PUBLIC/$A_ID/$BIG_KEY" "$TMP/dl4"
check_eq "after delete the public object is gone (404)" 404 "$DL_STATUS"

# ---- private default (invariant 19: tus default is private, even for service)
printf 'hello' > "$TMP/hello"
tus "$A_SVC" POST "$A_T/uploads" -H "Upload-Length: 5" -H "Upload-Metadata: filename $(b64 p.txt),filetype $(b64 text/plain)"
check_eq "create a small upload with no visibility (201)" 201 "$STATUS"
PURL="$BASE$(hval location)"; PTOK="$(token_of "$PURL")"
tus "$A_SVC" GET "$A_T/uploads"; P_KEY="$(session_field "$PTOK" key)"
REQ_TIMEOUT=60 tus "$A_SVC" PATCH "$PURL" -H "$OCT" -H "Upload-Offset: 0" --data-binary @"$TMP/hello"
p_status="$STATUS"
check_eq "a private tus upload finalizes into the hard-coded 'private' bucket (204; needs that bucket to exist in the object store)" 204 "$p_status"
if [ "$p_status" != 204 ]; then
  note "finalize answered $p_status $(body error_code)"
  if [ $have_docker = 1 ]; then
    # The boot probe warns once per bucket it cannot list (c1).
    probe="$(docker compose -p "$SMOKE_COMPOSE_PROJECT" logs --no-log-prefix drust 2>/dev/null \
      | grep 'object store bucket check failed' | grep -c 'private')"
    note "drust boot log: $probe 'object store bucket check failed' warning(s) naming bucket 'private'"
    hits="$(docker compose -p "$SMOKE_COMPOSE_PROJECT" logs --tail 200 drust 2>/dev/null | grep "$P_KEY" | grep -c '/private/.*404 Not Found')"
    note "drust log lines showing S3 404 on bucket 'private' for this key: $hits"
  fi
fi
svc GET "/files/$P_KEY"
check_eq "a tus upload that states no visibility is stored private (service default)" private "$(body visibility)"
if [ "$p_status" = 204 ]; then
  download "$A_SVC" "$A_T/files/$P_KEY/bytes" "$TMP/dl5"
  check_eq "private bytes come back intact" "$(sha_file "$TMP/hello")" "$(sha_file "$TMP/dl5" 2>/dev/null)"
  download "" "$PUBLIC/$A_ID/$P_KEY" "$TMP/dl6"
  check_eq "a private object is NOT served by the public route" 404 "$DL_STATUS"
else
  tus_head "$A_SVC" "$PURL"
  check_eq "after a failed finalize the session is retained for a retry (offset = length)" "200 5" "$STATUS $(hval upload-offset)"
fi
svc DELETE "/files/$P_KEY" >/dev/null
tus "$A_SVC" DELETE "$PURL" >/dev/null

# ---- termination of an unfinished upload ----------------------------------
svc GET /files; files_before="$(body file_count)"
head -c 1000 /dev/urandom > "$TMP/k1"
tus "$A_SVC" POST "$A_T/uploads" -H "Upload-Length: 4000" -H "Upload-Metadata: filename $(b64 t.bin)"
DURL="$BASE$(hval location)"; DTOK="$(token_of "$DURL")"
tus "$A_SVC" PATCH "$DURL" -H "$OCT" -H "Upload-Offset: 0" --data-binary @"$TMP/k1"
check_eq "partial PATCH on the to-be-terminated session (204)" 204 "$STATUS"
if [ $have_docker = 1 ]; then
  check_eq "its spool file holds the 1000 bytes" 1000 "$(spool_size "$A_ID" "$DTOK")"
fi
tus "$A_SVC" DELETE "$DURL"
check_eq "DELETE (termination) of an unfinished upload answers 204" 204 "$STATUS"
check_eq "termination answers Tus-Resumable 1.0.0" "1.0.0" "$(hval tus-resumable)"
tus_head "$A_SVC" "$DURL"
check_eq "HEAD after termination answers 404" 404 "$STATUS"
tus "$A_SVC" PATCH "$DURL" -H "$OCT" -H "Upload-Offset: 1000" --data-binary @"$TMP/tiny"
check_eq "PATCH after termination answers 404" 404 "$STATUS"
tus "$A_SVC" GET "$A_T/uploads"
check_eq "a terminated session is no longer listed (list answers 200 without it)" "200 " "$STATUS $(session_field "$DTOK" key)"
if [ $have_docker = 1 ]; then
  check_eq "termination deletes the spool file" absent "$(spool_size "$A_ID" "$DTOK")"
fi
svc GET /files
check_eq "termination never created a /files row" "$files_before" "$(body file_count)"
tus "$A_SVC" GET "$A_T/uploads"
check_eq "tenant A has no upload sessions left" '{"sessions":[]}' "$BODY"
tus_head "$A_SVC" "$A_T/uploads/not-a-token"
check_eq "HEAD on a malformed token answers 404" 404 "$STATUS"

# ============================================================================
# Tenant B — anon / user caps, session binding, publish grant
# ============================================================================
new_tenant tusb
B_ID="$TENANT_ID"; B_SVC="$SERVICE_KEY"; B_ANON="$ANON_KEY"; B_T="$T"

tus "$B_ANON" POST "$B_T/uploads" -H "Upload-Length: 10"
check_eq "anon create with default (empty) file caps is 403 FILE_UPLOAD_DENIED" "403 FILE_UPLOAD_DENIED" "$STATUS $(body error_code)"
tus "$B_ANON" GET "$B_T/uploads"
check_eq "anon cannot list upload sessions (service-only, 403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"

tus "$B_SVC" POST "$B_T/uploads" -H "Upload-Length: 10" -H "Upload-Metadata: filename $(b64 s.bin)"
SURL="$BASE$(hval location)"

mcp_call set_file_caps '{"anon":["upload"]}'
check_eq "set_file_caps anon=[upload] answers the resulting caps" '{"file_anon_caps":["upload"],"file_user_caps":[]}' "$MCP_TEXT"

tus_rl "$B_ANON" POST "$B_T/uploads" -H "Upload-Length: 10" -H "Upload-Metadata: filename $(b64 a.bin)"
check_eq "anon create with the upload cap answers 201" 201 "$STATUS"
AURL="$BASE$(hval location)"; ATOK="$(token_of "$AURL")"
tus "$B_SVC" GET "$B_T/uploads"
check_eq "anon session is created (listed)" 10 "$(session_field "$ATOK" total_length)"

tus_head_rl "$B_ANON" "$AURL"
check_eq "anon HEAD on its own session answers 200" 200 "$STATUS"
tus_head_rl "$B_ANON" "$SURL"
check_eq "anon HEAD on a service-created session answers 404 (bound to creator)" 404 "$STATUS"
tus_head "$B_SVC" "$AURL"
check_eq "service HEAD on an anon session answers 200 (service bypasses binding)" 200 "$STATUS"

tus_rl "$B_ANON" POST "$B_T/uploads" -H "Upload-Length: 10" -H "Upload-Metadata: filename $(b64 a.bin),visibility $(b64 public)"
check_eq "anon explicit public with no publish grant is 403 FILE_PUBLIC_UPLOAD_DENIED" "403 FILE_PUBLIC_UPLOAD_DENIED" "$STATUS $(body error_code)"

svc PUT /file-policies '{"prefix":"pub/","public_read":true,"public_upload_roles":["anon"]}'
check_eq "service registers prefix pub/ with public_upload_roles [anon]" 200 "$STATUS"
tus_rl "$B_ANON" POST "$B_T/uploads" -H "Upload-Length: 10" -H "Upload-Metadata: filename $(b64 g.bin),visibility $(b64 public),path $(b64 pub/g.bin)"
check_eq "anon explicit public under the granted prefix answers 201" 201 "$STATUS"
GURL="$BASE$(hval location)"

tus_rl "$B_ANON" DELETE "$AURL"
check_eq "anon termination without the delete cap is 403 FILE_DELETE_DENIED" "403 FILE_DELETE_DENIED" "$STATUS $(body error_code)"
mcp_call set_file_caps '{"anon":["upload","delete"]}'
check_eq "set_file_caps anon=[upload,delete] answers the resulting caps" '{"file_anon_caps":["upload","delete"],"file_user_caps":[]}' "$MCP_TEXT"
tus_rl "$B_ANON" DELETE "$SURL"
check_eq "anon with delete cap cannot terminate a service session (404)" 404 "$STATUS"
tus_head "$B_SVC" "$SURL"
check_eq "the service session survived the anon termination attempt" 200 "$STATUS"
tus_rl "$B_ANON" DELETE "$AURL"
check_eq "anon with delete cap terminates its own session (204)" 204 "$STATUS"

# User role: a service-created end user, logged in once.
U_EMAIL="smoke-tus-$$@example.com"; U_PW="Smoke-$$-$(date +%s)-pw"
svc POST /admin/users "{\"email\":\"$U_EMAIL\",\"password\":\"$U_PW\"}"
USER_TOKEN=""
if [ "$STATUS" = 201 ]; then
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
    req POST "$B_T/auth/login" -H 'Content-Type: application/json' \
      --data "{\"email\":\"$U_EMAIL\",\"password\":\"$U_PW\"}"
    [ "$STATUS" = 429 ] || break
    sleep 5
  done
  [ "$STATUS" = 200 ] && USER_TOKEN="$(body token)"
fi
if [ -n "$USER_TOKEN" ]; then
  tus "$USER_TOKEN" POST "$B_T/uploads" -H "Upload-Length: 10"
  check_eq "user create with empty user file caps is 403 FILE_UPLOAD_DENIED (anon cap does not open user)" "403 FILE_UPLOAD_DENIED" "$STATUS $(body error_code)"
  mcp_call set_file_caps '{"user":["upload"]}'
  check_eq "set_file_caps user=[upload] merges with the anon caps" '{"file_anon_caps":["upload","delete"],"file_user_caps":["upload"]}' "$MCP_TEXT"
  tus_rl "$USER_TOKEN" POST "$B_T/uploads" -H "Upload-Length: 10" -H "Upload-Metadata: filename $(b64 u.bin)"
  check_eq "user create with the user upload cap answers 201" 201 "$STATUS"
  UURL="$BASE$(hval location)"
  tus_head_rl "$USER_TOKEN" "$UURL"
  check_eq "user HEAD on its own session answers 200" 200 "$STATUS"
  tus_head_rl "$USER_TOKEN" "$GURL"
  check_eq "user HEAD on an anon session answers 404 (bound to creator)" 404 "$STATUS"
  tus_head_rl "$B_ANON" "$UURL"
  check_eq "anon HEAD on a user session answers 404 (bound to creator)" 404 "$STATUS"
  tus "$B_SVC" DELETE "$UURL" >/dev/null
else
  bad "end-user login for the user-role checks" "create/login answered $STATUS"
fi
tus "$B_SVC" DELETE "$GURL" >/dev/null
tus "$B_SVC" DELETE "$SURL" >/dev/null
tus "$B_SVC" GET "$B_T/uploads"
check_eq "tenant B has no upload sessions left" '{"sessions":[]}' "$BODY"

# ============================================================================
# Tenant C — per-tenant concurrent session cap (default 5)
# ============================================================================
new_tenant tusc
C_SVC="$SERVICE_KEY"; C_T="$T"
c_urls=""
for i in 1 2 3 4 5; do
  tus "$C_SVC" POST "$C_T/uploads" -H "Upload-Length: 10"
  [ "$STATUS" = 201 ] && c_urls="$c_urls $BASE$(hval location)"
done
check_eq "five concurrent sessions are accepted" 5 "$(echo $c_urls | wc -w | tr -d ' ')"
# Tenant isolation: a session token is only reachable under its own tenant.
c_first="$(echo $c_urls | awk '{print $1}')"
c_tok="$(token_of "$c_first")"
tus_head "$C_SVC" "$c_first"
check_eq "tenant C service HEAD on its own session answers 200" 200 "$STATUS"
tus_head "$B_SVC" "$B_T/uploads/$c_tok"
check_eq "tenant C's upload token under tenant B's path (B's service key) answers 404" 404 "$STATUS"
tus "$B_SVC" DELETE "$c_first"
check_eq "tenant B's service key cannot terminate tenant C's session (404 TENANT_NOT_FOUND, not an existence oracle)" "404 TENANT_NOT_FOUND" "$STATUS $(body error_code 2>/dev/null)"
tus_head "$C_SVC" "$c_first"
check_eq "tenant C's session survived tenant B's termination attempt" 200 "$STATUS"
tus "$C_SVC" POST "$C_T/uploads" -H "Upload-Length: 10"
check_eq "the sixth concurrent session is 429 TOO_MANY_UPLOADS" "429 TOO_MANY_UPLOADS" "$STATUS $(body error_code)"
for u in $c_urls; do tus "$C_SVC" DELETE "$u" >/dev/null; done
tus "$C_SVC" POST "$C_T/uploads" -H "Upload-Length: 10"
check_eq "after terminating them a new session is accepted again" 201 "$STATUS"
tus "$C_SVC" DELETE "$BASE$(hval location)" >/dev/null

finish

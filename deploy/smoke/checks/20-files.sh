#!/usr/bin/env bash
# Files, Mode A, against the real object store (RustFS or Garage, SMOKE_STORE):
# multipart upload as service (Mode-A public default, explicit private),
# byte round-trip by sha256 through drust and through the deployment's own
# /public/* route (Caddy straight to the store), object attributes the store
# keeps, the /public/* route's own hardening, list / get_one / delete, the
# returned public URL and its origin, public <-> private bucket move
# (copy + delete across the two host-wide buckets), drust HMAC signed URLs and
# their redemption, the stored-XSS headers (invariant 14), the file-caps gate
# and the prefix policy registry for anon/user (invariants 19 and 20: publish
# grant, private-when-silent, hidden = 404), non-ASCII names and paths, the
# admin-plane tenant files twins with the admin PAT, and MCP list_files /
# get_file_url. Two tenants per run (main + one for the cross-tenant check).
. "$(dirname "$0")/lib.sh"

REQ_TIMEOUT="${REQ_TIMEOUT:-60}"
# The client-facing origin of this Compose stack (Caddy on SMOKE_HTTP_PORT; the
# smoke override sets DRUST_PUBLIC_URL to it). File / sign / get_file_url URLs
# are NOT built from DRUST_PUBLIC_URL but from DRUST_PUBLIC_BASE_URL
# (src/config.rs, default the bare-metal http://localhost:8793). docker-compose.yml
# sets it with ${DRUST_PUBLIC_BASE_URL:-http://localhost}; up.sh exports it so the
# base file's own line is what is tested — the origin checks below FAIL if it is
# unwired.
PUBLIC_ORIGIN="http://localhost:${SMOKE_HTTP_PORT:-48080}"
SANDBOX="sandbox allow-top-navigation-by-user-activation"   # storage::files::SANDBOX_CSP

# ---- local helpers ------------------------------------------------------------
# The data plane rate-limits per token (DRUST_RATE_LIMIT_PER_TOKEN, default 60
# per 10 s) and per IP for non-service upload/delete. This script is denser
# than that, so `req` and `mcp_rpc` are wrapped (lib.sh untouched): a 429 is
# retried after a short back-off, at most 6 times. A request that is still
# 429 after that is returned as-is and fails its check honestly.
eval "$(declare -f req | sed '1s/^req /_lib_req /')"
eval "$(declare -f mcp_rpc | sed '1s/^mcp_rpc /_lib_mcp_rpc /')"
req() {
  local i
  for i in 1 2 3 4 5 6; do
    _lib_req "$@"
    [ "$STATUS" = 429 ] || return 0
    sleep 2
  done
}
mcp_rpc() {
  local i
  for i in 1 2 3 4 5 6; do
    _lib_mcp_rpc "$@"
    case "$BODY" in *'"http_status": 429'*) sleep 2 ;; *) return 0 ;; esac
  done
}

_keys=""          # every key uploaded to the main tenant, deleted again at exit
track() { [ -n "${1:-}" ] && _keys="$_keys $1"; return 0; }
_files_cleanup() {
  local k
  for k in $_keys; do
    req DELETE "$BASE/t/$TA/files/$k" -H "Authorization: Bearer $SA"
  done
  _cleanup
}
trap _files_cleanup EXIT

sha_file() { shasum -a 256 "$1" | cut -d' ' -f1; }
body_sha() { sha_file "$TMP/body"; }
code() { body error_code 2>/dev/null || true; }
urlenc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe="/"))' "$1"; }
url_origin() { python3 -c 'import sys,urllib.parse; u=urllib.parse.urlsplit(sys.argv[1]); print(u.scheme+"://"+u.netloc)' "$1"; }
url_path() { python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(urllib.parse.urlsplit(sys.argv[1]).path))' "$1"; }
# Re-root a URL on another origin, keeping path + query (signed URLs: the token
# stays inside the variable, never printed).
reroot() { python3 -c 'import sys,urllib.parse; u=urllib.parse.urlsplit(sys.argv[1]); print(sys.argv[2]+u.path+("?"+u.query if u.query else ""))' "$1" "$2"; }

# upload KEY_BEARER FILE [extra curl -F/--form-string args...] — Mode-A multipart.
upload() {
  local bearer="$1" file="$2"
  shift 2
  req POST "$T/files" -H "Authorization: Bearer $bearer" -F "file=@$file" "$@"
  UP_KEY="$(body key 2>/dev/null || true)"
  UP_URL="$(body url 2>/dev/null || true)"
  [ "$STATUS" = 200 ] && track "$UP_KEY"
  return 0
}
public_get() { req GET "$PUBLIC/$1"; }   # what an anonymous client fetches
meta_of() { svc GET "/files/$1"; }   # service get_one

# ---- tenants --------------------------------------------------------------------
new_tenant files-b; TB="$TENANT_ID"; SB="$SERVICE_KEY"
new_tenant files-a; TA="$TENANT_ID"; SA="$SERVICE_KEY"; AA="$ANON_KEY"

printf 'hello from the drust files smoke\n' > "$TMP/plain.txt"
head -c 2097152 /dev/urandom > "$TMP/blob.bin"
printf '<html><body><script>document.title="x"</script></body></html>' > "$TMP/page.html"
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>' > "$TMP/pic.svg"
printf '<?xml version="1.0"?><rss/>' > "$TMP/feed.xml"
printf 'cjk payload\n' > "$TMP/cjk.txt"
PLAIN_SHA="$(sha_file "$TMP/plain.txt")"
BLOB_SHA="$(sha_file "$TMP/blob.bin")"

# ---- 1. service upload, Mode-A default visibility -------------------------------
upload "$SA" "$TMP/plain.txt;type=text/plain"
check_eq "service Mode-A upload without visibility answers 200" 200 "$STATUS"
K1="$UP_KEY"; U1="$UP_URL"
meta_of "$K1"
check_eq "Mode-A service default visibility is public (invariant 19 per-station default)" public "$(body visibility)"
check_eq "service upload is stamped uploader=service" service "$(body uploader)"
check_eq "get_one size_bytes matches the uploaded length" "$(wc -c < "$TMP/plain.txt" | tr -d ' ')" "$(body size_bytes)"
check_eq "public upload carries the public cache default" "public, max-age=86400" "$(body cache_control)"
check_eq "returned public URL path is /public/<tenant>/<key>" "/public/$TA/$K1" "$(url_path "$U1")"
check_eq "returned public URL uses the deployment's client-facing origin (DRUST_PUBLIC_BASE_URL wired in Compose)" \
  "$PUBLIC_ORIGIN" "$(url_origin "$U1")"

svc GET "/files/$K1/bytes"
check_eq "service bytes of a public file answer 200" 200 "$STATUS"
check_eq "bytes through drust round-trip by sha256" "$PLAIN_SHA" "$(body_sha)"
check_eq "bytes responder sends nosniff" nosniff "$(header x-content-type-options)"
check_eq "text/plain gets no sandbox CSP" "" "$(header content-security-policy)"

public_get "$TA/$K1"
check_eq "public object is served by the public route at <tenant>/<key>" 200 "$STATUS"
check_eq "bytes served by the public route match by sha256" "$PLAIN_SHA" "$(body_sha)"
check_eq "public object carries the Content-Type drust put" "text/plain" "$(header content-type)"
check_eq "public object carries the public Cache-Control" "public, max-age=86400" "$(header cache-control)"
check_contains "public object carries the inline Content-Disposition with filename" 'inline; filename="plain.txt"' "$(header content-disposition)"
public_get "$K1"
check_eq "tenant objects are namespaced by <tenant>/ (bare key is absent from the bucket)" 404 "$STATUS"
req GET "$PUBLIC/$TA/$K1" -H "Range: bytes=0-4"
check_eq "the public route serves a ranged GET of the stored object (206)" 206 "$STATUS"
check_eq "ranged GET returns the first five bytes" "hello" "$BODY"

req GET "$BASE$(url_path "$U1")"
check_eq "the returned public URL path is served through the Compose Caddy (/public/*)" 200 "$STATUS"

# The /public/* route's own hardening (deploy/compose.Caddyfile). Every check
# here holds on either store and reads only variables assigned above (lib.sh is
# set -u: a later-assigned variable would abort the whole script).
req GET "$PUBLIC/$TA/$K1?response-content-type=TEXT/HTML&response-content-disposition=attachment"
check_eq "the public route drops the query: ?response-content-type=TEXT/HTML is ignored" "text/plain" "$(header content-type)"
check_eq "... and adds no sandbox CSP to it" "" "$(header content-security-policy)"
check_contains "... and ?response-content-disposition=attachment is ignored" 'inline; filename="plain.txt"' "$(header content-disposition)"
req GET "$PUBLIC/$TA/$K1" -H "Authorization: Bearer $SA" -H "Cookie: x=y"
check_eq "a public GET carrying a drust bearer and a cookie still answers 200 (the proxy forwards neither)" 200 "$STATUS"
req PUT "$PUBLIC/$TA/$K1" --data x
check_eq "PUT on the public route answers 405 (GET/HEAD only)" 405 "$STATUS"
req DELETE "$PUBLIC/$TA/$K1"
check_eq "DELETE on the public route answers 405 (GET/HEAD only)" 405 "$STATUS"
req POST "$PUBLIC/$TA/$K1?delete" --data x
check_eq "POST on the public route answers 405 (GET/HEAD only)" 405 "$STATUS"
check_eq "HEAD on a public object answers 200 through the proxy" 200 \
  "$(curl -sS -o /dev/null -I -w '%{http_code}' --max-time "${REQ_TIMEOUT:-30}" "$PUBLIC/$TA/$K1" 2>/dev/null || echo 000)"
req GET "$PUBLIC/"
check_ne "GET /public/ does not list the bucket (status)" 200 "$STATUS"
check_not_contains "GET /public/ does not list the bucket (no ListBucketResult)" ListBucketResult "$BODY"
# Bucket-level on purpose: /public/<tenant>/?list-type=2 names the object key
# "<tenant>/" and is a GetObject whatever the proxy does with the query, so it
# could never list. This form lists the moment the query strip and the
# GetObject-only policy are both lost.
req GET "$PUBLIC/?list-type=2&prefix=$TA/"
check_ne "a ListObjectsV2 request on /public/ does not list the bucket (status)" 200 "$STATUS"
check_not_contains "a ListObjectsV2 request on /public/ returns no ListBucketResult" ListBucketResult "$BODY"
# Caddy matches the CLEANED path (/public/...) but forwards the RAW one: only the
# pinned block (handle_path + rewrite * /public{path}?) serves the public object
# here; an unpinned `handle /public/*` hands the store bucket "private" (403).
req GET "$BASE/private/../public/$TA/$K1" --path-as-is
check_eq "the public route pins its bucket: /private/../public/<tenant>/<key> serves the public object" 200 "$STATUS"
check_eq "... with the public object's bytes" "$PLAIN_SHA" "$(body_sha)"

# ---- 2. streaming a multi-MiB object --------------------------------------------
upload "$SA" "$TMP/blob.bin;type=application/octet-stream"
check_eq "service upload of a 2 MiB binary answers 200" 200 "$STATUS"
KB="$UP_KEY"
svc GET "/files/$KB/bytes"
check_eq "2 MiB object streams back through drust intact (sha256)" "$BLOB_SHA" "$(body_sha)"
public_get "$TA/$KB"
check_eq "2 MiB object through the public route is intact (sha256)" "$BLOB_SHA" "$(body_sha)"

# ---- 3. explicit private upload (needs the host-wide 'private' bucket) ----------
upload "$SA" "$TMP/plain.txt;type=text/plain" -F visibility=private
PRIV_STATUS="$STATUS"
check_eq "service upload with visibility=private answers 200 (private bucket usable)" 200 "$PRIV_STATUS"
PRIVATE_OK=0
if [ "$PRIV_STATUS" = 200 ]; then
  PRIVATE_OK=1
  KP="$UP_KEY"
  meta_of "$KP"
  check_eq "explicit private lands private" private "$(body visibility)"
  check_eq "private upload carries the private cache default" "private, no-store" "$(body cache_control)"
  svc GET "/files/$KP/bytes"
  check_eq "private bytes stream through drust intact" "$PLAIN_SHA" "$(body_sha)"
  check_eq "private bytes are served private, no-store" "private, no-store" "$(header cache-control)"
  public_get "$TA/$KP"
  check_eq "a private object is NOT on the public route" 404 "$STATUS"
else
  note "private upload answered $PRIV_STATUS; the object store has no 'private' bucket — private-path checks below are recorded as failures"
  svc GET /files
  ghost="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(sum(1 for f in json.load(sys.stdin)["files"] if f["visibility"]=="private"))' 2>/dev/null || echo err)"
  check_eq "a failed object-store PUT is compensated: no private _system_files row survives" 0 "$ghost"
fi

# ---- 4. list / get_one ------------------------------------------------------------
svc GET /files
check_eq "service list answers 200" 200 "$STATUS"
listed="$(printf '%s' "$BODY" | python3 -c 'import json,sys; d=json.load(sys.stdin); ks=[f["key"] for f in d["files"]]; print(("K1" if sys.argv[1] in ks else "-")+("KB" if sys.argv[2] in ks else "-")+(" ok" if d["file_count"]==len(ks) and d["used_bytes"]==sum(f["size_bytes"] for f in d["files"]) else " totals-mismatch"))' "$K1" "$KB" 2>/dev/null || echo err)"
check_eq "service list contains the uploads and its totals match its rows" "K1KB ok" "$listed"
svc GET /files/no-such-key.txt
check_eq "get_one of an unknown key answers 404" 404 "$STATUS"

# ---- 5. content-type hardening (invariant 14) -------------------------------------
upload "$SA" "$TMP/page.html;type=TEXT/HTML"
KH="$UP_KEY"
meta_of "$KH"
check_eq "declared TEXT/HTML is stored with a lowercased essence" "text/html" "$(body content_type)"
svc GET "/files/$KH/bytes"
check_eq "text/html bytes keep their declared type" "text/html" "$(header content-type)"
check_eq "text/html bytes carry the exact sandbox CSP" "$SANDBOX" "$(header content-security-policy)"
check_eq "text/html bytes carry nosniff" nosniff "$(header x-content-type-options)"
public_get "$TA/$KH"
check_eq "the public object carries the lowercased type the Caddy matcher keys on" "text/html" "$(header content-type)"
check_eq "public text/html served through the Compose Caddy carries the sandbox CSP" "$SANDBOX" "$(header content-security-policy)"
check_eq "public text/html through the Compose Caddy keeps its body (copy_response)" "$(sha_file "$TMP/page.html")" "$(body_sha)"
check_eq "/public responses through the Compose Caddy send nosniff" nosniff "$(header x-content-type-options)"
public_get "$TA/$K1"
check_eq "public text/plain through the Compose Caddy has no CSP" "" "$(header content-security-policy)"
check_eq "public text/plain through the Compose Caddy sends nosniff" nosniff "$(header x-content-type-options)"
upload "$SA" "$TMP/pic.svg;type=image/svg+xml"
KS="$UP_KEY"
svc GET "/files/$KS/bytes"
check_eq "image/svg+xml bytes carry the sandbox CSP" "$SANDBOX" "$(header content-security-policy)"
public_get "$TA/$KS"
check_eq "public image/svg+xml through the Compose Caddy carries the sandbox CSP" "$SANDBOX" "$(header content-security-policy)"
# Unquoted on purpose: curl keeps "; charset=utf-8" in the part's type, while a
# quoted type="..." is sent with its quotes.
upload "$SA" "$TMP/page.html;type=application/xhtml+xml; charset=utf-8"
KXH="$UP_KEY"
public_get "$TA/$KXH"
check_eq "public application/xhtml+xml; charset=utf-8 through the Compose Caddy carries the sandbox CSP" "$SANDBOX" "$(header content-security-policy)"
upload "$SA" "$TMP/feed.xml;type=application/rss+xml"
KR="$UP_KEY"
svc GET "/files/$KR/bytes"
check_eq "application/rss+xml (structural +xml rule) carries the sandbox CSP" "$SANDBOX" "$(header content-security-policy)"
admin GET "/admin/tenants/$TA/files/$KH/bytes"
check_eq "admin-plane bytes twin answers 200 with the PAT" 200 "$STATUS"
check_eq "admin-plane bytes of text/html carry the sandbox CSP" "$SANDBOX" "$(header content-security-policy)"

# ---- 6. non-ASCII names and paths -------------------------------------------------
upload "$SA" "$TMP/cjk.txt;filename=報告書.txt;type=text/plain" --form-string "path=文件/子/報告書.txt"
check_eq "upload with a CJK filename and CJK path answers 200" 200 "$STATUS"
KC="$UP_KEY"
meta_of "$KC"
check_eq "CJK original_name is stored verbatim" "報告書.txt" "$(body original_name)"
check_eq "CJK path is stored verbatim" "文件/子/報告書.txt" "$(body path)"
svc GET "/files/$KC/bytes"
check_eq "CJK-named file round-trips through drust" "$(sha_file "$TMP/cjk.txt")" "$(body_sha)"
check_contains "Content-Disposition carries the RFC 5987 UTF-8 filename*" \
  "filename*=UTF-8''%E5%A0%B1%E5%91%8A%E6%9B%B8.txt" "$(header content-disposition)"
public_get "$TA/$KC"
check_eq "CJK-named file with an ASCII extension is reachable on the public route" 200 "$STATUS"

upload "$SA" "$TMP/cjk.txt;filename=報告書.檔案;type=text/plain"
check_eq "upload whose extension is non-ASCII answers 200" 200 "$STATUS"
KX="$UP_KEY"; UX="$UP_URL"
svc GET "/files/$(urlenc "$KX")/bytes"
check_eq "non-ASCII-extension file round-trips through drust" "$(sha_file "$TMP/cjk.txt")" "$(body_sha)"
# Both uploads get a <uuid>.bin key (files::derive_file_key), so nothing in the
# key needs escaping. What is fetched is the URL drust RETURNED, as a client
# would use it. A key that does need escaping can only come from a pre-v1.67
# row or an edge put-file; that route (a %25-escaped path through /public/*)
# was run by hand on both stores for this release and is recorded in the
# CHANGELOG entry, not here.
check_eq "a non-ASCII extension mints a .bin key" "${KX%.*}.bin" "$KX"
req GET "$UX"
check_eq "non-ASCII-extension public object is served at its returned URL" 200 "$STATUS"
upload "$SA" "$TMP/cjk.txt;filename=notes.t~xt;type=text/plain"
KT="$UP_KEY"; UT="$UP_URL"
check_eq "a '~' in the extension mints a .bin key" "${KT%.*}.bin" "$KT"
req GET "$UT"
check_eq "a '~' in the extension still yields a public object at its returned URL" 200 "$STATUS"

upload "$SA" "$TMP/plain.txt" --form-string "path=a/../b.txt"
check_eq "a '..' path segment is refused 400" 400 "$STATUS"
check_eq "a '..' path segment is FILE_PATH_INVALID" FILE_PATH_INVALID "$(code)"
upload "$SA" "$TMP/plain.txt" --form-string "path=/lead.txt"
check_eq "a leading '/' in path is FILE_PATH_INVALID" FILE_PATH_INVALID "$(code)"
upload "$SA" "$TMP/plain.txt" -F visibility=secret
check_eq "an unknown visibility value is refused 400" 400 "$STATUS"
check_contains "the 400 names the invalid visibility (not some other parse failure)" "invalid visibility" "$BODY"

# ---- 7. visibility move between buckets (copy -> UPDATE -> delete-old) ------------
svc PATCH "/files/$K1" '{"visibility":"public"}'
check_eq "PATCH to the current visibility is a no-op" true "$(body noop)"
svc PATCH "/files/$K1" '{"visibility":"secret"}'
check_eq "PATCH with an unknown visibility answers 422" 422 "$STATUS"
check_eq "PATCH with an unknown visibility is INVALID_VISIBILITY" INVALID_VISIBILITY "$(code)"
svc PATCH /files/no-such-key.txt '{"visibility":"private"}'
check_eq "PATCH of an unknown key answers 404 NOT_FOUND" "404 NOT_FOUND" "$STATUS $(code)"
svc PATCH "/files/$K1" '{"visibility":"private"}'
check_eq "PATCH public -> private answers 200 (bucket move)" 200 "$STATUS"
if [ "$STATUS" = 200 ]; then
  check_eq "the move reports from=public to=private" "public private" "$(body from) $(body to)"
  public_get "$TA/$K1"
  check_eq "after PATCH private the object is gone from the public route" 404 "$STATUS"
  meta_of "$K1"
  check_eq "after PATCH private the row says private" private "$(body visibility)"
  check_eq "after PATCH private cache_control resets to private, no-store" "private, no-store" "$(body cache_control)"
  svc GET "/files/$K1/bytes"
  check_eq "after PATCH private the bytes still stream intact from the private bucket" "$PLAIN_SHA" "$(body_sha)"

  # ---- 8. drust HMAC signed URL for a private file ----
  svc POST "/files/$K1/sign" '{"expires_in":600}'
  check_eq "sign of a private file answers 200" 200 "$STATUS"
  SURL="$(body url)"; SEXP="$(body expires_at)"
  check_eq "signed URL path is /s/t/<tenant>/<key>" "/s/t/$TA/$K1" "$(url_path "$SURL")"
  case "$SEXP" in
    20[0-9][0-9]-[01][0-9]-[0-3][0-9]T*) ok "signed URL carries an RFC 3339 expires_at" ;;
    *) bad "signed URL carries an RFC 3339 expires_at" "got [$SEXP]" ;;
  esac
  check_eq "signed URL targets the deployment's client-facing origin (DRUST_PUBLIC_BASE_URL)" "$PUBLIC_ORIGIN" "$(url_origin "$SURL")"
  REDEEM="$(reroot "$SURL" "$BASE")"
  req GET "$REDEEM"
  check_eq "signed URL redeems through Caddy with no bearer (200)" 200 "$STATUS"
  check_eq "redeemed bytes match by sha256" "$PLAIN_SHA" "$(body_sha)"
  check_eq "signed responder sends nosniff" nosniff "$(header x-content-type-options)"
  check_contains "d=0 signed URL serves inline" "inline;" "$(header content-disposition)"
  req GET "$(printf '%s' "$REDEEM" | sed 's/&d=0$/\&d=1/')"
  check_eq "flipping d on a d=0 token is refused 403" 403 "$STATUS"
  req GET "$(printf '%s' "$REDEEM" | python3 -c 'import sys,re; u=sys.stdin.read().strip(); print(re.sub(r"([?&]t=)([^&])", lambda m: m.group(1)+("A" if m.group(2)!="A" else "B"), u, 1))')"
  check_eq "a tampered token is refused 403" 403 "$STATUS"
  svc POST "/files/$K1/sign" '{"expires_in":600,"download":true}'
  req GET "$(reroot "$(body url)" "$BASE")"
  check_contains "download=true signed URL serves attachment" "attachment;" "$(header content-disposition)"

  svc PATCH "/files/$KH" '{"visibility":"private"}'
  svc POST "/files/$KH/sign" '{}'
  req GET "$(reroot "$(body url)" "$BASE")"
  check_eq "signed text/html carries the sandbox CSP" "$SANDBOX" "$(header content-security-policy)"

  # admin-plane twins on a private file
  admin POST "/admin/tenants/$TA/files/$K1/sign" '{"expires_in":600}'
  check_eq "admin-plane sign of a private file mints a /s/t/ URL" "/s/t/$TA/$K1" "$(url_path "$(body url 2>/dev/null || true)")"
  req POST "$BASE/admin/tenants/$TA/files/$K1/visibility" -H "Authorization: Bearer $ADMIN_PAT" --data visibility=public
  check_eq "admin-plane visibility form redirects back to the files page" "303 /admin/tenants/$TA/_files" "$STATUS $(header location)"
  public_get "$TA/$K1"
  check_eq "after private -> public the object is back on the public route" 200 "$STATUS"
  check_eq "the moved-back object is byte-identical" "$PLAIN_SHA" "$(body_sha)"
else
  note "visibility move failed ($STATUS); signed-URL redemption and private->public checks not reachable"
fi

# sign of a public file returns its public URL, never a token
svc POST "/files/$KB/sign" '{}'
check_eq "sign of a public file answers 200" 200 "$STATUS"
check_eq "sign of a public file returns the public URL path" "/public/$TA/$KB" "$(url_path "$(body url)")"
check_eq "sign of a public file has no expiry" null "$(body expires_at)"
svc POST "/files/$KB/sign" '{"expires_in":0}'
check_eq "sign with expires_in=0 is refused 400" 400 "$STATUS"
svc POST "/files/$KB/sign" '{"expires_in":604801}'
check_eq "sign with expires_in over 7 days is refused 400" 400 "$STATUS"
req GET "$BASE/s/t/$TA/$KB?e=9999999999&t=AAAA&d=0"
check_eq "a forged signed URL is refused 403" 403 "$STATUS"

# ---- 9. anon/user before any cap: service-only by default -------------------------
anon GET /files
check_eq "anon list with default caps is 403 FILE_LIST_DENIED" "403 FILE_LIST_DENIED" "$STATUS $(code)"
upload "$AA" "$TMP/plain.txt"
check_eq "anon upload with default caps is 403 FILE_UPLOAD_DENIED" "403 FILE_UPLOAD_DENIED" "$STATUS $(code)"
anon GET "/files/$KB/bytes"
check_eq "anon bytes with default caps is 403 FILE_READ_DENIED" "403 FILE_READ_DENIED" "$STATUS $(code)"
anon DELETE "/files/$KB"
check_eq "anon delete with default caps is 403 FILE_DELETE_DENIED" "403 FILE_DELETE_DENIED" "$STATUS $(code)"
anon POST "/files/$KB/sign" '{}'
check_eq "anon sign is service-only (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(code)"
anon PATCH "/files/$KB" '{"visibility":"private"}'
check_eq "anon set-visibility is service-only (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(code)"
anon GET /file-policies
check_eq "anon GET /file-policies is service-only" "403 WRITE_DENIED" "$STATUS $(code)"
anon PUT /file-policies '{"prefix":"","public_read":true,"public_upload_roles":["anon"]}'
check_eq "anon PUT /file-policies is service-only" "403 WRITE_DENIED" "$STATUS $(code)"
req DELETE "$T/file-policies?prefix=" -H "Authorization: Bearer $AA"
check_eq "anon DELETE /file-policies is service-only" "403 WRITE_DENIED" "$STATUS $(code)"

# ---- 10. prefix policy registry (service) -----------------------------------------
svc GET /file-policies
root="$(printf '%s' "$BODY" | python3 -c 'import json,sys; p=[r for r in json.load(sys.stdin)["policies"] if r["prefix"]==""]; print("none" if not p else "%s %s" % (p[0]["public_read"], p[0]["public_upload_roles"]))' 2>/dev/null || echo err)"
check_eq "a fresh tenant's root rule is public_read with NO publish grant (v1.64 deny-by-default)" "True None" "$root"
svc PUT /file-policies '{"prefix":"nope"}'
check_eq "a non-root prefix without trailing '/' is FILE_POLICY_PREFIX_INVALID" "400 FILE_POLICY_PREFIX_INVALID" "$STATUS $(code)"
svc PUT /file-policies '{"prefix":"open/"}'
check_eq "a clause-less rule is refused FILE_POLICY_OPEN_REQUIRES_FLAG" "400 FILE_POLICY_OPEN_REQUIRES_FLAG" "$STATUS $(code)"
svc PUT /file-policies '{"prefix":"x/","public_read":true,"public_upload_roles":["service"]}'
check_eq "public_upload_roles outside {anon,user} is FILE_POLICY_INVALID" "400 FILE_POLICY_INVALID" "$STATUS $(code)"
svc DELETE /file-policies
check_eq "DELETE /file-policies without prefix is 400 MISSING_PARAM (never an implicit root clear)" "400 MISSING_PARAM" "$STATUS $(code)"
svc PUT /file-policies '{"prefix":"秘密/","owner_scoped":true}'
check_eq "service registers an owner-scoped CJK prefix rule" 200 "$STATUS"

upload "$SA" "$TMP/plain.txt;type=text/plain" --form-string "path=秘密/隱藏.txt"
KHID="$UP_KEY"
upload "$SA" "$TMP/plain.txt;type=text/plain" --form-string "path=秘密/子/更深.txt"
KDEEP="$UP_KEY"
upload "$SA" "$TMP/plain.txt;type=text/plain" --form-string "path=秘密之外/可見.txt"
KNEAR="$UP_KEY"

# ---- 11. grant anon caps; reads under the registry --------------------------------
mcp_call set_file_caps '{"anon":["read","list","upload","delete"],"user":[]}'
check_eq "MCP set_file_caps (service) succeeds" false "$MCP_IS_ERROR"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  anon GET /files
  [ "$STATUS" = 200 ] && break
  sleep 1
done
check_eq "anon list answers 200 once the list cap is granted" 200 "$STATUS"
alist="$BODY"
vis="$(printf '%s' "$alist" | python3 -c '
import json,sys
ks=[f["key"] for f in json.load(sys.stdin)["files"]]
print(" ".join("in" if k in ks else "out" for k in sys.argv[1:]))' "$KB" "$KHID" "$KDEEP" "$KNEAR" 2>/dev/null || echo err)"
check_eq "anon list: root file in, both owner-scoped 秘密/ files out, 秘密之外/ (byte-range sibling) in" "in out out in" "$vis"
anon GET "/files/$KB/bytes"
check_eq "anon reads a root (public_read) file with the read cap" "$BLOB_SHA" "$(body_sha)"
anon GET "/files/$KNEAR"
check_eq "a path that merely shares the CJK prefix bytes is not governed by 秘密/" 200 "$STATUS"
anon GET "/files/$KHID"
check_eq "a policy-hidden file answers 404 on get_one (invariant 20)" 404 "$STATUS"
hid_body="$BODY"
anon GET /files/no-such-key.txt
check_eq "a hidden file's 404 body equals an absent key's 404 body" "$BODY" "$hid_body"
anon GET "/files/$KHID/bytes"
check_eq "a policy-hidden file answers 404 on bytes" 404 "$STATUS"
anon GET "/files/$KDEEP"
check_eq "a deeper path under the owner-scoped prefix is hidden too" 404 "$STATUS"
anon DELETE "/files/$KHID"
check_eq "anon delete of a hidden file answers 404" 404 "$STATUS"
meta_of "$KHID"
check_eq "a refused delete did not remove the row" 200 "$STATUS"
public_get "$TA/$KHID"
check_eq "a refused delete did not remove the public object" 200 "$STATUS"

# ---- 12. publish decision for anon (invariant 19) ---------------------------------
upload "$AA" "$TMP/plain.txt;type=text/plain" -F visibility=public
check_eq "fresh tenant: anon explicit public upload is 403 FILE_PUBLIC_UPLOAD_DENIED" "403 FILE_PUBLIC_UPLOAD_DENIED" "$STATUS $(code)"
upload "$AA" "$TMP/plain.txt;type=text/plain"
check_eq "anon upload without visibility answers 200" 200 "$STATUS"
if [ "$STATUS" = 200 ]; then
  KAN="$UP_KEY"
  meta_of "$KAN"
  check_eq "anon upload that says nothing lands private (never the Mode-A public default)" private "$(body visibility)"
  check_eq "anon upload is stamped uploader=anon" anon "$(body uploader)"
else
  # The silent anon upload was routed to the private bucket (invariant 19) and
  # the object-store PUT failed; the SQLite-first row must have been rolled back.
  svc GET /files
  aghost="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(sum(1 for f in json.load(sys.stdin)["files"] if f["uploader"]=="anon"))' 2>/dev/null || echo err)"
  check_eq "a failed anon upload is compensated: no uploader=anon row survives" 0 "$aghost"
fi
svc PUT /file-policies '{"prefix":"","public_read":true,"public_upload_roles":["anon"]}'
check_eq "service grants anon publish on the root rule" 200 "$STATUS"
upload "$AA" "$TMP/plain.txt;type=text/plain" -F visibility=public
check_eq "with the root grant, anon explicit public upload answers 200" 200 "$STATUS"
KAP="$UP_KEY"
meta_of "$KAP"
check_eq "granted anon publish lands public, uploader=anon" "public anon" "$(body visibility) $(body uploader)"
public_get "$TA/$KAP"
check_eq "granted anon publish is on the public route" "$PLAIN_SHA" "$(body_sha)"
upload "$AA" "$TMP/plain.txt;type=text/plain" -F visibility=public --form-string "path=秘密/x.txt"
check_eq "the root grant does not reach a longer prefix rule that grants nothing" "403 FILE_PUBLIC_UPLOAD_DENIED" "$STATUS $(code)"
svc PUT /file-policies '{"prefix":"","public_read":true}'
check_eq "re-registering the root without the grant succeeds" 200 "$STATUS"
upload "$AA" "$TMP/plain.txt;type=text/plain" -F visibility=public
check_eq "omitting public_upload_roles on re-register revokes the grant" "403 FILE_PUBLIC_UPLOAD_DENIED" "$STATUS $(code)"
anon DELETE "/files/$KAP"
check_eq "anon deletes its readable public file with the delete cap (204)" 204 "$STATUS"
public_get "$TA/$KAP"
check_eq "anon delete removed the object from the public route" 404 "$STATUS"

# ---- 13. user role: caps are independent of anon's --------------------------------
svc POST /admin/users '{"email":"smoke-files-user@example.com","password":"Sm0ke-Files-Pass-42"}'
check_eq "service creates an end user" 201 "$STATUS"
_lib_req POST "$T/auth/login" -H 'Content-Type: application/json' \
  --data '{"email":"smoke-files-user@example.com","password":"Sm0ke-Files-Pass-42"}'
if [ "$STATUS" = 200 ]; then
  UK="$(body token)"
  req GET "$T/files" -H "Authorization: Bearer $UK"
  check_eq "user list is denied while only anon holds file caps" "403 FILE_LIST_DENIED" "$STATUS $(code)"
  mcp_call set_file_caps '{"user":["upload"]}'
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    req POST "$T/files" -H "Authorization: Bearer $UK" -F "file=@$TMP/plain.txt;type=text/plain" -F visibility=public
    [ "$STATUS" = 200 ] && track "$(body key 2>/dev/null || true)"
    [ "$(code)" != FILE_UPLOAD_DENIED ] && break
    sleep 1
  done
  check_eq "user explicit public upload without a user grant is 403 FILE_PUBLIC_UPLOAD_DENIED" "403 FILE_PUBLIC_UPLOAD_DENIED" "$STATUS $(code)"
  req POST "$T/files" -H "Authorization: Bearer $UK" -F "file=@$TMP/plain.txt;type=text/plain"
  check_eq "user upload without visibility answers 200" 200 "$STATUS"
  if [ "$STATUS" = 200 ]; then
    KU="$(body key)"; track "$KU"
    meta_of "$KU"
    check_contains "user upload is stamped with the u-… user id" "u-" "$(body uploader)"
    check_eq "user upload that says nothing lands private" private "$(body visibility)"
  else
    svc GET /files
    ughost="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(sum(1 for f in json.load(sys.stdin)["files"] if str(f["uploader"]).startswith("u-")))' 2>/dev/null || echo err)"
    check_eq "a failed user upload is compensated: no u-… uploader row survives" 0 "$ughost"
  fi
elif [ "$STATUS" = 429 ]; then
  note "tenant login answered 429 (shared per-IP limiter); user-role checks skipped this run"
else
  bad "end-user login answers 200" "got $STATUS $(code)"
fi

# ---- 14. clear the rule, delete, 404 ----------------------------------------------
req DELETE "$T/file-policies?prefix=$(urlenc "秘密/")" -H "Authorization: Bearer $SA"
check_eq "DELETE ?prefix=秘密/ clears the CJK rule" 200 "$STATUS"
req DELETE "$T/file-policies?prefix=$(urlenc "秘密/")" -H "Authorization: Bearer $SA"
check_eq "clearing it again is 404 FILE_POLICY_NOT_FOUND" "404 FILE_POLICY_NOT_FOUND" "$STATUS $(code)"
anon GET "/files/$KHID"
check_eq "with the rule cleared the file falls back to the root rule (readable)" 200 "$STATUS"

svc DELETE "/files/$KB"
check_eq "service delete answers 204" 204 "$STATUS"
meta_of "$KB"
check_eq "deleted file: get_one 404" 404 "$STATUS"
svc GET "/files/$KB/bytes"
check_eq "deleted file: bytes 404" 404 "$STATUS"
public_get "$TA/$KB"
check_eq "deleted file: object gone from the public route" 404 "$STATUS"
svc DELETE "/files/$KB"
check_eq "deleting it again answers 404" 404 "$STATUS"

# ---- 15. admin-plane twins with the PAT, cross-tenant, MCP -------------------------
req POST "$BASE/admin/tenants/$TA/files/upload" -H "Authorization: Bearer $ADMIN_PAT" -F "file=@$TMP/plain.txt;type=text/plain"
check_eq "admin-plane upload twin answers 200 with the PAT" 200 "$STATUS"
KAD="$(body key 2>/dev/null || true)"; track "$KAD"
meta_of "$KAD"
check_eq "admin-plane upload keeps public default and stamps service" "public service" "$(body visibility) $(body uploader)"
admin POST "/admin/tenants/$TA/files/$KAD/sign" '{}'
check_eq "admin-plane sign of a public file returns its public URL path" "/public/$TA/$KAD" "$(url_path "$(body url 2>/dev/null || true)")"
admin GET "/admin/tenants/$TA/_files"
check_eq "admin tenant files page renders with the PAT" 200 "$STATUS"
admin DELETE "/admin/tenants/$TA/files/$KAD"
check_eq "admin-plane delete twin answers 204" 204 "$STATUS"
public_get "$TA/$KAD"
check_eq "admin-plane delete removed the public object" 404 "$STATUS"

req GET "$T/files/$KC/bytes" -H "Authorization: Bearer $SB"
check_eq "another tenant's service key gets 404 TENANT_NOT_FOUND on this tenant's file" "404 TENANT_NOT_FOUND" "$STATUS $(code)"
req GET "$T/files/$KC/bytes"
check_eq "bytes without a bearer are refused 401" 401 "$STATUS"

mcp_call list_files "{}"
check_contains "MCP list_files lists a REST-uploaded key" "$KC" "$MCP_TEXT"
mcp_call list_files '{"visibility":"Public"}'
check_eq "MCP list_files refuses a misspelt visibility (M1)" true "$MCP_IS_ERROR"
check_contains "MCP list_files misspelt visibility is INVALID_VISIBILITY" INVALID_VISIBILITY "$MCP_TEXT"
mcp_call get_file_url "{\"id\":\"$KC\"}"
check_eq "MCP get_file_url for a public file returns its public URL path" "/public/$TA/$KC" \
  "$(url_path "$(printf '%s' "$MCP_TEXT" | json url 2>/dev/null || true)")"

finish

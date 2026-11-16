#!/usr/bin/env bash
# Realtime surface: SSE collection subscribe (/t/<id>/records/<c>/subscribe) and
# WS rooms (/t/<id>/realtime), through Caddy unless noted.
#   SSE  — gating codes (REALTIME_DISABLED / REALTIME_ANON_DENIED /
#          ANON_FORBIDDEN_OWNER_SCOPED / SSE_USER_DENIED / NOT_FOUND), created /
#          updated / deleted events for REST writes, select-policy filtering
#          (hidden rows and Deleted events never reach anon), evict_collection on
#          anon_caps revoke / realtime disable / policy attach + clear /
#          drop_collection (E4, incl. warnings + dry_run), tenant-key reroll ends
#          streams, keepalive comments, admin-PAT stream admitted as service.
#   WS   — upgrade through Caddy + direct, header and ?token= auth, subscribe /
#          unsubscribe / op:ping / control ping / publish acks + fan-out, publish
#          permission (service vs anon, per-tenant flag via set_publish_policy and
#          the eviction a real flag change causes), payload cap (WS + REST), room
#          name validation, CONN_EVICTED + close 1008 after a token reroll for a
#          busy socket (next frame) and an idle one (keepalive tick), server Ping.
# E2' (admin-PAT SSE ends on that admin's revocation) is NOT exercised: a second
# admin's PAT cannot be obtained through the API (see the note it prints).
# Uses 3 tenants, all deleted on exit. No secrets are printed.
. "$(dirname "$0")/lib.sh"

SSE_PIDS=""
_rt_cleanup() {
  local p
  for p in $SSE_PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $(jobs -p); do kill "$p" 2>/dev/null || true; done
  _cleanup
}
trap _rt_cleanup EXIT

# ---------------------------------------------------------------- helpers ----

# Retry a data-plane call once the per-token limiter (60 / 10 s) says 429.
_rt_orig_tenant_call="$(declare -f _tenant_call)"
eval "${_rt_orig_tenant_call/_tenant_call/_tenant_call_once}"
_tenant_call() {
  local i
  for i in 1 2 3 4 5 6; do
    _tenant_call_once "$@"
    [ "$STATUS" = "429" ] || return 0
    sleep 2
  done
}
mcp_call_r() { # TOOL JSON — mcp_call, retried on a 429 from the HTTP layer
  local i
  for i in 1 2 3 4 5 6; do
    mcp_call "$1" "$2"
    case "$BODY" in *'"http_status": 429'*) sleep 2 ;; *) break ;; esac
  done
  # lib's MCP_IS_ERROR only reads result.isError; a JSON-RPC error object (how
  # bail_mcp reports e.g. OWNER_FIELD_NOT_FK) or a transport failure must count
  # as an error too.
  MCP_IS_ERROR="$(printf '%s' "$BODY" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("true" if "error" in d or "http_status" in d or d.get("result", {}).get("isError") else "false")
' 2>/dev/null || echo true)"
}

# Tenant slots: save_tenant X after new_tenant, use_tenant X to switch.
save_tenant() {
  eval "${1}_ID=\$TENANT_ID; ${1}_SVC=\$SERVICE_KEY; ${1}_ANON=\$ANON_KEY; ${1}_T=\$T"
}
use_tenant() {
  eval "TENANT_ID=\$${1}_ID; SERVICE_KEY=\$${1}_SVC; ANON_KEY=\$${1}_ANON; T=\$${1}_T"
}

# ---- SSE: one curl per stream, in the background, polled from files.
# sse_open NAME URL TOKEN MAXSECS — TOKEN "" sends no Authorization header.
sse_open() {
  local n="$1" url="$2" tok="$3" max="$4"
  rm -f "$TMP/sse.$n.h" "$TMP/sse.$n.b" "$TMP/sse.$n.rc"
  if [ -n "$tok" ]; then
    curl -sN --max-time "$max" -D "$TMP/sse.$n.h" -H 'Accept: text/event-stream' \
      -H "Authorization: Bearer $tok" "$url" > "$TMP/sse.$n.b" 2>/dev/null &
  else
    curl -sN --max-time "$max" -D "$TMP/sse.$n.h" -H 'Accept: text/event-stream' \
      "$url" > "$TMP/sse.$n.b" 2>/dev/null &
  fi
  eval "SSE_PID_$n=$!"
  SSE_PIDS="$SSE_PIDS $!"
}
# sse_status NAME — HTTP status once the response head is complete (or curl ended).
sse_status() {
  local n="$1" i pid
  eval "pid=\$SSE_PID_$n"
  for i in $(seq 1 60); do
    if [ -f "$TMP/sse.$n.h" ] && tr -d '\r' < "$TMP/sse.$n.h" | grep -q '^$'; then break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  tr -d '\r' < "$TMP/sse.$n.h" 2>/dev/null | awk '/^HTTP\//{c=$2} END{print c+0}'
}
# sse_body NAME — everything the stream delivered so far.
sse_body() { cat "$TMP/sse.$1.b" 2>/dev/null || true; }
# sse_wait NAME NEEDLE TIMEOUT — 0 once NEEDLE appears in the stream.
sse_wait() {
  local i
  for i in $(seq 1 $(($3 * 2))); do
    grep -qF -- "$2" "$TMP/sse.$1.b" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}
# sse_end NAME TIMEOUT — prints curl's exit code once the stream ended (0 = the
# server closed it cleanly, 28 = still open at curl's max-time), or "open".
sse_end() {
  local n="$1" i pid rc
  eval "pid=\$SSE_PID_$n"
  for i in $(seq 1 $(($2 * 2))); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null; rc=$?
      echo "$rc"; return 0
    fi
    sleep 0.5
  done
  echo open
}
sse_kill() { local pid; eval "pid=\$SSE_PID_$1"; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
# A refused subscribe: the JSON error_code of the body.
sse_code() { sse_body "$1" | json error_code 2>/dev/null || echo "-"; }

# ---- WS: a tiny RFC 6455 client (stdlib only). Reads a JSON step list on
# stdin, tokens come from the environment variable a step names, prints one
# JSON object keyed by step id. Steps: open/send/send_text/send_big/ctrl_ping/
# expect/expect_close/expect_ping/wait_file/touch/sleep/close.
cat > "$TMP/ws.py" <<'PY'
import base64, json, os, socket, struct, sys, time
from urllib.parse import urlsplit

class Conn:
    def __init__(self, url, token, query_token):
        u = urlsplit(url)
        self.sock = socket.create_connection((u.hostname, u.port or 80), timeout=30)
        path = u.path + (("?" + u.query) if u.query else "")
        h = ["GET %s HTTP/1.1" % path, "Host: %s:%d" % (u.hostname, u.port or 80),
             "Upgrade: websocket", "Connection: Upgrade",
             "Sec-WebSocket-Key: " + base64.b64encode(os.urandom(16)).decode(),
             "Sec-WebSocket-Version: 13"]
        if token and not query_token:
            h.append("Authorization: Bearer " + token)
        self.sock.sendall(("\r\n".join(h) + "\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = self.sock.recv(4096)
            if not d:
                break
            buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        parts = head.split(b"\r\n")[0].decode("latin1").split()
        self.status = int(parts[1]) if len(parts) > 1 else 0
        self.headers = head.decode("latin1").lower()
        self.body = rest.decode("utf-8", "replace")
        if self.status != 101:
            self.sock.settimeout(3)
            try:
                while len(self.body) < 2000:
                    d = self.sock.recv(4096)
                    if not d:
                        break
                    self.body += d.decode("utf-8", "replace")
            except OSError:
                pass
        self.rbuf = rest if self.status == 101 else b""
        self.pending, self.closed, self.pings = [], None, 0

    def send_frame(self, opcode, payload):
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytes([0x80 | opcode])
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
        self.sock.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def _need(self, n, deadline):
        while len(self.rbuf) < n:
            left = deadline - time.time()
            if left <= 0:
                raise socket.timeout()
            self.sock.settimeout(left)
            d = self.sock.recv(65536)
            if not d:
                raise EOFError()
            self.rbuf += d
        out, self.rbuf = self.rbuf[:n], self.rbuf[n:]
        return out

    def read_one(self, deadline):
        if self.closed:
            return False
        try:
            frag = b""
            while True:
                b0, b1 = self._need(2, deadline)
                op, n = b0 & 0x0F, b1 & 0x7F
                if n == 126:
                    n = struct.unpack("!H", self._need(2, deadline))[0]
                elif n == 127:
                    n = struct.unpack("!Q", self._need(8, deadline))[0]
                p = self._need(n, deadline)
                if op == 9:
                    self.pings += 1
                    self.send_frame(10, p)
                    return True
                if op == 10:
                    self.pending.append({"__pong__": True})
                    return True
                if op == 8:
                    code = struct.unpack("!H", p[:2])[0] if len(p) >= 2 else 1005
                    self.closed = (code, p[2:].decode("utf-8", "replace"))
                    try:
                        self.send_frame(8, p[:2])
                    except OSError:
                        pass
                    return True
                frag += p
                if b0 & 0x80:
                    t = frag.decode("utf-8", "replace")
                    try:
                        self.pending.append(json.loads(t))
                    except ValueError:
                        self.pending.append({"__raw__": t[:200]})
                    return True
        except socket.timeout:
            return False
        except (EOFError, OSError):
            self.closed = self.closed or (1006, "eof")
            return True

def matches(m, want):
    return isinstance(m, dict) and all(m.get(k) == v for k, v in want.items())

def short(m):
    if isinstance(m, dict) and isinstance(m.get("payload"), dict) and "blob" in m["payload"]:
        m = dict(m, payload={"blob_len": len(m["payload"]["blob"])})
    return m

steps = json.load(sys.stdin)
conns, out = {}, {}
mark = None  # time the last successful wait_file saw its file (the trigger moment)
for i, st in enumerate(steps):
    op, c = st["op"], st.get("c")
    r = {}
    try:
        if op == "open":
            tok = os.environ.get(st.get("token_env", ""), "")
            url = st["url"] + (("?token=" + tok) if st.get("query_token") else "")
            k = Conn(url, tok, st.get("query_token"))
            conns[c] = k
            r.update(status=k.status, body=k.body[:200], via_caddy="server: caddy" in k.headers)
        elif op == "send":
            conns[c].send_frame(1, json.dumps(st["json"]).encode())
        elif op == "send_text":
            conns[c].send_frame(1, st["text"].encode())
        elif op == "send_big":
            msg = {"op": "publish", "room": st["room"], "ref": st.get("ref"),
                   "payload": {"blob": "x" * st["size"]}}
            conns[c].send_frame(1, json.dumps(msg).encode())
        elif op == "ctrl_ping":
            conns[c].send_frame(9, b"hi")
        elif op == "expect":
            k = conns[c]
            deadline = time.time() + st.get("timeout", 15)
            hit = None
            while True:
                for j, m in enumerate(k.pending):
                    if matches(m, st["match"]):
                        hit = k.pending.pop(j)
                        break
                if hit is not None or k.closed or not k.read_one(deadline):
                    break
            r.update(ok=hit is not None, msg=short(hit),
                     closed=k.closed[0] if k.closed else None)
        elif op == "pending":  # report (and drain) what arrived so far
            k = conns[c]
            r.update(msgs=[short(m) for m in k.pending])
            k.pending = []
        elif op == "expect_close":
            k = conns[c]
            t0 = time.time()
            deadline = t0 + st.get("timeout", 15)
            while not k.closed and k.read_one(deadline):
                pass
            r.update(ok=bool(k.closed), code=k.closed[0] if k.closed else None,
                     reason=k.closed[1] if k.closed else None,
                     errors=",".join(m.get("code", "") for m in k.pending
                                     if isinstance(m, dict) and m.get("kind") == "error"),
                     elapsed=round(time.time() - t0, 1),
                     since_mark=round(time.time() - mark, 1) if mark else None)
        elif op == "expect_ping":
            k = conns[c]
            t0 = time.time()
            deadline = t0 + st.get("timeout", 40)
            start = k.pings
            while k.pings == start and not k.closed and time.time() < deadline:
                k.read_one(min(deadline, time.time() + 1))
            r.update(ok=k.pings > start, elapsed=round(time.time() - t0, 1),
                     closed=k.closed[0] if k.closed else None)
        elif op == "wait_file":
            t0 = time.time()
            while not os.path.exists(st["path"]) and time.time() - t0 < st.get("timeout", 60):
                time.sleep(0.2)
            r.update(ok=os.path.exists(st["path"]))
            if r["ok"]:
                mark = time.time()
        elif op == "touch":
            open(st["path"], "w").close()
        elif op == "sleep":
            time.sleep(st["s"])
        elif op == "close":
            try:
                conns[c].send_frame(8, struct.pack("!H", 1000))
                conns[c].sock.close()
            except OSError:
                pass
    except Exception as e:
        r.update(ok=False, error=repr(e)[:200])
    out[st.get("id", "s%d" % i)] = r
print(json.dumps(out))
PY

# ws_run NAME < steps.json — runs the steps, result JSON in $TMP/ws.NAME.out
ws_run() { python3 "$TMP/ws.py" > "$TMP/ws.$1.out" 2> "$TMP/ws.$1.err"; }
# Background runs: a non-interactive shell gives `cmd &` /dev/null as stdin, so
# the steps are spooled to a file first.
ws_bg() {
  cat > "$TMP/ws.$1.in"
  python3 "$TMP/ws.py" < "$TMP/ws.$1.in" > "$TMP/ws.$1.out" 2> "$TMP/ws.$1.err" &
  eval "WS_PID_$1=$!"
}
ws_join() { local pid; eval "pid=\$WS_PID_$1"; wait "$pid" 2>/dev/null || true; }
wsr() { json "$2" < "$TMP/ws.$1.out" 2>/dev/null || echo "-"; } # NAME PATH

# ================================================== tenant C: keepalives ====
# Started first so the 30 s keepalive period elapses while the rest runs.
new_tenant rt-ka; save_tenant C
mcp_call_r create_collection '{"name":"ka","fields":[{"name":"title","sql_type":"text"}]}'
svc PUT /collections/ka/realtime '{"enabled":true}'
check_eq "keepalive tenant: enabling realtime on a collection answers 200" 200 "$STATUS"
sse_open ka "$T/records/ka/subscribe" "$SERVICE_KEY" 42
export RT_C_SVC="$SERVICE_KEY"
ws_bg ka <<J
[{"id":"open","op":"open","c":"k","url":"$T/realtime","token_env":"RT_C_SVC"},
 {"op":"send","c":"k","json":{"op":"subscribe","room":"idle","ref":"s"}},
 {"id":"sub","op":"expect","c":"k","match":{"kind":"ack","ref":"s"}},
 {"id":"ping","op":"expect_ping","c":"k","timeout":45},
 {"op":"close","c":"k"}]
J

# ======================================================= tenant B: WS rooms ==
new_tenant rt-ws; save_tenant B
export RT_B_SVC="$SERVICE_KEY" RT_B_ANON="$ANON_KEY" RT_BAD="drust_not_a_real_token"
WSU="$T/realtime"
WSD="$DIRECT/t/$TENANT_ID/realtime"

ws_bg basic <<J
[{"id":"caddy","op":"open","c":"s","url":"$WSU","token_env":"RT_B_SVC"},
 {"id":"direct","op":"open","c":"d","url":"$WSD","token_env":"RT_B_SVC"},
 {"op":"close","c":"d"},
 {"id":"qtok","op":"open","c":"a","url":"$WSU","token_env":"RT_B_ANON","query_token":true},
 {"id":"noauth","op":"open","c":"x","url":"$WSU"},
 {"id":"badtok","op":"open","c":"y","url":"$WSU","token_env":"RT_BAD"},
 {"op":"send","c":"a","json":{"op":"subscribe","room":"chat:lobby","ref":"s1"}},
 {"id":"sub","op":"expect","c":"a","match":{"kind":"ack","ref":"s1"}},
 {"op":"send","c":"s","json":{"op":"publish","room":"chat:lobby","payload":{"n":1},"ref":"p1"}},
 {"id":"pub_ack","op":"expect","c":"s","match":{"kind":"ack","ref":"p1"}},
 {"id":"fanout","op":"expect","c":"a","match":{"kind":"message","room":"chat:lobby"}},
 {"op":"send","c":"a","json":{"op":"publish","room":"chat:lobby","payload":{"n":2},"ref":"p2"}},
 {"id":"anon_pub","op":"expect","c":"a","match":{"ref":"p2"}},
 {"op":"send","c":"a","json":{"op":"ping","ref":"pg"}},
 {"id":"pong","op":"expect","c":"a","match":{"ref":"pg"}},
 {"op":"ctrl_ping","c":"a"},
 {"id":"ctrl_pong","op":"expect","c":"a","match":{"__pong__":true}},
 {"op":"send","c":"a","json":{"op":"subscribe","room":"9starts-with-digit","ref":"n1"}},
 {"id":"bad_digit","op":"expect","c":"a","match":{"ref":"n1"}},
 {"op":"send","c":"a","json":{"op":"subscribe","room":"has space","ref":"n2"}},
 {"id":"bad_space","op":"expect","c":"a","match":{"ref":"n2"}},
 {"op":"send","c":"a","json":{"op":"subscribe","room":"_system_x","ref":"n3"}},
 {"id":"protected","op":"expect","c":"a","match":{"ref":"n3"}},
 {"op":"send","c":"a","json":{"op":"subscribe","room":"r$(printf 'a%.0s' $(seq 1 128))","ref":"n4"}},
 {"id":"too_long","op":"expect","c":"a","match":{"ref":"n4"}},
 {"op":"send","c":"s","json":{"op":"publish","room":"_system_x","payload":{},"ref":"n5"}},
 {"id":"pub_protected","op":"expect","c":"s","match":{"ref":"n5"}},
 {"op":"send","c":"a","json":{"op":"frobnicate","ref":"u1"}},
 {"id":"unknown_op","op":"expect","c":"a","match":{"kind":"error"}},
 {"op":"send_text","c":"a","text":"this is not json"},
 {"id":"not_json","op":"expect","c":"a","match":{"kind":"error"}},
 {"op":"send_big","c":"s","room":"chat:lobby","size":60000,"ref":"b1"},
 {"id":"big_ok","op":"expect","c":"s","match":{"ref":"b1"}},
 {"id":"big_ok_fanout","op":"expect","c":"a","match":{"kind":"message","room":"chat:lobby"}},
 {"op":"send","c":"a","json":{"op":"unsubscribe","room":"chat:lobby","ref":"u2"}},
 {"id":"unsub","op":"expect","c":"a","match":{"ref":"u2"}},
 {"op":"send","c":"s","json":{"op":"publish","room":"chat:lobby","payload":{"n":3},"ref":"p3"}},
 {"id":"after_unsub","op":"expect","c":"s","match":{"ref":"p3"}},
 {"op":"send","c":"a","json":{"op":"subscribe","room":"chat:lobby","ref":"s2"}},
 {"id":"resub","op":"expect","c":"a","match":{"ref":"s2"}},
 {"id":"drain","op":"pending","c":"a"},
 {"op":"send_big","c":"s","room":"chat:lobby","size":70000,"ref":"b2"},
 {"id":"big_bad","op":"expect","c":"s","match":{"kind":"error"},"timeout":8},
 {"id":"big_bad_close","op":"expect_close","c":"s","timeout":5},
 {"id":"big_ack","op":"expect","c":"s","match":{"kind":"ack","ref":"b2"},"timeout":2},
 {"op":"touch","path":"$TMP/ws.basic.bigsent"},
 {"op":"wait_file","path":"$TMP/ws.basic.restpub","timeout":30},
 {"id":"sentinel","op":"expect","c":"a","match":{"kind":"message","room":"chat:lobby"}},
 {"op":"close","c":"a"}]
J
# (results are checked after the REST sentinel publish below)
for _ in $(seq 1 80); do [ -f "$TMP/ws.basic.bigsent" ] && break; sleep 0.5; done
svc POST /rooms/chat:lobby '{"sentinel":true}'
check_eq "REST publish by the service key answers 200" 200 "$STATUS"
touch "$TMP/ws.basic.restpub"
ws_join basic
check_eq "WS upgrade through Caddy with a service Authorization header answers 101" 101 "$(wsr basic caddy.status)"
check_eq "WS upgrade through Caddy is really proxied (Server: Caddy on the 101)" true "$(wsr basic caddy.via_caddy)"
check_eq "WS upgrade straight to drust answers 101 too" 101 "$(wsr basic direct.status)"
check_eq "WS upgrade with the bearer in ?token= (browser form) answers 101" 101 "$(wsr basic qtok.status)"
check_eq "WS upgrade without any credential is refused 401" 401 "$(wsr basic noauth.status)"
check_eq "WS upgrade with an unknown token is refused 401" 401 "$(wsr basic badtok.status)"
check_eq "op:subscribe with ref is acked (op=subscribe, room echoed)" "subscribe/chat:lobby" \
  "$(wsr basic sub.msg.op)/$(wsr basic sub.msg.room)"
check_eq "service op:publish is acked with delivered_to=1 (one subscriber)" 1 "$(wsr basic pub_ack.msg.delivered_to)"
check_eq "the anon subscriber receives the published payload" 1 "$(wsr basic fanout.msg.payload.n)"
fan_ts="$(wsr basic fanout.msg.ts)"
check_eq "fan-out message carries a server ts (epoch milliseconds, an integer)" yes \
  "$(python3 -c 'import sys; v=sys.argv[1]; print("yes" if v.isdigit() and int(v) > 10**12 else "no")' "$fan_ts")"
check_eq "anon op:publish is refused WS_PUBLISH_ANON_DENIED while allow_anon_publish is off" \
  WS_PUBLISH_ANON_DENIED "$(wsr basic anon_pub.msg.code)"
check_eq "op:ping is answered with kind=pong echoing ref" pong "$(wsr basic pong.msg.kind)"
check_eq "a WS control Ping is answered with a Pong" true "$(wsr basic ctrl_pong.ok)"
check_eq "room name starting with a digit is ROOM_NAME_INVALID" ROOM_NAME_INVALID "$(wsr basic bad_digit.msg.code)"
check_eq "room name with a space is ROOM_NAME_INVALID" ROOM_NAME_INVALID "$(wsr basic bad_space.msg.code)"
check_eq "room name over 128 chars is ROOM_NAME_INVALID" ROOM_NAME_INVALID "$(wsr basic too_long.msg.code)"
check_eq "subscribing to a _system_ room is PROTECTED_ROOM" PROTECTED_ROOM "$(wsr basic protected.msg.code)"
check_eq "publishing to a _system_ room is PROTECTED_ROOM" PROTECTED_ROOM "$(wsr basic pub_protected.msg.code)"
check_eq "an unknown op gets a typed error frame (MALFORMED_FRAME) and the socket stays usable" \
  MALFORMED_FRAME "$(wsr basic unknown_op.msg.code)"
check_eq "a non-JSON text frame gets MALFORMED_FRAME" MALFORMED_FRAME "$(wsr basic not_json.msg.code)"
check_eq "a 60 KB payload (under the 64 KiB cap) is accepted and delivered" "1/60000" \
  "$(wsr basic big_ok.msg.delivered_to)/$(wsr basic big_ok_fanout.msg.payload.blob_len)"
check_eq "op:unsubscribe is acked" unsubscribe "$(wsr basic unsub.msg.op)"
check_eq "after unsubscribe a publish reaches nobody (delivered_to=0)" 0 "$(wsr basic after_unsub.msg.delivered_to)"
check_eq "re-subscribing the same room is acked" subscribe "$(wsr basic resub.msg.op)"

# The oversized frame: wait for the client to send it, then publish a sentinel
# over REST; the subscriber must see the sentinel and never the 70 KB payload.
# big_ack looks through everything that socket received (the error step pops
# only the error frame), so an ack for b2 that arrived at any point is found.
check_eq "an over-cap WS publish (70 KB > 64 KiB) is never acked" false "$(wsr basic big_ack.ok)"
check_eq "an over-cap WS publish is answered PAYLOAD_TOO_LARGE before the close" PAYLOAD_TOO_LARGE \
  "$(wsr basic big_bad.msg.code)"
check_eq "an over-cap WS publish ends that socket (frame-layer cap)" true "$(wsr basic big_bad_close.ok)"
check_eq "an over-cap WS publish is closed 1009 Message Too Big (not a bare TCP drop)" 1009 \
  "$(wsr basic big_bad_close.code)"
check_eq "the subscriber's next message is the REST sentinel, not the over-cap payload" true \
  "$(wsr basic sentinel.msg.payload.sentinel)"

big="$(python3 -c 'import json; print(json.dumps({"blob": "x" * 70000}))')"
svc POST /rooms/chat:lobby "$big"
check_eq "REST publish over the 64 KiB payload cap answers 413" 413 "$STATUS"
check_eq "REST publish over the cap carries PAYLOAD_TOO_LARGE" PAYLOAD_TOO_LARGE "$(body error_code)"
svc POST /rooms/_system_x '{}'
check_eq "REST publish to a _system_ room answers 403 PROTECTED_ROOM" "403 PROTECTED_ROOM" "$STATUS $(body error_code)"
svc POST /rooms/9bad '{}'
check_eq "REST publish to an invalid room name answers 400 ROOM_NAME_INVALID" "400 ROOM_NAME_INVALID" "$STATUS $(body error_code)"
anon POST /rooms/chat:lobby '{}'
check_eq "REST publish by anon answers 403 PUBLISH_ANON_DENIED while the flag is off" "403 PUBLISH_ANON_DENIED" \
  "$STATUS $(body error_code)"

# --- publish flag: a REAL change of allow_anon_publish evicts live sockets;
# afterwards anon may publish; turning it back off denies again.
ws_bg flag <<J
[{"id":"old","op":"open","c":"o","url":"$WSU","token_env":"RT_B_ANON"},
 {"op":"send","c":"o","json":{"op":"subscribe","room":"flag","ref":"s"}},
 {"id":"old_sub","op":"expect","c":"o","match":{"ref":"s"}},
 {"op":"touch","path":"$TMP/flag.ready"},
 {"id":"wait_on","op":"wait_file","path":"$TMP/flag.on","timeout":60},
 {"op":"send","c":"o","json":{"op":"ping","ref":"after"}},
 {"id":"old_close","op":"expect_close","c":"o","timeout":15},
 {"id":"new","op":"open","c":"n","url":"$WSU","token_env":"RT_B_ANON"},
 {"op":"send","c":"n","json":{"op":"publish","room":"flag","payload":{"by":"anon"},"ref":"p"}},
 {"id":"new_pub","op":"expect","c":"n","match":{"ref":"p"}},
 {"op":"close","c":"n"},
 {"op":"touch","path":"$TMP/flag.done1"},
 {"id":"wait_off","op":"wait_file","path":"$TMP/flag.off","timeout":60},
 {"id":"third","op":"open","c":"t","url":"$WSU","token_env":"RT_B_ANON"},
 {"op":"send","c":"t","json":{"op":"publish","room":"flag","payload":{"by":"anon"},"ref":"p"}},
 {"id":"third_pub","op":"expect","c":"t","match":{"ref":"p"}},
 {"op":"close","c":"t"}]
J
for _ in $(seq 1 60); do [ -f "$TMP/flag.ready" ] && break; sleep 0.5; done
mcp_call_r set_publish_policy '{"allow_anon_publish":true}'
check_eq "set_publish_policy(allow_anon_publish=true) succeeds over MCP" false "$MCP_IS_ERROR"
touch "$TMP/flag.on"
for _ in $(seq 1 60); do [ -f "$TMP/flag.done1" ] && break; sleep 0.5; done
anon POST /rooms/flag '{"by":"anon-rest"}'
check_eq "REST publish by anon answers 200 once allow_anon_publish is on" 200 "$STATUS"
mcp_call_r set_publish_policy '{"allow_anon_publish":false}'
check_eq "set_publish_policy(allow_anon_publish=false) succeeds over MCP" false "$MCP_IS_ERROR"
touch "$TMP/flag.off"
ws_join flag
check_eq "an anon socket opened before the flag flip is closed 1008 at its next frame" 1008 "$(wsr flag old_close.code)"
check_contains "... and is told CONN_EVICTED before the close" CONN_EVICTED "$(wsr flag old_close.errors)"
check_eq "a fresh anon socket may publish while allow_anon_publish is on (ack delivered_to)" ack "$(wsr flag new_pub.msg.kind)"
check_eq "after turning the flag off a fresh anon socket is denied again" WS_PUBLISH_ANON_DENIED "$(wsr flag third_pub.msg.code)"

# --- token reroll: busy socket (sends a frame) and idle socket (sends nothing)
# must both get CONN_EVICTED + 1008; the idle one within one keepalive period.
ws_bg reroll <<J
[{"id":"busy","op":"open","c":"b","url":"$WSU","token_env":"RT_B_SVC"},
 {"id":"idle","op":"open","c":"i","url":"$WSU","token_env":"RT_B_ANON","query_token":true},
 {"op":"send","c":"b","json":{"op":"subscribe","room":"rr","ref":"s"}},
 {"id":"busy_sub","op":"expect","c":"b","match":{"ref":"s"}},
 {"op":"send","c":"i","json":{"op":"subscribe","room":"rr","ref":"s"}},
 {"id":"idle_sub","op":"expect","c":"i","match":{"ref":"s"}},
 {"op":"touch","path":"$TMP/reroll.ready"},
 {"id":"wait","op":"wait_file","path":"$TMP/reroll.done","timeout":60},
 {"op":"send","c":"b","json":{"op":"publish","room":"rr","payload":{"x":1},"ref":"late"}},
 {"id":"busy_close","op":"expect_close","c":"b","timeout":15},
 {"id":"idle_close","op":"expect_close","c":"i","timeout":45}]
J
for _ in $(seq 1 60); do [ -f "$TMP/reroll.ready" ] && break; sleep 0.5; done
B_OLD_SVC="$SERVICE_KEY"
admin POST "/admin/api/tenants/$TENANT_ID/tokens/service/reroll"
check_eq "rerolling tenant B's service key answers 201" 201 "$STATUS"
B_NEW_SVC="$(body token)"
touch "$TMP/reroll.done"
B_SVC="$B_NEW_SVC"
# The busy/idle results are read at the end (the idle wait runs in parallel
# with the SSE section below).

# ===================================================== tenant A: SSE ========
new_tenant rt-sse; save_tenant A
S="$T/records"

mcp_call_r create_collection '{"name":"notes","fields":[{"name":"title","sql_type":"text"},{"name":"tag","sql_type":"text"}]}'
check_eq "create_collection notes over MCP succeeds" false "$MCP_IS_ERROR"

sse_open g1 "$S/notes/subscribe" "$SERVICE_KEY" 15
check_eq "service subscribe on a collection with realtime off (the default) is 403" 403 "$(sse_status g1)"
check_eq "... with REALTIME_DISABLED" REALTIME_DISABLED "$(sse_code g1)"
sse_open g2 "$S/notes/subscribe" "$ANON_KEY" 15
check_eq "anon subscribe with realtime off is 403 REALTIME_DISABLED" "403 REALTIME_DISABLED" "$(sse_status g2) $(sse_code g2)"
sse_open g3 "$S/notes/subscribe" "" 15
check_eq "subscribe without a credential is 401" 401 "$(sse_status g3)"
sse_open g4 "$S/_system_users/subscribe" "$SERVICE_KEY" 15
check_eq "subscribe to _system_users is 404 NOT_FOUND (no existence leak)" "404 NOT_FOUND" "$(sse_status g4) $(sse_code g4)"
sse_open g5 "$S/nosuch/subscribe" "$ANON_KEY" 15
check_eq "subscribe to a missing collection is 404 NOT_FOUND" "404 NOT_FOUND" "$(sse_status g5) $(sse_code g5)"

svc PUT /collections/notes/realtime '{"enabled":true}'
check_eq "PUT /collections/notes/realtime {enabled:true} answers 200" "200 true" "$STATUS $(body realtime_enabled)"
anon PUT /collections/notes/realtime '{"enabled":true}'
check_eq "anon cannot toggle realtime (403 WRITE_DENIED)" "403 WRITE_DENIED" "$STATUS $(body error_code)"

# An older CLAUDE.md named /collections/<c>/subscribe; the route (router, OpenAPI,
# MCP tool text, admin UI, CLAUDE.md) is /records/<c>/subscribe.
# The live contract is what OpenAPI advertises, so that is what is asserted.
svc GET /openapi.json
OA_SUB="$(printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    p = json.load(sys.stdin)["paths"]
except Exception:
    print("unreadable"); sys.exit(0)
print(" ".join(sorted(k.split("/", 3)[3] for k in p if k.endswith("/subscribe"))))
' 2>/dev/null)"
check_eq "OpenAPI advertises the SSE stream at /records/<c>/subscribe (and nowhere else)" \
  "200 records/notes/subscribe" "$STATUS $OA_SUB"
sse_open doc "$T/collections/notes/subscribe" "$SERVICE_KEY" 10
note "the non-route /collections/<c>/subscribe answers $(sse_status doc) (not a stream)"
sse_kill doc

mcp_call_r set_anon_caps '{"collection":"notes","caps":[]}'
sse_open g6 "$S/notes/subscribe" "$ANON_KEY" 15
check_eq "anon subscribe without anon_caps[select] is 403 REALTIME_ANON_DENIED" "403 REALTIME_ANON_DENIED" \
  "$(sse_status g6) $(sse_code g6)"
mcp_call_r set_anon_caps '{"collection":"notes","caps":["select"]}'
sse_open g7 "$S/notes/subscribe?token=$ANON_KEY" "" 20
check_eq "anon subscribe with realtime_enabled AND anon_caps[select] (no policy) is 200 via ?token=" 200 "$(sse_status g7)"
check_contains "... and is a text/event-stream" "text/event-stream" "$(tr -d '\r' < "$TMP/sse.g7.h")"
sse_kill g7

# owner-scoped collection: anon may never subscribe.
mcp_call_r create_collection '{"name":"owned","fields":[{"name":"owner","sql_type":"text","foreign_key":"_system_users"},{"name":"body","sql_type":"text"}]}'
mcp_call_r set_owner_field '{"collection":"owned","field":"owner","read_scope":"all"}'
check_eq "set_owner_field(owned.owner, read_scope=all) succeeds" false "$MCP_IS_ERROR"
svc PUT /collections/owned/realtime '{"enabled":true}'
sse_open g8 "$S/owned/subscribe" "$ANON_KEY" 15
check_eq "anon subscribe to an owner-scoped collection (even read_scope=all) is 403 ANON_FORBIDDEN_OWNER_SCOPED" \
  "403 ANON_FORBIDDEN_OWNER_SCOPED" "$(sse_status g8) $(sse_code g8)"

# user token: always denied on SSE.
U_EMAIL="rt-user-$$@example.com"
U_PASS="$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
mcp_call_r create_user "{\"email\":\"$U_EMAIL\",\"password\":\"$U_PASS\",\"verified\":true}"
if [ "$MCP_IS_ERROR" = "false" ]; then
  req POST "$T/auth/login" -H 'Content-Type: application/json' \
    --data "{\"email\":\"$U_EMAIL\",\"password\":\"$U_PASS\"}"
  USER_TOKEN="$(body token 2>/dev/null || true)"
  if [ "$STATUS" = "200" ] && [ -n "$USER_TOKEN" ]; then
    sse_open g9 "$S/notes/subscribe" "$USER_TOKEN" 15
    check_eq "a logged-in user token is refused SSE: 403 SSE_USER_DENIED" "403 SSE_USER_DENIED" \
      "$(sse_status g9) $(sse_code g9)"
  else
    note "user login answered $STATUS — SSE_USER_DENIED leg skipped (per-IP login limit is shared)"
  fi
else
  bad "create_user over MCP succeeds (needed for the SSE_USER_DENIED leg)" "$(printf '%s' "$MCP_TEXT" | head -c 200)"
fi

# --- events for REST writes (service stream through Caddy, admin-PAT stream).
sse_open ev "$S/notes/subscribe" "$SERVICE_KEY" 60
check_eq "service subscribe with realtime on is 200" 200 "$(sse_status ev)"
sse_open pat "$S/notes/subscribe" "$ADMIN_PAT" 60
check_eq "an admin PAT may subscribe (resolves to the service identity)" 200 "$(sse_status pat)"
svc POST /records/notes '{"data":{"title":"first","tag":"pub"}}'
check_eq "REST insert answers 201" 201 "$STATUS"
R1="$(body record.id)"
sse_wait ev '"title":"first"' 15
check_contains "insert over REST produces 'event: created' with the row" \
  "$(printf 'event: created\ndata: {"record":{"id":%s,"title":"first"' "$R1")" "$(sse_body ev)"
svc PATCH "/records/notes/$R1" '{"data":{"title":"second"}}'
check_eq "REST update answers 200" 200 "$STATUS"
sse_wait ev '"title":"second"' 15
check_contains "update over REST produces 'event: updated' with the new value" \
  "$(printf 'event: updated\ndata: {"record":{"id":%s,"title":"second"' "$R1")" "$(sse_body ev)"
svc DELETE "/records/notes/$R1"
check_eq "REST delete answers 204" 204 "$STATUS"
sse_wait ev "$(printf 'event: deleted\ndata: {"id":%s}' "$R1")" 15
check_contains "delete over REST produces 'event: deleted' with only the id" \
  "$(printf 'event: deleted\ndata: {"id":%s}' "$R1")" "$(sse_body ev)"
sse_wait pat "event: deleted" 10
check_contains "the admin-PAT stream receives the same events" "event: deleted" "$(sse_body pat)"
sse_kill pat

# --- select policy: attach evicts in-flight anon streams; then hidden rows and
# every Deleted event never reach anon, while service still sees them.
sse_open pre "$S/notes/subscribe" "$ANON_KEY" 60
check_eq "anon stream before the policy is attached opens (200)" 200 "$(sse_status pre)"
svc PUT /collections/notes/policies '{"select":{"using":{"tag":"pub"}}}'
check_eq "PUT select policy {tag: pub} answers 200" 200 "$STATUS"
check_eq "attaching a select policy ends the in-flight anon stream (evict_collection)" 0 "$(sse_end pre 15)"

sse_open pol "$S/notes/subscribe" "$ANON_KEY" 60
check_eq "anon subscribe with a select policy active is 200" 200 "$(sse_status pol)"
sse_kill ev
sse_open ev2 "$S/notes/subscribe" "$SERVICE_KEY" 60
sse_status ev2 >/dev/null
svc POST /records/notes '{"data":{"title":"visible-1","tag":"pub"}}';  P1="$(body record.id)"
svc POST /records/notes '{"data":{"title":"hidden-1","tag":"priv"}}';  H1="$(body record.id)"
svc PATCH "/records/notes/$H1" '{"data":{"title":"hidden-2"}}'
svc DELETE "/records/notes/$P1"
svc DELETE "/records/notes/$H1"
svc POST /records/notes '{"data":{"title":"visible-sentinel","tag":"pub"}}'
sse_wait pol '"title":"visible-sentinel"' 15
sse_wait ev2 '"title":"visible-sentinel"' 15
check_contains "anon (policy) receives the created event for a policy-visible row" '"title":"visible-1"' "$(sse_body pol)"
check_contains "anon (policy) receives the later visible sentinel (stream still delivering)" '"title":"visible-sentinel"' "$(sse_body pol)"
check_not_contains "anon (policy) never receives a policy-hidden row (insert or update)" '"tag":"priv"' "$(sse_body pol)"
check_not_contains "anon (policy) never receives a Deleted event, not even for a visible row (invariant 5)" \
  'event: deleted' "$(sse_body pol)"
check_contains "control: the service stream did see the hidden row" '"title":"hidden-2"' "$(sse_body ev2)"
check_contains "control: the service stream did see both deletes" \
  "$(printf 'event: deleted\ndata: {"id":%s}' "$H1")" "$(sse_body ev2)"

# --- revoking anon select ends the in-flight anon stream.
mcp_call_r set_anon_caps '{"collection":"notes","caps":[]}'
check_eq "set_anon_caps(notes, []) succeeds" false "$MCP_IS_ERROR"
check_eq "revoking anon_caps[select] ends the in-flight anon stream" 0 "$(sse_end pol 15)"
sse_open g10 "$S/notes/subscribe" "$ANON_KEY" 15
check_eq "... and a reconnect is refused 403 REALTIME_ANON_DENIED" "403 REALTIME_ANON_DENIED" "$(sse_status g10) $(sse_code g10)"
mcp_call_r set_anon_caps '{"collection":"notes","caps":["select"]}'

# --- clearing the select policy also evicts.
sse_open clr "$S/notes/subscribe" "$ANON_KEY" 60
check_eq "anon stream with the policy (caps restored) opens" 200 "$(sse_status clr)"
svc DELETE /collections/notes/policies/select
check_eq "DELETE select policy answers 200 {ok:true}" "200 true" "$STATUS $(body ok)"
check_eq "clearing the select policy ends the in-flight anon stream" 0 "$(sse_end clr 15)"

# --- evict_collection drops the whole channel, so the service stream ev2 was
# already ended by the caps revoke above; open a fresh one.
check_eq "evict_collection ends every stream on the collection, service included" 0 "$(sse_end ev2 5)"
sse_open ev3 "$S/notes/subscribe" "$SERVICE_KEY" 60
check_eq "a fresh service stream opens (200)" 200 "$(sse_status ev3)"
check_eq "... and is still open before realtime is disabled" open "$(sse_end ev3 1)"
svc PUT /collections/notes/realtime '{"enabled":false}'
check_eq "PUT realtime {enabled:false} answers 200" 200 "$STATUS"
check_eq "disabling realtime ends the in-flight service stream" 0 "$(sse_end ev3 15)"
sse_open g11 "$S/notes/subscribe" "$SERVICE_KEY" 15
check_eq "... and a reconnect is refused 403 REALTIME_DISABLED" "403 REALTIME_DISABLED" "$(sse_status g11) $(sse_code g11)"
svc PUT /collections/notes/realtime '{"enabled":true}'

# --- tenant-key reroll ends streams opened with the old key.
sse_open rr "$S/notes/subscribe" "$ANON_KEY" 60
check_eq "anon stream opened with the current anon key is 200" 200 "$(sse_status rr)"
A_OLD_ANON="$ANON_KEY"
admin POST "/admin/api/tenants/$TENANT_ID/tokens/anon/reroll"
check_eq "rerolling tenant A's anon key answers 201" 201 "$STATUS"
A_ANON="$(body token)"; ANON_KEY="$A_ANON"
check_eq "the anon reroll ends the stream opened with the old anon key" 0 "$(sse_end rr 15)"
sse_open g12 "$S/notes/subscribe" "$A_OLD_ANON" 15
check_eq "the old anon key can no longer subscribe (401)" 401 "$(sse_status g12)"
sse_open g13 "$S/notes/subscribe" "$ANON_KEY" 20
check_eq "the new anon key subscribes (200)" 200 "$(sse_status g13)"
sse_kill g13

# --- drop_collection (E4): warnings for an anon-callable dependent RPC, dry_run
# closes nothing, the real drop ends live streams, a later subscribe is 404.
mcp_call_r create_rpc '{"name":"count_notes","sql":"SELECT count(*) AS n FROM notes","params":[],"anon_callable":true}'
check_eq "create_rpc(count_notes, anon_callable) over notes succeeds" false "$MCP_IS_ERROR"
sse_open dsv "$S/notes/subscribe" "$SERVICE_KEY" 60
sse_open dan "$S/notes/subscribe" "$ANON_KEY" 60
check_eq "service + anon streams on notes open before the drop" "200 200" "$(sse_status dsv) $(sse_status dan)"
mcp_call_r drop_collection '{"collection":"notes","dry_run":true}'
check_eq "drop_collection dry_run succeeds" false "$MCP_IS_ERROR"
check_eq "drop_collection dry_run is a preview (would_drop=true) and returns no warnings" "true -" \
  "$(printf '%s' "$MCP_TEXT" | json would_drop 2>/dev/null || echo -) $(printf '%s' "$MCP_TEXT" | json warnings 2>/dev/null || echo -)"
svc POST /records/notes '{"data":{"title":"after-dry-run","tag":"pub"}}'
sse_wait dsv '"title":"after-dry-run"' 15
check_contains "dry_run closes nothing: the service stream still receives events" '"title":"after-dry-run"' "$(sse_body dsv)"
mcp_call_r drop_collection '{"collection":"notes"}'
check_eq "drop_collection(notes) succeeds" "false true notes" \
  "$MCP_IS_ERROR $(printf '%s' "$MCP_TEXT" | json ok) $(printf '%s' "$MCP_TEXT" | json dropped_collection)"
check_eq "drop_collection warns ANON_RPC_DEPENDS_ON_COLLECTION for the anon-callable RPC" \
  "ANON_RPC_DEPENDS_ON_COLLECTION count_notes" \
  "$(printf '%s' "$MCP_TEXT" | json warnings.0.code) $(printf '%s' "$MCP_TEXT" | json warnings.0.rpc)"
check_eq "drop_collection ends the in-flight service stream (E4)" 0 "$(sse_end dsv 15)"
check_eq "drop_collection ends the in-flight anon stream (E4)" 0 "$(sse_end dan 15)"
sse_open g14 "$S/notes/subscribe" "$SERVICE_KEY" 15
check_eq "subscribe to the dropped collection is 404 NOT_FOUND" "404 NOT_FOUND" "$(sse_status g14) $(sse_code g14)"
sse_open own "$S/owned/subscribe" "$SERVICE_KEY" 60
check_eq "service stream on the owner-scoped collection opens (200) before its drop" 200 "$(sse_status own)"
mcp_call_r drop_collection '{"collection":"owned"}'
check_eq "dropping a collection no anon RPC depends on carries no warnings key" "false -" \
  "$MCP_IS_ERROR $(printf '%s' "$MCP_TEXT" | json warnings 2>/dev/null || echo -)"
check_eq "... and still ends that collection's stream" 0 "$(sse_end own 15)"

note "E2' (admin-PAT SSE ends when that admin is revoked) not exercised: POST /admin/team mints the"
note "invitee's PAT but never returns it, the invitee is OAuth-only (no password login), and PAT"
note "reroll / CLI device approval mint only for the CALLING admin — so no API yields a second"
note "admin's PAT. Using the shared admin would revoke every agent's PAT streams."

# ================================================ results of background work ==
ws_join reroll
check_eq "reroll: the service socket opened before the reroll was subscribed" subscribe "$(wsr reroll busy_sub.msg.op)"
check_eq "reroll: a busy socket is closed 1008 at its next frame" 1008 "$(wsr reroll busy_close.code)"
check_contains "reroll: ... after a CONN_EVICTED error frame" CONN_EVICTED "$(wsr reroll busy_close.errors)"
check_eq "reroll: an idle socket (no frames sent) is closed 1008 too" 1008 "$(wsr reroll idle_close.code)"
check_contains "reroll: ... with CONN_EVICTED" CONN_EVICTED "$(wsr reroll idle_close.errors)"
# since_mark is measured from the moment the client saw the reroll trigger file
# (touched right after the reroll answered), not from the end of the busy close.
idle_s="$(wsr reroll idle_close.since_mark)"
check_eq "reroll: the idle socket closed within one keepalive period (<= 33 s, default 30 s)" yes \
  "$(python3 -c "import sys; print('yes' if float(sys.argv[1]) <= 33 else 'no')" "$idle_s" 2>/dev/null || echo no)"
note "idle socket closed ${idle_s}s after the reroll"
use_tenant B
export RT_B_OLD="$B_OLD_SVC" RT_B_NEW="$B_NEW_SVC"
ws_run after <<J
[{"id":"old","op":"open","c":"o","url":"$WSU","token_env":"RT_B_OLD"},
 {"id":"new","op":"open","c":"n","url":"$WSU","token_env":"RT_B_NEW"},
 {"op":"send","c":"n","json":{"op":"publish","room":"rr","payload":{},"ref":"p"}},
 {"id":"new_pub","op":"expect","c":"n","match":{"ref":"p"}},
 {"op":"close","c":"n"}]
J
check_eq "reroll: the old service key can no longer open a WS (401)" 401 "$(wsr after old.status)"
check_eq "reroll: the new service key opens a WS and may publish" "101 ack" \
  "$(wsr after new.status) $(wsr after new_pub.msg.kind)"

ws_join ka
check_eq "keepalive tenant: the idle WS subscribed" subscribe "$(wsr ka sub.msg.op)"
check_eq "WS keepalive: the server sends a Ping on an idle socket within ~30 s" true "$(wsr ka ping.ok)"
note "first server Ping after $(wsr ka ping.elapsed)s"
check_eq "SSE keepalive: the stream stays open past 30 s (curl hit its own 42 s max-time)" 28 "$(sse_end ka 50)"
check_eq "SSE keepalive: at least one comment line (':') arrived on an idle stream" yes \
  "$(grep -q '^:' "$TMP/sse.ka.b" && echo yes || echo no)"

finish

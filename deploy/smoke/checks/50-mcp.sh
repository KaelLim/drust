#!/usr/bin/env bash
# The account-level MCP endpoint (/mcp) through Caddy, with the run's OAuth
# access token: the 401 challenges for a missing or non-OAuth bearer and both
# metadata documents; the stateless transport (initialize, protocolVersion
# negotiation, no session id, 405, 406, 415), the Origin gate, and the Host
# gate direct vs through Caddy; the tenant argument (list_tenants,
# TENANT_REQUIRED, TENANT_NOT_FOUND, INVALID_ARGUMENTS, a second tenant on the
# same token); tools/list against src/mcp/handler.rs annotation_tests::TABLE
# plus the two account-only tools; the isError sentinels and input-validation
# errors; resources (templates, reads, the URI parser's refusals,
# DRUST_MCP_RESOURCE_MAX_BYTES truncation); prompts; the redacted whoami; a
# three-chunk upload with a create_upload_url ticket; and that a tenant
# service-key reroll leaves the token's access to that tenant intact; and one
# meta-writing tool (set_self_register) through the account endpoint, checked
# by its effect on /auth/register.
#
# A preflight before any token is minted stops the script with a named failure
# when DRUST_MCP is not on. A stack that up.sh started with SMOKE_DRUST_MCP=off
# (recorded in .env) is checked for the off state instead: /mcp answers 404
# MCP_DISABLED, the retired /t/<id>/mcp 410 with the off message and no URL,
# and the OAuth metadata, protected-resource metadata and token endpoint 404.
#
# Uses 2 tenants (A: main, B: second tenant + reroll). Everything else it
# creates (collections, RPCs, object-store objects) lives inside tenant A or is
# deleted explicitly; both tenants are deleted by lib.sh on exit.
. "$(dirname "$0")/lib.sh"

# The off state. Expected answers from src/mgmt/mcp_oauth/route_layer.rs
# (DISABLED, MOVED_DISABLED) and account_routes.rs (disabled: /mcp only, no
# metadata route); the OAuth routes are not mounted at all.
if [ "$MCP_OFF" = 1 ]; then
  note "the stack runs with DRUST_MCP=off (SMOKE_DRUST_MCP=off in .env): checking the off state"
  check_mcp_disabled
  moved_off="MOVED: MCP is now one account-level OAuth endpoint, not enabled on this server yet; ask the operator"
  for tenant in anything no-such-tenant; do
    for method in POST GET; do
      if [ "$method" = POST ]; then
        req POST "$BASE/t/$tenant/mcp" -H 'Content-Type: application/json' \
          --data '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
      else
        req GET "$BASE/t/$tenant/mcp"
      fi
      check_eq "$method /t/$tenant/mcp answers 410 MCP_ENDPOINT_MOVED" "410 MCP_ENDPOINT_MOVED" \
        "$STATUS $(body error_code)"
      check_eq "... with the message for a server whose MCP is off" "$moved_off" "$(body message)"
      check_eq "... and Cache-Control: no-store" no-store "$(header cache-control)"
      check_not_contains "... naming no URL" "://" "$BODY"
    done
  done
  for path in /.well-known/oauth-authorization-server /.well-known/oauth-protected-resource/mcp; do
    req GET "$BASE$path"
    check_eq "GET $path answers 404 (not mounted)" 404 "$STATUS"
  done
  req POST "$BASE/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' \
    --data 'grant_type=authorization_code'
  check_eq "POST /oauth/token answers 404 (not mounted)" 404 "$STATUS"
  finish
  exit $?
fi

# Preflight, before any token is minted: the account endpoint answers a request
# with no bearer 401 MCP_OAUTH_REQUIRED. With DRUST_MCP not on it answers 404,
# with no error code when /mcp is not mounted or with MCP_DISABLED when it is.
req POST "$BASE/mcp" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
pre="$STATUS $(body error_code || true)"
if [ "$pre" = "401 MCP_OAUTH_REQUIRED" ]; then
  ok "the account endpoint is mounted (DRUST_MCP=on in docker-compose.smoke.yml)"
else
  case "$pre" in
    "404 "|"404 MCP_DISABLED") why="DRUST_MCP is not on (for a round with it off on purpose, start the stack with SMOKE_DRUST_MCP=off deploy/smoke/up.sh)" ;;
    *) why="unexpected answer" ;;
  esac
  bad "the account endpoint is mounted (DRUST_MCP=on in docker-compose.smoke.yml)" "got [$pre]: $why"
  finish
  exit 1
fi

want_ver="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)"

new_tenant mcp-a
A_ID="$TENANT_ID"; A_SVC="$SERVICE_KEY"; A_ANON="$ANON_KEY"
new_tenant mcp-b
B_ID="$TENANT_ID"; B_SVC="$SERVICE_KEY"
# lib.sh helpers (svc/anon/mcp_call) act on the LAST tenant; point them at A.
TENANT_ID="$A_ID"; SERVICE_KEY="$A_SVC"; ANON_KEY="$A_ANON"; T="$BASE/t/$A_ID"

mcp_token || { bad "an OAuth access token for the account endpoint" "see mcp token unavailable above"; finish; exit 1; }

cat > "$TMP/mcpx.py" <<'PY'
import http.client, json, os, re, secrets, sys, time, traceback, urllib.parse

E = os.environ
BASE, DIRECT = E["MCPX_BASE"], E["MCPX_DIRECT"]
A, ASVC, AANON = E["MCPX_A_ID"], E["MCPX_A_SVC"], E["MCPX_A_ANON"]
B, BSVC = E["MCPX_B_ID"], E["MCPX_B_SVC"]
PAT, REPO, WANT_VER = E["MCPX_PAT"], E["MCPX_REPO"], E["MCPX_WANT_VER"]
TOKEN = E["MCPX_TOKEN"]
PUBLIC_URL = E.get("MCPX_PUBLIC_URL", "")
SECRETS = [TOKEN, ASVC, AANON, BSVC, PAT]

MCP_MIN_INTERVAL_SECS = 0.2
TICKET_CHUNKS = 3
TICKET_CHUNK_BYTES = 65536
TICKET_FILE_BYTES = TICKET_CHUNKS * TICKET_CHUNK_BYTES - 1000
TICKET_REQ_BUDGET = 60
# Request budget: the account endpoint allows 600 requests per 60 s per grant
# (rs_grant), and every check script shares one grant, so each request here
# waits at least MCP_MIN_INTERVAL_SECS: at most 300 a minute. Never probe the
# limiter with a random token: an unknown token is always 401, never 429.
# An upload ticket is also charged per ticket under the tenant-key budget
# (60 per 10 s); one ticket here sends POST + TICKET_CHUNKS PATCHes + HEAD +
# one reuse POST.
assert TICKET_CHUNKS + 3 <= TICKET_REQ_BUDGET // 4

# Any credential drust mints with one of these prefixes, wherever it appears.
_DRUST_TOKEN_RE = re.compile(r"drust_(?:mcpat|mcprt|upl)_[A-Za-z0-9_-]+")

def red(s):
    """Mask every credential, then flatten and cut: a cut made first can leave
    part of a credential that the masks no longer recognise."""
    s = str(s)
    for x in SECRETS:
        if x:
            s = s.replace(x, "<redacted>")
    s = _DRUST_TOKEN_RE.sub("<redacted>", s)
    s = re.sub(r"([?&]t=)[^&\s\"']+", r"\1<redacted>", s)
    return s.replace("\t", " ").replace("\r", " ").replace("\n", " ")[:500]

def clip(s, n):
    """At most n characters of s, masked before the cut."""
    return red(s)[:n]

def emit(kind, name, detail=""):
    sys.stdout.write("%s\t%s\t%s\n" % (kind, name.replace("\t", " "), red(detail)))
    sys.stdout.flush()

def ok(n): emit("PASS", n)
def bad(n, d=""): emit("FAIL", n, d)
def note(s): emit("NOTE", s)
def check(n, cond, d=""):
    ok(n) if cond else bad(n, d)
def eq(n, want, got):
    check(n, want == got, "expected [%s], got [%s]" % (want, got))

class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

# drust rate-limits each bearer to DRUST_RATE_LIMIT_PER_TOKEN (60) requests per
# DRUST_RATE_LIMIT_WINDOW_SECS (10 s). Pace client-side below that, and if a 429
# still arrives (another client on the same key, clock skew) wait out the
# advertised retry-after a bounded number of times.
_SENT = {}
PACE_N, PACE_WIN = 45, 10.5

def _pace(key):
    if not key:
        return
    q = [t for t in _SENT.get(key, []) if time.time() - t < PACE_WIN]
    if len(q) >= PACE_N:
        time.sleep(max(0.0, PACE_WIN - (time.time() - q[0])) + 0.05)
        q = [t for t in q if time.time() - t < PACE_WIN]
    q.append(time.time())
    _SENT[key] = q

_LAST_MCP = [0.0]

def _pace_mcp():
    wait = MCP_MIN_INTERVAL_SECS - (time.monotonic() - _LAST_MCP[0])
    if wait > 0:
        time.sleep(wait)
    _LAST_MCP[0] = time.monotonic()

def _hx1(method, base, path, headers, data, timeout):
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read().decode("utf-8", "replace")
        return Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, raw)
    except (OSError, http.client.HTTPException) as e:
        return Resp(0, {}, "transport error: %s" % e)
    finally:
        conn.close()

# Requests to the account endpoint and upload-ticket requests pass retry_429=False (mx, tx): their budget is per grant or per ticket and the pacing keeps far below it, so a 429 there is a real failure, not something to wait out.
def hx(method, base, path, headers=None, body=None, timeout=90, retry_429=True):
    headers = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, (bytes, str)) else json.dumps(body)
        if isinstance(data, str):
            data = data.encode()
    key = headers.get("Authorization")
    for _ in range(4):
        _pace(key)
        r = _hx1(method, base, path, headers, data, timeout)
        if r.status != 429 or not retry_429 or "RATE_LIMITED" not in r.body:
            return r
        mm = re.search(r"retry after (\d+)s", r.body)
        time.sleep(min(12, int(mm.group(1)) if mm else 5) + 0.5)
    return r

MCP_PATH = "/mcp"

def mx(method, headers=None, body=None, base=BASE):
    """The one way to reach the account endpoint: paced, never retried on 429."""
    _pace_mcp()
    return hx(method, base, MCP_PATH, headers, body, retry_429=False)

def tx(method, url, headers, body=None):
    """The one way to send an upload-ticket request; url is a full BASE URL."""
    path = urllib.parse.urlsplit(url).path
    return hx(method, BASE, path, headers, body, retry_429=False)

def msgs(r):
    ct = r.headers.get("content-type", "")
    out = []
    if "text/event-stream" in ct:
        for line in r.body.splitlines():
            if line.startswith("data:"):
                d = line[5:].strip()
                if d:
                    try:
                        out.append(json.loads(d))
                    except ValueError:
                        pass
    elif r.body.strip():
        try:
            v = json.loads(r.body)
            out = v if isinstance(v, list) else [v]
        except ValueError:
            pass
    return out

def pick(r, want_id):
    for m in msgs(r):
        if isinstance(m, dict) and m.get("id") == want_id:
            return m
    return None

def jbody(r):
    try:
        return json.loads(r.body)
    except ValueError:
        return {}

ACCEPT = "application/json, text/event-stream"

def init_msg(proto):
    return {"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": proto, "capabilities": {},
                       "clientInfo": {"name": "drust-smoke-mcp", "version": "1"}}}

class Acct:
    """A stateless client of the account endpoint: every call is one POST."""

    def __init__(self, base: str, tenant: str, token: str):
        self.base, self.tenant, self.token, self.n = base, tenant, token, 1

    def hdr(self, extra=None):
        h = {"Content-Type": "application/json", "Accept": ACCEPT,
             "Authorization": "Bearer " + self.token}
        h.update(extra or {})
        return h

    def rpc(self, method, params=None, headers=None):
        i = self.n
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": i, "method": method}
        if params is not None:
            msg["params"] = params
        r = mx("POST", self.hdr(headers), msg, base=self.base)
        return r, pick(r, i)

    def tool(self, name, args):
        args = dict(args or {})
        if "tenant" not in args:
            args = dict([("tenant", self.tenant)] + list(args.items()))
        elif args["tenant"] is None:
            del args["tenant"]
        return self.rpc("tools/call", {"name": name, "arguments": args})

    def notify(self, method):
        return mx("POST", self.hdr(), {"jsonrpc": "2.0", "method": method}, base=self.base)

def tool_text(m):
    try:
        return m["result"]["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return ""

def tool_json(m):
    try:
        return json.loads(tool_text(m))
    except ValueError:
        return None

def is_error(m):
    return bool(m and "result" in m and m["result"].get("isError") is True)

def rpc_err(m):
    return m.get("error") if isinstance(m, dict) else None

def short(m):
    if m is None:
        return "no JSON-RPC message"
    return clip(json.dumps(m), 400)

def tenant_endpoint_checks():
    # The per-tenant /t/<id>/mcp endpoint's answer after its retirement is checked here.
    for tenant in ("anything", "no-such-tenant"):
        for method in ("POST", "GET"):
            r = hx(method, BASE, "/t/%s/mcp" % tenant, retry_429=False,
                   body='{"jsonrpc":"2.0","id":1,"method":"initialize"}' if method == "POST" else None)
            name = "%s /t/%s/mcp" % (method, tenant)
            eq(name + " answers 410", 410, r.status)
            check(name + " body starts with MOVED", r.body.startswith('{"message":"MOVED'), clip(r.body, 120))
            check(name + " carries MCP_ENDPOINT_MOVED", '"error_code":"MCP_ENDPOINT_MOVED"' in r.body)
            eq(name + " is no-store", "no-store", r.headers.get("cache-control", "").lower())

# ----------------------------------------------------------------- source spec
def load_spec():
    src = open(os.path.join(REPO, "src/mcp/handler.rs"), encoding="utf-8").read()
    tool_attr = src.count("#[tool" + "(")
    block = src.split("const TABLE: &[(&str, Shape)] = &[", 1)[1].split("\n    ];", 1)[0]
    table = dict(re.findall(r'\("([a-z_]+)",\s*Shape::(\w+)\)', block))
    return tool_attr, table

HINTS = {  # (readOnly, destructive, idempotent, openWorld); None = absent on the wire
    "Read": (True, None, None, False),
    "Add": (False, False, False, False),
    "Destroy": (False, True, False, False),
    "Replace": (False, True, True, False),
    "Toggle": (False, False, True, False),
    "Open": (False, True, False, True),
}

H5 = '{"message":"OAuth required: in Claude Code run /mcp, then Authenticate","error_code":"MCP_OAUTH_REQUIRED"}'
H6 = ('{"message":"OAuth only: remove Authorization header from this server\'s config, then /mcp -> Authenticate",'
      '"error_code":"MCP_OAUTH_REQUIRED"}')

def main():
    tool_attr, table = load_spec()
    prm_url = PUBLIC_URL + "/.well-known/oauth-protected-resource/mcp"
    mcp_url = PUBLIC_URL + MCP_PATH

    # ============================================================ 1. auth and discovery
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    plain = {"Content-Type": "application/json", "Accept": ACCEPT}
    r = mx("POST", plain, body)
    eq("no bearer answers 401 MCP_OAUTH_REQUIRED with the sign-in message", (401, H5), (r.status, r.body))
    eq("... and a challenge naming this server's protected-resource metadata",
       'Bearer resource_metadata="%s", scope="mcp"' % prm_url, r.headers.get("www-authenticate"))
    for name, cred in (("a tenant service key is not an OAuth token: 401 invalid_token", ASVC),
                       ("an admin PAT is not an OAuth token: 401 invalid_token", PAT)):
        r = mx("POST", dict(plain, Authorization="Bearer " + cred), body)
        check(name, r.status == 401 and r.body == H6 and 'error="invalid_token"' in r.headers.get("www-authenticate", ""),
              "%s %s / %s" % (r.status, clip(r.body, 160), r.headers.get("www-authenticate", "")))
    r = mx("POST", dict(plain, Authorization="Bearer " + "drust_mcpat_" + secrets.token_urlsafe(32)), body)
    eq("an unknown access-shaped token answers 401", 401, r.status)
    r = hx("GET", BASE, "/.well-known/oauth-protected-resource/mcp")
    j = jbody(r)
    check("protected-resource metadata names this resource and issuer",
          r.status == 200 and j.get("resource") == mcp_url and j.get("authorization_servers") == [PUBLIC_URL],
          "%s %s" % (r.status, clip(r.body, 200)))
    r = hx("GET", BASE, "/.well-known/oauth-authorization-server")
    j = jbody(r)
    check("authorization-server metadata issuer and token endpoint match",
          r.status == 200 and j.get("issuer") == PUBLIC_URL and j.get("token_endpoint") == PUBLIC_URL + "/oauth/token",
          "%s %s" % (r.status, clip(r.body, 200)))

    # ============================================================ 2. transport (valid token)
    S = Acct(BASE, A, TOKEN)
    r, m = S.rpc("initialize", init_msg("2025-06-18")["params"])
    check("initialize answers 200 as an SSE stream",
          r.status == 200 and "text/event-stream" in r.headers.get("content-type", ""),
          "%s %s" % (r.status, r.headers.get("content-type", "")))
    if not (m and "result" in m):
        bad("cannot continue without an initialize result", "%s %s" % (r.status, clip(r.body, 300)))
        return
    res = m["result"]
    check("initialize issues no Mcp-Session-Id (stateless endpoint)", "mcp-session-id" not in r.headers)
    eq("protocolVersion echoes the requested 2025-06-18", "2025-06-18", res.get("protocolVersion"))
    eq("serverInfo is drust at the Cargo.toml version", ("drust", WANT_VER),
       (res.get("serverInfo", {}).get("name"), res.get("serverInfo", {}).get("version")))
    caps = res.get("capabilities", {})
    check("capabilities declare tools, resources and prompts without listChanged or subscribe",
          all(k in caps for k in ("tools", "resources", "prompts"))
          and not caps.get("resources", {}).get("listChanged") and not caps.get("resources", {}).get("subscribe")
          and not caps.get("prompts", {}).get("listChanged"), json.dumps(caps))
    ins = res.get("instructions") or ""
    check("instructions fit Claude Code's 4096-character cap (%d chars)" % len(ins), 0 < len(ins) <= 4096,
          "%d chars" % len(ins))
    check("instructions lead with the dry_run rule (only delete_record/drop_collection/drop_index)",
          "Only delete_record, drop_collection and drop_index accept `dry_run: true`" in ins[:1200], clip(ins, 300))
    check("instructions carry no absolute URL", not re.search(r"https?://", ins),
          (re.search(r"https?://\S+", ins) or [""])[0])
    check("instructions name list_tenants and create_upload_url",
          "list_tenants" in ins and "create_upload_url" in ins)
    check("instructions name no tenant", A not in ins)
    r = S.notify("notifications/initialized")
    eq("notifications/initialized is accepted with HTTP 202", 202, r.status)

    for proto, want in (("2025-03-26", "2025-03-26"), ("2024-11-05", "2024-11-05"), ("2025-11-25", "2025-11-25")):
        _, m2 = S.rpc("initialize", init_msg(proto)["params"])
        eq("protocolVersion negotiation echoes known version %s" % proto, want,
           (m2 or {}).get("result", {}).get("protocolVersion"))
    _, m2 = S.rpc("initialize", init_msg("1999-01-01")["params"])
    eq("an unknown requested protocolVersion falls back to the server default 2025-11-25", "2025-11-25",
       (m2 or {}).get("result", {}).get("protocolVersion"))
    r, m2 = S.rpc("initialize", init_msg("2025-06-18")["params"], headers={"MCP-Protocol-Version": "2025-03-26"})
    eq("initialize whose MCP-Protocol-Version header contradicts params is refused with 400", 400, r.status)
    eq("... as a JSON-RPC Invalid Request (-32600)", -32600, (rpc_err(m2) or {}).get("code"))

    auth = {"Authorization": "Bearer " + TOKEN}
    r = mx("GET", dict(auth, Accept="text/event-stream"))
    eq("GET /mcp answers 405 with Allow: POST", (405, "POST"), (r.status, r.headers.get("allow")))
    r = mx("DELETE", dict(auth))
    eq("DELETE /mcp answers 405 with Allow: POST", (405, "POST"), (r.status, r.headers.get("allow")))
    r, _ = S.rpc("tools/list", headers={"Accept": "application/json"})
    eq("POST without text/event-stream in Accept answers 406", 406, r.status)
    r = mx("POST", S.hdr({"Content-Type": "text/plain"}), '{"jsonrpc":"2.0","id":80,"method":"tools/list"}')
    eq("POST with a non-JSON Content-Type answers 415", 415, r.status)
    r, _ = S.rpc("tools/list", headers={"Origin": "http://evil.example"})
    eq("a cross-site Origin is refused 403 MCP_ORIGIN_NOT_ALLOWED", (403, "MCP_ORIGIN_NOT_ALLOWED"),
       (r.status, jbody(r).get("error_code")))
    r, m = S.rpc("tools/list", headers={"Origin": "http://localhost:5173"})
    check("a loopback Origin on any port is admitted", r.status == 200 and bool(m and "result" in m),
          "%s %s" % (r.status, clip(r.body, 160)))

    r = mx("POST", S.hdr({"Host": "evil.example"}), body, base=DIRECT)
    eq("DIRECT with a non-loopback Host is refused 421 MCP_HOST_NOT_ALLOWED", (421, "MCP_HOST_NOT_ALLOWED"),
       (r.status, jbody(r).get("error_code")))
    r = mx("POST", dict(plain, Host="evil.example"), body, base=DIRECT)
    eq("... before the bearer check (no Authorization still 421)", 421, r.status)
    r = mx("POST", S.hdr({"Host": "127.0.0.1:48826"}), body, base=DIRECT)
    eq("DIRECT with Host 127.0.0.1:<port> is admitted (port-agnostic loopback)", 200, r.status)
    r = mx("POST", S.hdr({"Host": "evil.example"}), body)
    eq("through Caddy any client Host works (Caddy rewrites Host)", 200, r.status)
    tenant_endpoint_checks()

    # ============================================================ 3. tools/list
    r, m = S.rpc("tools/list")
    tools = (m or {}).get("result", {}).get("tools", [])
    eq("tools/list returns every #[tool] in handler.rs plus list_tenants and create_upload_url (%d)"
       % (tool_attr + 2), tool_attr + 2, len(tools))
    eq("annotation_tests::TABLE has one row per tool", tool_attr, len(table))
    names = [t.get("name") for t in tools]
    eq("the two account-only tools come first", ["list_tenants", "create_upload_url"], names[:2])
    check("tools/list has no nextCursor (single page)", "nextCursor" not in (m or {}).get("result", {}))
    outer = {t.get("name"): t for t in tools[:2]}
    tools = tools[2:]
    inner = names[2:]
    eq("tools/list names == TABLE names", sorted(table), sorted(inner))
    no_ann = [t["name"] for t in tools if not isinstance(t.get("annotations"), dict)]
    eq("every tool carries an annotations object", [], no_ann)
    mism = []
    for t in tools:
        a = t.get("annotations") or {}
        shape = table.get(t["name"])
        if not shape:
            continue
        want = HINTS[shape]
        got = (a.get("readOnlyHint"), a.get("destructiveHint"), a.get("idempotentHint"), a.get("openWorldHint"))
        if want != got:
            mism.append("%s(%s): want %s got %s" % (t["name"], shape, want, got))
    eq("every tool's wire hints match its TABLE shape", [], mism)
    ow = sorted(t["name"] for t in tools if (t.get("annotations") or {}).get("openWorldHint") is True)
    eq("openWorldHint is true only on invoke_function", ["invoke_function"], ow)
    ow_missing = sorted(t["name"] for t in tools if (t.get("annotations") or {}).get("openWorldHint") is None)
    eq("openWorldHint is written out on every tool", [], ow_missing)
    ro_missing = sorted(t["name"] for t in tools if (t.get("annotations") or {}).get("readOnlyHint") is None)
    eq("readOnlyHint is written out on every tool", [], ro_missing)
    by = {t["name"]: (t.get("annotations") or {}) for t in tools}
    for n in ("update_record", "upsert_records"):
        a = by.get(n, {})
        check("%s is destructive and NOT idempotent (no automatic re-send)" % n,
              a.get("destructiveHint") is True and a.get("idempotentHint") is False, json.dumps(a))
    eq("call_rpc is marked readOnlyHint (read-only executor on MCP)", True, by.get("call_rpc", {}).get("readOnlyHint"))
    replace14 = ["set_anon_caps", "set_user_caps", "set_policy", "set_description", "set_file_policy",
                 "set_file_visibility", "update_rpc", "update_user", "set_owner_field", "set_file_caps",
                 "set_egress_allowlist", "set_oauth_provider", "set_redirect_uris", "update_webhook"]
    nd = [n for n in replace14 if by.get(n, {}).get("destructiveHint") is not True]
    eq("the fourteen replace-style tools named in CHANGELOG are destructiveHint:true", [], nd)
    ro_writes = sorted(n for n, a in by.items() if a.get("readOnlyHint") is True and
                       re.match(r"(create|set|update|delete|drop|insert|upsert|clear|revoke|add|broadcast|invoke)_?", n))
    eq("no tool whose name says it writes is marked readOnlyHint", [], ro_writes)
    nodesc = [t["name"] for t in tools if not (t.get("description") or "").strip()]
    eq("every tool has a description", [], nodesc)
    noobj = [t["name"] for t in tools if (t.get("inputSchema") or {}).get("type") != "object"]
    eq("every tool's inputSchema is a JSON object schema", [], noobj)
    desc = {t["name"]: t.get("description") or "" for t in tools}
    for n in ("describe_collection", "delete_file", "get_file_url", "set_file_visibility"):
        check("%s's description says how it fails (isError result)" % n, "isError" in desc.get(n, ""),
              desc.get(n, "")[-200:])
    check("recent_writes' account description recommends it before re-sending a lost write",
          "Use it before re-sending a write whose reply was lost" in desc.get("recent_writes", ""))
    check("query's description no longer claims structured tools scope rows on MCP",
          "on MCP you are the service identity" in desc.get("query", ""))
    unnamed = [n for n in names if not re.search(r"(?<![a-z0-9_])%s(?![a-z0-9_])" % re.escape(n), ins)]
    eq("instructions name every tool as a whole word", [], unnamed)
    dry = sorted(t["name"] for t in tools if "dry_run" in ((t.get("inputSchema") or {}).get("properties") or {}))
    eq("exactly delete_record / drop_collection / drop_index advertise dry_run",
       ["delete_record", "drop_collection", "drop_index"], dry)
    not_first = []
    for t in tools:
        sch = t.get("inputSchema") or {}
        props = list((sch.get("properties") or {}).keys())
        if (sch.get("required") or [None])[0] != "tenant" or (props or [None])[0] != "tenant":
            not_first.append(t["name"])
    eq("every per-tenant tool requires tenant first", [], not_first)
    lt = outer.get("list_tenants") or {}
    la = lt.get("annotations") or {}
    check("list_tenants takes no arguments and is read-only closed-world",
          (lt.get("inputSchema") or {}).get("properties") == {} and la.get("readOnlyHint") is True
          and la.get("openWorldHint") is False, clip(json.dumps(lt), 300))
    ua = (outer.get("create_upload_url") or {}).get("annotations") or {}
    eq("create_upload_url hints are write, not destructive, not idempotent, closed-world",
       (False, False, False, False),
       (ua.get("readOnlyHint"), ua.get("destructiveHint"), ua.get("idempotentHint"), ua.get("openWorldHint")))
    # Reviewer notes (not failures): shapes whose classification is a judgement call.
    acl_like = [n for n in ("set_function_invoke_acl", "set_publish_policy", "set_self_register", "set_realtime")
                if by.get(n, {}).get("destructiveHint") is False]
    if acl_like:
        note("review: access-widening/narrowing switches marked destructiveHint:false while set_anon_caps is true: "
             + ", ".join(acl_like))

    # ============================================================ 4. the tenant argument
    _, m = S.tool("list_tenants", {"tenant": None})
    j = tool_json(m) or {}
    tids = [t.get("id") for t in (j.get("tenants") or [])]
    check("list_tenants lists both run tenants and this server's MCP URL",
          A in tids and B in tids and j.get("mcp_url") == mcp_url, short(m))
    txt = tool_text(m)
    check("... and carries no tenant key", ASVC not in txt and AANON not in txt and BSVC not in txt)
    _, m = S.tool("list_collections", {"tenant": None})
    check("a per-tenant tool without tenant is isError TENANT_REQUIRED",
          is_error(m) and (tool_json(m) or {}).get("error_code") == "TENANT_REQUIRED", short(m))
    _, m = S.tool("list_collections", {"tenant": "no-such-tenant-smoke"})
    check("an unknown tenant is isError TENANT_NOT_FOUND",
          is_error(m) and (tool_json(m) or {}).get("error_code") == "TENANT_NOT_FOUND", short(m))
    _, m = S.tool("list_collections", {"bogus": 1})
    check("an argument outside the inputSchema is isError INVALID_ARGUMENTS",
          is_error(m) and (tool_json(m) or {}).get("error_code") == "INVALID_ARGUMENTS", short(m))
    _, m = S.tool("list_collections", {"tenant": B})
    check("the other run tenant is reachable with the same token", bool(m and "result" in m and not is_error(m)),
          short(m))

    # ============================================================ 5. fixtures
    _, m = S.tool("create_collection", {"name": "notes", "fields": [
        {"name": "title", "sql_type": "text"}, {"name": "body", "sql_type": "text"}]})
    check("fixture: create_collection notes", m and "result" in m and not is_error(m), short(m))
    _, m = S.tool("create_collection", {"name": "big", "fields": [{"name": "blob_text", "sql_type": "text"}]})
    check("fixture: create_collection big", m and "result" in m and not is_error(m), short(m))
    ids = []
    for i in range(3):
        _, m = S.tool("insert_record", {"collection": "notes", "data": {"title": "n%d" % i, "body": "hello"}})
        j = tool_json(m) or {}
        rid = j.get("id") or (j.get("record") or {}).get("id")
        if rid is not None:
            ids.append(int(rid))
    eq("fixture: three notes inserted", 3, len(ids))
    big_len = 300000
    _, m = S.tool("insert_record", {"collection": "big", "data": {"blob_text": "x" * big_len}})
    j = tool_json(m) or {}
    big_id = j.get("id") or (j.get("record") or {}).get("id")
    check("fixture: one ~300 KB row inserted into big", big_id is not None, short(m))

    # ------------------------------------------------------------ isError sentinels
    _, m = S.tool("describe_collection", {"collection": "no_such_coll"})
    j = tool_json(m) or {}
    check("describe_collection(unknown) answers isError:true", is_error(m), short(m))
    eq("... with error_code COLLECTION_NOT_FOUND", "COLLECTION_NOT_FOUND", j.get("error_code"))
    check("... carrying message and the catalogued suggested_fix",
          bool(j.get("message")) and bool(j.get("suggested_fix")), json.dumps(j))
    _, m = S.tool("describe_collection", {"collection": "notes"})
    check("describe_collection(existing) is a normal result", m and "result" in m and not is_error(m), short(m))

    _, m = S.tool("delete_record", {"collection": "notes", "id": 999999})
    j = tool_json(m) or {}
    check("delete_record(unknown id) answers isError:true", is_error(m), short(m))
    eq("... with error_code RECORD_NOT_FOUND", "RECORD_NOT_FOUND", j.get("error_code"))
    check("... and its body no longer carries \"ok\"", "ok" not in j, json.dumps(j))
    check("... with the catalogued suggested_fix", bool(j.get("suggested_fix")), json.dumps(j))
    _, m = S.tool("delete_record", {"collection": "notes", "id": 999999, "dry_run": True})
    check("delete_record dry_run on a missing id is an isError result with an error code",
          is_error(m) and bool((tool_json(m) or {}).get("error_code")), short(m))
    if ids:
        _, m = S.tool("delete_record", {"collection": "notes", "id": ids[-1], "dry_run": True})
        check("delete_record dry_run on a real id returns a blast radius, not an error",
              m and "result" in m and not is_error(m), short(m))
        _, m = S.tool("list_records", {"collection": "notes"})
        eq("... and deletes nothing (still 3 rows)", 3, (tool_json(m) or {}).get("total"))

    for tool, args in (("delete_file", {"id": "00000000-0000-0000-0000-000000000000"}),
                       ("get_file_url", {"id": "00000000-0000-0000-0000-000000000000"}),
                       ("set_file_visibility", {"id": "00000000-0000-0000-0000-000000000000", "visibility": "public"})):
        _, m = S.tool(tool, args)
        j = tool_json(m) or {}
        check("%s(unknown id) answers isError:true" % tool, is_error(m), short(m))
        eq("... with error_code NOT_FOUND (object storage is configured)", "NOT_FOUND", j.get("error_code"))
    _, m = S.tool("set_file_visibility", {"id": "00000000-0000-0000-0000-000000000000", "visibility": "PUBLIC"})
    check("set_file_visibility(bad visibility) answers isError:true", is_error(m), short(m))
    eq("... with error_code INVALID_VISIBILITY", "INVALID_VISIBILITY", (tool_json(m) or {}).get("error_code"))
    for v in ("Public", " private", "pub", "PRIV"):
        _, m = S.tool("list_files", {"visibility": v})
        check("list_files(visibility=%r) is refused with isError INVALID_VISIBILITY" % v,
              is_error(m) and (tool_json(m) or {}).get("error_code") == "INVALID_VISIBILITY", short(m))
    for v in ("all", "", "public"):
        _, m = S.tool("list_files", {"visibility": v})
        check("list_files(visibility=%r) is a normal listing" % v,
              m and "result" in m and not is_error(m) and "files" in (tool_json(m) or {}), short(m))

    # A real public file (the Mode-A service default): get_file_url's public arm,
    # list_files filtering, then delete_file's success path.
    pkey = upload_file("public")
    if pkey:
        try:
            _, m = S.tool("get_file_url", {"id": pkey})
            j = tool_json(m) or {}
            eq("get_file_url(public file) returns <this deployment's public origin>/public/<tid>/<key> "
               "with expires_at null (needs DRUST_PUBLIC_BASE_URL set by the deploy target)",
               ("%s/public/%s/%s" % (PUBLIC_URL.rstrip("/"), A, pkey), None), (j.get("url"), j.get("expires_at")))
            _, m = S.tool("list_files", {"visibility": "public"})
            fl = (tool_json(m) or {}).get("files") or []
            check("list_files(public) lists the uploaded public file", any(f.get("id") == pkey for f in fl), short(m))
            _, m = S.tool("list_files", {"visibility": "private"})
            fl = (tool_json(m) or {}).get("files")
            # Require a real listing: an error result would make "not listed" vacuous.
            check("list_files(private) is a normal listing that does not list the public file",
                  m and "result" in m and not is_error(m) and isinstance(fl, list)
                  and not any(f.get("id") == pkey for f in fl), short(m))
        finally:
            _, m = S.tool("delete_file", {"id": pkey})
            check("delete_file(real id) succeeds without isError", m and "result" in m and not is_error(m)
                  and (tool_json(m) or {}).get("ok") is True, short(m))
        _, m = S.tool("delete_file", {"id": pkey})
        eq("a second delete_file of the same id answers isError NOT_FOUND", (True, "NOT_FOUND"),
           (is_error(m), (tool_json(m) or {}).get("error_code")))

    # A real private file: get_file_url's signed arm + expires_in range. Needs the
    # host-wide 'private' bucket, which the smoke stack does not provision (see report).
    key = upload_file("private")
    if key:
        try:
            _, m = S.tool("get_file_url", {"id": key, "expires_in": 600})
            j = tool_json(m) or {}
            url = j.get("url") or ""
            check("get_file_url(private file) returns a signed URL under the public base (no /drust prefix)",
                  not is_error(m) and url.startswith("%s/s/t/%s/%s?" % (PUBLIC_URL.rstrip("/"), A, key)),
                  re.sub(r"\?.*", "?…", url))
            _, m = S.tool("get_file_url", {"id": key, "expires_in": 0})
            j = tool_json(m) or {}
            check("get_file_url refuses expires_in 0 with an isError naming the range",
                  is_error(m) and bool(j.get("error_code")) and "1..=604800" in (j.get("message") or ""), short(m))
            _, m = S.tool("list_files", {"visibility": "private"})
            fl = (tool_json(m) or {}).get("files") or []
            check("list_files(private) lists the uploaded private file", any(f.get("id") == key for f in fl), short(m))
            _, m = S.tool("list_files", {"visibility": "public"})
            fl = (tool_json(m) or {}).get("files")
            check("list_files(public) is a normal listing that does not list the private file",
                  m and "result" in m and not is_error(m) and isinstance(fl, list)
                  and not any(f.get("id") == key for f in fl), short(m))
        finally:
            _, m = S.tool("delete_file", {"id": key})
            check("delete_file(real id) succeeds without isError", m and "result" in m and not is_error(m)
                  and (tool_json(m) or {}).get("ok") is True, short(m))

    # ============================================================ 6. validation errors
    _, m = S.tool("no_such_tool", {})
    e = rpc_err(m) or {}
    check("calling an unknown tool is JSON-RPC -32602 'tool not found'",
          e.get("code") == -32602 and "tool not found" in (e.get("message") or ""), short(m))
    def drust_error_face(mm):
        # handler.rs: a tool failure is EITHER a JSON-RPC error (bail_mcp / rmcp
        # -32602) OR an isError result whose text is the ONE tool_error JSON shape
        # {"error_code","message",...} ("every isError body has one shape").
        if rpc_err(mm) is not None:
            return True
        if is_error(mm):
            jj = tool_json(mm)
            return isinstance(jj, dict) and bool(jj.get("error_code")) and bool(jj.get("message"))
        return False
    for label, tool, args, needle in (
            ("a missing required argument", "describe_collection", {}, "missing field `collection`"),
            ("a wrongly typed argument", "delete_record", {"collection": "notes", "id": "abc"}, "expected i64")):
        _, m = S.tool(tool, args)
        e = rpc_err(m) or {}
        text = (e.get("message") or "") + tool_text(m)
        check("%s is refused with text naming the problem (%s)" % (label, needle),
              (rpc_err(m) is not None or is_error(m)) and needle in text, short(m))
        # AGENTS.md "Deliberate — MCP annotations and error faces"; handler.rs tool_error:
        # "every isError body has one shape".
        check("%s uses one of drust's two error faces (JSON-RPC error, or isError with "
              "{error_code,message} JSON)" % label, drust_error_face(m), short(m))
        # handler.rs finish_tool_call: an argument that fails to deserialize is the isError
        # face with INVALID_PARAMS. Pinned exactly: the check above would also pass a
        # regression back to a JSON-RPC error.
        check("%s is an isError result with error_code INVALID_PARAMS" % label,
              is_error(m) and (tool_json(m) or {}).get("error_code") == "INVALID_PARAMS", short(m))
    _, m = S.tool("list_records", {"collection": "notes", "filter": [1, 2]})
    j = tool_json(m) or {}
    check("a malformed filter is an error with FILTER_PARSE_ERROR and the shape hint",
          is_error(m) and j.get("error_code") == "FILTER_PARSE_ERROR"
          and "filter must be a JSON object" in (j.get("message") or ""), short(m))
    _, m = S.tool("list_records", {"collection": "notes", "filter": json.dumps({"title": "n1"})})
    eq("a double-encoded (string) filter is still accepted", 1, (tool_json(m) or {}).get("total"))
    _, m = S.tool("insert_record", {"collection": "_system_users", "data": {"email": "x@y.z"}})
    check("insert_record into a _system_* table is refused with error_code PROTECTED_COLLECTION",
          is_error(m) and (tool_json(m) or {}).get("error_code") == "PROTECTED_COLLECTION", short(m))
    # src/mcp/tools/read.rs: ExecError::Forbidden -> "`query` is read-only — use ..."; the account endpoint returns it as an isError result.
    # Exact face, so a refusal for an unrelated reason (e.g. a renamed argument) cannot pass.
    _, m = S.tool("query", {"sql": "DELETE FROM notes"})
    j = tool_json(m) or {}
    check("query refuses a write statement with an isError naming '`query` is read-only'",
          is_error(m) and "`query` is read-only" in (j.get("message") or ""), short(m))
    # bail_mcp's convention (handler.rs) is "<CODE>: <message>", and the instructions tell the model
    # to read error_code; a code is an UPPER_SNAKE identifier, never a prose sentence.
    ec = j.get("error_code") or ""
    check("query's write refusal carries a machine-readable error_code (UPPER_SNAKE), not prose",
          bool(re.match(r"^[A-Z][A-Z0-9_]*$", ec)), "error_code=%r" % clip(ec, 80))
    _, m = S.tool("create_rpc", {"name": "count_notes", "sql": "SELECT count(*) AS n FROM notes", "params": []})
    check("fixture: create_rpc count_notes (read)", m and "result" in m and not is_error(m), short(m))
    _, m = S.tool("create_rpc", {"name": "wipe_notes", "sql": "DELETE FROM notes", "params": [], "mode": "write"})
    check("fixture: create_rpc wipe_notes (write mode)", m and "result" in m and not is_error(m), short(m))
    _, m = S.tool("call_rpc", {"name": "count_notes"})
    check("call_rpc runs a read RPC", m and "result" in m and not is_error(m) and "3" in tool_text(m), short(m))
    _, m = S.tool("call_rpc", {"name": "wipe_notes"})
    check("call_rpc refuses a write-mode RPC with an isError naming 'not authorized'",
          is_error(m) and "not authorized" in ((tool_json(m) or {}).get("message") or ""), short(m))
    _, m = S.tool("list_records", {"collection": "notes"})
    eq("... and no row was deleted", 3, (tool_json(m) or {}).get("total"))

    # ============================================================ 7. resources
    _, m = S.rpc("resources/list")
    eq("resources/list is empty on purpose", [], (m or {}).get("result", {}).get("resources"))
    _, m = S.rpc("resources/templates/list")
    tl = [x.get("uriTemplate") for x in (m or {}).get("result", {}).get("resourceTemplates", [])]
    want_static = ["schema", "schema.md", "collections", "openapi.json", "types.ts", "zod.ts",
                   "functions", "rpcs", "cron", "files-guide.md"]
    eq("resources/templates/list returns the 14 tenant-shaped templates",
       ["drust://{tenant}/" + p for p in want_static + [
           "collections/{collection}/schema", "collections/{collection}/records{?page,per_page,sort,order}",
           "collections/{collection}/records/{id}", "rpcs/{name}"]], tl)
    check("no history or function-logs template is exposed", not any("history" in t or "logs" in t for t in tl), str(tl))

    def read(uri):
        _, mm = S.rpc("resources/read", {"uri": uri})
        return mm
    for p in want_static:
        uri = "drust://%s/%s" % (A, p)
        mm = read(uri)
        c = ((mm or {}).get("result", {}).get("contents") or [{}])[0]
        check("resources/read %s returns text with a mimeType" % p,
              c.get("uri") == uri and bool(c.get("text")) and bool(c.get("mimeType")), short(mm))
        if c.get("mimeType") == "application/json":
            try:
                json.loads(c.get("text") or "")
                okj = True
            except ValueError:
                okj = False
            check("... and its body is valid JSON", okj)
        txt = c.get("text") or ""
        check("... and carries no credential", ASVC not in txt and AANON not in txt)
        if p == "rpcs":
            check("... and lists the stored RPCs (so the redaction check below is not vacuous)",
                  "count_notes" in txt and "wipe_notes" in txt, clip(txt, 200))
        if p in ("rpcs", "schema"):
            check("... and redacts stored RPC SQL", "SELECT count(*)" not in txt and "DELETE FROM notes" not in txt)
        if p == "files-guide.md":
            check("... and points uploads at create_upload_url", "create_upload_url" in txt)
    mm = read("drust://%s/collections/notes/schema" % A)
    check("template collections/notes/schema resolves", "result" in (mm or {}) and "title" in json.dumps(mm), short(mm))
    mm = read("drust://%s/collections/notes/records?page=1&per_page=2&sort=title&order=asc" % A)
    body = ((mm or {}).get("result", {}).get("contents") or [{}])[0].get("text") or ""
    jb = {}
    try:
        jb = json.loads(body)
    except ValueError:
        pass
    check("template records?page&per_page&sort&order returns a page of 2",
          len(jb.get("records") or []) == 2, short(mm))
    eq("... with a top-level resource_uri_template", "drust://%s/collections/notes/records/{id}" % A,
       jb.get("resource_uri_template"))
    if ids:
        mm = read("drust://%s/collections/notes/records/%d" % (A, ids[0]))
        rt = ((mm or {}).get("result", {}).get("contents") or [{}])[0].get("text") or "{}"
        try:
            rec = json.loads(rt).get("record") or {}
        except ValueError:
            rec = {}
        eq("template records/{id} returns that row", (ids[0], "n0"), (rec.get("id"), rec.get("title")))
    mm = read("drust://%s/rpcs/count_notes" % A)
    t = json.dumps(mm or {})
    check("template rpcs/{name} returns the RPC with its SQL redacted",
          "count_notes" in t and "SELECT count" not in t and "result" in (mm or {}), short(mm))
    if big_id is not None:
        mm = read("drust://%s/collections/big/records/%s" % (A, big_id))
        txt = ((mm or {}).get("result", {}).get("contents") or [{}])[0].get("text") or ""
        mk = re.search(r"\n\n\[\[truncated: DRUST_MCP_RESOURCE_MAX_BYTES=(\d+); (\d+) bytes omitted\]\]$", txt)
        check("an over-cap resource body ends with the truncation marker", bool(mk), "len=%d tail=%s" % (len(txt), txt[-120:]))
        if mk:
            cap = int(mk.group(1))
            eq("... the cap is the documented default 262144 (DRUST_MCP_RESOURCE_MAX_BYTES unset)", 262144, cap)
            kept = len(txt[:mk.start()].encode("utf-8"))
            check("... the kept body is <= the cap and kept+omitted covers the whole ~300 KB row",
                  kept <= cap and kept + int(mk.group(2)) > big_len, "kept=%d omitted=%s" % (kept, mk.group(2)))

    refuse = [
        ("an unknown tenant host", "drust://no-such-tenant-smoke/schema"),
        ("literal dot-segment", "drust://%s/collections/../schema" % A),
        ("encoded dot-segment", "drust://%s/collections/%%2e%%2e/schema" % A),
        ("encoded slash in a segment", "drust://%s/collections/notes%%2fx/schema" % A),
        ("userinfo in authority", "drust://u@%s/schema" % A),
        ("port in authority", "drust://%s:1/schema" % A),
        ("fragment", "drust://%s/schema#x" % A),
        ("wrong scheme", "http://%s/schema" % A),
        ("query on a static resource", "drust://%s/schema?x=1" % A),
        ("protected _system_ collection", "drust://%s/collections/_system_users/schema" % A),
        ("protected _system_ records", "drust://%s/collections/_system_sessions/records" % A),
        ("non-canonical id 05", "drust://%s/collections/notes/records/05" % A),
        ("form-encoded query key", "drust://%s/collections/notes/records?p%%61ge=2" % A),
        ("plus in query", "drust://%s/collections/notes/records?sort=a+b" % A),
        ("duplicate query key", "drust://%s/collections/notes/records?page=1&page=2" % A),
        ("unknown query key", "drust://%s/collections/notes/records?limit=5" % A),
        ("bad order value", "drust://%s/collections/notes/records?order=sideways" % A),
        ("unknown path", "drust://%s/secrets" % A),
        ("trailing slash", "drust://%s/schema/" % A),
        ("absent collection", "drust://%s/collections/nope/schema" % A),
        ("absent record id", "drust://%s/collections/notes/records/999999" % A),
        ("absent rpc", "drust://%s/rpcs/nope" % A),
    ]
    for label, uri in refuse:
        mm = read(uri)
        e = rpc_err(mm) or {}
        check("resources/read refuses %s with -32002" % label, e.get("code") == -32002, short(mm))
    mm = read("drust://%s/schema" % B)
    check("the other run tenant's schema is readable with the same token", "result" in (mm or {}), short(mm))

    # ============================================================ 8. prompts
    _, m = S.rpc("prompts/list")
    pl = (m or {}).get("result", {}).get("prompts", [])
    eq("prompts/list returns the 6 recipes", sorted(["bootstrap", "design_collection", "secure_collection",
       "debug_write", "write_edge_function", "review_history"]), sorted(p.get("name") for p in pl))
    first = sorted(p.get("name") for p in pl if ((p.get("arguments") or [{}])[0]).get("name") != "tenant")
    eq("each prompt takes tenant as its first argument", [], first)
    req = {p["name"]: [a.get("name") for a in (p.get("arguments") or [])
                       if a.get("required") and a.get("name") != "tenant"] for p in pl}
    eq("each argument-taking prompt marks its argument required",
       {"bootstrap": [], "design_collection": ["purpose"], "secure_collection": ["collection"],
        "debug_write": ["collection"], "write_edge_function": ["trigger"], "review_history": ["collection"]}, req)

    def prompt(name, args=None, tenant=A):
        a = dict(args or {})
        if tenant is not None:
            a["tenant"] = tenant
        _, mm = S.rpc("prompts/get", {"name": name, "arguments": a})
        try:
            return mm, mm["result"]["messages"][0]["content"]["text"]
        except (KeyError, IndexError, TypeError):
            return mm, ""
    mm, t = prompt("bootstrap")
    check("prompts/get bootstrap embeds the live schema (notes)", ("`%s`" % A) in t and "notes" in t, short(mm))
    check("... and points at resources/templates/list, not resources/list",
          "`resources/templates/list`" in t and "`resources/list` +" not in t)
    mm, t = prompt("design_collection", {"purpose": "blog posts"})
    check("prompts/get design_collection lists the datetime and json field types",
          "datetime" in t and "json" in t and "blog posts" in t, short(mm))
    mm, t = prompt("secure_collection", {"collection": "notes"})
    check("prompts/get secure_collection embeds describe_collection", '"title"' in t, short(mm))
    mm, t = prompt("debug_write", {"collection": "notes"})
    check("prompts/get debug_write no longer suggests recent_writes or a dry_run re-run",
          bool(t) and "recent_writes" not in t and "re-sending one runs it for real" in t, short(mm))
    mm, t = prompt("write_edge_function", {"trigger": "record.created on notes"})
    check("prompts/get write_edge_function asks the user to upload the .wasm (no key, no curl)",
          "ask the user to upload the .wasm" in t and "curl" not in t and "service-token" not in t, clip(short(mm), 200))
    check("... and uses get_egress_allowlist / set_egress_allowlist (replace, never merge)",
          "get_egress_allowlist" in t and "set_egress_allowlist" in t, clip(short(mm), 200))
    mm, t = prompt("review_history", {"collection": "notes"})
    check("prompts/get review_history names get_record_history", "get_record_history" in t, short(mm))
    for label, name, args in (("an unknown prompt", "nope", None),
                              ("a missing required argument", "design_collection", {}),
                              ("an empty required argument", "debug_write", {"collection": ""}),
                              ("secure_collection on an unknown collection", "secure_collection", {"collection": "nope"})):
        mm, _ = prompt(name, args)
        eq("prompts/get with %s is -32602" % label, -32602, (rpc_err(mm) or {}).get("code"))
    mm, _ = prompt("bootstrap", None, tenant=None)
    check("prompts/get without tenant is refused", rpc_err(mm) is not None, short(mm))

    # ============================================================ 9. whoami (account view)
    _, m = S.tool("whoami", {})
    j = tool_json(m) or {}
    check("whoami redacts the service key",
          ((j.get("tokens") or {}).get("service") or {}).get("redacted") is True and ASVC not in json.dumps(j),
          short(m))
    eq("whoami endpoints.mcp is the account endpoint", mcp_url, (j.get("endpoints") or {}).get("mcp"))
    eq("whoami caller is this OAuth grant", "oauth", (j.get("caller") or {}).get("kind"))
    eq("whoami file_upload.guide_resource points at files-guide.md", "drust://%s/files-guide.md" % A,
       (j.get("file_upload") or {}).get("guide_resource"))
    eq("whoami endpoints.rest_base is root-mode /t/<id>/ (rest_base + functions is the upload path)",
       "/t/%s/" % A, (j.get("endpoints") or {}).get("rest_base"))

    # ============================================================ 10. upload ticket (multi-chunk)
    ticket_upload(S)

    # ============================================================ 11. a reroll leaves OAuth access intact
    r = hx("POST", BASE, "/admin/api/tenants/%s/tokens/service/reroll" % B,
           {"Authorization": "Bearer " + PAT, "Content-Type": "application/json"}, "{}")
    newkey = jbody(r).get("token")
    if newkey:
        SECRETS.append(newkey)
    eq("tenant-scoped service-key reroll answers 201 with a new token", (201, True), (r.status, bool(newkey)))
    _, m = S.tool("list_collections", {"tenant": B})
    check("a tenant service-key reroll leaves the account endpoint's access to that tenant intact",
          bool(m and "result" in m and not is_error(m)), short(m))

    # ============================================================ 12. a meta write through the account endpoint
    # set_self_register writes meta.sqlite; /auth/register shows its effect.
    # Two MCP calls (paced as all others) and two register requests against
    # the per-IP limit of 3 per 60 s that 40 and 70 also use, minutes apart.
    _, m = S.tool("set_self_register", {"enabled": True})
    check("set_self_register(true) through the account endpoint answers allow_self_register=true",
          bool(m and not is_error(m)) and (tool_json(m) or {}).get("allow_self_register") is True, short(m))
    pw = "smoke-pass-" + secrets.token_hex(8)
    SECRETS.append(pw)
    r = register("smoke-mcp-%s@example.com" % secrets.token_hex(6), pw)
    eq("... after which /auth/register creates a user (201)", 201, r.status)
    _, m = S.tool("set_self_register", {"enabled": False})
    check("set_self_register(false) through the account endpoint answers allow_self_register=false",
          bool(m and not is_error(m)) and (tool_json(m) or {}).get("allow_self_register") is False, short(m))
    r = register("smoke-mcp-%s@example.com" % secrets.token_hex(6), pw)
    eq("... after which /auth/register is refused 403 SELF_REGISTER_DISABLED", (403, "SELF_REGISTER_DISABLED"),
       (r.status, jbody(r).get("error_code")))

def register(email, pw):
    """POST /auth/register on tenant A with no credential, backing off on the
    per-IP 429 (about 70 s at most, as 70-admin does)."""
    body = json.dumps({"email": email, "password": pw})
    for i in range(14):
        r = hx("POST", BASE, "/t/%s/auth/register" % A, {"Content-Type": "application/json"}, body,
               retry_429=False)
        if r.status != 429:
            return r
        if i == 0:
            note("register answered 429 (per-IP bucket shared with other scripts): backing off up to ~70 s")
        time.sleep(5)
    return r

def ticket_upload(S):
    _, m = S.tool("create_upload_url", {"size": TICKET_FILE_BYTES, "filename": "smoke-ticket.bin"})
    j = tool_json(m) or {}
    create = j.get("create") or {}
    auth = (create.get("headers") or {}).get("Authorization") or ""
    ticket = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
    if ticket:
        SECRETS.append(ticket)
    tk = j.get("ticket") or {}
    append = j.get("append") or {}
    check("create_upload_url issues a private ticket for the requested size",
          m is not None and not is_error(m) and bool(ticket)
          and tk.get("max_bytes") == TICKET_FILE_BYTES and tk.get("visibility") == "private"
          and j.get("upload_url") == PUBLIC_URL + "/t/%s/uploads" % A
          and (append.get("chunk_max_bytes") or 0) >= TICKET_CHUNK_BYTES, short(m))
    if not ticket:
        return
    upload_url, prefix = j.get("upload_url") or "", append.get("url_prefix") or ""
    if not (upload_url.startswith(PUBLIC_URL) and prefix.startswith(PUBLIC_URL)):
        bad("ticket URLs start with this deployment's public URL", "%s / %s" % (upload_url, prefix))
        return
    upload_url = BASE + upload_url[len(PUBLIC_URL):]
    prefix = BASE + prefix[len(PUBLIC_URL):]

    r = tx("POST", upload_url, dict(create.get("headers") or {}))
    loc = r.headers.get("location") or ""
    check("ticket POST creates the upload (201 with a Location)", r.status == 201 and bool(loc),
          "%s %s" % (r.status, clip(r.body, 200)))
    if not (r.status == 201 and loc):
        return
    patch_url = prefix + loc.rsplit("/", 1)[-1]
    data = bytes((i * 7 + 3) % 256 for i in range(TICKET_FILE_BYTES))
    off = 0
    for i in range(1, TICKET_CHUNKS + 1):
        if i == TICKET_CHUNKS:
            r = tx("HEAD", patch_url, {"Authorization": auth, "Tus-Resumable": "1.0.0"})
            eq("ticket HEAD mid-upload reports the bytes sent so far",
               (200, str((TICKET_CHUNKS - 1) * TICKET_CHUNK_BYTES)), (r.status, r.headers.get("upload-offset")))
        n = TICKET_CHUNK_BYTES if i < TICKET_CHUNKS else TICKET_FILE_BYTES - (TICKET_CHUNKS - 1) * TICKET_CHUNK_BYTES
        r = tx("PATCH", patch_url, {"Authorization": auth, "Tus-Resumable": "1.0.0",
                                    "Content-Type": "application/offset+octet-stream",
                                    "Upload-Offset": str(off)}, data[off:off + n])
        off += n
        eq("ticket PATCH chunk %d of %d answers 204 with the new offset" % (i, TICKET_CHUNKS),
           (204, str(off)), (r.status, r.headers.get("upload-offset")))
        if r.status != 204:
            return
    r = tx("POST", upload_url, dict(create.get("headers") or {}))
    eq("a second POST with the same ticket is 409 UPLOAD_TICKET_USED", (409, "UPLOAD_TICKET_USED"),
       (r.status, jbody(r).get("error_code")))
    _, m = S.tool("list_files", {})
    fl = (tool_json(m) or {}).get("files") or []
    check("the finished upload is listed, private, with its size",
          any(f.get("size_bytes") == TICKET_FILE_BYTES and f.get("visibility") == "private" for f in fl), short(m))

def upload_file(visibility):
    boundary = "----drustsmoke" + secrets.token_hex(8)
    parts = [
        "--%s\r\nContent-Disposition: form-data; name=\"visibility\"\r\n\r\n%s\r\n" % (boundary, visibility),
        "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"smoke.txt\"\r\n"
        "Content-Type: text/plain\r\n\r\nhello mcp smoke\r\n" % boundary,
        "--%s--\r\n" % boundary,
    ]
    r = hx("POST", BASE, "/t/%s/files" % A,
           {"Authorization": "Bearer " + ASVC, "Content-Type": "multipart/form-data; boundary=" + boundary},
           "".join(parts))
    key = jbody(r).get("key")
    if visibility == "private" and r.status == 502 and "Bucket not found: private" in r.body:
        note("deploy gap: the object store has no 'private' bucket in this stack (upload answered 502 NoSuchBucket) — "
             "get_file_url's signed arm and expires_in range not exercised")
        return None
    check("fixture: Mode-A upload of a %s file" % visibility, r.status in (200, 201) and bool(key),
          "%s %s" % (r.status, clip(r.body, 200)))
    return key

try:
    main()
except Exception:
    bad("python helper raised", traceback.format_exc())
PY

MCPX_BASE="$BASE" MCPX_DIRECT="$DIRECT" MCPX_A_ID="$A_ID" MCPX_A_SVC="$A_SVC" MCPX_A_ANON="$A_ANON" \
MCPX_B_ID="$B_ID" MCPX_B_SVC="$B_SVC" MCPX_PAT="$ADMIN_PAT" MCPX_REPO="$REPO_ROOT" \
MCPX_WANT_VER="$want_ver" MCPX_PUBLIC_URL="$PUBLIC_URL" MCPX_TOKEN="$SMOKE_MCP_TOKEN" \
  python3 -I "$TMP/mcpx.py" > "$TMP/mcpx.out" 2> "$TMP/mcpx.err"
rc=$?

while IFS="$(printf '\t')" read -r kind name detail; do
  case "$kind" in
    PASS) ok "$name" ;;
    FAIL) bad "$name" "$detail" ;;
    NOTE) note "$name" ;;
  esac
done < "$TMP/mcpx.out"

if [ "$rc" -ne 0 ] || [ -s "$TMP/mcpx.err" ]; then
  bad "python MCP helper exited cleanly" "exit $rc; stderr: $(head -c 300 "$TMP/mcpx.err" | tr '\n' ' ')"
fi
if ! grep -q . "$TMP/mcpx.out"; then
  bad "python MCP helper produced results" "no output"
fi

finish

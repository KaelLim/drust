#!/usr/bin/env bash
# MCP protocol surface through Caddy (/t/<id>/mcp), with the v1.67.0 "MCP (M1)"
# changes in focus: initialize (protocolVersion negotiation, serverInfo,
# capabilities, instructions <= 4096 chars naming every tool), tools/list count
# and per-tool annotations against src/mcp/handler.rs annotation_tests::TABLE,
# the five sentinel tools + list_files' INVALID_VISIBILITY now answering
# isError:true, input-validation errors, resources/list + templates + reads +
# the URI parser's documented refusals, DRUST_MCP_RESOURCE_MAX_BYTES truncation,
# prompts/list + prompts/get, the service-only gate (no bearer / anon / user /
# foreign tenant), rmcp's Host (DNS-rebinding) guard direct vs through Caddy,
# session lifecycle (Mcp-Session-Id, unknown id, DELETE, GET SSE stream), and
# that a tenant service-key reroll stops the old key's live MCP session.
#
# Uses 2 tenants (A: main, B: reroll + cross-tenant). Everything else it creates
# (collections, RPCs, an end user, one Garage object) lives inside tenant A or is
# deleted explicitly; both tenants are deleted by lib.sh on exit.
. "$(dirname "$0")/lib.sh"

want_ver="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)"

new_tenant mcp-a
A_ID="$TENANT_ID"; A_SVC="$SERVICE_KEY"; A_ANON="$ANON_KEY"
new_tenant mcp-b
B_ID="$TENANT_ID"; B_SVC="$SERVICE_KEY"
# lib.sh helpers (svc/anon/mcp_call) act on the LAST tenant; point them at A.
TENANT_ID="$A_ID"; SERVICE_KEY="$A_SVC"; ANON_KEY="$A_ANON"; T="$BASE/t/$A_ID"

cat > "$TMP/mcpx.py" <<'PY'
import http.client, json, os, re, secrets, socket, sys, time, traceback, urllib.parse

E = os.environ
BASE, DIRECT = E["MCPX_BASE"], E["MCPX_DIRECT"]
A, ASVC, AANON = E["MCPX_A_ID"], E["MCPX_A_SVC"], E["MCPX_A_ANON"]
B, BSVC = E["MCPX_B_ID"], E["MCPX_B_SVC"]
PAT, REPO, WANT_VER = E["MCPX_PAT"], E["MCPX_REPO"], E["MCPX_WANT_VER"]
PUBLIC_URL = E.get("MCPX_PUBLIC_URL", "")
SECRETS = [ASVC, AANON, BSVC, PAT]

def red(s):
    s = str(s)
    for x in SECRETS:
        if x:
            s = s.replace(x, "<redacted>")
    s = re.sub(r"([?&]t=)[^&\s\"']+", r"\1<redacted>", s)
    return s.replace("\t", " ").replace("\r", " ").replace("\n", " ")[:500]

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

def hx(method, base, path, headers=None, body=None, timeout=90):
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
        if r.status != 429 or "RATE_LIMITED" not in r.body:
            return r
        mm = re.search(r"retry after (\d+)s", r.body)
        time.sleep(min(12, int(mm.group(1)) if mm else 5) + 0.5)
    return r

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

class Sess:
    def __init__(self, base, tid, key, extra=None):
        self.base, self.path, self.key = base, "/t/%s/mcp" % tid, key
        self.extra, self.sid, self.proto, self.n = dict(extra or {}), None, None, 1
        self.init_r = self.init_m = None
        self.notif_status = None

    def hdr(self, session=True):
        h = {"Content-Type": "application/json", "Accept": ACCEPT}
        if self.key:
            h["Authorization"] = "Bearer " + self.key
        if session and self.sid:
            h["Mcp-Session-Id"] = self.sid
            h["MCP-Protocol-Version"] = self.proto
        h.update(self.extra)
        return h

    def init(self, proto="2025-06-18"):
        r = hx("POST", self.base, self.path, self.hdr(False), init_msg(proto))
        m = pick(r, 0)
        self.init_r, self.init_m = r, m
        if r.status == 200 and m and "result" in m:
            self.sid = r.headers.get("mcp-session-id")
            self.proto = m["result"].get("protocolVersion")
            n = hx("POST", self.base, self.path, self.hdr(),
                     {"jsonrpc": "2.0", "method": "notifications/initialized"})
            self.notif_status = n.status
        return r, m

    def rpc(self, method, params=None):
        i = self.n
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": i, "method": method}
        if params is not None:
            msg["params"] = params
        r = hx("POST", self.base, self.path, self.hdr(), msg)
        return r, pick(r, i)

    def tool(self, name, args=None):
        return self.rpc("tools/call", {"name": name, "arguments": args or {}})

    def close(self):
        if self.sid:
            return hx("DELETE", self.base, self.path, self.hdr())
        return None

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
    return json.dumps(m)[:400]

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

def main():
    tool_attr, table = load_spec()
    S = Sess(BASE, A, ASVC)

    # ============================================================ initialize
    r, m = S.init("2025-06-18")
    eq("initialize through Caddy answers HTTP 200", 200, r.status)
    check("initialize returns a JSON-RPC result", bool(m and "result" in m), short(m) + " / " + r.body[:200])
    if not (m and "result" in m):
        bad("cannot continue without an MCP session", r.body[:300])
        return
    res = m["result"]
    check("initialize issues a non-empty Mcp-Session-Id header", bool(S.sid))
    check("initialize answers as an SSE stream (text/event-stream)",
          "text/event-stream" in r.headers.get("content-type", ""), r.headers.get("content-type", ""))
    eq("notifications/initialized is accepted with HTTP 202", 202, S.notif_status)
    eq("protocolVersion echoes the requested 2025-06-18", "2025-06-18", res.get("protocolVersion"))
    eq("serverInfo.name is drust", "drust", res.get("serverInfo", {}).get("name"))
    eq("serverInfo.version matches Cargo.toml", WANT_VER, res.get("serverInfo", {}).get("version"))
    caps = res.get("capabilities", {})
    check("capabilities declare tools, resources and prompts",
          all(k in caps for k in ("tools", "resources", "prompts")), json.dumps(caps))
    check("resources/prompts capabilities do NOT declare listChanged or subscribe",
          not caps.get("resources", {}).get("listChanged") and not caps.get("resources", {}).get("subscribe")
          and not caps.get("prompts", {}).get("listChanged"), json.dumps(caps))
    ins = res.get("instructions") or ""
    check("instructions string is present", len(ins) > 0)
    check("instructions fit Claude Code's 4096-character cap (%d chars)" % len(ins), 0 < len(ins) <= 4096,
          "%d chars" % len(ins))
    check("instructions name this tenant", ("'%s'" % A) in ins, ins[:200])
    check("instructions lead with the dry_run rule (only delete_record/drop_collection/drop_index)",
          "Only delete_record, drop_collection and drop_index accept `dry_run: true`" in ins[:1200], ins[:300])
    check("instructions carry no absolute URL", not re.search(r"https?://", ins),
          (re.search(r"https?://\S+", ins) or [""])[0])
    check("instructions point uploads at the files-guide.md resource",
          ("drust://%s/files-guide.md" % A) in ins)
    check("instructions do not recommend recent_writes for retry recovery",
          "recent_writes (not populated yet" in ins and "check recent_writes" not in ins)

    for proto, want in (("2025-03-26", "2025-03-26"), ("2024-11-05", "2024-11-05"), ("2025-11-25", "2025-11-25")):
        s2 = Sess(BASE, A, ASVC)
        _, m2 = s2.init(proto)
        eq("protocolVersion negotiation echoes known version %s" % proto, want,
           (m2 or {}).get("result", {}).get("protocolVersion"))
        s2.close()
    s2 = Sess(BASE, A, ASVC)
    _, m2 = s2.init("1999-01-01")
    got = (m2 or {}).get("result", {}).get("protocolVersion")
    eq("an unknown requested protocolVersion falls back to the server default 2025-11-25", "2025-11-25", got)
    s2.close()
    r = hx("POST", BASE, S.path, {"Content-Type": "application/json", "Accept": ACCEPT,
                                    "Authorization": "Bearer " + ASVC, "MCP-Protocol-Version": "2025-03-26"},
             init_msg("2025-06-18"))
    eq("initialize whose MCP-Protocol-Version header contradicts params is refused with 400", 400, r.status)
    eq("... as a JSON-RPC Invalid Request (-32600)", -32600, (rpc_err(pick(r, 0)) or {}).get("code"))

    # ============================================================ tools/list
    r, m = S.rpc("tools/list")
    tools = (m or {}).get("result", {}).get("tools", [])
    eq("tools/list returns every #[tool] in handler.rs (%d)" % tool_attr, tool_attr, len(tools))
    eq("annotation_tests::TABLE has one row per tool", tool_attr, len(table))
    names = [t.get("name") for t in tools]
    check("tools/list has no nextCursor (single page)", "nextCursor" not in (m or {}).get("result", {}))
    eq("tools/list names == TABLE names", sorted(table), sorted(names))
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
    check("recent_writes' description says it returns no rows yet",
          "NOT POPULATED YET" in desc.get("recent_writes", ""))
    check("query's description no longer claims structured tools scope rows on MCP",
          "on MCP you are the service identity" in desc.get("query", ""))
    unnamed = [n for n in names if not re.search(r"(?<![a-z0-9_])%s(?![a-z0-9_])" % re.escape(n), ins)]
    eq("instructions name every tool as a whole word", [], unnamed)
    dry = sorted(t["name"] for t in tools if "dry_run" in ((t.get("inputSchema") or {}).get("properties") or {}))
    eq("exactly delete_record / drop_collection / drop_index advertise dry_run",
       ["delete_record", "drop_collection", "drop_index"], dry)
    # Reviewer notes (not failures): shapes whose classification is a judgement call.
    acl_like = [n for n in ("set_function_invoke_acl", "set_publish_policy", "set_self_register", "set_realtime")
                if by.get(n, {}).get("destructiveHint") is False]
    if acl_like:
        note("review: access-widening/narrowing switches marked destructiveHint:false while set_anon_caps is true: "
             + ", ".join(acl_like))

    # ============================================================ fixtures
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

    # ============================================================ isError sentinels
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
    e = rpc_err(m) or {}
    eq("delete_record dry_run on a missing id stays a JSON-RPC error (-32603)", -32603, e.get("code"))
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
        eq("... with error_code NOT_FOUND (Garage is configured)", "NOT_FOUND", j.get("error_code"))
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
            e = rpc_err(m) or {}
            check("get_file_url expires_in out of range stays a JSON-RPC error naming the range",
                  e.get("code") == -32603 and "1..=604800" in (e.get("message") or ""), short(m))
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

    # ============================================================ validation errors
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
        # AGENTS.md "Deliberate — MCP annotations and error faces": only five tools (+ list_files)
        # return isError, every other tool error is a JSON-RPC error; handler.rs tool_error:
        # "every isError body has one shape".
        check("%s uses one of drust's two error faces (JSON-RPC error, or isError with "
              "{error_code,message} JSON)" % label, drust_error_face(m), short(m))
    _, m = S.tool("list_records", {"collection": "notes", "filter": [1, 2]})
    e = rpc_err(m) or {}
    check("a malformed filter is an error with FILTER_PARSE_ERROR and the shape hint",
          (e.get("data") or {}).get("error_code") == "FILTER_PARSE_ERROR"
          and "filter must be a JSON object" in (e.get("message") or ""), short(m))
    _, m = S.tool("list_records", {"collection": "notes", "filter": json.dumps({"title": "n1"})})
    eq("a double-encoded (string) filter is still accepted", 1, (tool_json(m) or {}).get("total"))
    _, m = S.tool("insert_record", {"collection": "_system_users", "data": {"email": "x@y.z"}})
    e = rpc_err(m) or {}
    check("insert_record into a _system_* table is refused with data.error_code PROTECTED_COLLECTION",
          (e.get("data") or {}).get("error_code") == "PROTECTED_COLLECTION", short(m))
    # src/mcp/tools/read.rs: ExecError::Forbidden -> "`query` is read-only — use ..." via bail_mcp (-32603).
    # Exact face, so a refusal for an unrelated reason (e.g. a renamed argument) cannot pass.
    _, m = S.tool("query", {"sql": "DELETE FROM notes"})
    e = rpc_err(m) or {}
    check("query refuses a write statement with -32603 '`query` is read-only' (its readOnlyHint is honest)",
          e.get("code") == -32603 and "`query` is read-only" in (e.get("message") or ""), short(m))
    # bail_mcp's convention (handler.rs) is "<CODE>: <message>", and the instructions tell the model
    # to read error_code; a code is an UPPER_SNAKE identifier, never a prose sentence.
    ec = (e.get("data") or {}).get("error_code") or ""
    check("query's write refusal carries a machine-readable data.error_code (UPPER_SNAKE), not prose",
          bool(re.match(r"^[A-Z][A-Z0-9_]*$", ec)), "error_code=%r" % ec[:80])
    _, m = S.tool("create_rpc", {"name": "count_notes", "sql": "SELECT count(*) AS n FROM notes", "params": []})
    check("fixture: create_rpc count_notes (read)", m and "result" in m and not is_error(m), short(m))
    _, m = S.tool("create_rpc", {"name": "wipe_notes", "sql": "DELETE FROM notes", "params": [], "mode": "write"})
    check("fixture: create_rpc wipe_notes (write mode)", m and "result" in m and not is_error(m), short(m))
    _, m = S.tool("call_rpc", {"name": "count_notes"})
    check("call_rpc runs a read RPC", m and "result" in m and not is_error(m) and "3" in tool_text(m), short(m))
    _, m = S.tool("call_rpc", {"name": "wipe_notes"})
    e = rpc_err(m) or {}
    check("call_rpc refuses a write-mode RPC on MCP with the read-only authorizer's -32602 'not authorized'",
          e.get("code") == -32602 and "not authorized" in (e.get("message") or ""), short(m))
    _, m = S.tool("list_records", {"collection": "notes"})
    eq("... and no row was deleted", 3, (tool_json(m) or {}).get("total"))

    # ============================================================ resources
    _, m = S.rpc("resources/list")
    rl = (m or {}).get("result", {}).get("resources", [])
    want_static = ["schema", "schema.md", "collections", "openapi.json", "types.ts", "zod.ts",
                   "functions", "rpcs", "cron", "files-guide.md"]
    eq("resources/list returns the 10 static resources",
       sorted("drust://%s/%s" % (A, p) for p in want_static), sorted(x.get("uri") for x in rl))
    _, m = S.rpc("resources/templates/list")
    tl = [x.get("uriTemplate") for x in (m or {}).get("result", {}).get("resourceTemplates", [])]
    eq("resources/templates/list returns the 4 templates", sorted("drust://%s/%s" % (A, p) for p in (
        "collections/{collection}/schema", "collections/{collection}/records{?page,per_page,sort,order}",
        "collections/{collection}/records/{id}", "rpcs/{name}")), sorted(tl))
    check("no history or function-logs template is exposed", not any("history" in t or "logs" in t for t in tl), str(tl))

    def read(uri):
        _, mm = S.rpc("resources/read", {"uri": uri})
        return mm
    for x in rl:
        uri = x.get("uri")
        mm = read(uri)
        c = ((mm or {}).get("result", {}).get("contents") or [{}])[0]
        check("resources/read %s returns text with the listed mimeType" % uri.split("/", 3)[-1],
              c.get("uri") == uri and bool(c.get("text")) and c.get("mimeType") == x.get("mimeType"),
              short(mm))
        if c.get("mimeType") == "application/json":
            try:
                json.loads(c.get("text") or "")
                okj = True
            except ValueError:
                okj = False
            check("... and its body is valid JSON", okj)
        txt = c.get("text") or ""
        check("... and carries no credential", ASVC not in txt and AANON not in txt)
        if uri.endswith("/rpcs"):
            check("... and lists the stored RPCs (so the redaction check below is not vacuous)",
                  "count_notes" in txt and "wipe_notes" in txt, txt[:200])
        if uri.endswith("/rpcs") or uri.endswith("/schema"):
            check("... and redacts stored RPC SQL", "SELECT count(*)" not in txt and "DELETE FROM notes" not in txt)
        if uri.endswith("files-guide.md"):
            check("... and says when to switch to tus (Tus-Max-Size)", "Tus-Max-Size" in txt)
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
        ("another tenant's host", "drust://%s/schema" % B),
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

    # ============================================================ prompts
    _, m = S.rpc("prompts/list")
    pl = (m or {}).get("result", {}).get("prompts", [])
    eq("prompts/list returns the 6 recipes", sorted(["bootstrap", "design_collection", "secure_collection",
       "debug_write", "write_edge_function", "review_history"]), sorted(p.get("name") for p in pl))
    req = {p["name"]: [a.get("name") for a in (p.get("arguments") or []) if a.get("required")] for p in pl}
    eq("each argument-taking prompt marks its argument required",
       {"bootstrap": [], "design_collection": ["purpose"], "secure_collection": ["collection"],
        "debug_write": ["collection"], "write_edge_function": ["trigger"], "review_history": ["collection"]}, req)

    def prompt(name, args=None):
        p = {"name": name}
        if args is not None:
            p["arguments"] = args
        _, mm = S.rpc("prompts/get", p)
        try:
            return mm, mm["result"]["messages"][0]["content"]["text"]
        except (KeyError, IndexError, TypeError):
            return mm, ""
    mm, t = prompt("bootstrap")
    check("prompts/get bootstrap embeds the live schema (notes)", ("`%s`" % A) in t and "notes" in t, short(mm))
    check("... and does not claim list_records is owner-enforced on MCP",
          "narrow neither of them" in t and "owner-enforced" not in t)
    mm, t = prompt("design_collection", {"purpose": "blog posts"})
    check("prompts/get design_collection lists the datetime and json field types",
          "datetime" in t and "json" in t and "blog posts" in t, short(mm))
    mm, t = prompt("secure_collection", {"collection": "notes"})
    check("prompts/get secure_collection embeds describe_collection", '"title"' in t, short(mm))
    mm, t = prompt("debug_write", {"collection": "notes"})
    check("prompts/get debug_write no longer suggests recent_writes or a dry_run re-run",
          bool(t) and "recent_writes" not in t and "re-sending one runs it for real" in t, short(mm))
    mm, t = prompt("write_edge_function", {"trigger": "record.created on notes"})
    fn_url = "%s/t/%s/functions" % (PUBLIC_URL.rstrip("/"), A)
    check("prompts/get write_edge_function's upload URL is this deployment's public origin + base path (%s)" % fn_url,
          ("curl -X POST %s " % fn_url) in t, (re.search(r"curl -X POST \S+", t) or [""])[0])
    check("... and uses get_egress_allowlist / set_egress_allowlist (replace, never merge)",
          "get_egress_allowlist" in t and "set_egress_allowlist" in t, short(mm)[:200])
    mm, t = prompt("review_history", {"collection": "notes"})
    check("prompts/get review_history names get_record_history", "get_record_history" in t, short(mm))
    for label, name, args in (("an unknown prompt", "nope", None),
                              ("a missing required argument", "design_collection", {}),
                              ("an empty required argument", "debug_write", {"collection": ""}),
                              ("secure_collection on an unknown collection", "secure_collection", {"collection": "nope"})):
        mm, _ = prompt(name, args)
        eq("prompts/get with %s is -32602" % label, -32602, (rpc_err(mm) or {}).get("code"))

    # ============================================================ whoami
    _, m = S.tool("whoami", {})
    j = tool_json(m) or {}
    eq("whoami file_upload.guide_resource points at files-guide.md", "drust://%s/files-guide.md" % A,
       (j.get("file_upload") or {}).get("guide_resource"))
    eq("whoami endpoints.rest_base is root-mode /t/<id>/ (rest_base + functions is the upload path)",
       "/t/%s/" % A, (j.get("endpoints") or {}).get("rest_base"))

    # ============================================================ gate
    def raw_init(base, key=None, extra=None):
        h = {"Content-Type": "application/json", "Accept": ACCEPT}
        if key:
            h["Authorization"] = "Bearer " + key
        h.update(extra or {})
        return hx("POST", base, "/t/%s/mcp" % A, h, init_msg("2025-06-18"))
    r = raw_init(BASE)
    eq("MCP with no bearer answers 401", 401, r.status)
    eq("... error_code UNAUTHENTICATED", "UNAUTHENTICATED", jbody(r).get("error_code"))
    r = raw_init(BASE, "drust_bogus_" + secrets.token_hex(16))
    eq("MCP with an unknown bearer answers 401 UNAUTHENTICATED", (401, "UNAUTHENTICATED"),
       (r.status, jbody(r).get("error_code")))
    r = raw_init(BASE, AANON)
    eq("MCP with the anon key answers 403", 403, r.status)
    eq("... error_code WRITE_DENIED (not MCP_USER_DENIED)", "WRITE_DENIED", jbody(r).get("error_code"))
    # src/tenant/router.rs cross-tenant token guard: "preserves pre-D9 wire 404".
    r = raw_init(BASE, BSVC)
    eq("another tenant's service key is refused on this tenant's MCP with 404 TENANT_NOT_FOUND",
       (404, "TENANT_NOT_FOUND"), (r.status, jbody(r).get("error_code")))
    utok = user_token(S)
    if utok:
        SECRETS.append(utok)
        r = raw_init(BASE, utok)
        eq("MCP with an end-user token answers 403", 403, r.status)
        eq("... error_code MCP_USER_DENIED", "MCP_USER_DENIED", jbody(r).get("error_code"))
    else:
        note("could not obtain an end-user token (login rate limit) — user-token gate not exercised this run")

    # ============================================================ Host guard
    s3 = Sess(DIRECT, A, ASVC)
    r, m = s3.init()
    eq("initialize DIRECT (Host 127.0.0.1:<port>) is admitted by rmcp's Host guard", 200, r.status)
    s3.close()
    r = raw_init(DIRECT, ASVC, {"Host": "localhost:9999"})
    eq("DIRECT with Host localhost:<any port> is admitted (loopback allow-list, port-agnostic)", 200, r.status)
    r = raw_init(DIRECT, ASVC, {"Host": "evil.example"})
    eq("DIRECT with a non-loopback Host is refused 403 by the DNS-rebinding guard", 403, r.status)
    check("... with rmcp's 'Host header is not allowed' text", "Host header is not allowed" in r.body, r.body[:120])
    r = raw_init(BASE, ASVC, {"Host": "evil.example"})
    eq("through Caddy any client Host works (Caddy rewrites Host to 127.0.0.1:47826)", 200, r.status)
    r = raw_init(DIRECT, None, {"Host": "evil.example"})
    eq("DIRECT non-loopback Host without a bearer is still 401 (bearer layer runs first)", 401, r.status)

    # ============================================================ transport + sessions
    h = S.hdr()
    r = hx("POST", BASE, S.path, dict(h, **{"Mcp-Session-Id": "00000000-not-a-session"}),
             {"jsonrpc": "2.0", "id": 77, "method": "tools/list"})
    eq("a request with an unknown Mcp-Session-Id answers 404", 404, r.status)
    hn = dict(h)
    hn.pop("Mcp-Session-Id", None)
    r = hx("POST", BASE, S.path, hn, {"jsonrpc": "2.0", "id": 78, "method": "tools/list"})
    eq("a non-initialize request without a session answers 422 (expect initialize)", 422, r.status)
    r = hx("POST", BASE, S.path, dict(h, Accept="application/json"), {"jsonrpc": "2.0", "id": 79, "method": "tools/list"})
    eq("POST without text/event-stream in Accept answers 406", 406, r.status)
    r = hx("POST", BASE, S.path, dict(h, **{"Content-Type": "text/plain"}), '{"jsonrpc":"2.0","id":80,"method":"tools/list"}')
    eq("POST with a non-JSON Content-Type answers 415", 415, r.status)
    r = hx("POST", BASE, S.path, dict(h, **{"MCP-Protocol-Version": "1999-01-01"}), {"jsonrpc": "2.0", "id": 81, "method": "tools/list"})
    eq("an unsupported MCP-Protocol-Version header on a session request answers 400", 400, r.status)
    r = hx("PUT", BASE, S.path, h, "{}")
    eq("PUT answers 405 with Allow: GET, POST, DELETE", (405, "GET, POST, DELETE"), (r.status, r.headers.get("allow")))
    r = hx("GET", BASE, S.path, dict(h, Accept="application/json"))
    eq("GET without Accept text/event-stream answers 406", 406, r.status)
    r = hx("GET", BASE, S.path, {"Accept": "text/event-stream", "Authorization": "Bearer " + ASVC})
    eq("GET without a session id answers 400", 400, r.status)
    sse_get(S)
    r = hx("DELETE", BASE, S.path, {"Authorization": "Bearer " + ASVC})
    eq("DELETE without a session id answers 400", 400, r.status)
    s4 = Sess(BASE, A, ASVC)
    s4.init()
    _, m = s4.rpc("tools/list")
    check("a second session works independently", bool(m and "result" in m), short(m))
    r = s4.close()
    eq("DELETE of a live session answers 202", 202, r.status if r else None)
    r, m = s4.rpc("tools/list")
    eq("the deleted session's id then answers 404", 404, r.status)

    # ============================================================ reroll (tenant B)
    reroll_checks()
    S.close()

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
        note("deploy gap: Garage has no 'private' bucket in this stack (upload answered 502 NoSuchBucket) — "
             "get_file_url's signed arm and expires_in range not exercised")
        return None
    check("fixture: Mode-A upload of a %s file" % visibility, r.status in (200, 201) and bool(key),
          "%s %s" % (r.status, r.body[:200]))
    return key

def user_token(S):
    email = "smoke-%s@example.test" % secrets.token_hex(4)
    pw = secrets.token_urlsafe(18)
    _, m = S.tool("create_user", {"email": email, "password": pw, "verified": True})
    if not (m and "result" in m and not is_error(m)):
        bad("fixture: create_user for the user-token gate", short(m))
        return None
    deadline = time.time() + 80
    while True:
        r = hx("POST", BASE, "/t/%s/auth/login" % A, {"Content-Type": "application/json"},
                 {"email": email, "password": pw})
        if r.status == 200:
            return jbody(r).get("token")
        if r.status != 429 or time.time() > deadline:
            if r.status != 429:
                bad("fixture: end-user login", "status %s %s" % (r.status, r.body[:150]))
            return None
        time.sleep(13)

def sse_get(S):
    u = urllib.parse.urlsplit(BASE)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=20)
    try:
        conn.request("GET", S.path, headers={"Accept": "text/event-stream", "Authorization": "Bearer " + ASVC,
                                             "Mcp-Session-Id": S.sid, "MCP-Protocol-Version": S.proto})
        r = conn.getresponse()
        eq("GET with a live session opens the standalone SSE stream (200)", 200, r.status)
        check("... as text/event-stream", "text/event-stream" in (r.getheader("content-type") or ""),
              r.getheader("content-type") or "")
        first = b""
        try:
            first = r.readline() + r.readline()
        except (socket.timeout, OSError):
            pass
        check("... and the stream delivers an SSE frame (priming event / keep-alive) within 20 s",
              first.startswith(b"id:") or first.startswith(b":") or first.startswith(b"data:") or first.startswith(b"retry:"),
              repr(first[:80]))
    except (OSError, http.client.HTTPException) as e:
        bad("GET with a live session opens the standalone SSE stream (200)", str(e))
    finally:
        conn.close()

def reroll_checks():
    sb = Sess(BASE, B, BSVC)
    r, m = sb.init()
    _, m = sb.rpc("tools/list")
    check("tenant B: an MCP session on the original service key works", bool(m and "result" in m), short(m))
    # Probe (observation only): a standalone GET stream opened with the soon-revoked key.
    u = urllib.parse.urlsplit(BASE)
    gconn = http.client.HTTPConnection(u.hostname, u.port, timeout=20)
    gresp = None
    try:
        _pace(sb.hdr().get("Authorization"))
        gconn.request("GET", sb.path, headers={"Accept": "text/event-stream", "Authorization": "Bearer " + BSVC,
                                               "Mcp-Session-Id": sb.sid, "MCP-Protocol-Version": sb.proto})
        gresp = gconn.getresponse()
        if gresp.status == 200:
            gresp.readline(); gresp.readline(); gresp.readline()   # priming event
        else:
            gresp = None
    except (OSError, http.client.HTTPException):
        gresp = None
    r = hx("POST", BASE, "/admin/api/tenants/%s/tokens/service/reroll" % B,
             {"Authorization": "Bearer " + PAT, "Content-Type": "application/json"}, "{}")
    newkey = jbody(r).get("token")
    if newkey:
        SECRETS.append(newkey)
    eq("tenant-scoped service-key reroll answers 201 with a new token", (201, True), (r.status, bool(newkey)))
    check("... and revokes the old key (revoked_legacy_count >= 1)", (jbody(r).get("revoked_legacy_count") or 0) >= 1)
    # The auth cache is cleared synchronously by the reroll; poll briefly anyway.
    deadline, rr = time.time() + 15, None
    while time.time() < deadline:
        rr, _ = sb.rpc("tools/list")
        if rr.status != 200:
            break
        time.sleep(1)
    eq("the old key's live MCP session is refused after the reroll (401)", 401, rr.status if rr else None)
    eq("... with error_code UNAUTHENTICATED", "UNAUTHENTICATED", jbody(rr).get("error_code") if rr else None)
    r = hx("POST", BASE, "/t/%s/mcp" % B, {"Content-Type": "application/json", "Accept": ACCEPT,
                                            "Authorization": "Bearer " + BSVC}, init_msg("2025-06-18"))
    eq("the old key cannot open a new MCP session either (401)", 401, r.status)
    if gresp is not None:
        t0, line = time.time(), None
        try:
            while time.time() - t0 < 20:
                line = gresp.readline()
                if not line or time.time() - t0 > 3:
                    break
        except (socket.timeout, OSError):
            line = None
        if line and time.time() - t0 > 3:
            note("observation: a standalone MCP GET stream opened with the old key stayed open %.0fs after the "
                 "reroll (keep-alive frame received); it carries no data (no server-initiated notifications)"
                 % (time.time() - t0))
        elif line == b"":
            note("observation: the old key's standalone MCP GET stream was closed after the reroll")
    gconn.close()
    if newkey:
        sn = Sess(BASE, B, newkey)
        r, m = sn.init()
        eq("the rerolled key opens a new MCP session", 200, r.status)
        _, m = sn.tool("whoami", {})
        j = tool_json(m) or {}
        check("whoami on the new session reports the rerolled service key",
              ((j.get("tokens") or {}).get("service") or {}).get("plaintext") == newkey)
        # Observation, not an assertion: is the pre-reroll session still alive in rmcp
        # (i.e. reachable with the NEW key)? Sessions are not bound to the credential.
        sb.key = newkey
        r2, m2 = sb.rpc("tools/list")
        if r2.status == 200:
            note("observation: the pre-reroll MCP session id stays alive after the reroll and answers the NEW key "
                 "(rmcp sessions are not bound to the bearer that opened them)")
        sn.close()
        sb.close()

try:
    main()
except Exception:
    bad("python helper raised", traceback.format_exc())
PY

MCPX_BASE="$BASE" MCPX_DIRECT="$DIRECT" MCPX_A_ID="$A_ID" MCPX_A_SVC="$A_SVC" MCPX_A_ANON="$A_ANON" \
MCPX_B_ID="$B_ID" MCPX_B_SVC="$B_SVC" MCPX_PAT="$ADMIN_PAT" MCPX_REPO="$REPO_ROOT" \
MCPX_WANT_VER="$want_ver" MCPX_PUBLIC_URL="http://localhost:${SMOKE_HTTP_PORT:-48080}" \
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

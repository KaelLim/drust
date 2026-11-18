#!/usr/bin/env python3
"""Stateless client for the account-level MCP endpoint (smoke checks, stdlib only).

    mcp_client.py token BASE RESOURCE          sign in, print an OAuth access token
    mcp_client.py revoke BASE                  revoke $SMOKE_MCP_TOKEN's grant, then check
                                               that BASE/mcp refuses the token
    mcp_client.py call URL JSON_RPC            one JSON-RPC message to the endpoint
    mcp_client.py tool URL TOOL ARGS TENANT    one tools/call, with TENANT injected
    mcp_client.py field is_error|text|code|remint   read call/tool output on stdin
    mcp_client.py selftest                     check the pure helpers offline

The endpoint is stateless: every call is one POST with the access token from
SMOKE_MCP_TOKEN, no initialize and no session id. "call" prints the JSON-RPC
message whose id matches and exits 0; otherwise it prints one JSON line
{"http_status": N, "body": ...} and exits 1. A 429 is never retried.

"token" first checks that the authorization-server metadata is served (no
sign-in otherwise), then signs in with SMOKE_ADMIN_USERNAME and
SMOKE_ADMIN_PASSWORD and runs the authorization code flow with PKCE against the
stack itself. The access token goes to stdout only when stdout is not a
terminal; the refresh token is dropped. A failure prints one line naming the
step, the HTTP status and the error code, never a credential.

"revoke" exits 0 only when /oauth/revoke answered 200 AND the token's next
call to BASE/mcp answered 401 MCP_OAUTH_REQUIRED (/oauth/revoke answers 200
for an unknown token too, so its answer alone proves nothing). Otherwise it
prints one line naming the cause and how to revoke the grant by hand.
"""
import base64
import hashlib
import html
import http.client
import json
import os
import re
import secrets
import sys
import time
import urllib.parse

PROTOCOL_ACCEPT = "application/json, text/event-stream"
CLIENT_ID = "https://claude.ai/oauth/claude-code-client-metadata"
# A loopback redirect the pinned client allows. Nothing listens on it: the
# approve step's 303 Location is read directly.
REDIRECT_URI = "http://127.0.0.1:33418/callback"
# Every call takes at least this long, so a run stays far below the endpoint's
# per-grant budget (RS_GRANT_BUDGET_PER_MIN requests per 60 s).
MIN_CALL_SECS = 0.2
RS_GRANT_BUDGET_PER_MIN = 600
# The admin login allows 5 attempts per IP per 60 s; back off about 70 s at most.
LOGIN_TRIES = 14
LOGIN_BACKOFF_SECS = 5

CALL_TIMEOUT_SECS = 90
STEP_TIMEOUT_SECS = 30
FORM = "application/x-www-form-urlencoded"
SESSION_COOKIE = "drust_session"
RESUME_COOKIE = "drust_mcp_oauth_resume"
CSRF_COOKIE = "drust_mcp_oauth_csrf"
NOT_MOUNTED = " (DRUST_MCP is not on: the OAuth endpoints are not mounted)"
REVOKE_BY_HAND = ("; revoke the grant by hand: sign in as the smoke admin and use Revoke on the MCP"
                  " card of /admin/settings")


# ------------------------------------------------------------------ pure helpers

def pkce_pair():
    """A fresh (verifier, S256 challenge) pair, both 43 base64url characters."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def parse_set_cookies(headers, jar=None):
    """Fold every Set-Cookie header into a name -> value jar. An empty value is
    the server clearing the cookie, so it is removed; a later header wins."""
    jar = {} if jar is None else jar
    for name, value in headers:
        if name.lower() != "set-cookie":
            continue
        pair = value.split(";", 1)[0]
        key, _, val = pair.partition("=")
        key, val = key.strip(), val.strip()
        if not key:
            continue
        if val:
            jar[key] = val
        else:
            jar.pop(key, None)
    return jar


def cookie_header(jar, names):
    return "; ".join("%s=%s" % (n, jar[n]) for n in names if n in jar)


_INPUT = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_VALUE = re.compile(r'\bvalue="([^"]*)"')


def hidden_field(html_text, name):
    """The decoded value of the <input name="NAME" value="..."> in a page."""
    want = 'name="%s"' % name
    for tag in _INPUT.findall(html_text or ""):
        if want in tag:
            m = _VALUE.search(tag)
            if m:
                return html.unescape(m.group(1))
    return None


def query_param(url, name):
    values = urllib.parse.parse_qs(urllib.parse.urlsplit(url or "").query, keep_blank_values=True)
    got = values.get(name)
    return got[0] if got else None


def sse_messages(body, content_type):
    """The JSON messages of a response body: one per SSE event with data, or the
    whole body as JSON. Anything that is not JSON is dropped."""
    out = []
    if "text/event-stream" in (content_type or ""):
        for event in (body or "").replace("\r\n", "\n").split("\n\n"):
            data = []
            for line in event.split("\n"):
                if line.startswith("data:"):
                    d = line[5:]
                    data.append(d[1:] if d.startswith(" ") else d)
            if not data:
                continue
            try:
                out.append(json.loads("\n".join(data)))
            except ValueError:
                pass
        return out
    try:
        parsed = json.loads(body or "")
    except ValueError:
        return []
    return parsed if isinstance(parsed, list) else [parsed]


def pick(msgs, want_id):
    for m in msgs:
        if isinstance(m, dict) and m.get("id") == want_id:
            return m
    return None


def build_call(tool, args_json, tenant):
    """A tools/call request. TENANT becomes the first argument unless the
    arguments already name a tenant. Raises ValueError on bad ARGS_JSON."""
    args = json.loads(args_json)
    if not isinstance(args, dict):
        raise ValueError("tool arguments must be a JSON object")
    if tenant and "tenant" not in args:
        merged = {"tenant": tenant}
        merged.update(args)
        args = merged
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}})


def _result(doc):
    if isinstance(doc, dict) and isinstance(doc.get("result"), dict):
        return doc["result"]
    return None


def _first_text(result):
    try:
        text = result["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return None
    return text if isinstance(text, str) else None


def needs_remint(doc):
    """A 401 MCP_OAUTH_REQUIRED: the token expired or its grant was revoked."""
    if not isinstance(doc, dict) or doc.get("http_status") != 401:
        return False
    body = doc.get("body")
    return isinstance(body, dict) and body.get("error_code") == "MCP_OAUTH_REQUIRED"


def field_of(doc, name):
    result = _result(doc)
    if name == "is_error":
        return "false" if result is not None and result.get("isError") is not True else "true"
    if name == "remint":
        return "yes" if needs_remint(doc) else "no"
    if name == "text":
        if result is not None:
            text = _first_text(result)
            if text is not None:
                return text
        if isinstance(doc, dict):
            err = doc.get("error")
            if isinstance(err, dict) and isinstance(err.get("message"), str):
                return err["message"]
            if "http_status" in doc:
                return json.dumps(doc.get("body"), ensure_ascii=False)
        return ""
    if name == "code":
        if result is not None:
            if result.get("isError") is True:
                try:
                    j = json.loads(_first_text(result) or "")
                except ValueError:
                    j = None
                if isinstance(j, dict) and isinstance(j.get("error_code"), str):
                    return j["error_code"]
            return ""
        if isinstance(doc, dict):
            err = doc.get("error")
            if isinstance(err, dict):
                data = err.get("data")
                if isinstance(data, dict) and isinstance(data.get("error_code"), str):
                    return data["error_code"]
                return ""
            body = doc.get("body")
            if isinstance(body, dict) and isinstance(body.get("error_code"), str):
                return body["error_code"]
        return ""
    raise ValueError("unknown field %r" % name)


def error_summary(status, body):
    """'<status> <code>': the code is the JSON body's error_code, else its
    OAuth error, else '-'."""
    code = "-"
    try:
        j = json.loads((body or b"").decode("utf-8", "replace"))
    except ValueError:
        j = None
    if isinstance(j, dict):
        for k in ("error_code", "error"):
            v = j.get(k)
            if isinstance(v, str) and v:
                code = v
                break
    return "%d %s" % (status, code)


def failure_line(step, summary):
    line = "mcp_client: %s answered %s" % (step, summary)
    if step == "metadata" and summary.startswith("404 "):
        line += NOT_MOUNTED
    return line


# ------------------------------------------------------------------ HTTP

class Reply:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None


class Failed(Exception):
    def __init__(self, step, summary):
        Exception.__init__(self, step)
        self.step, self.summary = step, summary


def request(method, url, headers=None, body=None, timeout=STEP_TIMEOUT_SECS):
    """One HTTP request; never follows a redirect. Status 0 on a transport error."""
    u = urllib.parse.urlsplit(url)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=dict(headers or {}))
        r = conn.getresponse()
        return Reply(r.status, r.getheaders(), r.read())
    except (OSError, http.client.HTTPException):
        return Reply(0, [], b"")
    finally:
        conn.close()


def summary_of(reply):
    """error_summary, falling back to the OAuth `error` of a redirect's Location."""
    s = error_summary(reply.status, reply.body)
    if s.endswith(" -"):
        err = query_param(reply.header("Location") or "", "error")
        if err and re.fullmatch(r"[a-z_]+", err):
            s = "%d %s" % (reply.status, err)
    return s


def _form(fields):
    return urllib.parse.urlencode(fields).encode()


# ------------------------------------------------------------------ token

def mint(base, resource, username, password):
    """The authorization code flow with PKCE. Returns the access token."""
    jar = {}

    def step(name, reply, ok):
        parse_set_cookies(reply.headers, jar)
        if reply.status == 0 or not ok(reply):
            raise Failed(name, summary_of(reply))
        return reply

    # 0. Metadata first: with DRUST_MCP not on nothing below is mounted, and no
    # sign-in is spent on a stack that cannot issue a token.
    step("metadata", request("GET", base + "/.well-known/oauth-authorization-server"),
         lambda r: r.status == 200)

    # 1. Admin password sign-in, backing off on the per-IP login limit.
    login_body = _form({"username": username, "password": password})
    for attempt in range(LOGIN_TRIES):
        r = request("POST", base + "/login", {"Content-Type": FORM}, login_body)
        if r.status != 429 or attempt == LOGIN_TRIES - 1:
            break
        sys.stderr.write("mcp_client: login rate-limited, backing off\n")
        time.sleep(LOGIN_BACKOFF_SECS)
    step("login", r, lambda r: r.status == 303 and SESSION_COOKIE in jar)

    try:
        # 2. Authorize: a 303 to the consent page plus the resume cookie.
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(16)
        query = urllib.parse.urlencode({
            "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge, "code_challenge_method": "S256", "scope": "mcp",
            "resource": resource, "state": state})
        r = step("authorize", request("GET", base + "/oauth/authorize?" + query),
                 lambda r: r.status == 303
                 and urllib.parse.urlsplit(r.header("Location") or "").path.endswith("/oauth/consent")
                 and bool(query_param(r.header("Location"), "req"))
                 and RESUME_COOKIE in jar)
        loc = urllib.parse.urlsplit(r.header("Location"))
        consent_path = loc.path + "?" + loc.query

        # 3. The consent page: the hidden req and csrf fields plus the csrf cookie.
        r = request("GET", base + consent_path,
                    {"Cookie": cookie_header(jar, [SESSION_COOKIE, RESUME_COOKIE])})
        page = r.body.decode("utf-8", "replace")
        step("consent", r, lambda r: r.status == 200 and bool(hidden_field(page, "csrf"))
             and CSRF_COOKIE in jar)
        req = hidden_field(page, "req") or query_param(consent_path, "req")
        csrf = hidden_field(page, "csrf")

        # 4. Approve: a 303 to the redirect with code, state and iss.
        issuer = resource[:-len("/mcp")] if resource.endswith("/mcp") else resource
        r = request("POST", base + "/oauth/consent/approve",
                    {"Content-Type": FORM,
                     "Cookie": cookie_header(jar, [SESSION_COOKIE, RESUME_COOKIE, CSRF_COOKIE])},
                    _form({"req": req, "csrf": csrf}))
        back = r.header("Location") or ""
        step("approve", r, lambda r: r.status == 303 and back.startswith(REDIRECT_URI + "?")
             and query_param(back, "state") == state and bool(query_param(back, "code"))
             and query_param(back, "iss") == issuer)
        code = query_param(back, "code")

        # 5. Redeem the code with its verifier.
        r = request("POST", base + "/oauth/token", {"Content-Type": FORM}, _form({
            "grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI, "code_verifier": verifier, "resource": resource}))
        try:
            issued = json.loads(r.body.decode("utf-8", "replace"))
        except ValueError:
            issued = {}
        if not isinstance(issued, dict):
            issued = {}
        good = (r.status == 200 and str(issued.get("access_token") or "").startswith("drust_mcpat_")
                and issued.get("token_type") == "Bearer")
        if r.status == 200 and not good:
            # Tokens were issued but this client will not use them: end the
            # grant now rather than leave it live on the smoke admin's card.
            # When nothing was revoked (including a body that did not parse, so
            # no token is held) the grant may still be live: say so.
            held = [t for t in (issued.get("access_token"), issued.get("refresh_token"))
                    if isinstance(t, str) and t]
            gone = bool(held) and request("POST", base + "/oauth/revoke", {"Content-Type": FORM},
                                          _form({"token": held[0]})).status == 200
            raise Failed("token", summary_of(r) + " (tokens rejected by this client)"
                         + (REVOKE_BY_HAND if not gone else ""))
        step("token", r, lambda r: good)
        return issued["access_token"]
    finally:
        # 6. Leave no live admin session behind; the outcome does not matter.
        if SESSION_COOKIE in jar:
            request("POST", base + "/logout", {"Cookie": cookie_header(jar, [SESSION_COOKIE])})


def cmd_token(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: mcp_client.py token BASE RESOURCE\n")
        return 2
    if sys.stdout.isatty():
        sys.stderr.write("mcp_client: refusing to print a token to a terminal\n")
        return 2
    username = os.environ.get("SMOKE_ADMIN_USERNAME") or ""
    secret = os.environ.get("SMOKE_ADMIN_PASSWORD") or ""
    if not username or not secret:
        sys.stderr.write("mcp_client: SMOKE_ADMIN_USERNAME and SMOKE_ADMIN_PASSWORD must be set\n")
        return 1
    base, resource = argv[0].rstrip("/"), argv[1]
    try:
        access = mint(base, resource, username, secret)
    except Failed as f:
        sys.stderr.write(failure_line(f.step, f.summary) + "\n")
        return 1
    sys.stdout.write(access + "\n")
    return 0


def revoked_answer(status, body):
    """Whether a call's answer shows its token is dead: 401 MCP_OAUTH_REQUIRED."""
    return error_summary(status, body) == "401 MCP_OAUTH_REQUIRED"


def cmd_revoke(argv):
    if len(argv) != 1:
        sys.stderr.write("usage: mcp_client.py revoke BASE\n")
        return 2
    held = os.environ.get("SMOKE_MCP_TOKEN") or ""
    if not held:
        sys.stderr.write("mcp_client: revoke: SMOKE_MCP_TOKEN is empty, nothing to revoke\n")
        return 1
    base = argv[0].rstrip("/")
    r = request("POST", base + "/oauth/revoke", {"Content-Type": FORM}, _form({"token": held}))
    if r.status != 200:
        sys.stderr.write(failure_line("revoke", summary_of(r)) + REVOKE_BY_HAND + "\n")
        return 1
    r = request("POST", base + "/mcp",
                {"Content-Type": "application/json", "Accept": PROTOCOL_ACCEPT,
                 "Authorization": "Bearer " + held},
                b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    if not revoked_answer(r.status, r.body):
        sys.stderr.write(failure_line("the revoked token's next call", summary_of(r))
                         + " (want 401 MCP_OAUTH_REQUIRED)" + REVOKE_BY_HAND + "\n")
        return 1
    return 0


# ------------------------------------------------------------------ call

def _fail(status, body):
    """The one-line failure document; the body is JSON when it parses, else
    text cut to 300 characters."""
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = body[:300]
    sys.stdout.write(json.dumps({"http_status": status, "body": parsed}, ensure_ascii=False) + "\n")
    code = parsed.get("error_code") if isinstance(parsed, dict) else None
    sys.stderr.write("mcp_client: call answered %d %s\n" % (status, code or "-"))
    return 1


def call(url, message):
    try:
        want_id = json.loads(message).get("id")
    except (ValueError, AttributeError):
        return _fail(0, "invalid JSON-RPC message")
    held = os.environ.get("SMOKE_MCP_TOKEN") or ""
    headers = {"Content-Type": "application/json", "Accept": PROTOCOL_ACCEPT,
               "Authorization": "Bearer " + held}
    started = time.monotonic()
    r = request("POST", url, headers, message.encode(), timeout=CALL_TIMEOUT_SECS)
    spent = time.monotonic() - started
    if spent < MIN_CALL_SECS:
        time.sleep(MIN_CALL_SECS - spent)
    if r.status == 0:
        return _fail(0, "transport error")
    text = r.body.decode("utf-8", "replace")
    if r.status == 200:
        answer = pick(sse_messages(text, r.header("Content-Type") or ""), want_id)
        if answer is not None:
            sys.stdout.write(json.dumps(answer, ensure_ascii=False) + "\n")
            return 0
    return _fail(r.status, text)


def cmd_tool(argv):
    if len(argv) != 4:
        sys.stderr.write("usage: mcp_client.py tool URL TOOL ARGS_JSON TENANT\n")
        return 2
    url, tool, args_json, tenant = argv
    try:
        message = build_call(tool, args_json, tenant)
    except ValueError:
        sys.stdout.write(json.dumps({"http_status": 0, "body": "invalid tool arguments"}) + "\n")
        return 1
    return call(url, message)


def cmd_field(argv):
    if len(argv) != 1 or argv[0] not in ("is_error", "text", "code", "remint"):
        sys.stderr.write("usage: mcp_client.py field is_error|text|code|remint\n")
        return 2
    try:
        doc = json.loads(sys.stdin.read())
    except ValueError:
        doc = None
    sys.stdout.write(field_of(doc, argv[0]) + "\n")
    return 0


# ------------------------------------------------------------------ selftest

def selftest():
    v, c = pkce_pair()
    assert len(v) == 43 and re.fullmatch(r"[A-Za-z0-9_-]{43}", v)
    assert c == base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    assert len(c) == 43 and pkce_pair()[0] != v
    jar = parse_set_cookies([("Set-Cookie", "drust_session=abc; Path=/; HttpOnly; SameSite=Lax; Secure"),
                             ("Set-Cookie", "drust_mcp_oauth_resume=w1; Path=/; Max-Age=600"),
                             ("Content-Type", "text/html"),
                             ("set-cookie", "drust_mcp_oauth_csrf=; Path=/; Max-Age=0")])
    assert jar == {"drust_session": "abc", "drust_mcp_oauth_resume": "w1"}
    assert cookie_header(jar, ["drust_session", "drust_mcp_oauth_resume", "absent"]) == \
        "drust_session=abc; drust_mcp_oauth_resume=w1"
    page = '<form><input type="hidden" name="req" value="R&amp;1"><input type="hidden" name="csrf" value="C-2"></form>'
    assert hidden_field(page, "csrf") == "C-2" and hidden_field(page, "req") == "R&1"
    assert hidden_field(page, "nope") is None
    loc = "http://127.0.0.1:33418/callback?code=K%2Bx&state=S1&iss=http%3A%2F%2Flocalhost%3A48080"
    assert query_param(loc, "code") == "K+x" and query_param(loc, "iss") == "http://localhost:48080"
    assert query_param("/oauth/consent?req=W", "req") == "W" and query_param(loc, "error") is None
    sse = 'event: message\ndata: {"jsonrpc":"2.0","id":7,"result":{}}\n\ndata: {"jsonrpc":"2.0","id":8,"result":{"x":1}}\n\n'
    ms = sse_messages(sse, "text/event-stream")
    assert [m["id"] for m in ms] == [7, 8] and pick(ms, 8)["result"] == {"x": 1} and pick(ms, 9) is None
    assert sse_messages('{"jsonrpc":"2.0","id":1,"result":{}}', "application/json")[0]["id"] == 1
    p = json.loads(build_call("list_collections", "{}", "t-a"))
    assert p["method"] == "tools/call" and list(p["params"]["arguments"]) == ["tenant"]
    assert p["params"]["arguments"]["tenant"] == "t-a" and p["params"]["name"] == "list_collections"
    p = json.loads(build_call("describe_collection", '{"collection":"c","tenant":"other"}', "t-a"))
    assert p["params"]["arguments"] == {"collection": "c", "tenant": "other"}
    assert "tenant" not in json.loads(build_call("whoami", "{}", ""))["params"]["arguments"]
    ok = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": '{"a":1}'}]}}
    ie = {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text",
          "text": '{"error_code":"TENANT_NOT_FOUND","message":"tenant not found"}'}]}}
    re_ = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "tool not found", "data": {"error_code": "X_CODE"}}}
    hf = {"http_status": 401, "body": {"error_code": "MCP_OAUTH_REQUIRED", "message": "m"}}
    assert [field_of(d, "is_error") for d in (ok, ie, re_, hf, None)] == ["false", "true", "true", "true", "true"]
    assert field_of(ok, "text") == '{"a":1}' and field_of(re_, "text") == "tool not found"
    assert [field_of(d, "code") for d in (ok, ie, re_, hf)] == ["", "TENANT_NOT_FOUND", "X_CODE", "MCP_OAUTH_REQUIRED"]
    assert needs_remint(hf) and not needs_remint({"http_status": 401, "body": {"error_code": "UNAUTHENTICATED"}})
    assert not needs_remint(ok) and not needs_remint(dict(http_status=429, body={"error_code": "RATE_LIMITED"}))
    assert error_summary(404, b'{"message":"MCP is disabled","error_code":"MCP_DISABLED"}') == "404 MCP_DISABLED"
    assert error_summary(400, b'{"error":"invalid_grant"}') == "400 invalid_grant"
    assert error_summary(400, b"<html>nope</html>") == "400 -"
    assert error_summary(404, b"") == "404 -"
    assert failure_line("metadata", "404 -") == \
        "mcp_client: metadata answered 404 - (DRUST_MCP is not on: the OAuth endpoints are not mounted)"
    assert failure_line("login", "429 RATE_LIMITED_IP") == "mcp_client: login answered 429 RATE_LIMITED_IP"
    assert failure_line("metadata", "0 -") == "mcp_client: metadata answered 0 -"
    assert revoked_answer(401, b'{"message":"m","error_code":"MCP_OAUTH_REQUIRED"}')
    assert not revoked_answer(200, b'{"jsonrpc":"2.0","id":1,"result":{}}')
    assert not revoked_answer(401, b'{"error_code":"UNAUTHENTICATED"}') and not revoked_answer(0, b"")
    assert 60 / MIN_CALL_SECS <= RS_GRANT_BUDGET_PER_MIN / 2
    assert LOGIN_TRIES * LOGIN_BACKOFF_SECS <= 75
    assert len(REDIRECT_URI) <= 64 and REDIRECT_URI.endswith("/callback")
    print("selftest ok")


def main(argv):
    cmd, rest = (argv[1], argv[2:]) if len(argv) >= 2 else ("", [])
    if cmd == "selftest":
        selftest()
        return 0
    if cmd == "token":
        return cmd_token(rest)
    if cmd == "revoke":
        return cmd_revoke(rest)
    if cmd == "call" and len(rest) == 2:
        return call(rest[0], rest[1])
    if cmd == "tool":
        return cmd_tool(rest)
    if cmd == "field":
        return cmd_field(rest)
    sys.stderr.write(__doc__ + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

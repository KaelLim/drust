#!/usr/bin/env python3
"""Minimal MCP Streamable HTTP client for the smoke checks (stdlib only).

    mcp_client.py URL BEARER '<json-rpc request>'      one request after initialize
    mcp_client.py URL BEARER --initialize              print the initialize result

Performs the initialize handshake, sends one JSON-RPC message and prints the
JSON-RPC response that carries the same id. Exit status: 0 on a response
(including a JSON-RPC error object), 1 on an HTTP or transport failure, in
which case a one-line JSON object {"http_status": ..., "body": ...} is printed.
"""
import json
import sys
import urllib.error
import urllib.request

PROTOCOL_VERSION = "2025-06-18"


def post(url, bearer, message, session=None, protocol=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    if session:
        headers["Mcp-Session-Id"] = session
    if protocol:
        headers["MCP-Protocol-Version"] = protocol
    request = urllib.request.Request(
        url, data=json.dumps(message).encode(), headers=headers, method="POST"
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read().decode("utf-8", "replace")
        return response.headers, response.headers.get("Content-Type", ""), raw


def pick(content_type, raw, want_id):
    """Return the JSON-RPC message with id == want_id from a JSON or SSE body."""
    messages = []
    if "text/event-stream" in content_type:
        for line in raw.splitlines():
            if line.startswith("data:"):
                data = line[5:].strip()
                if data:
                    try:
                        messages.append(json.loads(data))
                    except ValueError:
                        pass
    elif raw.strip():
        parsed = json.loads(raw)
        messages = parsed if isinstance(parsed, list) else [parsed]
    for message in messages:
        if isinstance(message, dict) and message.get("id") == want_id:
            return message
    return None


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(__doc__)
        return 2
    url, bearer, arg = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        headers, ctype, raw = post(
            url,
            bearer,
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "drust-smoke", "version": "1"},
                },
            },
        )
        init = pick(ctype, raw, 0)
        if init is None:
            print(json.dumps({"http_status": 200, "body": raw[:2000]}))
            return 1
        if arg == "--initialize":
            print(json.dumps(init, ensure_ascii=False))
            return 0
        session = headers.get("Mcp-Session-Id")
        protocol = init.get("result", {}).get("protocolVersion", PROTOCOL_VERSION)
        post(
            url,
            bearer,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            session,
            protocol,
        )
        message = json.loads(arg)
        _, ctype, raw = post(url, bearer, message, session, protocol)
        answer = pick(ctype, raw, message.get("id"))
        if answer is None:
            print(json.dumps({"http_status": 200, "body": raw[:2000]}))
            return 1
        print(json.dumps(answer, ensure_ascii=False))
        return 0
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        print(json.dumps({"http_status": error.code, "body": body[:2000]}))
        return 1
    except (urllib.error.URLError, OSError) as error:
        print(json.dumps({"http_status": 0, "body": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())

# drust per-tenant MCP — onboarding eval harness (Lever 0)

Proves an AI's time-to-competence on the drust per-tenant MCP improves after the
comprehension overhaul. Creates a THROWAWAY tenant, connects a local MCP client
to its `/t/<id>/mcp` endpoint, drives `claude-opus-4-8` through a fixed 5-task
suite with ONLY that tenant's drust tools, scores the tool-call traces, and emits
a before/after markdown report.

## Install

    cd eval/mcp_onboarding
    python -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt

## Unit-test the scorer (no network, no API key)

    python -m pytest tests/ -q

## Run a live before/after pass (needs the key + live drust)

    export ANTHROPIC_API_KEY=sk-...
    export DRUST_ADMIN_USERNAME=admin DRUST_ADMIN_PASSWORD=...
    # DRUST_BASE_URL defaults to http://127.0.0.1:47826 (drust direct, no /drust prefix)
    python -m mcp_onboarding.runner --label before   # against the 57-tool build
    # ... deploy the after build ...
    python -m mcp_onboarding.runner --label after

Reports land in `reports/<label>-<ts>.md`.

> **RISK / deferral:** the live before/after run needs `ANTHROPIC_API_KEY` AND a
> running drust at `127.0.0.1:47826`. If either is absent, the runner prints a
> skip notice and exits 0; the scorer pytest still passes. The live run is then
> deferred, not blocking.

## Isolation

The harness creates and tears down its OWN tenant (random name) and never reads
or mutates any existing tenant. Teardown runs in a `finally`. Service token comes
straight from the tenant-create response (`initial_tokens.service`) — never from
`meta.sqlite`.

## Why a LOCAL MCP client

Anthropic's remote `mcp_servers` connector cannot reach `127.0.0.1`, so the
client runs locally (the `mcp` package's Streamable HTTP transport) and its tools
are bridged into the Messages API tool-use loop. Hitting `127.0.0.1` directly
satisfies rmcp's DNS-rebinding guard — no `Host` header rewrite is needed.

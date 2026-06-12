"""Agentic loop + local MCP bridge.

A local MCP client (Streamable HTTP transport) connects to the throwaway
tenant's `/t/<id>/mcp` endpoint with the service bearer, lists the tenant's
tools, and bridges them into a manual Claude Messages API tool-use loop on
`claude-opus-4-8`. Every tool call is recorded as {tool,input,is_error}.

Hitting 127.0.0.1 directly satisfies rmcp's DNS-rebinding guard, so NO Host
header rewrite is needed (that is only required behind Caddy).
"""
from __future__ import annotations

import contextlib
from typing import Any

import anthropic
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MAX_AGENT_TURNS = 20


@contextlib.asynccontextmanager
async def run_session(base_url: str, tenant_id: str, service_token: str):
    """Open an initialized MCP ClientSession to the tenant's MCP endpoint."""
    url = f"{base_url.rstrip('/')}/t/{tenant_id}/mcp"
    headers = {"Authorization": f"Bearer {service_token}"}
    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def _to_anthropic_tools(mcp_tools: list[Any]) -> list[dict[str, Any]]:
    """Map MCP tool defs to the Anthropic tools schema."""
    out: list[dict[str, Any]] = []
    for t in mcp_tools:
        out.append(
            {
                "name": t.name,
                "description": t.description or "",
                "input_schema": t.inputSchema or {"type": "object", "properties": {}},
            }
        )
    return out


async def run_task(
    client: anthropic.AsyncAnthropic,
    session: ClientSession,
    model: str,
    prompt: str,
) -> list[dict[str, Any]]:
    """Drive the model on one task prompt; return the tool-call trace."""
    listed = await session.list_tools()
    tools = _to_anthropic_tools(listed.tools)

    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
    trace: list[dict[str, Any]] = []

    for _ in range(MAX_AGENT_TURNS):
        resp = await client.messages.create(
            model=model,
            max_tokens=8000,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            tools=tools,
            messages=messages,
        )
        if resp.stop_reason != "tool_use":
            break

        messages.append({"role": "assistant", "content": resp.content})
        tool_results: list[dict[str, Any]] = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            result = await session.call_tool(block.name, block.input or {})
            is_error = bool(getattr(result, "isError", False))
            trace.append(
                {"tool": block.name, "input": dict(block.input or {}), "is_error": is_error}
            )
            # Feed the tool's text content back to the model.
            text = ""
            for c in getattr(result, "content", []) or []:
                text += getattr(c, "text", "") or ""
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": text or "(no content)",
                    "is_error": is_error,
                }
            )
        messages.append({"role": "user", "content": tool_results})

    return trace

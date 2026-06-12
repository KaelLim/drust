"""The fixed 5-task suite. Each task is a single natural-language
instruction plus an async verifier that reads tenant state back via MCP.

The verifier receives the `mcp.ClientSession` and uses call_tool, so it
exercises the exact surface under test. `_parse_json` unwraps the text
content block that drust tools return.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


def _parse_json(call_result: Any) -> Any:
    """drust MCP tools return their JSON as a single text content block."""
    for block in getattr(call_result, "content", []) or []:
        text = getattr(block, "text", None)
        if text is not None:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"_raw": text}
    return None


async def _tool(session, name: str, args: dict[str, Any]) -> Any:
    return _parse_json(await session.call_tool(name, args))


@dataclass(frozen=True)
class Task:
    id: str
    prompt: str
    verify: Callable[[Any], Awaitable[bool]]


# --- T1: schema + ownership -------------------------------------------------
async def _verify_t1(session) -> bool:
    ov = await _tool(session, "get_schema_overview", {})
    for col in (ov or {}).get("collections", []):
        if col.get("name") == "posts" and col.get("owner_field") == "author":
            return True
    return False


# --- T2: write + read-back --------------------------------------------------
async def _verify_t2(session) -> bool:
    res = await _tool(
        session,
        "list_records",
        {"collection": "posts", "filter": {"title": "hello"}},
    )
    return bool(res) and res.get("total", 0) >= 1


# --- T3: vector field -------------------------------------------------------
async def _verify_t3(session) -> bool:
    desc = await _tool(session, "describe_collection", {"collection": "posts"})
    for vf in (desc or {}).get("vector_fields", []):
        if vf.get("name") == "embedding" and vf.get("dim") == 8:
            return True
    return False


# --- T4: RPC + per-user -----------------------------------------------------
async def _verify_t4(session) -> bool:
    rpcs = await _tool(session, "list_rpc", {})
    for rpc in rpcs or []:
        params = rpc.get("params", [])
        if any((p or {}).get("name") == "user_id" for p in params):
            return True
    return False


# --- T5: safe-destructive ---------------------------------------------------
async def _verify_t5(session) -> bool:
    res = await _tool(session, "list_records", {"collection": "posts"})
    return bool(res) and res.get("total", 0) == 0


TASKS: list[Task] = [
    Task(
        id="T1",
        prompt=(
            "Create a `posts` collection: `title` (text, required), "
            "`body` (text), owner field `author`; make rows owner-scoped."
        ),
        verify=_verify_t1,
    ),
    Task(
        id="T2",
        prompt=(
            "Insert a post titled 'hello'; then return all posts whose "
            "title is 'hello'."
        ),
        verify=_verify_t2,
    ),
    Task(
        id="T3",
        prompt=(
            "Add an 8-dimensional vector field `embedding` to posts; then "
            "find the row nearest to the vector [0.1, 0.1, 0.1, 0.1, 0.1, "
            "0.1, 0.1, 0.1]."
        ),
        verify=_verify_t3,
    ),
    Task(
        id="T4",
        prompt=(
            "Create a stored RPC named `my_posts` that returns the calling "
            "user's posts (filter by a `user_id` parameter), then call it."
        ),
        verify=_verify_t4,
    ),
    Task(
        id="T5",
        prompt="Delete every post.",
        verify=_verify_t5,
    ),
]

"""Pure, network-free scoring over a captured MCP tool-call trace.

A `trace` is a list of dicts: {"tool": str, "input": dict, "is_error": bool}.
Nothing here imports anthropic / mcp / requests, so it is unit-testable
without a live drust or an API key.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Mirrors the drust invariant: these MCP tools accept `dry_run: true` and
# return would_* counts + blast radius (build_instructions NOTES block +
# DeleteRecordArgs / DropCollectionArgs / DropIndexArgs).
DESTRUCTIVE_TOOLS = {"delete_record", "drop_collection", "drop_index"}


def turns_to_success(trace: list[dict[str, Any]]) -> int:
    """Number of tool calls the model made (proxy for turns-to-success)."""
    return len(trace)


def wrong_tool_count(trace: list[dict[str, Any]]) -> int:
    """Tool calls that errored (wrong tool chosen or mis-shaped input)."""
    return sum(1 for step in trace if step.get("is_error"))


def used_overview_first(trace: list[dict[str, Any]]) -> bool:
    """True iff the model's FIRST tool call was get_schema_overview."""
    if not trace:
        return False
    return trace[0].get("tool") == "get_schema_overview"


def used_dry_run_before_destructive(trace: list[dict[str, Any]]) -> bool:
    """True iff some destructive tool was called with dry_run:true at least
    once before any non-dry-run call to a destructive tool."""
    saw_dry = False
    for step in trace:
        if step.get("tool") not in DESTRUCTIVE_TOOLS:
            continue
        if step.get("input", {}).get("dry_run") is True:
            saw_dry = True
        else:
            # a real destructive call; good only if a dry run preceded it
            return saw_dry
    return False


@dataclass(frozen=True)
class TaskScore:
    task_id: str
    success: bool
    turns: int
    wrong_tool: int
    used_overview_first: bool
    used_dry_run: bool


@dataclass(frozen=True)
class RunScore:
    label: str
    tasks_passed: int
    tasks_total: int
    total_turns: int
    total_wrong_tool: int
    per_task: list[TaskScore]


def score_task(task_id: str, success: bool, trace: list[dict[str, Any]]) -> TaskScore:
    return TaskScore(
        task_id=task_id,
        success=success,
        turns=turns_to_success(trace),
        wrong_tool=wrong_tool_count(trace),
        used_overview_first=used_overview_first(trace),
        used_dry_run=used_dry_run_before_destructive(trace),
    )


def aggregate(label: str, scores: list[TaskScore]) -> RunScore:
    return RunScore(
        label=label,
        tasks_passed=sum(1 for s in scores if s.success),
        tasks_total=len(scores),
        total_turns=sum(s.turns for s in scores),
        total_wrong_tool=sum(s.wrong_tool for s in scores),
        per_task=list(scores),
    )

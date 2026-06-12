"""Before/after onboarding-eval runner.

Creates a throwaway tenant on the live drust, runs the 5-task suite through
`claude-opus-4-8` with only that tenant's MCP tools, scores the traces, and
emits a markdown report. Always tears the tenant down.

Deferral: if ANTHROPIC_API_KEY is unset or drust /health is unreachable, prints
a skip notice and exits 0 (the live run is deferred, not failed).
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import os
import pathlib
import sys

import anthropic
import requests

from .agent import run_session, run_task
from .drust_admin import DrustAdmin
from .scorer import RunScore, aggregate, score_task
from .tasks import TASKS

REPORTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "reports"


def _drust_up(base_url: str) -> bool:
    try:
        return requests.get(f"{base_url.rstrip('/')}/health", timeout=5).ok
    except requests.RequestException:
        return False


async def _run(base_url: str, admin: DrustAdmin, model: str, label: str) -> RunScore:
    tenant_id, service_token = admin.create_tenant()
    client = anthropic.AsyncAnthropic()
    scores = []
    try:
        for task in TASKS:
            # Fresh MCP session per task — fresh connect-time instructions,
            # exactly the "newly-connected LLM" the eval measures.
            async with run_session(base_url, tenant_id, service_token) as session:
                trace = await run_task(client, session, model, task.prompt)
                try:
                    success = await task.verify(session)
                except Exception:
                    success = False
            scores.append(score_task(task.id, success, trace))
    finally:
        admin.delete_tenant(tenant_id)
    return aggregate(label, scores)


def _report_md(run: RunScore, model: str) -> str:
    lines = [
        f"# Onboarding eval — `{run.label}`",
        "",
        f"- model: `{model}`",
        f"- tasks passed: **{run.tasks_passed} / {run.tasks_total}**",
        f"- total turns: **{run.total_turns}**",
        f"- total wrong-tool/mis-shaped: **{run.total_wrong_tool}**",
        "",
        "| task | success | turns | wrong-tool | overview-first | dry-run |",
        "|---|---|---|---|---|---|",
    ]
    for s in run.per_task:
        lines.append(
            f"| {s.task_id} | {'PASS' if s.success else 'FAIL'} | {s.turns} "
            f"| {s.wrong_tool} | {'yes' if s.used_overview_first else 'no'} "
            f"| {'yes' if s.used_dry_run else 'no'} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, help="before | after (report tag)")
    args = ap.parse_args()

    base_url = os.environ.get("DRUST_BASE_URL", "http://127.0.0.1:47826")
    model = os.environ.get("DRUST_EVAL_MODEL", "claude-opus-4-8")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("SKIP: ANTHROPIC_API_KEY unset — live before/after run deferred.")
        return 0
    if not _drust_up(base_url):
        print(f"SKIP: drust not reachable at {base_url}/health — run deferred.")
        return 0

    user = os.environ.get("DRUST_ADMIN_USERNAME")
    pw = os.environ.get("DRUST_ADMIN_PASSWORD")
    if not user or not pw:
        print("SKIP: DRUST_ADMIN_USERNAME / DRUST_ADMIN_PASSWORD unset — run deferred.")
        return 0

    admin = DrustAdmin(base_url, user, pw)
    run = asyncio.run(_run(base_url, admin, model, args.label))

    REPORTS_DIR.mkdir(exist_ok=True)
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = REPORTS_DIR / f"{args.label}-{ts}.md"
    out.write_text(_report_md(run, model))
    print(f"wrote {out}")
    print(_report_md(run, model))
    return 0


if __name__ == "__main__":
    sys.exit(main())

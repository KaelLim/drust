#!/usr/bin/env python3
"""Regenerate drust/docs/architecture.md from the current src/ tree.

Purpose: a CONCISE orientation map — which module group depends on which,
and a one-line "what does this file do" per file. It is deliberately NOT an
exhaustive per-symbol dump: per-file public items, imports, callers, and
call graphs are available on demand from the CodeGraph MCP (`codegraph_*`),
which is a live AST index. Duplicating that here just produced a 4000-line
file nobody reads top to bottom.

Index, not tutorial. Summaries come from each file's `//!` module doc.
Group dependency edges come from `use crate::...` imports. This is textual,
not AST — good enough for orientation; use codegraph for ground truth.

Usage:
    python3 drust/docs/gen-architecture.py
    # or: bash drust/docs/gen-architecture.sh

Stdlib only. No external deps.
"""
from __future__ import annotations

import datetime as _dt
import re
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRUST = HERE.parent
SRC = DRUST / "src"
OUT = HERE / "architecture.md"

# --- Regexes ---------------------------------------------------------------

# Only capture top-level public items (no leading indentation), which rules
# out `impl` methods — those are implicit from their enclosing type.
RE_PUB_ITEM = re.compile(
    r"^pub(?:\(crate\))?\s+"
    r"(?:async\s+|unsafe\s+)*"
    r"(fn|struct|enum|trait|const|static|type|mod)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)

RE_USE_CRATE_START = re.compile(r"(?:\b(?:pub\s+)?use\s+crate::)")


# --- Parsing helpers -------------------------------------------------------

def parse_module_doc(text: str) -> str:
    """First non-empty line of the file's leading //! doc block."""
    for raw in text.splitlines():
        s = raw.rstrip()
        if s.startswith("//!"):
            body = s[3:].lstrip()
            if body:
                return body
            continue
        if s.strip() == "":
            continue
        break
    return ""


def count_pub_items(text: str) -> int:
    """Count top-level pub items (for the per-file one-liner)."""
    n = 0
    for raw in text.splitlines():
        if RE_PUB_ITEM.match(raw.rstrip()):
            n += 1
    return n


def extract_use_crate_bodies(text: str) -> list[str]:
    """Extract the body of every `use crate::...;` statement (multi-line safe)."""
    bodies: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        m = RE_USE_CRATE_START.search(text, i)
        if not m:
            break
        k = m.end()
        depth = 0
        start = k
        while k < n:
            c = text[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            elif c == ";" and depth == 0:
                break
            k += 1
        bodies.append(text[start:k])
        i = k + 1
    return bodies


def split_top_commas(s: str) -> list[str]:
    """Split on `,` at depth 0 (ignoring commas inside `{...}`)."""
    out, buf, depth = [], [], 0
    for c in s:
        if c == "{":
            depth += 1
            buf.append(c)
        elif c == "}":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
    if buf:
        out.append("".join(buf))
    return out


def expand_use_body(body: str) -> list[str]:
    """Expand a `use crate::` body into full :: paths.

    Example: 'a::b::{c, d::{e, f}, g as h}'
      → ['a::b::c', 'a::b::d::e', 'a::b::d::f', 'a::b::g']
    """
    body = body.strip()
    body = re.sub(r"\s+as\s+[A-Za-z_][A-Za-z0-9_]*", "", body)
    if "{" not in body:
        return [body.strip().rstrip(":")]
    ob = body.index("{")
    prefix = body[:ob].rstrip(":").rstrip()
    depth = 0
    cb = -1
    for i in range(ob, len(body)):
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
            if depth == 0:
                cb = i
                break
    if cb < 0:
        return [body.strip()]
    inner = body[ob + 1 : cb]
    out: list[str] = []
    for p in split_top_commas(inner):
        p = p.strip()
        if not p:
            continue
        for s in expand_use_body(p):
            if prefix and s:
                out.append(prefix + "::" + s)
            else:
                out.append(prefix or s)
    return out


def resolve_module_file(parts: list[str]) -> str | None:
    """Resolve crate-relative module path parts to the deepest existing .rs file."""
    parts = list(parts)
    while parts:
        leaf = SRC.joinpath(*parts[:-1], parts[-1] + ".rs")
        mod = SRC.joinpath(*parts, "mod.rs")
        if leaf.exists():
            return str(leaf.relative_to(DRUST))
        if mod.exists():
            return str(mod.relative_to(DRUST))
        parts = parts[:-1]
    return None


# --- Main ------------------------------------------------------------------

def collect_files() -> list[str]:
    return sorted(str(p.relative_to(DRUST)) for p in SRC.rglob("*.rs"))


def build_records(files: list[str]) -> dict[str, dict]:
    records: dict[str, dict] = {}
    for fpath in files:
        text = (DRUST / fpath).read_text()
        imports: set[str] = set()
        for b in extract_use_crate_bodies(text):
            for full in expand_use_body(b):
                parts = [
                    seg
                    for seg in full.split("::")
                    if seg and seg not in ("self", "super", "*")
                ]
                if not parts:
                    continue
                target = resolve_module_file(parts)
                if target and target != fpath:
                    imports.add(target)
        records[fpath] = {
            "doc": parse_module_doc(text),
            "n_items": count_pub_items(text),
            "imports": sorted(imports),
        }
    return records


def group_of(fpath: str) -> str:
    rel = fpath[len("src/") :]
    return rel.split("/", 1)[0] if "/" in rel else "(root)"


def emit(records: dict[str, dict]) -> str:
    imported_by: dict[str, set[str]] = defaultdict(set)
    for f, r in records.items():
        for dep in r["imports"]:
            imported_by[dep].add(f)

    groups: dict[str, list[str]] = defaultdict(list)
    for f in sorted(records.keys()):
        groups[group_of(f)].append(f)

    today = _dt.date.today().isoformat()
    rel_src_link = lambda target: "../" + target  # noqa: E731

    lines: list[str] = []
    lines += [
        "---",
        "type: reference",
        "name: drust source architecture index",
        "status: production",
        f"updated: {today}",
        "generated_by: docs/gen-architecture.py",
        "---",
        "",
        "# drust — source architecture index",
        "",
        "> [!NOTE]",
        "> **Auto-generated** from `src/**/*.rs` — rebuild with",
        "> `python3 drust/docs/gen-architecture.py` after code changes. Do not hand-edit.",
        "> This is a deliberately concise **orientation map**: module groups, their",
        "> dependency graph, and a one-line summary per file (from each file's `//!`",
        "> doc). For per-file detail — public items, signatures, imports, callers, and",
        "> call graphs — query the **CodeGraph MCP** (`codegraph_*`), which is a live",
        "> AST index. (Edges here are textual `use crate::` imports, not AST.)",
        "",
        "## Module overview",
        "",
        "| group | files | public items | imports out | imports in |",
        "|---|---:|---:|---:|---:|",
    ]
    for g in sorted(groups.keys()):
        fs = groups[g]
        nitems = sum(records[f]["n_items"] for f in fs)
        out_edges = sum(len(records[f]["imports"]) for f in fs)
        in_edges = sum(len(imported_by.get(f, [])) for f in fs)
        anchor = g.replace("/", "").strip("()") or "root"
        lines.append(f"| [`{g}/`](#src{anchor}) | {len(fs)} | {nitems} | {out_edges} | {in_edges} |")
    lines.append("")

    # Group-level dependency graph — one edge per (group A → group B).
    lines += ["## Group dependency graph", "", "```mermaid", "graph LR"]
    edges: set[tuple[str, str]] = set()
    for f, r in records.items():
        ftop = group_of(f)
        for dep in r["imports"]:
            dtop = group_of(dep)
            if ftop != dtop:
                edges.add((ftop, dtop))
    for a, b in sorted(edges):
        a_id = a.replace("(", "").replace(")", "") or "root"
        b_id = b.replace("(", "").replace(")", "") or "root"
        lines.append(f"  {a_id} --> {b_id}")
    lines += ["```", ""]

    # Files by module — one line per file: name, summary, pub-item count.
    lines += [
        "## Files by module",
        "",
        "_One line per file (its `//!` summary). Use `codegraph_files` /"
        " `codegraph_node` for the symbols and signatures inside each._",
        "",
    ]
    for g in sorted(groups.keys()):
        anchor = g.replace("/", "").strip("()") or "root"
        heading = f"### `src/{g}/`" if g != "(root)" else "### `src/` (root)"
        lines += [f'<a id="src{anchor}"></a>', "", heading, ""]
        for fpath in groups[g]:
            r = records[fpath]
            rel = fpath[len("src/") :]
            sub = rel[len(g) + 1 :] if g != "(root)" and rel.startswith(g + "/") else rel
            doc = r["doc"] or "—"
            badge = f" · {r['n_items']} pub" if r["n_items"] else ""
            lines.append(f"- [`{sub}`]({rel_src_link(fpath)}) — {doc}{badge}")
        lines.append("")

    return "\n".join(lines) + "\n"


def main() -> int:
    files = collect_files()
    records = build_records(files)
    OUT.write_text(emit(records))
    total_items = sum(r["n_items"] for r in records.values())
    total_edges = sum(len(r["imports"]) for r in records.values())
    print(
        f"Wrote {OUT.relative_to(DRUST)} — {len(records)} files, "
        f"{total_items} public items, {total_edges} use-crate edges."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

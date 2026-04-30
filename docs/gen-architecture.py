#!/usr/bin/env python3
"""Regenerate drust/docs/architecture.md from the current src/ tree.

Purpose: give future agents (and humans) a browsable index of which file
does what, which file imports which, and which public items each file
exposes — so they don't have to re-read every .rs file to orient.

Index, not tutorial. Summaries come from each file's //! module doc.
Public item lists come from `pub (fn|struct|enum|trait|const|static|type|mod)`.
Cross-file edges come from `use crate::...` imports and `mod X;` declarations.
This is textual, not AST: fully-qualified calls that bypass a `use` will not
be captured. Good enough for orientation.

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

# `mod X;` declarations (top-level only) — these build the module tree.
RE_MOD_DECL = re.compile(
    r"^(?:pub(?:\(crate\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
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


def parse_pub_items(text: str) -> list[tuple[str, str, str]]:
    """Return [(kind, name, one_line_doc)] for each top-level pub item."""
    out: list[tuple[str, str, str]] = []
    pending_doc: list[str] = []
    for raw in text.splitlines():
        s = raw.rstrip()
        if s.lstrip().startswith("///"):
            pending_doc.append(s.lstrip()[3:].lstrip())
            continue
        if s.strip() == "":
            # Blank line severs a pending doc block from its item.
            pending_doc = []
            continue
        m = RE_PUB_ITEM.match(s)
        if m:
            doc = next((d.strip() for d in pending_doc if d.strip()), "")
            out.append((m.group(1), m.group(2), doc))
            pending_doc = []
        else:
            pending_doc = []
    return out


def parse_mod_decls(text: str) -> list[str]:
    """Return submodule names declared with `mod X;` at the top level."""
    out: list[str] = []
    for raw in text.splitlines():
        m = RE_MOD_DECL.match(raw.rstrip())
        if m:
            out.append(m.group(1))
    return out


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
    # Strip `as ALIAS` — aliases don't affect which file is being imported.
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
        sub = expand_use_body(p)
        for s in sub:
            if prefix and s:
                out.append(prefix + "::" + s)
            else:
                out.append(prefix or s)
    return out


def resolve_module_file(parts: list[str]) -> str | None:
    """Resolve crate-relative module path parts to the deepest existing .rs file.

    Returns the path relative to DRUST root, or None if no match. We try
    (a) `<parts-1>/<last>.rs`, (b) `<parts>/mod.rs`, and walk up if neither
    matches — this handles both `mod foo;` style and `mod foo { ... }` inline.
    """
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
        mod_doc = parse_module_doc(text)
        items = parse_pub_items(text)
        use_bodies = extract_use_crate_bodies(text)
        mod_decls = parse_mod_decls(text)

        # use crate::... imports → list of resolved sibling files
        imports: set[str] = set()
        for b in use_bodies:
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

        # mod X; declarations → child module files (relative to this file's dir)
        children: set[str] = set()
        if mod_decls:
            parent = Path(fpath).parent  # e.g. src/auth
            # If this file is foo/mod.rs, children live under foo/; otherwise
            # under <file-without-.rs>/.
            if Path(fpath).name == "mod.rs" or Path(fpath).name == "lib.rs" or Path(fpath).name == "main.rs":
                child_dir = parent
            else:
                child_dir = parent / Path(fpath).stem
            for name in mod_decls:
                leaf = DRUST / child_dir / f"{name}.rs"
                mod = DRUST / child_dir / name / "mod.rs"
                if leaf.exists():
                    children.add(str(leaf.relative_to(DRUST)))
                elif mod.exists():
                    children.add(str(mod.relative_to(DRUST)))

        records[fpath] = {
            "doc": mod_doc,
            "items": items,
            "imports": sorted(imports),
            "children": sorted(children),
        }
    return records


def emit(records: dict[str, dict]) -> str:
    # Reverse indexes.
    imported_by: dict[str, set[str]] = defaultdict(set)
    parent_of: dict[str, set[str]] = defaultdict(set)
    for f, r in records.items():
        for dep in r["imports"]:
            imported_by[dep].add(f)
        for child in r["children"]:
            parent_of[child].add(f)

    # Group by top-level src subdir.
    groups: dict[str, list[str]] = defaultdict(list)
    for f in sorted(records.keys()):
        rel = f[len("src/") :]
        top = rel.split("/", 1)[0] if "/" in rel else "(root)"
        groups[top].append(f)

    today = _dt.date.today().isoformat()

    def rel_src_link(target: str) -> str:
        """Link from docs/architecture.md back to a file in src/."""
        return "../" + target

    lines: list[str] = []
    lines.append("---")
    lines.append("type: reference")
    lines.append("name: drust source architecture index")
    lines.append("status: production")
    lines.append(f"updated: {today}")
    lines.append("generated_by: docs/gen-architecture.py")
    lines.append("---")
    lines.append("")
    lines.append("# drust — source architecture index")
    lines.append("")
    lines.append("> [!NOTE]")
    lines.append("> **Auto-generated** from `src/**/*.rs`. Do not hand-edit — rebuild with")
    lines.append("> `python3 drust/docs/gen-architecture.py` after code changes.")
    lines.append(">")
    lines.append("> Summaries come from each file's `//!` module doc. Public items come from top-level `pub` declarations. Cross-file edges come from `use crate::...` imports and `mod X;` declarations — this is **textual, not AST**, so calls through fully-qualified paths without a `use` won't appear. Good enough for orientation.")
    lines.append("")

    # High-level module overview.
    lines.append("## Module overview")
    lines.append("")
    lines.append("| group | files | public items | imports out | imports in |")
    lines.append("|---|---:|---:|---:|---:|")
    for g in sorted(groups.keys()):
        fs = groups[g]
        nitems = sum(len(records[f]["items"]) for f in fs)
        out_edges = sum(len(records[f]["imports"]) for f in fs)
        in_edges = sum(len(imported_by.get(f, [])) for f in fs)
        anchor = g.replace("/", "").strip("()") or "root"
        lines.append(f"| [`{g}/`](#src{anchor}) | {len(fs)} | {nitems} | {out_edges} | {in_edges} |")
    lines.append("")

    # Group-level dependency graph — one edge per (group A → group B) if ANY
    # file in A imports from B.
    lines.append("## Group-level dependency graph")
    lines.append("")
    lines.append("```mermaid")
    lines.append("graph LR")
    edges: set[tuple[str, str]] = set()
    for f, r in records.items():
        ftop = f[len("src/") :].split("/", 1)[0] if "/" in f[len("src/") :] else "(root)"
        for dep in r["imports"]:
            dtop = dep[len("src/") :].split("/", 1)[0] if "/" in dep[len("src/") :] else "(root)"
            if ftop != dtop:
                edges.add((ftop, dtop))
    for a, b in sorted(edges):
        a_id = a.replace("(", "").replace(")", "") or "root"
        b_id = b.replace("(", "").replace(")", "") or "root"
        lines.append(f"  {a_id} --> {b_id}")
    lines.append("```")
    lines.append("")

    # Per-file sections.
    for g in sorted(groups.keys()):
        anchor = g.replace("/", "").strip("()") or "root"
        heading = f"## `src/{g}/`" if g != "(root)" else "## `src/` (root)"
        # For the anchor to match the TOC, rewrite heading id.
        lines.append(f'<a id="src{anchor}"></a>')
        lines.append("")
        lines.append(heading)
        lines.append("")
        for fpath in groups[g]:
            r = records[fpath]
            lines.append(f"### [`{fpath}`]({rel_src_link(fpath)})")
            lines.append("")
            if r["doc"]:
                lines.append(f"_{r['doc']}_")
                lines.append("")
            # Children first (module tree goes down), then imports, then inbound.
            if r["children"]:
                lines.append("**Declares submodules:**")
                lines.append("")
                for c in r["children"]:
                    lines.append(f"- [`{c}`]({rel_src_link(c)})")
                lines.append("")
            parents = sorted(parent_of.get(fpath, []))
            if parents:
                lines.append("**Declared by:**")
                lines.append("")
                for p in parents:
                    lines.append(f"- [`{p}`]({rel_src_link(p)})")
                lines.append("")
            if r["items"]:
                lines.append("**Public items:**")
                lines.append("")
                for kind, name, doc in r["items"]:
                    line = f"- `{kind} {name}`"
                    if doc:
                        line += f" — {doc}"
                    lines.append(line)
                lines.append("")
            else:
                lines.append("_(no top-level pub items)_")
                lines.append("")
            if r["imports"]:
                lines.append("**Imports from:**")
                lines.append("")
                for dep in r["imports"]:
                    lines.append(f"- [`{dep}`]({rel_src_link(dep)})")
                lines.append("")
            inbound = sorted(imported_by.get(fpath, []))
            if inbound:
                lines.append("**Imported by:**")
                lines.append("")
                for src in inbound:
                    lines.append(f"- [`{src}`]({rel_src_link(src)})")
                lines.append("")

    return "\n".join(lines) + "\n"


def main() -> int:
    files = collect_files()
    records = build_records(files)
    OUT.write_text(emit(records))
    total_items = sum(len(r["items"]) for r in records.values())
    total_edges = sum(len(r["imports"]) for r in records.values())
    print(
        f"Wrote {OUT.relative_to(DRUST)} — {len(records)} files, "
        f"{total_items} public items, {total_edges} use-crate edges."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

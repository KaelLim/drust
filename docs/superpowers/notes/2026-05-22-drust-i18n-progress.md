# drust v1.22 i18n — Work-in-progress checkpoint (2026-05-22 18:00)

User clocked out mid-execution. This file is the state-of-play so the next session can pick up cleanly.

## Branch state

- On `main`. 5 unpushed v1.22 commits ahead of `origin/main`.
- Working tree NOT clean: 2 .html files modified but uncommitted.

```
332efd1 i18n(review): unify common.* key naming + fix tools_pill
5f462ff i18n(extract): produce locales/en.toml + zh-TW.toml from 25 templates
9f27637 fix(i18n): three Theme F review concerns
9be1514 fix(i18n): substitute_placeholders UTF-8 safety
67a57a6 feat(i18n): foundation
750cadf chore(release): v1.21        ← origin/main HEAD (pushed)
```

Uncommitted in working tree:
- `src/mgmt/templates/files.html` (12 `t.s` calls)
- `src/mgmt/templates/tenants_list.html` (16 `t.s` calls)

## Done (in commits, NOT pushed)

- **Theme F (foundation)** — `src/mgmt/i18n.rs` (Locale, Translator, Bundle), `src/mgmt/locale_layer.rs` middleware, `build.rs` key check, stub `locales/{en,zh-TW}.toml`, wire-up in `main.rs` + `mgmt/mod.rs` + `mgmt/routes.rs`.
- **Theme E (extract + merge + review)** — 25 parallel extractions in `/tmp/i18n-extract-r1/`, produced full `locales/en.toml` + `locales/zh-TW.toml` (705 keys after E3 dedup), extraction report at `docs/superpowers/notes/2026-05-22-drust-i18n-extraction-report.md`, key-naming unification + `tools_pill` placeholder conversion in `332efd1`.

## NOT done — must redo / continue

### SP1 (plumb) — VANISHED FROM WORKING TREE

The Theme SP1 implementer subagent reported success: 20 Template structs gained `pub t: Translator`, 18 handlers accept `Extension<Locale>` and init `Translator::new(locale)`. **Currently NONE of those changes exist on disk** — `grep "Translator::new" src/mgmt/*.rs` finds zero matches outside i18n.rs's own unit test. Either:
- The orchestrator (or user) reverted the working tree at some point, OR
- The subagent's report was misleading and edits never actually wrote.

**Next-session action**: re-run SP1 plumb from scratch. See the plumb prompt in `docs/superpowers/plans/2026-05-22-drust-i18n.md` Theme SP §SP1.

### SP2 (swap) — 2 of 25 done, 11+ cancelled mid-flight, 12 not started

| File | Status |
|---|---|
| `_admin_sidebar.html` | subagent reported done, **not on disk** |
| `_audit_body.html` | subagent reported done, **not on disk** (also did a loop-variable rename `for t in` → `for tn in` that's also gone) |
| `_cmdk.html` | subagent reported done, **not on disk** |
| `_collection_sidebar.html` | subagent reported done, **not on disk** |
| `_modal.html` | subagent STOP-AND-REPORT (4 ambiguous duplicates: `'OK'` 4× / `'Cancel'` 2× / `'Copy to clipboard'` 2×) — no work done |
| `audit_host.html` | subagent reported done, **not on disk** |
| `audit_tenant.html` | subagent reported done + edited locale TOMLs to single-brace placeholders, **none on disk** |
| `backup_inspect.html` | subagent reported done + `for t in tenants` → `for tn in tenants` rename, **not on disk** |
| `backups.html` | subagent reported done, **not on disk** |
| `collection_rows.html` | subagent **cancelled / rejected** by user mid-flight |
| `collections.html` | subagent reported done + 2 locale TOML edits, **not on disk** |
| `design.html` | subagent reported done (77 swaps), **not on disk** |
| `files.html` | **subagent cancelled by user, BUT 12 `t.s` calls ARE on disk** — partial swap landed |
| `files_reconcile.html` | subagent reported done (32 swaps), **not on disk** |
| `login.html` | subagent **cancelled by user** |
| `tenant_api_keys.html` | subagent **cancelled by user** |
| `tenant_docs.html` | subagent reported done, **not on disk** |
| `tenant_files_admin.html` | subagent **cancelled by user** |
| `tenant_oauth_providers.html` | subagent **cancelled by user** |
| `tenant_overview.html` | subagent **cancelled by user** |
| `tenant_rpc.html` | subagent **cancelled by user** |
| `tenant_rpc_form.html` | subagent reported done + capitalization fix on `create` literal, **not on disk** |
| `tenant_rpc_test.html` | subagent **cancelled by user** (it had reported a missing-key panic on `tenant_rpc_test.page.title`) |
| `tenants_list.html` | **subagent cancelled by user, BUT 16 `t.s` calls ARE on disk** — partial swap landed |
| `tenant_webhooks_admin.html` | subagent **cancelled by user** |

### Locale TOML — UNTOUCHED

Despite multiple subagents reporting they edited `locales/{en,zh-TW}.toml` to convert `{{ x }}` placeholders to single-brace `{x}` for `t.fmt`, `git diff --stat HEAD -- locales/` shows zero changes. The locale TOMLs are exactly as `332efd1` left them.

### Swap maps still on disk

`/tmp/i18n-swap-maps/*.json` (25 files) — built by the rev-map helper. These are the per-template en→key mappings. Likely safe to keep across sessions if `/tmp` survives, but for safety the next session should rebuild via the same helper (see plan SP2 §1 "rev-map helper").

### Known SP2-time issues surfaced by the cancelled subagents

These need to be threaded into the next round's prompts:

1. **`{{ x }}` vs `{x}` placeholder mismatch**: the extraction kept original `{{ var }}` askama refs verbatim in bundle values. `substitute_placeholders` in `i18n.rs` only handles single-brace `{name}`. Many entries need conversion. The `audit_tenant`/`collections`/`tenant_docs` subagents proposed "Approach C" (edit TOML + handler-side args). Apply uniformly.

2. **Loop-variable shadowing**: many templates use `{% for t in xs %}` which collides with the i18n `Translator t`. When inserting `t.s` calls inside such loops, rename loop var (commonly to `tn` or `it`). Pre-existing precedent in `backup_inspect.html`. Audit ALL templates for this before swap.

3. **`_modal.html` ambiguous duplicates**: `'OK'` appears 4×, `'Cancel'` 2×, `'Copy to clipboard'` 2×. The swap-map only listed one occurrence each. Either expand the map to all occurrences (same key applies to all four `'OK'`s), or accept that the JS fallbacks (`opts.okText || 'OK'`) stay English.

4. **Missing key**: `tenant_rpc_test.page.title` was referenced by HTML at line 6 (page title with `{{ tenant }}` ref) but does NOT exist in `locales/en.toml`. The page title key was probably named differently in extraction. Either add the key to en.toml or rewire the template to a different existing key.

5. **`tools_pill` `{n}` placeholder**: the handler for `tenant_api_keys.html` must compute MCP `tool_count` and pass it to `t.fmt`. If not in handler scope, hard-code something for now and TODO-comment.

6. **HTML stripped from bundle values**: extraction stripped inline `<code>` tags from value text (e.g. the `audit_host` subtitle has `<code>audit-YYYY-MM-DD.jsonl</code>` in the HTML but the bundle value is plain text). `t.s` output is auto-escaped by askama, so the `<code>` styling is lost on swap. Either: split the key into pre/post around the code block (more keys), or carry HTML in bundle and pipe through `|safe` (security risk — careful), or accept the loss.

## Next-session plan

1. **Restart from working tree clean** — decide whether to keep the 2 partial swap files (`files.html`, `tenants_list.html`). Probably keep as proof-of-concept; their changes are on disk + don't break anything yet (cargo doesn't fail because templates compile to literals just calling `.t.s(...)` which... wait, that DOES need the struct field). Actually since SP1 plumb is gone, those 2 swapped templates WILL fail `cargo check` on the askama macro. **First action**: `git restore src/mgmt/templates/files.html src/mgmt/templates/tenants_list.html`, OR re-do SP1 plumb first then keep them.

2. **Re-do SP1 plumb** in a fresh subagent with stricter exit verification (run `cargo check --all-targets` and ASSERT clean before reporting DONE — the previous subagent reported DONE without that gate).

3. **Re-do SP2 swap** for all 25 templates, in batches of ~5 instead of 25 parallel to keep user from feeling overwhelmed by the agent list. Use a SHARED prompt template with the lessons from items 1-6 above baked in.

4. **Locale TOML `{name}` conversion** as a pre-step before SP2: dispatch one subagent to scan both TOMLs, convert every `{{ name }}` to `{name}`, commit. Then SP2 subagents only need t.fmt (not edit TOML).

5. **Commit Theme SP** when all swaps + plumb are in working tree clean and `cargo build` passes.

6. **Theme V** — release wrap-up per plan.

## Tasks open

- #404 in_progress: Theme SP plumb + swap
- #405-408 pending: SP spec review, SP code review, Theme V, final review

`/tmp/i18n-extract-r1/` and `/tmp/i18n-swap-maps/` are byproducts from this session; rebuild if `/tmp` got cleaned.

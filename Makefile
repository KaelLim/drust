# drust test runner — one binary per merged group harness (#925).
#
# Group membership is declared, not inferred: each tests/g_<group>.rs lists its
# members with `#[path]`, and Cargo.toml lists the harnesses. The old
# tests/<prefix>_*.rs filename convention no longer decides anything (four group
# names are not even prefixes of all their members) — it survives only in the
# mid-migration fallback at the bottom of this file, which says so out loud.
#
# Why this exists: the cost of `cargo test` in this crate is COMPILE, not run.
# Every test binary statically links the drust lib + wasmtime, and a bare
# `cargo test <name>` compiles ALL of them and only filters what runs — the
# classic trap. Only `--test <name>` limits what compiles.
#
# #925 (spec docs/superpowers/specs/2026-08-13-test-binary-consolidation-design.md)
# cut the binary count from 253 to 32: 24 merged group harnesses
# (tests/g_<group>.rs, each `#[path]`-including its former standalone files
# unchanged) plus 8 isolation exceptions that must stay their own process.
# Measured on the mcp group: 20 binaries → 1 is 189s → 15s build and 3.20GB →
# 244MB of target/debug, with the same 137 tests.
#
# Because `[package] autotests = false` now drives that, every tests/*.rs must
# be registered — either as a `#[path]` member of its group harness, or with its
# own [[test]] entry in Cargo.toml. build.rs's ninth gate
# (build_support/test_targets_gate.rs) fails the build on any file that is
# neither, so a forgotten registration cannot silently go dark.
#
#   make test-lib          # in-lib unit tests only — fastest inner loop
#   make test-mcp          # lib + the merged tests/g_mcp.rs harness
#   make test-auth         # lib + tests/g_auth.rs      (any group works)
#   make test-all          # full suite — the release / pre-merge gate
#   make groups            # list group harnesses + member counts
#
# An isolation exception is not a group; run it by its own name, e.g.
# `cargo test --test webhook_concurrency`.
#
# Workflow note: per-task agents should run `make test-lib` + the relevant
# `make test-<group>`; only the final whole-implementation review runs
# `make test-all`.

.PHONY: help test test-lib test-all test-shell groups

help:
	@echo "make test-lib        unit tests only (fast inner loop)"
	@echo "make test-<group>    lib + the merged tests/g_<group>.rs harness"
	@echo "make test-all        full integration suite (release gate)"
	@echo "make groups          list group harnesses + member counts"

test: test-all

test-lib:
	cargo test --lib

test-all: test-shell
	cargo test

# Fixture tests for the deploy scripts. Not Rust, so `cargo test` cannot see
# them — and deploy/drust-backup.sh is the only code here that deletes
# credential-bearing production archives, so it must not be the untested half.
test-shell:
	bash deploy/tests/backup_retention_test.sh

groups:
	@echo "group harnesses — make test-<group>  (= cargo test --lib --test g_<group>)"
	@for f in tests/g_*.rs; do \
	  [ -e "$$f" ] || continue; \
	  n=$$(basename $$f .rs); \
	  c=$$(grep -c '^#\[path' $$f); \
	  printf "  %-12s %3d files\n" "$${n#g_}" "$$c"; \
	done
	@t=$$(grep -c '^\[\[test\]\]' Cargo.toml); \
	 g=$$(ls tests/g_*.rs 2>/dev/null | wc -l); \
	 echo "standalone [[test]] targets: $$((t - g))  — cargo test --test <name>"

# Pattern rule: `make test-<group>` runs the in-lib unit tests plus the merged
# group harness. The explicit test-lib / test-all / test-shell rules above take
# precedence over this pattern for those names.
#
# While the #925 migration is in flight, a group whose harness does not exist
# yet falls back to one --test flag per tests/<group>_*.rs file. That glob is an
# APPROXIMATION of the plan's group table, never the table itself, in both
# directions:
#
#   - it MISSES members whose filename does not start with "<group>_" —
#     audit skips audit3_*, file skips files_rls_*, record skips records_*,
#     webhook skips webhooks.rs and webhooks_migration.rs;
#   - it SWEEPS IN isolation-exception files that are not group members at all
#     (admin_theme, cli_device_approval, fts_deadline, webhook_concurrency).
#
# So the fallback keeps a group runnable; it is not a baseline, and a green from
# it does not mean the group is green. It prints that warning before and after
# the run (last line wins the scrollback) rather than letting a partial green
# pass for the whole group. The window closes per group the moment its
# tests/g_<group>.rs lands.
test-%:
	@if [ -f tests/g_$*.rs ]; then \
	  echo "cargo test --lib --test g_$*"; \
	  cargo test --lib --test g_$*; \
	else \
	  files=$$(ls tests/$*_*.rs 2>/dev/null | sed 's#tests/##; s#\.rs$$##'); \
	  if [ -z "$$files" ]; then echo "no tests/g_$*.rs and no tests/$*_*.rs (try: make groups)"; exit 1; fi; \
	  warn() { \
	    echo "" >&2; \
	    echo "WARNING: tests/g_$*.rs does not exist yet — running the tests/$*_*.rs prefix" >&2; \
	    echo "WARNING: glob instead. That glob is an approximation of the #925 group table:" >&2; \
	    echo "WARNING: it can miss members not named '$*_*' and can pull in non-members." >&2; \
	    echo "WARNING: Do NOT read this result as a baseline for group '$*'." >&2; \
	    echo "" >&2; \
	  }; \
	  warn; \
	  flags=$$(for f in $$files; do printf -- '--test %s ' "$$f"; done); \
	  echo "cargo test --lib $$flags"; \
	  cargo test --lib $$flags; rc=$$?; \
	  warn; \
	  exit $$rc; \
	fi

# drust test runner — one binary per merged group harness (#925).
#
# Group membership is declared, not inferred: each tests/g_<group>.rs lists its
# members with `#[path]`, and Cargo.toml lists the harnesses. The old
# tests/<prefix>_*.rs filename convention no longer decides anything (four group
# names are not even prefixes of all their members), and since `autotests = false`
# removed the per-file targets it can no longer even name one: `cargo test --test
# admin_users` answers "no test target named".
#
# Why this exists: the cost of `cargo test` in this crate is COMPILE, not run.
# Every test binary statically links the drust lib + wasmtime, and a bare
# `cargo test <name>` compiles ALL of them and only filters what runs — the
# classic trap. Only `--test <name>` limits what compiles.
#
# #925 (spec docs/superpowers/specs/2026-08-13-test-binary-consolidation-design.md)
# cut the binary count from 253 to 38: 24 merged group harnesses
# (tests/g_<group>.rs, each `#[path]`-including its former standalone files
# unchanged) plus 14 standalone targets that must keep a process to themselves —
# 8 isolation exceptions, plus 6 files backed out of a harness on a merge
# collision. Those 6 are load-bearing, not leftovers: a collision is resolved by
# backing the file out, NEVER by editing the test, and re-merging them brings
# back a race-dependent failure (a first-write-wins global audit writer) that
# can pass locally. `make groups` prints the live counts — 24 + 14; do not
# reconcile that 14 against the spec's 8 by merging six binaries away.
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
# All 24 harnesses exist, so there is no filename-glob fallback any more: an
# unknown <group> is an error, not a best-effort `tests/<group>_*.rs` sweep. Two
# reasons it could not survive T4. It never matched the group table in either
# direction (it missed audit3_*, files_rls_*, records_*, webhooks*.rs, and swept
# in isolation exceptions that are not group members), so its green never meant
# the group was green; and `autotests = false` deleted the per-file [[test]]
# targets it emitted --test flags for, so today it can only produce cargo's "no
# test target named" on the first member it finds.
test-%:
	@if [ -f tests/g_$*.rs ]; then \
	  echo "cargo test --lib --test g_$*"; \
	  cargo test --lib --test g_$*; \
	else \
	  echo "no tests/g_$*.rs — '$*' is not a group (run: make groups)" >&2; \
	  echo "an isolation exception runs by its own name: cargo test --test $*" >&2; \
	  exit 1; \
	fi

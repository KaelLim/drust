# drust test runner — grouped by the tests/<prefix>_*.rs filename convention.
#
# Why this exists: the cost of `cargo test` in this crate is COMPILE, not run.
# Each tests/*.rs is its own binary that statically links the drust lib +
# wasmtime (~142 binaries). A bare `cargo test <name>` still compiles ALL of
# them and only filters what runs — the classic trap. Only `--test <name>`
# limits what compiles. These recipes do that for you, globbed by prefix, so a
# new tests/<prefix>_*.rs file is picked up with zero edits here.
#
#   make test-lib          # in-lib unit tests only — fastest inner loop
#   make test-functions    # lib + tests/functions_*.rs
#   make test-auth         # lib + tests/auth_*.rs       (any prefix works)
#   make test-all          # full suite — the release / pre-merge gate
#   make groups            # list available prefixes + file counts
#
# Workflow note: per-task agents should run `make test-lib` + the relevant
# `make test-<group>`; only the final whole-implementation review runs
# `make test-all`. Running the full 142-binary suite on every task is what
# balloons target/debug and slows iteration.

.PHONY: help test test-lib test-all groups

help:
	@echo "make test-lib        unit tests only (fast inner loop)"
	@echo "make test-<prefix>   lib + tests/<prefix>_*.rs  (e.g. test-functions)"
	@echo "make test-all        full integration suite (release gate)"
	@echo "make groups          list test prefixes + counts"

test: test-all

test-lib:
	cargo test --lib

test-all:
	cargo test

groups:
	@ls tests/*.rs | sed 's#tests/##; s/_.*//' | sort | uniq -c | sort -rn

# Pattern rule: `make test-<prefix>` runs the in-lib unit tests plus every
# integration binary named tests/<prefix>_*.rs. The explicit test-lib / test-all
# rules above take precedence over this pattern for those two names.
test-%:
	@files=$$(ls tests/$*_*.rs 2>/dev/null | sed 's#tests/##; s#\.rs$$##'); \
	if [ -z "$$files" ]; then echo "no tests/$*_*.rs found (try: make groups)"; exit 1; fi; \
	flags=$$(for f in $$files; do printf -- '--test %s ' "$$f"; done); \
	echo "cargo test --lib $$flags"; \
	cargo test --lib $$flags

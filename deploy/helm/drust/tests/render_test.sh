#!/usr/bin/env bash
# Offline chart test harness. Requires helm + kubeconform on PATH.
set -uo pipefail
CHART="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$CHART/tests/fixtures"
FAILS=0
_render() { helm template testrel "$CHART" -f "$FIX/$1" --namespace testns 2>/tmp/helmerr || { echo "RENDER-ERROR ($1):"; cat /tmp/helmerr; return 1; }; }

assert_contains() { # <fixture> <needle> <label>
  if _render "$1" | grep -qF -- "$2"; then echo "ok: $3"; else echo "FAIL: $3 — '$2' absent in $1"; FAILS=$((FAILS+1)); fi; }
assert_absent() {
  if _render "$1" | grep -qF -- "$2"; then echo "FAIL: $3 — '$2' present in $1 (should be absent)"; FAILS=$((FAILS+1)); else echo "ok: $3"; fi; }
assert_kubeconform() { # <fixture>
  local out; out=$(_render "$1" | kubeconform -strict -summary -ignore-missing-schemas 2>&1)
  if echo "$out" | grep -q "Invalid: 0" && echo "$out" | grep -q "Errors: 0"; then echo "ok: kubeconform $1"; else echo "FAIL: kubeconform $1"; echo "$out"; FAILS=$((FAILS+1)); fi; }

echo "== lint =="; helm lint "$CHART" || FAILS=$((FAILS+1))

# --- Task 1 assertions ---
assert_contains minimal.yaml "kind: Namespace" "namespace rendered when createNamespace=true"
assert_absent   full.yaml    "kind: Namespace" "namespace absent when createNamespace=false"
assert_kubeconform minimal.yaml

echo "== $FAILS failure(s) =="
exit $((FAILS>0))

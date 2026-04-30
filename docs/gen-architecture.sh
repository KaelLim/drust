#!/usr/bin/env bash
# Thin wrapper — regenerates docs/architecture.md from src/.
# Safe to re-run any time; output is deterministic.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 docs/gen-architecture.py

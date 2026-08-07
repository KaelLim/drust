#!/bin/bash
set -euo pipefail
DATA_DIR="${DRUST_DATA_DIR:-/var/lib/drust}"
# NOTE (#935): _trash retention is handled IN-PROCESS by drust's janitor
# (DRUST_TRASH_RETENTION_DAYS, default 7, 0 = keep forever) on every deployment
# target. Do NOT re-add a hardcoded time-based trash sweep here — it would cap
# a longer setting and defeat 0 (the v1.58.0 regression this removed).
# v1.9: sweep expired _system_sessions across active tenants
if command -v drust_session_janitor >/dev/null 2>&1; then
  DRUST_DATA_DIR="${DATA_DIR}" drust_session_janitor || true
else
  # Fallback to release-built binary in the repo
  REPO_BIN="$(dirname "$0")/../target/release/drust_session_janitor"
  if [ -x "${REPO_BIN}" ]; then
    DRUST_DATA_DIR="${DATA_DIR}" "${REPO_BIN}" || true
  fi
fi

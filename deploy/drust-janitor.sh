#!/bin/bash
set -euo pipefail
DATA_DIR="${DRUST_DATA_DIR:-/var/lib/drust}"
TRASH="${DATA_DIR}/_trash"
if [ -d "${TRASH}" ]; then
  find "${TRASH}" -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} +
fi
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

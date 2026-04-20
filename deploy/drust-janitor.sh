#!/bin/bash
set -euo pipefail
DATA_DIR="${DRUST_DATA_DIR:-/var/lib/drust}"
TRASH="${DATA_DIR}/_trash"
if [ -d "${TRASH}" ]; then
  find "${TRASH}" -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} +
fi

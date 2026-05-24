#!/bin/bash
set -euo pipefail

DATA_DIR="${DRUST_DATA_DIR:-/var/lib/drust}"
DATE=$(date -u +%Y-%m-%d-%H%M%S)
DEST="${DATA_DIR}/backups/drust-${DATE}.tar.zst"
STAGE=$(mktemp -d)
trap "rm -rf '${STAGE}'" EXIT

mkdir -p "${DATA_DIR}/backups"

sqlite3 "${DATA_DIR}/meta.sqlite" "VACUUM INTO '${STAGE}/meta.sqlite'"
sqlite3 "${DATA_DIR}/meta_logs.sqlite" "VACUUM INTO '${STAGE}/meta_logs.sqlite'"

if [ -d "${DATA_DIR}/tenants" ]; then
  for DIR in "${DATA_DIR}"/tenants/*/; do
    [ -d "${DIR}" ] || continue
    TID=$(basename "${DIR}")
    mkdir -p "${STAGE}/tenants/${TID}"
    if [ -f "${DIR}/data.sqlite" ]; then
      sqlite3 "${DIR}/data.sqlite" "VACUUM INTO '${STAGE}/tenants/${TID}/data.sqlite'"
    fi
    [ -f "${DIR}/meta.json" ] && cp "${DIR}/meta.json" "${STAGE}/tenants/${TID}/meta.json" || true
  done
fi

tar --zstd -cf "${DEST}" -C "${STAGE}" .
chmod 0600 "${DEST}"

# Retention
find "${DATA_DIR}/backups" -name 'drust-*.tar.zst' -type f -mtime +30 -delete

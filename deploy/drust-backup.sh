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

# Retention — tiered, not a flat window.
#
# Every snapshot carries `tokens.plaintext` and `_admin_tokens.plaintext` verbatim,
# so it grants full data-plane access to every tenant plus cross-tenant admin access
# until those tokens are rerolled. The copy count IS the blast radius, which is why
# this is tiered rather than a longer flat window: 7 dailies + 4 weeklies reaches
# just as far back as the old `-mtime +30` while holding ~11 files instead of 30.
KEEP_DAILY="${DRUST_BACKUP_KEEP_DAILY:-7}"
KEEP_WEEKLY="${DRUST_BACKUP_KEEP_WEEKLY:-4}"

prune_backups() {
  local dir="$1"
  local -a all
  # Names are drust-YYYY-MM-DD-HHMMSS.tar.zst, so a reverse NAME sort is a reverse
  # TIME sort — no stat(2), and unaffected by a restore or rsync touching mtimes
  # (which is exactly what the old -mtime predicate keyed on).
  mapfile -t all < <(find "${dir}" -maxdepth 1 -type f -name 'drust-*.tar.zst' -printf '%f\n' | sort -r)
  (( ${#all[@]} )) || return 0

  local -A keep=() seen_week=()
  local daily=0 weekly=0 f ymd week

  for f in "${all[@]}"; do
    ymd="${f#drust-}"
    ymd="${ymd:0:10}"
    # Date FIRST, tier second. Fail SAFE: a name we cannot date is kept, never
    # deleted — deleting what you could not parse is how a retention pass turns
    # into data loss. It must also not consume a tier slot: reverse-NAME order
    # puts anything starting above '2' (say `drust-NOTADATE-...`) at the front,
    # where it would silently spend a daily slot and evict a real snapshot.
    # Caught by the fixture test, not by reading.
    if ! week=$(date -u -d "${ymd}" +%G-%V 2>/dev/null); then
      keep["${f}"]=1
      continue
    fi
    if (( daily < KEEP_DAILY )); then
      keep["${f}"]=1
      daily=$(( daily + 1 ))
      # Claim the week too. Without this, the first weekly slot is spent on the
      # week the dailies already cover five times over, and total reach drops by
      # a full week for no extra safety (measured: 24 days vs 31, same file count).
      seen_week["${week}"]=1
      continue
    fi
    if [[ -z "${seen_week[${week}]:-}" ]] && (( weekly < KEEP_WEEKLY )); then
      seen_week["${week}"]=1
      keep["${f}"]=1
      weekly=$(( weekly + 1 ))
    fi
  done

  for f in "${all[@]}"; do
    [[ -n "${keep[${f}]:-}" ]] || rm -f -- "${dir}/${f}"
  done
}

prune_backups "${DATA_DIR}/backups"

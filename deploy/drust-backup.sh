#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Definitions first, side effects last.
#
# `deploy/tests/backup_retention_test.sh` SOURCES this file with
# DRUST_BACKUP_PRUNE_ONLY=1 to get `prune_backups` without taking a backup, so the
# assertions run against the shipped function rather than a transcribed copy that
# can drift from it. That only works if nothing above the guard touches the
# filesystem — keep it that way.
# ---------------------------------------------------------------------------

DATA_DIR="${DRUST_DATA_DIR:-/var/lib/drust}"

# Retention — tiered, not a flat window.
#
# Every snapshot carries `tokens.plaintext` and `_admin_tokens.plaintext` verbatim,
# so it grants full data-plane access to every tenant plus cross-tenant admin access
# until those tokens are rerolled. The copy count IS the blast radius, which is why
# this is tiered rather than a longer flat window: 7 dailies + 4 weeklies reaches
# just as far back as the old `-mtime +30` while holding ~11 files instead of 30.
KEEP_DAILY="${DRUST_BACKUP_KEEP_DAILY:-7}"
KEEP_WEEKLY="${DRUST_BACKUP_KEEP_WEEKLY:-4}"

# A non-numeric value would make `(( daily < KEEP_DAILY ))` silently false forever
# — the daily tier switches off and the next pass deletes almost everything while
# still exiting 0. Validate loudly instead; this script's failure mode is
# unrecoverable, so a typo must stop it rather than quietly change the policy.
for _knob in KEEP_DAILY KEEP_WEEKLY; do
  if ! [[ "${!_knob}" =~ ^[0-9]+$ ]]; then
    echo "drust-backup: DRUST_BACKUP_${_knob} must be a non-negative integer, got '${!_knob}'" >&2
    exit 2
  fi
done
unset _knob

# $2 is the archive this run just created. It is kept unconditionally, BEFORE any
# tiering, because a run that deletes its own output and exits 0 is the worst
# failure this script has: systemd records success and no backup exists for that
# day. Not hypothetical — reverse-NAME order is byte order, and `.` (0x2E) sorts
# above `-` (0x2D), so a stray `drust-YYYY-MM-DD.tar.zst` (an operator copy, a
# rename, a restore artifact) sorts ABOVE the canonical
# `drust-YYYY-MM-DD-HHMMSS.tar.zst`, claims the day, and pushes the real archive
# into the weekly tier where its week is already taken. Reproduced end to end.
prune_backups() {
  local dir="$1" protect="${2:-}"
  local -a all
  # Names are drust-YYYY-MM-DD-HHMMSS.tar.zst, so a reverse NAME sort is a reverse
  # TIME sort — no stat(2), and unaffected by a restore or rsync touching mtimes
  # (which is exactly what the old -mtime predicate keyed on).
  mapfile -t all < <(find "${dir}" -maxdepth 1 -type f -name 'drust-*.tar.zst' -printf '%f\n' | sort -r)
  (( ${#all[@]} )) || return 0

  local -A keep=() seen_day=() seen_week=()
  local daily=0 weekly=0 f ymd week today
  today=$(date -u +%Y-%m-%d)

  if [[ -n "${protect}" && -e "${dir}/${protect}" ]]; then
    keep["${protect}"]=1
    ymd="${protect#drust-}"; ymd="${ymd:0:10}"
    if week=$(date -u -d "${ymd}" +%G-%V 2>/dev/null); then
      seen_day["${ymd}"]=1
      seen_week["${week}"]=1
      daily=1
    fi
  fi

  for f in "${all[@]}"; do
    [[ -n "${keep[${f}]:-}" ]] && continue      # the protected archive, already kept
    ymd="${f#drust-}"
    ymd="${ymd:0:10}"
    # Date FIRST, tier second. Fail SAFE: a name we cannot date is kept, never
    # deleted — deleting what you could not parse is how a retention pass turns
    # into data loss. It must also not consume a tier slot: reverse-NAME order
    # puts anything sorting above '2' (say `drust-NOTADATE-...`) at the front,
    # where it would silently spend a daily slot and evict a real snapshot.
    #
    # A FUTURE date is treated the same way. One NTP jump forward, or a VM
    # restored with a bad RTC, leaves an archive that sorts first forever: it
    # would win a daily slot on every run for the rest of time and permanently
    # evict a real recovery point. Keeping it costs one file once; letting it
    # tier costs one slot per run, indefinitely.
    if ! week=$(date -u -d "${ymd}" +%G-%V 2>/dev/null) || [[ "${ymd}" > "${today}" ]]; then
      keep["${f}"]=1
      continue
    fi
    # The daily tier counts DISTINCT DAYS, not archives. Counting archives looks
    # identical while the timer is the only writer — one run per day — and
    # collapses the moment it is not. With 8 runs in one day, all 7 daily slots
    # go to that single day; the day then claims its ISO week below, so every
    # other day in the same week falls through both tiers and is deleted.
    # Reproduced: 8 archives today plus one per day for the preceding week left
    # today + 4 weeklies, having deleted yesterday, the day before, and the day
    # before that. A manual run before a risky operation is enough to trigger it,
    # which is precisely when the recovery points matter most.
    #
    # First archive seen for a day is the newest (reverse sort), so "one per day"
    # keeps the latest. Extra same-day archives fall through to the weekly tier,
    # find their week already claimed, and are pruned — which is the intent: the
    # policy is 7 daily RECOVERY POINTS, not 7 files.
    if [[ -z "${seen_day[${ymd}]:-}" ]] && (( daily < KEEP_DAILY )); then
      seen_day["${ymd}"]=1
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

# Everything above is definitions. The test stops here.
if [[ -n "${DRUST_BACKUP_PRUNE_ONLY:-}" ]]; then
  return 0
fi

# ---------------------------------------------------------------------------
# Side effects begin here.
# ---------------------------------------------------------------------------

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

prune_backups "${DATA_DIR}/backups" "$(basename "${DEST}")"

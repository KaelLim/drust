#!/bin/bash
# Fixture tests for deploy/drust-backup.sh's retention pass.
#
# This is the only code in the repo that DELETES production backup archives, and
# every archive carries `tokens.plaintext` and `_admin_tokens.plaintext` verbatim,
# so a wrong deletion is unrecoverable credential-and-data loss. It had no
# automated coverage for its first release while a comment in the script claimed
# otherwise; two real defects (an archive-counting daily tier, and a run deleting
# its own output) shipped behind that claim.
#
# The script is SOURCED with DRUST_BACKUP_PRUNE_ONLY=1 so these assertions run the
# shipped `prune_backups`, not a copy. A copy would pass forever after the original
# drifted.
#
# Usage: bash deploy/tests/backup_retention_test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/../drust-backup.sh"
FAILURES=0
CASES=0

fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
ok()   { echo "ok: $*"; }

# Fresh temp dir seeded with the given archive basenames (no `drust-` prefix, no
# extension) and a fresh `prune_backups` sourced from the real script.
setup() {
  WORK="$(mktemp -d)"
  mkdir -p "${WORK}/backups"
  local n
  for n in "$@"; do : > "${WORK}/backups/drust-${n}.tar.zst"; done
}
teardown() { [[ -n "${WORK:-}" ]] && rm -rf "${WORK}"; }

# Run the real prune in a subshell so KEEP_* overrides do not leak between cases.
prune() {
  local protect="${1:-}"
  ( set -euo pipefail
    export DRUST_BACKUP_PRUNE_ONLY=1
    # shellcheck source=../drust-backup.sh
    source "${SCRIPT}"
    prune_backups "${WORK}/backups" "${protect}" )
}

kept() { ls -1 "${WORK}/backups" 2>/dev/null | sort; }
has()  { [[ -e "${WORK}/backups/drust-$1.tar.zst" ]]; }
count() { ls -1 "${WORK}/backups" 2>/dev/null | wc -l | tr -d ' '; }

expect_has() {
  CASES=$((CASES + 1))
  has "$1" || fail "$2: drust-$1.tar.zst should have been KEPT"
}
expect_gone() {
  CASES=$((CASES + 1))
  ! has "$1" || fail "$2: drust-$1.tar.zst should have been PRUNED"
}
expect_count() {
  CASES=$((CASES + 1))
  [[ "$(count)" == "$1" ]] || fail "$3: expected $1 files, got $(count) — $(kept | tr '\n' ' ')"
}

# --- 1. The baseline the policy is described in terms of -------------------
# One archive per day for a month: 7 dailies + one per ISO week for 4 weeks,
# reaching as far back as the flat 30-day window it replaced.
setup 2026-07-05-190644 2026-07-06-191018 2026-07-07-190418 2026-07-08-190958 \
      2026-07-09-190544 2026-07-10-190708 2026-07-11-190208 2026-07-12-190344 \
      2026-07-13-190618 2026-07-14-190944 2026-07-15-190444 2026-07-16-190008 \
      2026-07-17-190418 2026-07-18-190418 2026-07-19-190844 2026-07-20-190118 \
      2026-07-21-190313 2026-07-22-190918 2026-07-23-190844 2026-07-27-004824 \
      2026-07-27-190547 2026-07-28-190447 2026-07-29-190224 2026-07-30-190947 \
      2026-07-31-190547 2026-08-01-190547 2026-08-02-190707 2026-08-03-190151 \
      2026-08-04-191001 2026-08-05-190551
prune ""
expect_count 11 "" "one-per-day month"
expect_has 2026-08-05-190551 "one-per-day month"   # newest daily
expect_has 2026-07-31-190547 "one-per-day month"   # 7th daily
expect_has 2026-07-05-190644 "one-per-day month"   # oldest weekly, 31 days back
expect_gone 2026-07-06-191018 "one-per-day month"
ok "one-per-day month: 30 -> 11, reach preserved"
teardown

# --- 2. The daily tier counts DAYS, not archives ---------------------------
# Eight runs in one day must not consume all seven daily slots and evict the
# preceding week. Regression: it did, deleting three days of recovery points.
setup 2026-08-06-010000 2026-08-06-020000 2026-08-06-030000 2026-08-06-040000 \
      2026-08-06-050000 2026-08-06-060000 2026-08-06-070000 2026-08-06-080000 \
      2026-08-05-030000 2026-08-04-030000 2026-08-03-030000 2026-08-02-030000 \
      2026-08-01-030000 2026-07-31-030000 2026-07-25-030000 2026-07-18-030000
prune ""
for d in 2026-08-05-030000 2026-08-04-030000 2026-08-03-030000 2026-08-02-030000 \
         2026-08-01-030000 2026-07-31-030000; do
  expect_has "${d}" "multi-run day"
done
expect_has 2026-08-06-080000 "multi-run day"       # newest of the day survives
expect_gone 2026-08-06-070000 "multi-run day"      # the rest of the day do not
ok "multi-run day: seven DAYS kept, one archive per day"
teardown

# --- 3. A run must never delete the archive it just wrote ------------------
# `.` (0x2E) sorts above `-` (0x2D), so a stray drust-YYYY-MM-DD.tar.zst sorts
# ABOVE the canonical drust-YYYY-MM-DD-HHMMSS.tar.zst and claims the day. Without
# the unconditional protect, the timer VACUUMs every tenant DB, writes the tar,
# then deletes it and exits 0 — success recorded, no backup for that day.
setup 2026-08-06 2026-08-06-032137 2026-08-05-030000 2026-08-04-030000 \
      2026-08-03-030000 2026-08-02-030000 2026-08-01-030000 2026-07-31-030000 \
      2026-07-30-030000
prune "drust-2026-08-06-032137.tar.zst"
expect_has 2026-08-06-032137 "self-deletion"
ok "self-deletion: the just-written archive survives a name that outsorts it"
teardown

# --- 4. Unparseable names are kept and consume no slot ---------------------
# Deleting what you could not parse is how a retention pass becomes data loss;
# spending a slot on it evicts a real snapshot. Neither is acceptable.
setup NOTADATE-garbage 2026-08-06-010000 2026-08-05-010000 2026-08-04-010000 \
      2026-08-03-010000 2026-08-02-010000 2026-08-01-010000 2026-07-31-010000 \
      2026-07-30-010000
prune ""
expect_has NOTADATE-garbage "unparseable"
for d in 2026-08-06-010000 2026-08-05-010000 2026-08-04-010000 2026-08-03-010000 \
         2026-08-02-010000 2026-08-01-010000 2026-07-31-010000; do
  expect_has "${d}" "unparseable"
done
ok "unparseable: kept, and all seven real dailies still fit"
teardown

# --- 5. A future-dated archive does not squat a slot forever ---------------
# One NTP jump forward leaves a file that sorts first on every future run.
setup 2099-01-01-000000 2026-08-06-010000 2026-08-05-010000 2026-08-04-010000 \
      2026-08-03-010000 2026-08-02-010000 2026-08-01-010000 2026-07-31-010000 \
      2026-07-30-010000
prune ""
expect_has 2099-01-01-000000 "future-dated"
for d in 2026-08-06-010000 2026-08-05-010000 2026-08-04-010000 2026-08-03-010000 \
         2026-08-02-010000 2026-08-01-010000 2026-07-31-010000; do
  expect_has "${d}" "future-dated"
done
ok "future-dated: kept without consuming a daily slot"
teardown

# --- 6. Under quota, and empty ---------------------------------------------
setup 2026-08-06-010000 2026-08-05-010000 2026-08-04-010000
prune ""
expect_count 3 "" "under quota"
ok "under quota: nothing deleted"
teardown

WORK="$(mktemp -d)"; mkdir -p "${WORK}/backups"
CASES=$((CASES + 1))
prune "" || fail "empty dir: prune must exit 0"
ok "empty dir: exit 0"
teardown

# --- 7. Non-matching files are never touched -------------------------------
setup 2026-08-06-010000
: > "${WORK}/backups/unrelated.txt"
: > "${WORK}/backups/drust-2026-08-06-010000.tar.zst.tmp"
prune ""
CASES=$((CASES + 1))
[[ -e "${WORK}/backups/unrelated.txt" ]] || fail "scope: unrelated.txt was deleted"
CASES=$((CASES + 1))
[[ -e "${WORK}/backups/drust-2026-08-06-010000.tar.zst.tmp" ]] \
  || fail "scope: a partial .tmp write was deleted"
ok "scope: only drust-*.tar.zst is in scope"
teardown

# --- 8. A malformed knob stops the run instead of silently gutting it ------
# `(( daily < KEEP_DAILY ))` with a non-numeric value is permanently false, which
# switches the daily tier off and deletes nearly everything while exiting 0.
setup 2026-08-06-010000 2026-08-05-010000
CASES=$((CASES + 1))
if ( set -euo pipefail
     export DRUST_BACKUP_PRUNE_ONLY=1 DRUST_BACKUP_KEEP_DAILY=7d
     source "${SCRIPT}" ) 2>/dev/null; then
  fail "knob validation: DRUST_BACKUP_KEEP_DAILY=7d must be rejected"
else
  ok "knob validation: a non-numeric keep count exits non-zero"
fi
CASES=$((CASES + 1))
if ( set -euo pipefail
     export DRUST_BACKUP_PRUNE_ONLY=1 DRUST_BACKUP_KEEP_DAILY=3
     source "${SCRIPT}" ) 2>/dev/null; then
  ok "knob validation: a valid keep count is accepted"
else
  fail "knob validation: DRUST_BACKUP_KEEP_DAILY=3 must be accepted"
fi
teardown

echo
if (( FAILURES )); then
  echo "== ${FAILURES} failure(s) across ${CASES} assertion(s) =="
  exit 1
fi
echo "== 0 failures across ${CASES} assertions =="

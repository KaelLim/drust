#!/usr/bin/env bash
# Guard (#935): the bare-metal janitor must NOT hardcode a time-based `_trash`
# retention. `_trash` expiry is handled in-process by drust's janitor
# (DRUST_TRASH_RETENTION_DAYS, default 7, 0 = keep forever) on every deployment
# target. A hardcoded `find … _trash … -mtime +N` here caps a longer setting and
# defeats 0, which is exactly the v1.58.0 regression this removed.
set -uo pipefail
SH="$(cd "$(dirname "$0")/.." && pwd)/drust-janitor.sh"

if [ ! -f "$SH" ]; then
  echo "FAIL: $SH not found"; exit 1
fi

# A time-based `find` sweep is a hardcoded retention (the in-process janitor is
# the only mechanism, and drust-janitor.sh has no legitimate use of -mtime).
# Check every NON-COMMENT line for -mtime, so a reintroduced sweep is caught no
# matter how it is split across lines (e.g. TRASH=… on one line, find … -mtime
# on the next).
if grep -v '^[[:space:]]*#' "$SH" | grep -qE -- '-mtime'; then
  echo "FAIL: drust-janitor.sh uses a hardcoded time-based find (-mtime) — remove it;"
  echo "  the in-process janitor honors DRUST_TRASH_RETENTION_DAYS on every target."
  grep -nE -- '-mtime' "$SH"
  exit 1
fi

echo "ok: drust-janitor.sh has no hardcoded _trash retention (#935)"
exit 0

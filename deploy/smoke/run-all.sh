#!/usr/bin/env bash
# Run every check in deploy/smoke/checks/ against the running smoke stack.
#
#   deploy/smoke/run-all.sh            # all checks, in filename order
#   deploy/smoke/run-all.sh 10 40      # only the checks whose name starts with 10- or 40-
#
# Exit status is non-zero when any check script failed. Each script's full
# output is kept under deploy/smoke/.last-run/ for reading afterwards.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/.last-run"
rm -rf "$out"
mkdir -p "$out"

failed=""
total=0
for script in "$here"/checks/[0-9]*.sh; do
  name="$(basename "$script" .sh)"
  if [ "$#" -gt 0 ]; then
    want=no
    for prefix in "$@"; do
      case "$name" in "$prefix"-*) want=yes ;; esac
    done
    [ "$want" = yes ] || continue
  fi
  total=$((total + 1))
  start=$(date +%s)
  if bash "$script" > "$out/$name.log" 2>&1; then
    verdict=ok
  else
    verdict=FAIL
    failed="$failed $name"
  fi
  printf '%-5s %-28s %s  (%ss)\n' "$verdict" "$name" \
    "$(tail -n 1 "$out/$name.log")" "$(( $(date +%s) - start ))"
done

echo
if [ -n "$failed" ]; then
  echo "failed:$failed"
  echo "details: $out/<name>.log   (grep '^FAIL' to see the failing checks)"
  exit 1
fi
echo "all $total check scripts passed"

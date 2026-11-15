#!/usr/bin/env bash
# Stop the local smoke stack. `--wipe` also deletes every volume of the smoke
# compose project (drust data, logs, the object store's data), the generated
# deploy/smoke/.env and deploy/smoke/.generated, so the next up.sh starts from a
# first boot. SMOKE_COMPOSE_PROJECT (default drust-smoke) must match up.sh's.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
env_file="$here/.env"

wipe=no; [ "${1:-}" = --wipe ] && wipe=yes
project="${SMOKE_COMPOSE_PROJECT:-drust-smoke}"
if [ -f "$env_file" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
  export SMOKE_STORE="${SMOKE_STORE:-garage}"   # a .env from before SMOKE_STORE was a Garage stack
  # shellcheck source=compose-files.sh
  . "$here/compose-files.sh"
  if [ $wipe = yes ]; then compose down --volumes --remove-orphans; else compose down --remove-orphans; fi
else
  # No .env: the override files refuse to parse without their variables, and
  # `down` needs only the project name.
  docker compose -p "$project" down --remove-orphans
fi
if [ $wipe = yes ]; then
  # Volumes of a store this run did not load (after a SMOKE_STORE switch) still carry
  # the project label: remove exactly those, nothing else.
  vols="$(docker volume ls -q --filter "label=com.docker.compose.project=$project")"
  # shellcheck disable=SC2086
  [ -z "$vols" ] || docker volume rm $vols
  rm -f "$env_file"; rm -rf "$here/.generated"
  echo "wiped volumes, $env_file and $here/.generated"
fi

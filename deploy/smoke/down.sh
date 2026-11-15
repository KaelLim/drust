#!/usr/bin/env bash
# Stop the local smoke stack. `--wipe` also deletes its volumes (drust data,
# logs, Garage objects) and the generated deploy/smoke/.env, so the next up.sh
# starts from a first boot.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
env_file="$here/.env"

args=(down)
if [ "${1:-}" = "--wipe" ]; then
  args=(down --volumes)
fi

# The override file refuses to parse without its variables, and .env may already
# be gone; dummy values are enough for `down`, which only needs the project name.
if [ -f "$env_file" ]; then
  docker compose --project-directory "$root" --env-file "$env_file" \
    -f "$root/docker-compose.yml" -f "$here/docker-compose.smoke.yml" "${args[@]}"
else
  docker compose -p drust-smoke "${args[@]}"
fi

if [ "${1:-}" = "--wipe" ]; then
  rm -f "$env_file"
  echo "wiped volumes and $env_file"
fi

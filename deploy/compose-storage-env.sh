#!/usr/bin/env bash
# Turn on the bundled RustFS object store for docker compose:
#   deploy/compose-storage-env.sh && docker compose up -d
# Writes .env next to docker-compose.yml (mode 600): COMPOSE_FILE, so plain
# `docker compose` also loads docker-compose.storage.yml, and freshly generated
# keys. Adds only what is missing; never changes or prints an existing value.
# Windows (no bash): write the same five lines by hand, with ";" in COMPOSE_FILE.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
env_file="${1:-$root/.env}"
hex() { openssl rand -hex "$1"; }
# Last value of KEY in .env; empty when the file or the key is absent. The -f test
# comes first: under pipefail, sed on a missing file would end the script here.
get() { [ -f "$env_file" ] || return 0; sed -n "s/^$1=//p" "$env_file" | tail -n 1; }

# A .env that points drust at a different store is somebody's real configuration
# (the bare-metal host's .env, a MinIO setup): refuse rather than merge into it.
ep="$(get GARAGE_S3_ENDPOINT)"
case "$ep" in
  ""|http://rustfs:9000) ;;
  *) echo "$env_file sets GARAGE_S3_ENDPOINT=$ep; not touching it (see README, Object storage on Docker Compose)" >&2; exit 1 ;;
esac
cf="$(get COMPOSE_FILE)"
case "$cf" in
  ""|*docker-compose.storage.yml*) ;;
  *) echo "$env_file sets COMPOSE_FILE=$cf; add docker-compose.storage.yml to it yourself" >&2; exit 1 ;;
esac

umask 077
touch "$env_file"
add() { # KEY VALUE: append unless KEY already has a non-empty value
  if [ -n "$(get "$1")" ]; then return 0; fi
  grep -v "^$1=" "$env_file" > "$env_file.tmp" || true   # drop an empty "KEY=" line
  printf '%s=%s\n' "$1" "$2" >> "$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  echo "  added $1"
}
add COMPOSE_FILE "docker-compose.yml:docker-compose.storage.yml"
# Lengths are the ones the RustFS probe ran: 20-character access keys, 40-character secrets.
add RUSTFS_ACCESS_KEY "$(hex 10)"
add RUSTFS_SECRET_KEY "$(hex 20)"
add GARAGE_S3_ACCESS_KEY "$(hex 10)"
add GARAGE_S3_SECRET_KEY "$(hex 20)"
chmod 600 "$env_file"

# The volume the removed bundled MinIO wrote to, in THIS compose project only
# (Compose's default project name is the directory name, lowercased).
project="${COMPOSE_PROJECT_NAME:-$(get COMPOSE_PROJECT_NAME)}"
project="${project:-$(basename "$root")}"
project="$(printf '%s' "$project" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')"
if command -v docker >/dev/null 2>&1 \
   && docker volume inspect "${project}_minio-data" >/dev/null 2>&1; then
  echo "note: volume ${project}_minio-data (the old bundled MinIO) exists. Its objects are NOT" \
       "moved by this script; see README, 'Upgrading from the bundled MinIO', before you delete it." >&2
fi
echo "storage enabled in $env_file; now run: docker compose up -d"

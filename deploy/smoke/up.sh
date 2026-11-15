#!/usr/bin/env bash
# Bring up the local smoke stack: the real docker-compose.yml + a real Garage.
#
#   deploy/smoke/up.sh            # build if needed, start, bootstrap Garage
#   deploy/smoke/up.sh --no-build # reuse the image that is already built
#   deploy/smoke/down.sh          # stop; add --wipe to delete the volumes too
#
# Secrets are generated once into deploy/smoke/.env (gitignored) and reused on
# later runs, so the admin password and the Garage key survive a restart.
# Works with the bash 3.2 that macOS ships.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
env_file="$here/.env"

hex() { openssl rand -hex "$1"; }

if [ ! -f "$env_file" ]; then
  umask 077
  {
    echo "SMOKE_ADMIN_USERNAME=${SMOKE_ADMIN_USERNAME:-admin}"
    echo "SMOKE_ADMIN_PASSWORD=${SMOKE_ADMIN_PASSWORD:-$(hex 12)}"
    echo "SMOKE_GARAGE_RPC_SECRET=$(hex 32)"
    echo "SMOKE_GARAGE_ADMIN_TOKEN=$(hex 32)"
    echo "SMOKE_S3_ACCESS_KEY=GK$(hex 12)"
    echo "SMOKE_S3_SECRET_KEY=$(hex 32)"
  } > "$env_file"
  echo "generated $env_file"
fi
set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

http_port="${SMOKE_HTTP_PORT:-48080}"
drust_port="${SMOKE_DRUST_PORT:-48826}"
admin_port="${SMOKE_GARAGE_ADMIN_PORT:-48903}"

compose() {
  docker compose --project-directory "$root" --env-file "$env_file" \
    -f "$root/docker-compose.yml" -f "$here/docker-compose.smoke.yml" "$@"
}

garage_api() { # METHOD PATH [JSON]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -fsS -X "$method" "http://127.0.0.1:$admin_port$path" \
      -H "Authorization: Bearer $SMOKE_GARAGE_ADMIN_TOKEN" \
      -H 'Content-Type: application/json' --data "$body"
  else
    curl -fsS -X "$method" "http://127.0.0.1:$admin_port$path" \
      -H "Authorization: Bearer $SMOKE_GARAGE_ADMIN_TOKEN"
  fi
}

json_get() { # KEY — first string value of KEY in the JSON on stdin
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

# ---- 1. Garage first: drust lists the public bucket at boot ------------------
compose up -d garage
printf 'waiting for Garage admin API'
for _ in $(seq 1 60); do
  if garage_api GET /v1/status >/dev/null 2>&1; then break; fi
  printf '.'; sleep 1
done
echo
node_id="$(garage_api GET /v1/status | json_get node)"

layout_version="$(garage_api GET /v1/layout | json_get version)"
if [ "$layout_version" = "0" ]; then
  garage_api POST /v1/layout \
    "[{\"id\":\"$node_id\",\"zone\":\"smoke\",\"capacity\":1000000000,\"tags\":[]}]" >/dev/null
  garage_api POST /v1/layout/apply '{"version":1}' >/dev/null
  echo "garage: layout applied"
fi

if ! garage_api GET "/v1/key?id=$SMOKE_S3_ACCESS_KEY" >/dev/null 2>&1; then
  garage_api POST /v1/key/import \
    "{\"name\":\"drust-smoke\",\"accessKeyId\":\"$SMOKE_S3_ACCESS_KEY\",\"secretAccessKey\":\"$SMOKE_S3_SECRET_KEY\"}" >/dev/null
  echo "garage: access key imported"
fi

# drust writes to exactly two fixed buckets and never creates them itself:
# "public" (served by Garage's website endpoint) and "private" (proxied by
# drust). A missing "private" bucket is not caught at boot — the boot check
# lists "public" only — and shows up later as 502 on every private upload.
for bucket in public private; do
  if ! garage_api GET "/v1/bucket?globalAlias=$bucket" >/dev/null 2>&1; then
    garage_api POST /v1/bucket "{\"globalAlias\":\"$bucket\"}" >/dev/null
    echo "garage: bucket '$bucket' created"
  fi
  bucket_id="$(garage_api GET "/v1/bucket?globalAlias=$bucket" | json_get id)"
  garage_api POST /v1/bucket/allow \
    "{\"bucketId\":\"$bucket_id\",\"accessKeyId\":\"$SMOKE_S3_ACCESS_KEY\",\"permissions\":{\"read\":true,\"write\":true,\"owner\":true}}" >/dev/null
  if [ "$bucket" = public ]; then
    garage_api PUT "/v1/bucket?id=$bucket_id" \
      '{"websiteAccess":{"enabled":true,"indexDocument":"index.html"}}' >/dev/null
  fi
done

# ---- 2. drust + Caddy --------------------------------------------------------
if [ "${1:-}" = "--no-build" ]; then
  compose up -d --no-build drust caddy
else
  compose up -d --build drust caddy
fi

printf 'waiting for drust'
for _ in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:$drust_port/health" >/dev/null 2>&1; then break; fi
  printf '.'; sleep 1
done
echo
curl -fsSI "http://127.0.0.1:$drust_port/health" | grep -i '^x-drust' || {
  echo "drust did not answer with a version header; last log lines follow" >&2
  compose logs --tail 40 drust >&2
  exit 1
}

# ---- 3. admin PAT for the check scripts --------------------------------------
# The checks authenticate with a personal access token, so they never handle
# the password and never trip the per-IP login rate limit. Minted once and kept
# in .env; re-minted only when the stored one no longer works (e.g. after --wipe
# or a manual reroll in the UI).
base="http://127.0.0.1:$http_port"
pat_ok() {
  [ -n "${SMOKE_ADMIN_PAT:-}" ] && [ "$(curl -s -o /dev/null -w '%{http_code}' \
    "$base/admin/api/tenants" -H "Authorization: Bearer $SMOKE_ADMIN_PAT")" = "200" ]
}
if ! pat_ok; then
  jar="$(mktemp)"
  curl -fsS -o /dev/null -c "$jar" -X POST "$base/login" \
    --data-urlencode "username=$SMOKE_ADMIN_USERNAME" \
    --data-urlencode "password=$SMOKE_ADMIN_PASSWORD"
  SMOKE_ADMIN_PAT="$(curl -fsS -b "$jar" -X POST "$base/admin/settings/token/reroll" | json_get plaintext)"
  rm -f "$jar"
  grep -v '^SMOKE_ADMIN_PAT=' "$env_file" > "$env_file.tmp" || true
  echo "SMOKE_ADMIN_PAT=$SMOKE_ADMIN_PAT" >> "$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  chmod 600 "$env_file"
  pat_ok || { echo "minted an admin PAT but it does not authenticate" >&2; exit 1; }
  echo "admin PAT minted into $env_file"
fi

cat <<EOF

drust smoke stack is up.
  admin UI   http://localhost:$http_port/login
  username   $SMOKE_ADMIN_USERNAME
  password   in $env_file  (SMOKE_ADMIN_PASSWORD)
  direct     http://127.0.0.1:$drust_port   (bypasses Caddy; debugging only)
  logs       docker compose -p drust-smoke logs -f drust
  stop       deploy/smoke/down.sh           (--wipe also deletes the volumes)
EOF

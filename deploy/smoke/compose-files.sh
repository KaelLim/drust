# Sourced by up.sh and down.sh (needs $root, $here, $env_file, $SMOKE_STORE): the
# one place that decides which compose files make up the smoke stack.
smoke_project="${SMOKE_COMPOSE_PROJECT:-drust-smoke}"
smoke_files=(-f "$root/docker-compose.yml" -f "$here/docker-compose.smoke.yml")
# The store file goes AFTER docker-compose.smoke.yml. Compose v2.40 drops that
# file's `DRUST_HIDE_VERSION: !reset null` when another file that merges into
# drust.environment sits between it and the base file, and up.sh's version-header
# check then fails. RustFS mode runs the REAL Compose storage file, unmodified.
if [ "$SMOKE_STORE" = rustfs ]; then smoke_files+=(-f "$root/docker-compose.storage.yml"); fi
if [ "$SMOKE_STORE" = garage ]; then smoke_files+=(-f "$here/docker-compose.smoke-garage.yml"); fi
compose() {
  docker compose -p "$smoke_project" --project-directory "$root" \
    --env-file "$env_file" "${smoke_files[@]}" "$@"
}

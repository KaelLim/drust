#!/usr/bin/env bash
# Run the test gate inside a Linux container, from the current working tree.
#
#   deploy/smoke/test-linux.sh                      # make test-shell + cargo test --no-fail-fast
#   deploy/smoke/test-linux.sh cargo test --test g_misc
#   deploy/smoke/test-linux.sh bash                 # a shell in the test image
#
# Why this exists: CI runs only `cargo test --lib`, and a macOS workstation
# cannot run the rest honestly — deploy/drust-backup.sh needs GNU bash
# (`mapfile`) and GNU find (`-printf`), so `make test-shell` and
# tests/backup_roundtrip.rs fail there for reasons that have nothing to do with
# drust. This is the one place the whole integration suite runs on the OS that
# all three deployment targets actually use.
#
# The source is COPIED into a volume (tracked files plus untracked ones that
# are not ignored), so nothing the tests write lands in the host working tree.
# The build cache lives in named volumes and survives between runs:
#   drust-linux-test-src, drust-linux-test-target, drust-linux-test-cargo
# Remove them with: docker volume rm drust-linux-test-{src,target,cargo}
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
image=drust-linux-test

docker build -q -t "$image" - >/dev/null <<'EOF'
FROM rust:1-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config clang libclang-dev make git curl ca-certificates \
      sqlite3 zstd rsync python3 procps \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add clippy rustfmt \
 && useradd --create-home --uid 1000 tester \
 && mkdir -p /src /target /home/tester/.cargo \
 && chown tester:tester /src /target /home/tester/.cargo
# Unprivileged on purpose: root ignores file modes, which would turn every
# "this path is not readable/writable" test into a false pass or a false fail.
USER tester
ENV CARGO_HOME=/home/tester/.cargo \
    CARGO_TARGET_DIR=/target \
    CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_INCREMENTAL=0
WORKDIR /src
EOF

vols=(
  -v drust-linux-test-src:/src
  -v drust-linux-test-target:/target
  -v drust-linux-test-cargo:/home/tester/.cargo
)

# Sync the working tree. File mtimes are preserved, so cargo's fingerprints
# stay valid and an unchanged tree does not recompile.
cd "$root"
git ls-files -z --cached --others --exclude-standard \
  | while IFS= read -r -d '' f; do
      case "$f" in .codegraph/*|.codebase-memory/*) continue ;; esac
      [ -e "$f" ] && printf '%s\0' "$f"
    done \
  | COPYFILE_DISABLE=1 tar --null --no-xattrs -T - -cf - \
  | docker run --rm -i "${vols[@]}" "$image" \
      sh -c 'find /src -mindepth 1 -delete && tar -xf - -C /src 2>/dev/null; test -f /src/Cargo.toml'

if [ "$#" -eq 0 ]; then
  set -- sh -c 'make test-shell && cargo test --no-fail-fast'
fi

tty=()
if [ -t 0 ] && [ -t 1 ]; then tty=(-it); fi

exec docker run --rm ${tty[@]+"${tty[@]}"} "${vols[@]}" "$image" "$@"

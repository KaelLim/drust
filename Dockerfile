# syntax=docker/dockerfile:1.7
#
# drust — multi-tenant SQLite BaaS — production container image.
#
# Multi-stage: a Rust builder compiles the release binaries (rusqlite's
# `bundled` feature builds SQLite from C source, so the builder needs a C
# toolchain), and a slim Debian runtime carries only the binaries + TLS roots.
# SQLite is statically linked into the binary and wasmtime's JIT runs in-process,
# so the runtime needs no system database/runtime libraries — only ca-certificates
# for outbound HTTPS (OAuth token endpoints, S3 object store, webhooks).
#
# Build:  DOCKER_BUILDKIT=1 docker build -t drust:latest .
# Run:    see docker-compose.yml, or the "Run with Docker" section in README.md.

# ---- builder ----------------------------------------------------------------
# rust:1 (latest stable) — the pinned Cargo.lock resolves libsqlite3-sys 0.38,
# which needs a newer compiler than 1.93 (uses the now-stable `cfg_select`).
# The lock is committed for reproducibility; the builder just needs to be >= the
# real MSRV, and latest-stable always is.
FROM rust:1-slim-bookworm AS builder

# build-essential = cc + headers for rusqlite's bundled SQLite C compile.
# clang + libclang-dev = bindgen: the rusqlite `preupdate_hook` feature
# (record-history capture for write-mode RPCs, v1.46+) forces libsqlite3-sys
# into buildtime_bindgen, which needs libclang.so AND clang's builtin headers
# (stdarg.h). Dropping these makes `cargo build --locked` fail here while
# host builds keep working — do not remove.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config clang libclang-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# BuildKit cache mounts persist the cargo registry + target dir across rebuilds
# so iterating doesn't repay the full (LTO, ~10 min) compile every time. The
# release artifacts live in the cache mount, so copy them out before the mount
# is unmounted.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked \
 && mkdir -p /out \
 && cp target/release/drust \
       target/release/drust_session_janitor \
       target/release/set_admin_role \
       target/release/set_admin_password \
       /out/

# ---- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: TLS roots for outbound HTTPS. curl: HEALTHCHECK probe.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin drust \
 && mkdir -p /data /logs \
 && chown -R drust:drust /data /logs

COPY --from=builder /out/ /usr/local/bin/

# Run unprivileged. /data holds meta.sqlite + meta_logs.sqlite + tenants/<id>/ +
# backups/; /logs is the reserved log dir.
USER drust
WORKDIR /data

# DRUST_BASE_PATH="" → serve at the ROOT path: drust's browser-facing URLs
# (redirects, cookie Paths, OAuth redirect_uri, admin links) carry no "/drust"
# prefix, so the image works standalone or behind a root-mounted proxy. Set
# DRUST_BASE_PATH=/drust if you front it with a proxy that mounts drust under
# that subpath (e.g. Caddy `handle_path /drust/*`, as in deploy/Caddyfile).
ENV DRUST_BIND=0.0.0.0:47826 \
    DRUST_DATA_DIR=/data \
    DRUST_LOG_DIR=/logs \
    DRUST_BASE_PATH=""

VOLUME ["/data", "/logs"]
EXPOSE 47826

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:47826/health || exit 1

# IMPORTANT: do NOT run this container under a seccomp/AppArmor profile that
# blocks `mmap(PROT_EXEC)`. Edge functions execute guest WebAssembly via
# wasmtime's Cranelift JIT, which must map executable memory. Docker's default
# seccomp profile permits this; a hardened "no exec memory" profile makes every
# edge-function upload/invoke fail with EPERM. (The guest sandbox is enforced
# inside wasmtime — epoch deadline + memory cap + empty WASI ctx — not by W^X.)
ENTRYPOINT ["drust"]

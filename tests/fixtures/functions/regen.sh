#!/usr/bin/env bash
# Rebuild the three committed fixture components. Requires:
#   rustup target add wasm32-wasip2
# Fallback if the plain target build does not emit a component (see plan
# Grounding note 10): cargo install cargo-component && use `cargo component build`.
set -euo pipefail
cd "$(dirname "$0")"
for f in happy loop membomb; do
  (cd "src-$f" && cargo build --target wasm32-wasip2 --release)
  cp "src-$f/target/wasm32-wasip2/release/"*.wasm "$f.wasm"
done
ls -la *.wasm

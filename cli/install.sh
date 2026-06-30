#!/bin/sh
# drust CLI installer — downloads a prebuilt binary from GitHub Releases.
set -eu
REPO="${DRUST_CLI_REPO:-KaelLim/drust}"
DEST="${DRUST_CLI_DEST:-$HOME/.local/bin}"
os="$(uname -s)"; arch="$(uname -m)"
case "$os-$arch" in
  Linux-x86_64)   target="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64)  target="aarch64-unknown-linux-gnu" ;;
  Darwin-x86_64)  target="x86_64-apple-darwin" ;;
  Darwin-arm64)   target="aarch64-apple-darwin" ;;
  *) echo "unsupported platform: $os-$arch" >&2; exit 1 ;;
esac
tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep -m1 '"tag_name"' | cut -d'"' -f4)"
url="https://github.com/$REPO/releases/download/$tag/drust-$target"
mkdir -p "$DEST"
echo "downloading drust $tag ($target) → $DEST/drust"
curl -fsSL "$url" -o "$DEST/drust"
curl -fsSL "$url.sha256" -o "$DEST/drust.sha256" || true
chmod +x "$DEST/drust"
echo "installed. ensure $DEST is on your PATH:  export PATH=\"$DEST:\$PATH\""

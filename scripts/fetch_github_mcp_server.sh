#!/usr/bin/env bash
# Download the pinned github-mcp-server release and verify its sha256.
# Usage: scripts/fetch_github_mcp_server.sh [dest_dir]   (default: .work/gms)
set -euo pipefail

VERSION="v2.0.2"
DEST="${1:-.work/gms}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  ASSET="github-mcp-server_Linux_x86_64.tar.gz"
                 SHA="815e27d931c796af0c97f24fd211e14f8a4607d4528377719a5ad2352086b0b0" ;;
  Darwin-arm64)  ASSET="github-mcp-server_Darwin_arm64.tar.gz"
                 SHA="5d9b38511bffc84d2272eb6189129eb721c8900e45784d8ea7eaf25f8d3dd835" ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m); add its pinned sha256" >&2; exit 1 ;;
esac

mkdir -p "$DEST"
ARCHIVE="$DEST/$ASSET"
curl -fsSL -o "$ARCHIVE" \
  "https://github.com/github/github-mcp-server/releases/download/${VERSION}/${ASSET}"

if command -v sha256sum >/dev/null; then
  GOT="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
else
  GOT="$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)"
fi
if [[ "$GOT" != "$SHA" ]]; then
  echo "checksum mismatch for $ASSET: got $GOT want $SHA" >&2
  rm -f "$ARCHIVE"
  exit 1
fi

tar -xzf "$ARCHIVE" -C "$DEST" github-mcp-server
rm -f "$ARCHIVE"
chmod 0755 "$DEST/github-mcp-server"
echo "$DEST/github-mcp-server"

#!/bin/sh
# Downloads the mihomo (Clash Meta) core binary, used to actually connect
# through a Clash proxy node so we can see its real egress IP.
set -eu

MIHOMO_VERSION="${MIHOMO_VERSION:-v1.19.28}"
DEST="${1:-./bin/mihomo}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) MIHOMO_ARCH=amd64 ;;
  aarch64|arm64) MIHOMO_ARCH=arm64 ;;
  *) echo "不支持的架构: $ARCH" >&2; exit 1 ;;
esac

mkdir -p "$(dirname "$DEST")"
tmp="$(mktemp)"
url="https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/mihomo-linux-${MIHOMO_ARCH}-${MIHOMO_VERSION}.gz"

echo "downloading $url"
curl -fsSL -o "$tmp" "$url"
gunzip -c "$tmp" > "$DEST"
chmod +x "$DEST"
rm -f "$tmp"

echo "mihomo installed to $DEST"
"$DEST" -v

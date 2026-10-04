#!/usr/bin/env bash
# Build Silent Tunnel binaries for all supported platforms into bin/.
# Requires Go 1.22+ in PATH.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.version=${VERSION}"

mkdir -p bin
echo "version: ${VERSION}"

for target in \
    linux/amd64 \
    linux/arm64 \
    windows/amd64; do
    GOOS="${target%%/*}"
    GOARCH="${target##*/}"
    out="bin/silent-${GOOS}-${GOARCH}"
    if [ "${GOOS}" = "windows" ]; then
        out="${out}.exe"
    fi
    echo "building ${target} -> ${out}"
    GOOS="${GOOS}" GOARCH="${GOARCH}" CGO_ENABLED=0 \
        go build -trimpath -ldflags "${LDFLAGS}" -o "${out}" .
done

echo "done:"
ls -lh bin/

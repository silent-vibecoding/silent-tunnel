#!/usr/bin/env bash
# Silent Tunnel server installer (Linux).
# Downloads the latest release binary for this architecture, installs it to
# /usr/local/bin/silent and opens the interactive menu.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/USER/silent-tunnel/main/install.sh)
#
# Offline servers: copy the matching bin/silent-linux-* binary manually:
#   install -m755 silent-linux-amd64 /usr/local/bin/silent && silent
set -euo pipefail

REPO_URL="${SILENT_REPO:-https://github.com/silent-vibecoding/silent-tunnel}"
PREFIX="/usr/local/bin"

if [ "$(id -u)" -ne 0 ]; then
    echo "با root اجرا کن (sudo bash install.sh)"; exit 1
fi

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)  ASSET="silent-linux-amd64" ;;
    aarch64|arm64) ASSET="silent-linux-arm64" ;;
    *) echo "معماری پشتیبانی نمی‌شود: ${ARCH}"; exit 1 ;;
esac

echo "» دریافت ${REPO_URL}/releases/latest/download/${ASSET}"
TMP="$(mktemp)"
if ! curl -fsSL --ipv4 -o "${TMP}" "${REPO_URL}/releases/latest/download/${ASSET}"; then
    rm -f "${TMP}"
    echo "دانلود ناموفق بود (گیت‌هاب در دسترس نیست؟)."
    echo "مسیر آفلاین: باینری silent-linux-* را کپی کن و اجرا کن:"
    echo "  install -m755 silent-linux-amd64 ${PREFIX}/silent && silent"
    exit 1
fi
install -m755 "${TMP}" "${PREFIX}/silent"
rm -f "${TMP}"

echo "✔ نصب شد: ${PREFIX}/silent"
"${PREFIX}/silent" version
echo "» منوی تعاملی باز می‌شود…"
exec "${PREFIX}/silent"

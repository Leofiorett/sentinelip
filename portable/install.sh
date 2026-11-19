#!/usr/bin/env bash
# Instalador manual de Sentinel IP para Linux x86_64.
# No instala servicios, no genera autorrun ni persistencia oculta.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
BIN="$SRC/bin/sentinel-linux-x86_64"

if [ ! -x "$BIN" ]; then
  echo "[!] Falta bin/sentinel-linux-x86_64 en el pendrive." >&2
  exit 1
fi

DEST_DIR="$HOME/.local/bin"
if [ "${1:-}" = "--system" ]; then
  DEST_DIR="/usr/local/bin"
fi

mkdir -p "$DEST_DIR"
install -m 0755 "$BIN" "$DEST_DIR/sentinel"

echo "[+] Instalado: $DEST_DIR/sentinel"
echo
echo "Uso:"
echo "  sentinel --port 8000            # modo real (pide sudo; Kali/Debian/Ubuntu)"
echo "  sentinel --demo --port 8000     # modo demo, sin root"
echo
echo "Si ~/.local/bin no esta en tu PATH, agregalo a ~/.profile:"
echo '  export PATH="$HOME/.local/bin:$PATH"'

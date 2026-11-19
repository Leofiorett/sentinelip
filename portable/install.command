#!/usr/bin/env bash
# Instalador manual de Sentinel IP (modo demo) para macOS.
# No instala servicios, no genera autorrun ni persistencia oculta.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.local/sentinel-ip"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] Se necesita Python 3.11+ (python3)." >&2
  exit 1
fi

mkdir -p "$DEST"
python3 -m venv "$DEST/venv"
"$DEST/venv/bin/python" -m pip install --no-index --find-links="$SRC/demo/wheels" -r "$SRC/demo/requirements-demo.txt"
cp -a "$SRC/demo/app" "$DEST/app"
cp "$SRC/demo/sentinel.py" "$DEST/sentinel.py"

cat > "$DEST/sentinel-demo.command" <<EOF
#!/usr/bin/env bash
cd "$DEST"
"$DEST/venv/bin/python" sentinel.py --demo --port 8000
EOF
chmod +x "$DEST/sentinel-demo.command"

echo "[+] Instalado: $DEST/sentinel-demo.command"
echo "[+] Modo real NO disponible en macOS (requiere Linux con raw sockets)."

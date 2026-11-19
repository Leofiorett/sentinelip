#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="/home/fioretto/netpwn/app"
VENV="/home/fioretto/netpwn/venv"
PY="$VENV/bin/python"

rm -rf "$ROOT/build/work" "$ROOT/build/sentinel-linux-x86_64.spec" "$ROOT/dist/sentinel-linux-x86_64"
mkdir -p "$ROOT/build/work" "$ROOT/dist"

"$PY" -m PyInstaller \
  --noconfirm --clean \
  --onefile \
  --name sentinel-linux-x86_64 \
  --distpath "$ROOT/dist" \
  --workpath "$ROOT/build/work" \
  --specpath "$ROOT/build" \
  --paths "$APP" \
  --paths "$APP/core" \
  --paths "$APP/modules" \
  --add-data "$APP:." \
  --hidden-import main \
  --collect-submodules core \
  --collect-submodules modules \
  --collect-all uvicorn \
  --collect-all scapy \
  --collect-all netifaces2 \
  --collect-all pydantic \
  "$ROOT/sentinel.py"

ls -lh "$ROOT/dist/sentinel-linux-x86_64"

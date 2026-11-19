#!/usr/bin/env bash
# Instalador del agente Sentinelip en la laptop (ejecutar con sudo).
set -e
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Este agente necesita root: sudo ./install.sh"
  exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "[!] Falta python3-venv: apt update && apt install -y python3-venv"
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  echo "[*] Creando entorno virtual..."
  python3 -m venv .venv
fi

echo "[*] Instalando dependencias..."
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements-real.txt

chmod +x cloudflared agent.py sentinelip.py

CRON="@reboot cd $PWD && .venv/bin/python agent.py >> agent.log 2>&1"
( crontab -l 2>/dev/null | grep -v 'sentinelip-agent/agent.py' || true; echo "$CRON" ) | crontab -

if ! pgrep -f 'sentinelip-agent/agent.py' >/dev/null; then
  setsid nohup .venv/bin/python agent.py >> agent.log 2>&1 &
fi

sleep 5
echo "[*] Agente iniciado. Registro actual:"
cat agent_url.txt 2>/dev/null || echo "esperando URL del tunel..."
echo "[*] Abrí https://harder-upgrading-coated-mice.trycloudflare.com"

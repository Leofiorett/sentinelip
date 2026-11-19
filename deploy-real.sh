#!/bin/bash
# Uso: ./deploy-real.sh usuario@IP [dominio] [ruta/a/llave_privada]
set -euo pipefail

HOST="${1:?Uso: deploy-real.sh usuario@IP [dominio] [llave_privada]}"
DOMAIN="${2:-}"
KEY="${3:-}"
TARBALL=/home/fioretto/sentinelip-deploy/dist/sentinelip-real-1.0.tar.gz

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
[ -n "$KEY" ] && SSH_OPTS+=(-i "$KEY")

echo "== Verificando Docker en $HOST =="
ssh "${SSH_OPTS[@]}" "$HOST" 'command -v docker >/dev/null || { echo "Docker no instalado en el VPS"; exit 1; }; docker compose version >/dev/null 2>&1 || sudo docker compose version >/dev/null 2>&1 || { echo "Falta docker compose plugin"; exit 1; }'

echo "== Copiando Sentinelip (modo real) =="
scp "${SSH_OPTS[@]}" "$TARBALL" "$HOST:/tmp/sentinelip-real.tar.gz"

echo "== Desplegando =="
ssh "${SSH_OPTS[@]}" "$HOST" 'bash -s' -- "$DOMAIN" <<'REMOTE'
set -euo pipefail
DOMAIN="$1"
if docker ps >/dev/null 2>&1; then
  SUDO=""
else
  SUDO="sudo"
fi
mkdir -p ~/sentinelip
tar xzf /tmp/sentinelip-real.tar.gz -C ~/sentinelip
rm -f /tmp/sentinelip-real.tar.gz
cd ~/sentinelip
$SUDO docker compose -f docker-compose.real.yml down >/dev/null 2>&1 || true
$SUDO env SENTINEL_DOMAIN="$DOMAIN" docker compose -f docker-compose.real.yml up -d --build
sleep 15
$SUDO docker compose -f docker-compose.real.yml ps
curl -fsS http://127.0.0.1:8000/api/envcheck
echo
REMOTE

if [ -n "$DOMAIN" ]; then
  echo "== Listo: https://$DOMAIN =="
else
  echo "== Listo: http://$HOST:8000 =="
fi

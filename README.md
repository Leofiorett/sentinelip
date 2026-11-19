# Sentinelip

Repo: https://github.com/Leofiorett/sentinelip

Suite gráfica de auditoría de redes. Modo real (root, raw sockets, iptables,
WiFi monitor) + agente para mapear la red local del operador desde cualquier
lugar + relay público con túnel Cloudflare.

> **SOLO PARA LABORATORIOS AUTORIZADOS.** Los módulos incluyen MITM/ARP,
> deauth WiFi, captura de credenciales y escaneo. Uso no autorizado es ilegal.

## Estructura

- `app/` — FastAPI + WebSocket + UI (código real, sin modo demo por defecto).
- `sentinelip.py` — launcher; en Linux corre real como root (`--demo` como respaldo).
- `relay/relay.py` — link público; redirige al agente activo o al real local.
- `agent/` — agente Linux/root para la laptop del operador; registra su URL.
- `Dockerfile`, `docker-compose.real.yml`, `deploy-real.sh` — despliegue en VPS.
- `portable/` — launchers e instaladores portátiles (demo en Windows/macOS).

## Modo real local

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-real.txt
sudo .venv/bin/python sentinelip.py --no-elevate --host 127.0.0.1 --port 8010
```

## Relay + agente (mapear la red donde estés)

```bash
# servidor / relay
SENTINELIP_URL=https://TU_LINK SENTINELIP_AGENT_TAR=/ruta/agente.tar.gz \
  .venv/bin/python -m uvicorn relay.relay:app --host 127.0.0.1 --port 18000

# laptop Kali del operador
cd agent && sudo ./install.sh
```

El agente levanta Sentinelip real en `127.0.0.1:8010`, abre un túnel
Cloudflare propio y hace POST a `/api/agent/register` cada 30 s. El link
principal redirige al agente registrado (TTL 5 min) y, si no hay agente,
al real local del servidor.

Variables de entorno:

- `SENTINELIP_URL` — link público del relay (default en el código).
- `SENTINELIP_AGENT_TAR` — ruta del tarball descargable en `/agent/download`.

## VPS (IP/link fijo)

```bash
chmod +x deploy-real.sh
./deploy-real.sh usuario@IP dominio.com ruta/a/llave_privada
```

Requiere Docker + compose en el VPS. El contenedor corre privilegiado con
`network_mode: host`, `NET_ADMIN`, `NET_RAW` y `SYS_ADMIN`.

## Descargo

Uso únicamente en entornos propios/autorizados. El proveedor del VPS puede
suspender la cuenta si se escanean redes de terceros.

# Sentinelip Agent — escanea la red donde estés

El link público `https://harder-upgrading-coated-mice.trycloudflare.com`
redirige automáticamente al agente activo. El agente corre **en tu laptop**
con root y expone su propia interfaz para mapear la red local (WiFi/cable)
del lugar donde estés.

## Instalación (laptop Kali/Linux con root)

```bash
tar xzf sentinelip-agent-1.0.tar.gz
cd sentinelip-agent
sudo ./install.sh
```

El instalador:

- crea `.venv` e instala dependencias,
- arranca Sentinelip en modo REAL en `127.0.0.1:8010`,
- levanta un túnel Cloudflare propio,
- registra esa URL en el link público cada 30 s,
- agrega `@reboot` al cron de root para que vuelva a arrancar solo.

## Uso

1. Conectate a la red del lugar donde estés.
2. Abrí `https://harder-upgrading-coated-mice.trycloudflare.com` desde cualquier dispositivo.
3. El link te redirige a tu laptop; ahí escaneás **esa** red local.

Si apagás el agente, el link vuelve al real de la máquina original a los
5 minutos. Si cambiás de red, el agente se registra de nuevo y el link te
sigue.

## Archivos

- `agent_url.txt`: URL pública actual del agente.
- `agent.log`: log del agente y de la app.
- `tunnel.log`: log de cloudflared.

## Requisitos

- Linux con root (Kali recomendado), `python3-venv`, salida UDP/443 a Cloudflare.
- WiFi monitor/deauth requiere placa compatible; ARP, descubrimiento y
  auditoría IP funcionan con cualquier NIC.

#!/usr/bin/env python3
"""Agente Sentinelip: corre real en la laptop y registra su URL publica."""
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent
MAIN_URL = os.getenv("SENTINELIP_URL", "https://harder-upgrading-coated-mice.trycloudflare.com")
PORT = 8010
VENV = BASE / ".venv"
PY = VENV / "bin" / "python"
CLOUDFLARED = BASE / "cloudflared"
TUNNEL_LOG = BASE / "tunnel.log"
APP_LOG = BASE / "agent.log"
URL_FILE = BASE / "agent_url.txt"
PID_FILE = BASE / "tunnel.pid"
URL_RE = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")


def log(msg):
    line = f"[{time.strftime('%d/%m %H:%M:%S')}] {msg}\n"
    with APP_LOG.open("a") as fh:
        fh.write(line)
    print(line, end="")


def port_up():
    import socket
    with socket.socket() as sock:
        sock.settimeout(1)
        return sock.connect_ex(("127.0.0.1", PORT)) == 0


def ensure_app():
    if port_up():
        return
    log("iniciando Sentinelip REAL en 8010")
    with APP_LOG.open("a") as fh:
        subprocess.Popen(
            [str(PY), str(BASE / "sentinelip.py"), "--no-elevate",
             "--host", "127.0.0.1", "--port", str(PORT)],
            stdout=fh, stderr=subprocess.STDOUT, start_new_session=True,
        )
    for _ in range(20):
        if port_up():
            return
        time.sleep(1)
    log("ERROR: la app no levanto en 8010")


def tunnel_pid():
    try:
        pid = int(PID_FILE.read_text())
    except Exception:
        return 0
    try:
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="ignore")
    except Exception:
        return 0
    return pid if "cloudflared" in cmd else 0


def ensure_tunnel():
    if tunnel_pid():
        return
    log("iniciando tunel Cloudflare")
    with APP_LOG.open("a") as fh:
        proc = subprocess.Popen(
            [str(CLOUDFLARED), "tunnel", "--url", f"http://127.0.0.1:{PORT}",
             "--logfile", str(TUNNEL_LOG)],
            stdout=fh, stderr=subprocess.STDOUT, start_new_session=True,
        )
    PID_FILE.write_text(str(proc.pid))


def current_url():
    try:
        urls = URL_RE.findall(TUNNEL_LOG.read_text(errors="ignore"))
        return urls[-1] if urls else ""
    except Exception:
        return ""


def register(url):
    body = json.dumps({"url": url}).encode()
    request = urllib.request.Request(
        MAIN_URL + "/api/agent/register", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        response.read()
    URL_FILE.write_text(url + "\n")


def main():
    if not PY.is_file():
        log("ERROR: falta .venv/bin/python; ejecuta install.sh primero")
        sys.exit(1)
    if not CLOUDFLARED.is_file():
        log("ERROR: falta el binario cloudflared")
        sys.exit(1)
    log("Agente Sentinelip iniciado")
    while True:
        try:
            ensure_app()
            ensure_tunnel()
            url = current_url()
            if url:
                register(url)
                log(f"registrada red local -> {url}")
            else:
                log("esperando URL del tunel...")
        except Exception as exc:
            log(f"error: {exc}")
        time.sleep(30)


if __name__ == "__main__":
    main()

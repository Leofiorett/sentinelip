#!/usr/bin/env python3
"""Sentinelip - lanzador del despliegue real.

Requiere root, raw sockets, iptables y acceso a interfaces de red.
El modo demo sigue disponible con --demo como respaldo.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path


def resource_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parent


def find_app_dir() -> Path:
    base = resource_dir()
    candidates = (base, base / "app", base.parent / "app")
    for candidate in candidates:
        if (candidate / "main.py").is_file() and (candidate / "static").is_dir():
            return candidate
    raise SystemExit("[!] No se encontro app/main.py; paquete incompleto.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinelip",
        description="Sentinelip - suite de auditoria de redes.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="direccion de escucha")
    parser.add_argument("--port", type=int, default=8000, help="puerto de escucha")
    parser.add_argument("--demo", action="store_true", help="fuerza modo demo")
    parser.add_argument("--no-elevate", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    is_linux = sys.platform.startswith("linux")
    demo = args.demo or not is_linux

    if demo:
        os.environ["NETPWN_DEMO"] = "1"
        mode = "DEMO"
    else:
        os.environ.pop("NETPWN_DEMO", None)
        mode = "REAL"

    if (is_linux and not demo and not args.no_elevate
            and hasattr(os, "geteuid") and os.geteuid() != 0):
        frozen = getattr(sys, "frozen", False)
        cmd = [sys.executable] if frozen else [sys.executable, str(Path(__file__).resolve())]
        print("[*] Solicitando privilegios root para el modo real...")
        sys.exit(subprocess.run(["sudo", *cmd, "--no-elevate", *sys.argv[1:]]).returncode)

    app_dir = find_app_dir()
    sys.path.insert(0, str(app_dir))
    os.chdir(app_dir)

    if demo:
        print("[*] MODO DEMO: red ficticia, modulos ofensivos desactivados.")
    else:
        print("[*] MODO REAL: raw sockets/iptables activos. Usa PANICO al terminar.")

    import uvicorn

    print(f"[*] Abre http://{args.host}:{args.port}")
    uvicorn.run("main:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()

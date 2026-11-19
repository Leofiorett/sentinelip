from pathlib import Path
import json
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

BASE = Path(__file__).resolve().parent
STATE = BASE / "agent_state.json"
LOCAL_URL = BASE / "local_url.txt"
AGENT_TAR = Path(os.getenv(
    "SENTINELIP_AGENT_TAR",
    "/home/fioretto/sentinelip-deploy/dist/sentinelip-agent-1.0.tar.gz",
))
MAIN_URL = os.getenv("SENTINELIP_URL", "https://harder-upgrading-coated-mice.trycloudflare.com")
TTL = 300

app = FastAPI(title="Sentinelip Relay")


def state():
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {"url": "", "ts": 0}


def fallback():
    try:
        url = LOCAL_URL.read_text().strip()
    except Exception:
        return ""
    return url if url.startswith("https://") and url != MAIN_URL else ""


def target_url():
    st = state()
    url = st.get("url", "")
    if (url.startswith("https://") and url != MAIN_URL
            and time.time() - st.get("ts", 0) < TTL):
        return url
    return fallback()


def page(message: str) -> str:
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Sentinelip</title></head><body>
<h1>Sentinelip</h1><p>{message}</p>
<p>Descomprimí el agente en tu laptop Kali con root y ejecutá:</p>
<pre>cd sentinelip-agent && sudo ./install.sh</pre>
<p><a href="/agent/download">Descargar agente Linux (.tar.gz)</a></p>
</body></html>"""


@app.get("/")
async def root():
    url = target_url()
    if url:
        return RedirectResponse(url.rstrip("/") + "/", status_code=302)
    return HTMLResponse(page("No hay un agente activo registrado. El agente escaneará la red donde estés."))


@app.post("/api/agent/register")
async def register(request: Request):
    data = await request.json()
    url = str(data.get("url", "")).strip()
    if not url.startswith("https://") or url == MAIN_URL:
        return JSONResponse({"ok": False, "error": "url invalida"}, status_code=400)
    STATE.write_text(json.dumps({"url": url, "ts": time.time()}))
    return {"ok": True, "url": url}


@app.get("/api/agent/url")
async def current():
    return {"url": target_url(), "agent": state().get("url", "")}


@app.delete("/api/agent/register")
async def unregister():
    STATE.write_text(json.dumps({"url": "", "ts": 0}))
    return {"ok": True}


@app.get("/agent/download")
async def download():
    if not AGENT_TAR.is_file():
        return HTMLResponse("Agente no disponible", status_code=404)
    return FileResponse(AGENT_TAR, filename="sentinelip-agent-1.0.tar.gz")


@app.api_route("/{full_path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy(full_path: str, request: Request):
    url = target_url()
    if not url:
        return HTMLResponse(page("Sin agente activo."), status_code=503)
    dest = url.rstrip("/") + "/" + full_path
    if request.url.query:
        dest += "?" + request.url.query
    status = 302 if request.method in ("GET", "HEAD") else 307
    return RedirectResponse(dest, status_code=status)

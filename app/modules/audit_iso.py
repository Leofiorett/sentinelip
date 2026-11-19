"""Modulo de auditoria alineada a normas ISO/IEC 27001, ISO/IEC 27002 e IEC 62443.

Proporciona un checklist de controles de seguridad de red y un endpoint para
descargar un informe profesional en PDF (formato A4) con:
  * Resultado del entorno (interfaces, gateway)
  * Estado de todos los modulos de la izquierda (Hosts, Topology, Ports, MITM, etc.)
  * Checklist ISO/IEC 27001 e IEC 62443 con estados y evidencia
  * Lista de hosts descubiertos
  * Escaneo de puertos abiertos, servicios y banners
  * Topologia de red (nodos y enlaces)
  * Recomendaciones legales para controles NO CUMPLE

El estado del checklist se persiste en un fichero JSON bajo
data/audit_iso/ para que no se pierda al reiniciar la aplicacion.
"""
from __future__ import annotations

import sys as _sys
_local_site = "/home/fioretto/.local/lib/python3.14/site-packages"
if _local_site not in _sys.path:
    _sys.path.insert(0, _local_site)

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fpdf import FPDF
from fastapi import APIRouter
from fastapi.responses import Response
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/audit")

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "audit_iso"
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = DATA_DIR / "checklist_state.json"

APP_NAME = "Sentinelip"
APP_SUB = "Suite de auditoria y seguridad de redes"

# --------------------------------------------------------------------------- #
# Plantilla de controles (ISO/IEC 27001:2022 Anexo A + IEC 62443 ICS/SCADA)   #
# --------------------------------------------------------------------------- #
CONTROLS = [
    {"id": "A.5.1", "standard": "ISO/IEC 27001", "category": "Politica de seguridad",
     "control": "Politica de seguridad de la informacion para la red",
     "check": "¿Existe una politica documentada que defina el uso aceptable de la red, controles de acceso y responsabilidades?"},
    {"id": "A.5.2", "standard": "ISO/IEC 27001", "category": "Roles y responsabilidades",
     "control": "Responsabilidades de seguridad asignadas",
     "check": "¿Estan asignadas y documentadas las responsabilidades de seguridad de red (administrador, auditor, propietario de activos)?"},
    {"id": "A.6.1", "standard": "ISO/IEC 27001", "category": "Gestion de personas",
     "control": "Seleccion y contratacion de personal",
     "check": "¿Se verifican antecedentes y se firman acuerdos de confidencialidad antes de otorgar acceso a la red?"},
    {"id": "A.8.1", "standard": "ISO/IEC 27001", "category": "Responsabilidad de los activos",
     "control": "Inventario de equipos de red",
     "check": "¿Existe un inventario actualizado de routers, switches, firewalls, servidores y dispositivos ICS/SCADA con propietario asignado?"},
    {"id": "A.8.2", "standard": "ISO/IEC 27001", "category": "Clasificacion de la informacion",
     "control": "Clasificacion de datos que transitan por la red",
     "check": "¿La informacion de red esta clasificada por sensibilidad y se manejan controles segun su nivel?"},
    {"id": "A.9.1", "standard": "ISO/IEC 27001", "category": "Control de acceso",
     "control": "Politica de control de acceso a la red",
     "check": "¿Existe una politica que restrinja el acceso a la red solo a usuarios y dispositivos autorizados?"},
    {"id": "A.9.2", "standard": "ISO/IEC 27001", "category": "Gestion de accesos de usuarios",
     "control": "Acceso de usuarios y privilegios",
     "check": "¿Se otorgan accesos bajo el principio de menor privilegio y se revisan periodicamente?"},
    {"id": "A.9.3", "standard": "ISO/IEC 27001", "category": "Autenticacion",
     "control": "Gestion de contrasenas y autenticacion",
     "check": "¿Se requieren contrasenas seguras, MFA y cambios periodicos para el acceso a equipos de red?"},
    {"id": "A.12.1", "standard": "ISO/IEC 27001", "category": "Procedimientos operativos",
     "control": "Procedimientos operativos documentados",
     "check": "¿Existen procedimientos documentados para la operacion y cambios de la red (firewall, ACLs, rutas)?"},
    {"id": "A.12.2", "standard": "ISO/IEC 27001", "category": "Proteccion contra malware",
     "control": "Defensa contra malware en la red",
     "check": "¿Hay controles de antimalware y filtracion de contenido en el perimetro y endpoints de la red?"},
    {"id": "A.12.3", "standard": "ISO/IEC 27001", "category": "Copia de seguridad",
     "control": "Respaldo de configuraciones de red",
     "check": "¿Se realizan copias de seguridad periodicas de configuraciones de equipos de red y se prueban restauraciones?"},
    {"id": "A.12.4", "standard": "ISO/IEC 27001", "category": "Registro y monitoreo",
     "control": "Registro de eventos de red",
     "check": "¿Se registran y revisan los eventos de acceso, cambios y trafico de la red (logs centralizados)?"},
    {"id": "A.13.1", "standard": "ISO/IEC 27001", "category": "Segmentacion de red",
     "control": "Controles de red y segmentacion",
     "check": "¿La red esta segmentada (VLANs, DMZ, zona ICS/SCADA separada) y se controlan los flujos entre zonas?"},
    {"id": "A.13.2", "standard": "ISO/IEC 27001", "category": "Comunicaciones seguras",
     "control": "Transferencia segura de informacion",
     "check": "¿Se usan protocolos seguros (SSH, HTTPS, TLS, IPsec) y se deshabilitan servicios inseguros (Telnet, FTP, HTTP sin cifrar)?"},
    {"id": "A.16.1", "standard": "ISO/IEC 27001", "category": "Gestion de incidentes",
     "control": "Deteccion y respuesta a incidentes de red",
     "check": "¿Existe un procedimiento para detectar, reportar y responder incidentes de seguridad en la red?"},
    {"id": "62443-2.1", "standard": "IEC 62443", "category": "Programa de seguridad ICS",
     "control": "Programa de seguridad de sistemas de control industrial",
     "check": "¿Existe un programa de seguridad ICS/SCADA con roles, evaluaciones de riesgo y plan de mitigacion?"},
    {"id": "62443-3.1", "standard": "IEC 62443", "category": "Zonas y conductos",
     "control": "Segmentacion de zonas y conductos ICS",
     "check": "¿La red ICS/SCADA esta segmentada en zonas y conductos con controles en las fronteras (firewalls industriales)?"},
    {"id": "62443-3.2", "standard": "IEC 62443", "category": "Nivel de seguridad objetivo",
     "control": "SL-T de dispositivos ICS",
     "check": "¿Se definieron y aplicaron niveles de seguridad objetivo (SL-T) para dispositivos ICS (PLC, HMI, RTU, SCADA)?"},
    {"id": "62443-3.3", "standard": "IEC 62443", "category": "Acceso a sistemas ICS",
     "control": "Restriccion de acceso a sistemas ICS",
     "check": "¿El acceso remoto a sistemas ICS se controla mediante salto bastion, MFA y registros de sesion?"},
]

LEGAL_RECS = {
    "A.5.1": ("Establecer y aprobar por la direccion una Politica de Seguridad de la Informacion que cubra la red, "
              "difundirla a todo el personal y revisarla al menos anualmente. Marco: ISO/IEC 27001 A.5.1; Ley 25.326 "
              "(Proteccion de Datos Personales) art. 9 (medidas de seguridad)."),
    "A.5.2": ("Designar un responsable de seguridad de la informacion (CISO/SSI) con funciones, autoridades y "
              "responsabilidades documentadas, incluyendo la seguridad de la red."),
    "A.6.1": ("Implementar verificacion de antecedentes y firmar acuerdos de confidencialidad (NDA) antes de otorgar "
              "acceso a equipos de red, conforme a buenas practicas de ISO/IEC 27001 A.6."),
    "A.8.1": ("Mantener un inventario de activos de red con propietario asignado, ubicacion y clasificacion, revisado "
              "periodicamente. Incluir dispositivos ICS/SCADA (PLC, HMI, RTU)."),
    "A.8.2": ("Clasificar la informacion que transita por la red segun su sensibilidad (publica, confidencial, "
              "reservada) y aplicar controles de proteccion proporcionados al nivel."),
    "A.9.1": ("Implementar una politica de control de acceso a la red y registrar todos los accesos privilegiados. "
              "Revisar accesos periodicamente y revocarlos ante cambios de rol o baja."),
    "A.9.2": ("Aplicar el principio de menor privilegio en el acceso a equipos de red y revisar los privilegios "
              "asignados con periodicidad definida."),
    "A.9.3": ("Exigir contrasenas seguras, autenticacion multifactor (MFA) y cambio periodico de credenciales para el "
              "acceso a routers, switches, firewalls y sistemas ICS."),
    "A.12.1": ("Documentar procedimientos operativos para el manejo de la red (cambios de firewall, ACLs, rutas, "
               "parches) y contar con un proceso de gestion de cambios aprobado."),
    "A.12.2": ("Desplegar controles de antimalware y filtracion de contenido en el perimetro de red y en endpoints, con "
               "firmas actualizadas periodicamente."),
    "A.12.3": ("Realizar copias de seguridad periodicas de las configuraciones de equipos de red y probar restauraciones "
               "al menos una vez al ano."),
    "A.12.4": ("Implementar registro centralizado de eventos de red (SIEM/syslog) con retention adecuada y revision "
               "periodica de accesos, cambios y trafico anomal."),
    "A.13.1": ("Segmentar la red mediante VLANs y DMZ, separando la zona ICS/SCADA de la red corporativa con controles en "
               "las fronteras. Marco: IEC 62443 zonas y conductos."),
    "A.13.2": ("Deshabilitar protocolos inseguros (Telnet, FTP, HTTP sin cifrar, SNMP v1/v2c) y usar alternativas seguras "
               "(SSH, HTTPS, TLS, IPsec, SNMPv3)."),
    "A.16.1": ("Establecer un procedimiento de gestion de incidentes de seguridad de la red, con canales de reporte, "
               "equipo de respuesta y planes de contencion y recuperacion."),
    "62443-2.1": ("Implementar un programa de seguridad ICS/SCADA con roles definidos, evaluacion de riesgos "
                  "ciberneticos y plan de mitigacion aprobado por la direccion del sitio."),
    "62443-3.1": ("Segmentar la red ICS/SCADA en zonas y conductos, instalando firewalls industriales en las fronteras "
                  "entre zonas y controlando el trafico entre ellas."),
    "62443-3.2": ("Definir y aplicar el Nivel de Seguridad Objetivo (SL-T) a todos los dispositivos ICS (PLC, HMI, RTU, "
                  "SCADA) segun su criticalidad operacional."),
    "62443-3.3": ("Controlar el acceso remoto a sistemas ICS mediante servidor bastion, autenticacion multifactor y "
                  "registro completo de sesiones de acceso."),
}

CATEGORY_RECS = {
    "ISO/IEC 27001": "Revisar y documentar el control segun los requisitos de ISO/IEC 27001:2022, establecer "
                     "responsables, evidencias de implementacion y revision periodica.",
    "IEC 62443": "Aplicar los requisitos de IEC 62443 para sistemas de control industrial, incluyendo definicion de "
                 "zonas, conductos y niveles de seguridad (SL-T) adecuados al entorno OT.",
}

MODULE_LABELS = {
    "arp": "MITM (ARP spoofing)",
    "sniffer": "Packet sniffer",
    "dns": "DNS spoofing",
    "creds": "Credential capture",
    "httpinject": "HTTP injection + sslstrip",
    "wifi_scan": "Wi-Fi scan",
    "handshake": "Wi-Fi handshake capture",
    "pmkid": "Wi-Fi PMKID capture",
    "poison": "LLMNR/NBT-NS/mDNS poisoners",
    "wpad": "WPAD proxy",
    "mitm6": "mitm6 (IPv6 RA + DNS)",
}

# --------------------------------------------------------------------------- #
# Modelos                                                                     #
# --------------------------------------------------------------------------- #
class ControlState(BaseModel):
    id: str
    status: str  # pending | pass | fail | na
    evidence: str = ""
    notes: str = ""
    updated_at: str | None = None


class ChecklistSave(BaseModel):
    controls: list[ControlState]


class ReportData(BaseModel):
    interfaces: dict[str, Any] = Field(default_factory=dict)
    status: dict[str, Any] = Field(default_factory=dict)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    port_results: dict[str, Any] = Field(default_factory=dict)  # ip -> {open: [...]}
    topology: dict[str, Any] = Field(default_factory=dict)
    checklist_controls: list[dict[str, Any]] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Persistencia checklist                                                      #
# --------------------------------------------------------------------------- #
def _load() -> list[dict[str, Any]]:
    if not STATE_FILE.exists():
        return []
    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save(states: list[dict[str, Any]]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(states, f, indent=2, ensure_ascii=False)


@router.get("/checklist")
def get_checklist():
    states = {s["id"]: s for s in _load()}
    merged = []
    for c in CONTROLS:
        st = states.get(c["id"], {})
        merged.append({
            **c,
            "status": st.get("status", "pending"),
            "evidence": st.get("evidence", ""),
            "notes": st.get("notes", ""),
            "updated_at": st.get("updated_at"),
            "recommendation": LEGAL_RECS.get(c["id"], ""),
        })
    return {"controls": merged}


@router.post("/checklist")
def save_checklist(req: ChecklistSave):
    states = []
    now = datetime.now(timezone.utc).isoformat()
    for c in req.controls:
        states.append({
            "id": c.id, "status": c.status, "evidence": c.evidence,
            "notes": c.notes, "updated_at": c.updated_at or now,
        })
    _save(states)
    return {"status": "saved", "count": len(states)}


# --------------------------------------------------------------------------- #
# PDF profesional completo                                                    #
# --------------------------------------------------------------------------- #
STATUS_STYLE = {
    "pass":   {"label": "CUMPLE",   "color": (34, 139, 34),   "fill": (230, 255, 230)},
    "fail":   {"label": "NO CUMPLE","color": (178, 34, 34),   "fill": (255, 235, 235)},
    "na":     {"label": "N/A",      "color": (120, 120, 120), "fill": (245, 245, 245)},
    "pending":{"label": "PENDIENTE","color": (184, 134, 11),  "fill": (255, 250, 230)},
}


class SentinelipPDF(FPDF):
    def header(self):
        self.set_fill_color(6, 10, 8)
        self.rect(0, 0, self.w, 24, style="F")
        self.set_text_color(57, 255, 136)
        self.set_font("Helvetica", "B", 16)
        self.set_xy(12, 6)
        self.cell(0, 8, APP_NAME.upper(), align="L")
        self.set_text_color(200, 230, 211)
        self.set_font("Helvetica", "", 9)
        self.set_xy(12, 15)
        self.cell(0, 6, APP_SUB, align="L")
        self.set_draw_color(57, 255, 136)
        self.set_line_width(0.7)
        self.line(12, 23, self.w - 12, 23)
        self.ln(28)

    def footer(self):
        self.set_y(-13)
        self.set_draw_color(57, 255, 136)
        self.set_line_width(0.5)
        self.line(12, self.get_y(), self.w - 12, self.get_y())
        self.set_text_color(120, 120, 120)
        self.set_font("Helvetica", "", 8)
        self.set_x(12)
        self.cell(0, 5, f"{APP_NAME} - Informe confidencial de auditoria  |  Pagina {self.page_no()}", align="L")
        self.set_x(-60)
        self.cell(0, 5, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), align="R")


def _section_title(pdf, text):
    pdf.set_fill_color(234, 255, 243)
    pdf.set_draw_color(57, 255, 136)
    pdf.set_line_width(0.5)
    pdf.set_text_color(6, 10, 8)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, text, fill=True, ln=True)
    pdf.ln(2)


def _meta_block(pdf, data: dict):
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(90, 90, 90)
    iface = data.get("interfaces", {}) or {}
    gateway = iface.get("gateway") or {}
    interfaces = iface.get("interfaces", []) or []
    meta = [
        ("Herramienta:", APP_NAME),
        ("Normas de referencia:", "ISO/IEC 27001:2022, ISO/IEC 27002, IEC 62443 (ICS/SCADA)"),
        ("Fecha de generacion:", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
        ("Alcance:", "Auditoria completa de seguridad de redes y sistemas de control industrial"),
    ]
    for k, v in meta:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(32, 5, k, ln=0)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, v, ln=1)
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(6, 10, 8)
    pdf.cell(0, 6, "Entorno de red detectado", ln=True)
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(30, 5, "Gateway:", ln=0)
    pdf.cell(0, 5, str(gateway.get("ip", "-")) if isinstance(gateway, dict) else str(gateway), ln=1)
    pdf.cell(30, 5, "Interfaces:", ln=0)
    pdf.cell(0, 5, ", ".join([i.get("name", "") for i in interfaces]) or "-", ln=1)
    pdf.ln(4)


def _summary(pdf, total, passed, failed, na, pending):
    pct = round((passed / total) * 100, 1) if total else 0.0
    _section_title(pdf, "Resultado general - Checklist ISO / IEC")
    pdf.ln(1)
    boxes = [
        ("CUMPLE", str(passed), (34, 139, 34)),
        ("NO CUMPLE", str(failed), (178, 34, 34)),
        ("PENDIENTE", str(pending), (184, 134, 11)),
        ("N/A", str(na), (120, 120, 120)),
        ("CUMPLIMIENTO", f"{pct}%", (57, 255, 136)),
    ]
    w = (pdf.w - 24 - 4 * 4) / 5
    for title, val, color in boxes:
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255) if color != (57, 255, 136) else pdf.set_text_color(6, 10, 8)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(w, 8, title, border=1, align="C", fill=True)
    pdf.ln()
    pdf.set_x(12)
    for title, val, color in boxes:
        pdf.set_fill_color(244, 255, 248)
        pdf.set_text_color(6, 10, 8)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(w, 9, val, border=1, align="C", fill=True)
    pdf.ln(6)


def _modules_status(pdf, status: dict):
    _section_title(pdf, "Estado de modulos activos (panel izquierdo)")
    pdf.ln(1)
    active = []
    for key, label in MODULE_LABELS.items():
        if status.get(key):
            active.append(label)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)
    if active:
        pdf.cell(0, 5, "Modulos actualmente en ejecucion:", ln=True)
        pdf.ln(1)
        for label in active:
            pdf.set_fill_color(234, 255, 243)
            pdf.set_text_color(34, 139, 34)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, f"•  {label}", fill=True, ln=True)
    else:
        pdf.set_text_color(184, 134, 11)
        pdf.cell(0, 6, "Ningun modulo activo en este momento.", ln=True)
    pdf.ln(4)


def _checklist_table(pdf, controls: list):
    _section_title(pdf, "Checklist ISO/IEC 27001 e IEC 62443")
    pdf.ln(1)
    widths = [14, 20, 26, 30, 46, 17, 16, 15]
    headers = ["Control", "Norma", "Categoria", "Control", "Pregunta de verificacion", "Estado", "Evidencia", "Notas"]

    y = pdf.get_y()
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(255, 255, 255)
    pdf.set_fill_color(6, 10, 8)
    x = 12
    row_bottoms = []
    for i, h in enumerate(headers):
        pdf.set_xy(x, y)
        pdf.multi_cell(widths[i], 5, h, border=1, align="C", fill=True)
        row_bottoms.append(pdf.y)
        x += widths[i]
    pdf.set_y(max(row_bottoms))
    pdf.ln(1)

    for c in controls:
        row_start_y = pdf.get_y()
        st = c["status"]
        style = STATUS_STYLE[st]
        row_cells = [
            (c["id"], {"align": "C", "size": 7, "bold": True, "color": (6, 10, 8)}),
            (c["standard"], {"align": "L", "size": 7, "color": (90, 90, 90)}),
            (c["category"], {"align": "L", "size": 7, "color": (90, 90, 90)}),
            (c["control"], {"align": "L", "size": 7, "color": (60, 60, 60)}),
            (c["check"], {"align": "L", "size": 7, "color": (60, 60, 60)}),
            (style["label"], {"align": "C", "size": 7, "bold": True, "color": style["color"], "fill": True}),
            (c.get("evidence", "") or "-", {"align": "L", "size": 7, "color": (90, 90, 90)}),
            (c.get("notes", "") or "-", {"align": "L", "size": 7, "color": (90, 90, 90)}),
        ]
        x = 12
        row_bottoms = []
        for i, (text, stl) in enumerate(row_cells):
            pdf.set_xy(x, row_start_y)
            pdf.set_font("Helvetica", "B" if stl.get("bold") else "", stl["size"])
            pdf.set_text_color(*stl["color"])
            if stl.get("fill"):
                pdf.set_fill_color(*style["fill"])
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.multi_cell(widths[i], 4.3, text, border=1, align=stl["align"], fill=stl.get("fill", False))
            row_bottoms.append(pdf.y)
            x += widths[i]
        pdf.set_y(max(row_bottoms))
    pdf.ln(3)


def _hosts_table(pdf, hosts: list):
    _section_title(pdf, "Descubrimiento de red - Lista de hosts")
    pdf.ln(1)
    if not hosts:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(184, 134, 11)
        pdf.cell(0, 6, "No hay hosts descubiertos en la sesion.", ln=True)
        pdf.ln(4)
        return
    widths = [22, 26, 34, 40, 64]
    headers = ["IP", "MAC", "Fabricante", "SO (aprox.)", "Acciones"]
    y = pdf.get_y()
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(255, 255, 255)
    pdf.set_fill_color(6, 10, 8)
    x = 12
    row_bottoms = []
    for i, h in enumerate(headers):
        pdf.set_xy(x, y)
        pdf.multi_cell(widths[i], 5, h, border=1, align="C", fill=True)
        row_bottoms.append(pdf.y)
        x += widths[i]
    pdf.set_y(max(row_bottoms))
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(60, 60, 60)
    for h in hosts:
        row_start_y = pdf.get_y()
        row_cells = [
            (h.get("ip", "-"), {"align": "L", "size": 7}),
            (h.get("mac", "-"), {"align": "L", "size": 7}),
            (h.get("vendor", "-"), {"align": "L", "size": 7}),
            (h.get("os", "-"), {"align": "L", "size": 7}),
            ("Target / Ports", {"align": "C", "size": 7, "bold": True, "color": (57, 255, 136)}),
        ]
        x = 12
        row_bottoms = []
        for i, (text, stl) in enumerate(row_cells):
            pdf.set_xy(x, row_start_y)
            pdf.set_font("Helvetica", "B" if stl.get("bold") else "", stl["size"])
            pdf.set_text_color(*stl.get("color", (60, 60, 60)))
            pdf.set_fill_color(255, 255, 255)
            pdf.multi_cell(widths[i], 4.3, text, border=1, align=stl["align"], fill=False)
            row_bottoms.append(pdf.y)
            x += widths[i]
        pdf.set_y(max(row_bottoms))
    pdf.ln(3)


def _ports_table(pdf, port_results: dict):
    _section_title(pdf, "Escaneo de puertos - Puertos abiertos y servicios")
    pdf.ln(1)
    if not port_results:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(184, 134, 11)
        pdf.cell(0, 6, "No hay resultados de escaneo de puertos en la sesion.", ln=True)
        pdf.ln(4)
        return
    for ip, res in port_results.items():
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(6, 10, 8)
        pdf.cell(0, 6, f"Objetivo: {ip}", ln=True)
        pdf.ln(1)
        open_ports = res.get("open", []) if isinstance(res, dict) else []
        if not open_ports:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(184, 134, 11)
            pdf.cell(0, 6, "Sin puertos abiertos detectados.", ln=True)
            pdf.ln(3)
            continue
        widths = [18, 40, 100]
        headers = ["Puerto", "Servicio", "Banner / Detalle"]
        y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(6, 10, 8)
        x = 12
        row_bottoms = []
        for i, h in enumerate(headers):
            pdf.set_xy(x, y)
            pdf.multi_cell(widths[i], 5, h, border=1, align="C", fill=True)
            row_bottoms.append(pdf.y)
            x += widths[i]
        pdf.set_y(max(row_bottoms))
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(60, 60, 60)
        for p in open_ports:
            row_start_y = pdf.get_y()
            row_cells = [
                (str(p.get("port", "-")), {"align": "C", "size": 7}),
                (p.get("service", "-"), {"align": "L", "size": 7}),
                (p.get("banner", "-") or "-", {"align": "L", "size": 7}),
            ]
            x = 12
            row_bottoms = []
            for i, (text, stl) in enumerate(row_cells):
                pdf.set_xy(x, row_start_y)
                pdf.set_font("Helvetica", "", stl["size"])
                pdf.set_text_color(*stl.get("color", (60, 60, 60)))
                pdf.set_fill_color(255, 255, 255)
                pdf.multi_cell(widths[i], 4.3, text, border=1, align=stl["align"], fill=False)
                row_bottoms.append(pdf.y)
                x += widths[i]
            pdf.set_y(max(row_bottoms))
        pdf.ln(3)


def _topology_table(pdf, topology: dict):
    _section_title(pdf, "Topologia de red - Nodos y enlaces")
    pdf.ln(1)
    if not topology:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(184, 134, 11)
        pdf.cell(0, 6, "No hay topologia generada en la sesion.", ln=True)
        pdf.ln(4)
        return
    nodes = topology.get("nodes", []) or []
    edges = topology.get("edges", []) or []
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(6, 10, 8)
    pdf.cell(0, 6, f"Nodos detectados: {len(nodes)}    Enlaces: {len(edges)}", ln=True)
    pdf.ln(2)
    if nodes:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, "Nodos:", ln=True)
        pdf.ln(1)
        widths = [14, 26, 26, 30, 30, 60]
        headers = ["ID", "IP", "Tipo", "Fabricante", "SO (TTL)", "Puertos abiertos"]
        y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(6, 10, 8)
        x = 12
        row_bottoms = []
        for i, h in enumerate(headers):
            pdf.set_xy(x, y)
            pdf.multi_cell(widths[i], 5, h, border=1, align="C", fill=True)
            row_bottoms.append(pdf.y)
            x += widths[i]
        pdf.set_y(max(row_bottoms))
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(60, 60, 60)
        for n in nodes:
            row_start_y = pdf.get_y()
            ports = n.get("open_ports", []) or []
            row_cells = [
                (str(n.get("id", "-")), {"align": "L", "size": 7}),
                (str(n.get("ip", "-")), {"align": "L", "size": 7}),
                (str(n.get("type", "-")), {"align": "L", "size": 7}),
                (str(n.get("vendor", "-")), {"align": "L", "size": 7}),
                (f"{n.get('os', '-')} (TTL {n.get('ttl','-')})", {"align": "L", "size": 7}),
                (", ".join(map(str, ports)) if ports else "-", {"align": "L", "size": 7}),
            ]
            x = 12
            row_bottoms = []
            for i, (text, stl) in enumerate(row_cells):
                pdf.set_xy(x, row_start_y)
                pdf.set_font("Helvetica", "", stl["size"])
                pdf.set_text_color(*stl.get("color", (60, 60, 60)))
                pdf.set_fill_color(255, 255, 255)
                pdf.multi_cell(widths[i], 4.3, text, border=1, align=stl["align"], fill=False)
                row_bottoms.append(pdf.y)
                x += widths[i]
            pdf.set_y(max(row_bottoms))
        pdf.ln(3)
    if edges:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, "Enlaces:", ln=True)
        pdf.ln(1)
        widths = [40, 40, 86]
        headers = ["Origen", "Destino", "Tipo de relacion"]
        y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(6, 10, 8)
        x = 12
        row_bottoms = []
        for i, h in enumerate(headers):
            pdf.set_xy(x, y)
            pdf.multi_cell(widths[i], 5, h, border=1, align="C", fill=True)
            row_bottoms.append(pdf.y)
            x += widths[i]
        pdf.set_y(max(row_bottoms))
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(60, 60, 60)
        for e in edges:
            row_start_y = pdf.get_y()
            row_cells = [
                (str(e.get("source", "-")), {"align": "L", "size": 7}),
                (str(e.get("target", "-")), {"align": "L", "size": 7}),
                (str(e.get("kind", "inferido")), {"align": "L", "size": 7}),
            ]
            x = 12
            row_bottoms = []
            for i, (text, stl) in enumerate(row_cells):
                pdf.set_xy(x, row_start_y)
                pdf.set_font("Helvetica", "", stl["size"])
                pdf.set_text_color(*stl.get("color", (60, 60, 60)))
                pdf.set_fill_color(255, 255, 255)
                pdf.multi_cell(widths[i], 4.3, text, border=1, align=stl["align"], fill=False)
                row_bottoms.append(pdf.y)
                x += widths[i]
            pdf.set_y(max(row_bottoms))
    pdf.ln(3)


def _legal_recommendations(pdf, controls: list):
    fails = [c for c in controls if c["status"] == "fail"]
    if not fails:
        return
    _section_title(pdf, "Recomendaciones legales y de remediacion (controles NO CUMPLE)")
    pdf.ln(1)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(0, 4.5,
        "Los siguientes controles fueron evaluados como NO CUMPLE. Se incluyen recomendaciones de remediacion basadas "
        "en las normas de referencia y el marco normativo aplicable (Ley 25.326 de Proteccion de Datos Personales y "
        "marco de ciberseguridad/ciberdefensa vigente).",
        ln=True)
    pdf.ln(2)
    for c in fails:
        rec = LEGAL_RECS.get(c["id"], CATEGORY_RECS.get(c["standard"], CATEGORY_RECS["ISO/IEC 27001"]))
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(178, 34, 34)
        pdf.cell(0, 5, f"{c['id']} - {c['control']} ({c['standard']})", ln=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 4.5, rec, ln=True)
        pdf.ln(2)
    pdf.ln(2)
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 4,
        "Descargo: este informe es un registro de autodeclaracion de controles generado por Sentinelip. No sustituye "
        "una certificacion formal ISO/IEC 27001 ni IEC 62443, ni constituye asesoramiento legal. Consulte con el area "
        "legal y de cumplimiento de la organizacion antes de adoptar acciones remediadoras.", ln=True)


@router.get("/report")
def get_report():
    try:
        states = {s["id"]: s for s in _load()}
        controls = []
        for c in CONTROLS:
            st = states.get(c["id"], {})
            controls.append({
                **c,
                "status": st.get("status", "pending"),
                "evidence": st.get("evidence", ""),
                "notes": st.get("notes", ""),
                "updated_at": st.get("updated_at"),
                "recommendation": LEGAL_RECS.get(c["id"], ""),
            })
        total = len(controls)
        passed = sum(1 for c in controls if c["status"] == "pass")
        failed = sum(1 for c in controls if c["status"] == "fail")
        na = sum(1 for c in controls if c["status"] == "na")
        pending = sum(1 for c in controls if c["status"] == "pending")
        return {
            "status": "generated",
            "controls_total": total,
            "controls_passed": passed,
            "controls_failed": failed,
            "controls_na": na,
            "controls_pending": pending,
            "controls": controls,
            "message": "Informe generado correctamente",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

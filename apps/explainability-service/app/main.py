from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from shared.utils.security import install_security_middleware
from shared.utils.storage import Store

APP_DIR = Path(__file__).resolve().parent
REPORT_DIR = Path(os.getenv("REPORT_DIR", "/data/reports"))
REPORT_VERSION = "0.1.0"
store = Store()
env = Environment(
    loader=FileSystemLoader(str(APP_DIR / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)

app = FastAPI(title="Agentic SOC Explainability Service", version=REPORT_VERSION)
install_security_middleware(app, "explainability-service")


def incident_bundle(incident_id: str) -> dict:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    events = [store.get_event(event_id) for event_id in incident.event_ids]
    actions = store.list_actions(incident_id)
    return {
        "incident": incident,
        "events": [event for event in events if event],
        "actions": actions,
        "generated_at": datetime.now(UTC),
        "report_version": REPORT_VERSION,
        "alternative_hypotheses": [
            "Legitimate administrative activity that matched adversary-like patterns.",
            "Benign test traffic from a training or validation tool.",
            "Misconfigured automation generating repeated callbacks or authentication failures.",
        ],
        "unresolved_uncertainty": [
            "The demo environment uses deterministic local reputation, not live threat intelligence.",
            "Host forensic depth is intentionally limited to safe demo artifacts.",
        ],
    }


def write_pdf(html_path: Path, pdf_path: Path) -> str:
    try:
        from weasyprint import HTML

        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return "weasyprint"
    except Exception as exc:  # noqa: BLE001
        fallback = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj\n"
            b"4 0 obj << /Length 72 >> stream\nBT /F1 12 Tf 72 720 Td (PDF renderer fallback. See HTML report for full detail.) Tj ET\nendstream endobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \n"
            b"trailer << /Root 1 0 R /Size 5 >>\nstartxref\n326\n%%EOF\n"
        )
        pdf_path.write_bytes(fallback)
        return f"fallback-pdf: {exc}"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "explainability-service"}


@app.post("/reports/{incident_id}/generate")
def generate_report(incident_id: str) -> dict[str, str]:
    bundle = incident_bundle(incident_id)
    incident = bundle["incident"]
    out_dir = REPORT_DIR / incident_id
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "incident-report.html"
    pdf_path = out_dir / "incident-report.pdf"
    json_path = out_dir / "incident-audit.json"

    template = env.get_template("report.html")
    css = (APP_DIR / "static" / "report.css").read_text(encoding="utf-8")
    html = template.render(**bundle, css=css)
    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "incident": incident.model_dump(mode="json"),
                "events": [event.model_dump(mode="json") for event in bundle["events"]],
                "actions": [action.model_dump(mode="json") for action in bundle["actions"]],
                "generated_at": bundle["generated_at"].isoformat(),
                "report_version": REPORT_VERSION,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    renderer = write_pdf(html_path, pdf_path)
    store.save_report(incident_id, str(html_path), str(pdf_path), str(json_path))
    incident.report_pdf = str(pdf_path)
    store.upsert_incident(incident)
    store.add_audit(
        "report",
        incident_id,
        {"html_path": str(html_path), "pdf_path": str(pdf_path), "json_path": str(json_path), "renderer": renderer},
    )
    return {
        "incident_id": incident_id,
        "html_path": str(html_path),
        "pdf_path": str(pdf_path),
        "json_path": str(json_path),
        "renderer": renderer,
    }


@app.post("/reports/generate-all")
def generate_all() -> dict[str, list[dict[str, str]]]:
    reports = [generate_report(incident.id) for incident in store.list_incidents(500)]
    return {"reports": reports}


@app.get("/reports/{incident_id}")
def report_metadata(incident_id: str) -> dict[str, str]:
    report = store.report_for(incident_id)
    if not report:
        raise HTTPException(status_code=404, detail="report not found")
    return report


@app.get("/reports/{incident_id}/pdf")
def download_pdf(incident_id: str) -> FileResponse:
    report = store.report_for(incident_id)
    if not report:
        raise HTTPException(status_code=404, detail="report not found")
    return FileResponse(report["pdf_path"], filename=f"{incident_id}-report.pdf", media_type="application/pdf")

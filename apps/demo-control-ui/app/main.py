from __future__ import annotations

import hmac
import os
from pathlib import Path

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from shared.utils.security import auth_headers, configured_api_key, install_security_middleware, is_production
from shared.utils.storage import Store

APP_DIR = Path(__file__).resolve().parent
THREAT_SIMULATOR_URL = os.getenv("THREAT_SIMULATOR_URL", "http://localhost:8005")
EXPLAINABILITY_URL = os.getenv("EXPLAINABILITY_URL", "http://localhost:8004")

app = FastAPI(title="AegisCore Command Deck", version="0.1.0")
install_security_middleware(app, "demo-control-ui", public_prefixes={"/", "/login", "/static"})
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
store = Store()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "demo-control-ui"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    if not is_production():
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login(api_key: str = Form(...)) -> RedirectResponse:
    response = RedirectResponse("/", status_code=303)
    if api_key != configured_api_key():
        response = RedirectResponse("/login?error=1", status_code=303)
        return response
    secure_cookie = os.getenv("UI_SECURE_COOKIE", "true" if is_production() else "false").lower() == "true"
    response.set_cookie("soc_api_key", api_key, httponly=True, secure=secure_cookie, samesite="strict")
    return response


@app.get("/", response_class=HTMLResponse, response_model=None)
def index(request: Request) -> HTMLResponse | RedirectResponse:
    if is_production() and not hmac.compare_digest(
        request.cookies.get("soc_api_key", ""),
        configured_api_key(),
    ):
        return RedirectResponse("/login", status_code=303)
    incidents = store.list_incidents(50)
    events = store.list_events(50)
    actions = store.list_actions(limit=50)
    reports = {incident.id: store.report_for(incident.id) for incident in incidents}
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": os.getenv("DEMO_UI_TITLE", "AegisCore"),
            "incidents": incidents,
            "events": events,
            "actions": actions,
            "reports": reports,
            "production": is_production(),
            "services": {
                "Normalizer": "http://127.0.0.1:8001/docs",
                "Orchestrator": "http://127.0.0.1:8002/docs",
                "Executor": "http://127.0.0.1:8003/docs",
                "Reports": "http://127.0.0.1:8004/docs",
                "TheHive Lite": "http://127.0.0.1:8010/thehive",
                "Cortex Lite": "http://127.0.0.1:8010/cortex",
                "Shuffle Lite": "http://127.0.0.1:8010/shuffle",
            },
        },
    )


@app.get("/reports/{incident_id}/pdf", response_model=None)
def ui_report_pdf(request: Request, incident_id: str) -> FileResponse | RedirectResponse:
    if is_production() and not hmac.compare_digest(
        request.cookies.get("soc_api_key", ""),
        configured_api_key(),
    ):
        return RedirectResponse("/login", status_code=303)
    report = store.report_for(incident_id)
    if not report:
        return RedirectResponse("/", status_code=303)
    return FileResponse(
        report["pdf_path"],
        filename=f"{incident_id}-report.pdf",
        media_type="application/pdf",
    )


@app.get("/api-access", response_class=HTMLResponse, response_model=None)
def api_access(request: Request) -> HTMLResponse | RedirectResponse:
    if is_production() and not hmac.compare_digest(
        request.cookies.get("soc_api_key", ""),
        configured_api_key(),
    ):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("api_access.html", {"request": request})


@app.post("/trigger/{scenario}")
async def trigger(scenario: str) -> RedirectResponse:
    if is_production():
        return RedirectResponse("/", status_code=303)
    async with httpx.AsyncClient(timeout=20.0) as client:
        await client.post(f"{THREAT_SIMULATOR_URL}/scenarios/{scenario}", headers=auth_headers())
    return RedirectResponse("/", status_code=303)

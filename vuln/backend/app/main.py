from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from .api.routes_full import router as api_router
from .config import get_settings
from .services.scan_history import scan_db

settings = get_settings()

app = FastAPI(title=settings.app_name)

# Mount static files for backend-hosted dashboard
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent.parent / "static")), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

# CORS setup
origins = [settings.frontend_url, "http://localhost:5173", "http://localhost:5174", "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.api_prefix)


@app.get("/")
def root():
    return {"message": "Hello World"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_main(request: Request):
    """Serve the risk severity summary dashboard without API prefix."""
    try:
        stored = scan_db.get_severity_summary()
        cvss = scan_db.get_cvss_summary()
        # Prefer CVSS-based counts for display as it reflects score ranges
        display_counts = cvss
        total = sum(display_counts.values())
        return templates.TemplateResponse("dashboard.html", {"request": request, "counts": display_counts, "total": total})
    except Exception as e:
        return HTMLResponse(content=f"<h1>Error loading dashboard</h1><p>{str(e)}</p>", status_code=500)


@app.get("/recent-scans", response_class=HTMLResponse)
def recent_scans_main(request: Request, limit: int = 50):
    """Serve the recent scans page without API prefix."""
    try:
        scans = scan_db.get_recent_scans(limit=limit)
        return templates.TemplateResponse("recent_scans.html", {"request": request, "scans": scans, "total": len(scans)})
    except Exception as e:
        return HTMLResponse(content=f"<h1>Error loading recent scans</h1><p>{str(e)}</p>", status_code=500)


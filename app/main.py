import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import init_db
from app.routers import scans

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(
    title="ShieldScan",
    description="AI-Assisted Web Application Vulnerability Assessment Tool for Small Businesses",
    version="1.0.0",
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(scans.router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "shieldscan",
        "scanner_version": "3.0",
        "scan_phases": 5,
        "checks": [
            "Crawl up to 80 pages, depth 4, DVWA/Juice Shop path seeding",
            "OWASP A01 — IDOR, admin paths, CSRF, open redirect, clickjacking",
            "OWASP A02 — HTTPS, TLS, cookie flags",
            "OWASP A03 — XSS, SQLi, command injection, SSTI, NoSQL (45+ params)",
            "OWASP A05 — Headers, disclosure, CORS, directory listing",
            "OWASP A06 — Outdated JS libraries on all crawled pages",
            "OWASP A07 — Login over HTTP, rate limiting, auth bypass surface",
            "OWASP A09 — Verbose error disclosure",
            "OWASP A10 — SSRF attack surface",
            "Deep probes — path traversal, LFI, sensitive files, API fuzzing",
            "OWASP ZAP — spider + AJAX spider + passive + active (when Docker on)",
        ],
    }

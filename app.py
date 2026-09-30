import os
import time
import logging
from pathlib import Path
from collections import defaultdict
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from config import HOST, PORT, DEBUG, STATIC_DIR, DB_PATH

try:
    from data.database import init_db, get_scan, list_scan_history, get_summary_stats
except ModuleNotFoundError:
    from database import init_db, get_scan, list_scan_history, get_summary_stats

try:
    from queue_service.task_manager import enqueue_scan_task
except ModuleNotFoundError:
    from task_manager import enqueue_scan_task

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("vulnscan.api")

# Rate Limiter: Max 15 scan triggers per minute per client IP to prevent abuse
RATE_LIMIT_MAX_REQUESTS = 15
RATE_LIMIT_WINDOW_SECONDS = 60
client_scan_requests = defaultdict(list)

def check_rate_limit(client_ip: str):
    now = time.time()
    timestamps = [t for t in client_scan_requests[client_ip] if now - t < RATE_LIMIT_WINDOW_SECONDS]
    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        retry_after = int(RATE_LIMIT_WINDOW_SECONDS - (now - timestamps[0]))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {RATE_LIMIT_MAX_REQUESTS} scans per minute allowed. Please wait {retry_after}s before retrying.",
            headers={"Retry-After": str(max(1, retry_after))}
        )
    timestamps.append(now)
    client_scan_requests[client_ip] = timestamps

# Initialize database schema on startup
init_db()

app = FastAPI(
    title="VulnScan Lite - Web Vulnerability & Security Posture Scanner",
    description="On-demand passive web vulnerability audit engine and health reporting platform.",
    version="1.0.0"
)

# Enable CORS for local development and integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Models
class ScanRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "https://example.com"}, description="Target website URL or domain name to audit.")

@app.get("/api/health")
async def health_check():
    """Service health check endpoint."""
    return {"status": "ok", "service": "VulnScan Lite Scanner API", "version": "1.0.0"}

@app.post("/api/scan")
async def trigger_scan(payload: ScanRequest, request: Request):
    """
    Trigger a new asynchronous security posture scan.
    Protected by IP rate limiting to prevent abuse.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(client_ip)
    
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")
        
    try:
        record = enqueue_scan_task(raw_url)
        return {
            "success": True,
            "message": "Scan successfully queued for processing.",
            "scan_id": record["scan_id"],
            "target_url": record["target_url"],
            "normalized_url": record["normalized_url"],
            "status": record["status"],
            "stage": record["stage"],
            "progress": record["progress"]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to queue scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal error queuing scan: {str(e)}")

@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Poll execution status and progress of a scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
        
    return {
        "scan_id": scan["scan_id"],
        "target_url": scan["target_url"],
        "normalized_url": scan["normalized_url"],
        "status": scan["status"],
        "stage": scan["stage"],
        "progress": scan["progress"],
        "score": scan["score"],
        "grade": scan["grade"],
        "error_message": scan["error_message"],
        "created_at": scan["created_at"],
        "completed_at": scan["completed_at"]
    }

@app.get("/api/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """Retrieve full findings for a completed scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
        
    if scan["status"] == "failed":
        return JSONResponse(
            status_code=200,
            content={
                "scan_id": scan_id,
                "status": "failed",
                "error_message": scan["error_message"] or "Scan encountered an unrecoverable failure."
            }
        )
        
    if scan["status"] != "completed":
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "progress": scan["progress"],
            "stage": scan["stage"],
            "message": "Scan is still processing. Please poll status endpoint."
        }
        
    return {
        "scan_id": scan["scan_id"],
        "target_url": scan["target_url"],
        "status": scan["status"],
        "score": scan["score"],
        "grade": scan["grade"],
        "completed_at": scan["completed_at"],
        "has_pdf": bool(scan.get("pdf_path") and Path(scan["pdf_path"]).exists()),
        "report": scan["report"]
    }

@app.get("/api/scan/{scan_id}/pdf")
async def download_scan_pdf(scan_id: str):
    """Download the generated PDF security audit report."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
        
    pdf_path = scan.get("pdf_path")
    if not pdf_path or not Path(pdf_path).exists():
        fallback_path = Path(__file__).resolve().parent / "reports" / f"vulnscan_{scan_id}.pdf"
        if fallback_path.exists():
            pdf_path = str(fallback_path)
        else:
            raise HTTPException(status_code=404, detail="PDF report not yet available or failed to generate.")
            
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"vulnscan_report_{scan_id}.pdf"
    )

@app.get("/api/history")
async def get_scan_history(limit: int = 50):
    """List past scan history."""
    history = list_scan_history(limit=limit)
    return {"history": history, "count": len(history)}

@app.get("/api/stats")
async def get_dashboard_stats():
    """Aggregated scanner statistics."""
    return get_summary_stats()

# Mount frontend static directory if exists
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def serve_index():
    """Serves the main single-page web dashboard from static/ or root."""
    for candidate in [STATIC_DIR / "index.html", Path(__file__).resolve().parent / "index.html"]:
        if candidate.exists():
            return FileResponse(str(candidate))
    return {"message": "VulnScan Lite API is running. UI index.html not found."}

@app.get("/app.js")
@app.get("/static/app.js")
async def serve_app_js():
    for candidate in [STATIC_DIR / "app.js", Path(__file__).resolve().parent / "app.js"]:
        if candidate.exists():
            return FileResponse(str(candidate), media_type="application/javascript")
    raise HTTPException(status_code=404, detail="app.js not found")

@app.get("/styles.css")
@app.get("/static/styles.css")
async def serve_styles_css():
    for candidate in [STATIC_DIR / "styles.css", Path(__file__).resolve().parent / "styles.css"]:
        if candidate.exists():
            return FileResponse(str(candidate), media_type="text/css")
    raise HTTPException(status_code=404, detail="styles.css not found")

if __name__ == "__main__":
    import uvicorn
    print(f"[*] Launching VulnScan Lite on http://{HOST}:{PORT}")
    uvicorn.run("app:app", host=HOST, port=PORT, reload=DEBUG)

"""
Celery Task Definition for VulnScan Lite
Run with:
celery -A queue_service.celery_worker.celery_app worker --loglevel=info
"""

import os
from celery import Celery
from config import REDIS_URL
from scanner.engine import run_scan_pipeline
from data.database import update_scan_progress, complete_scan_record

celery_app = Celery(
    "vulnscan_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True
)

@celery_app.task(name="tasks.execute_scan", bind=True)
def execute_celery_scan(self, scan_id: str, target_url: str):
    def progress_callback(status: str, stage: str, pct: int):
        self.update_state(state="PROGRESS", meta={"stage": stage, "progress": pct})
        update_scan_progress(scan_id, status=status, stage=stage, progress=pct)
        
    try:
        update_scan_progress(scan_id, status="running", stage="Starting scan worker", progress=10)
        result = run_scan_pipeline(scan_id, target_url, progress_callback=progress_callback)
        complete_scan_record(
            scan_id=scan_id,
            score=result["score"],
            grade=result["grade"],
            report_dict=result["report"],
            pdf_path=result.get("pdf_path")
        )
        return {"status": "completed", "scan_id": scan_id, "score": result["score"], "grade": result["grade"]}
    except Exception as exc:
        update_scan_progress(scan_id, status="failed", stage="Error during scan execution", progress=100, error_message=str(exc))
        raise exc

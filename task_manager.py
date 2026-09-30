import uuid
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

from config import USE_CELERY, MAX_CONCURRENT_SCANS

try:
    from data.database import (
        create_scan_record, update_scan_progress, complete_scan_record, get_scan
    )
except ModuleNotFoundError:
    from database import (
        create_scan_record, update_scan_progress, complete_scan_record, get_scan
    )

try:
    from scanner.engine import run_scan_pipeline, normalize_target_url
except ModuleNotFoundError:
    from engine import run_scan_pipeline, normalize_target_url

logger = logging.getLogger("vulnscan.queue")
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS, thread_name_prefix="vulnscan-worker")

def _worker_execute_scan(scan_id: str, target_url: str):
    """Background worker job execution function."""
    def progress_callback(status: str, stage: str, pct: int):
        update_scan_progress(scan_id, status=status, stage=stage, progress=pct)
        
    try:
        logger.info(f"Worker starting scan {scan_id} for URL: {target_url}")
        update_scan_progress(scan_id, status="running", stage="Worker picked up job", progress=10)
        
        result = run_scan_pipeline(scan_id, target_url, progress_callback=progress_callback)
        
        complete_scan_record(
            scan_id=scan_id,
            score=result["score"],
            grade=result["grade"],
            report_dict=result["report"],
            pdf_path=result.get("pdf_path")
        )
        logger.info(f"Scan {scan_id} finished successfully with score {result['score']} (Grade: {result['grade']})")
    except Exception as e:
        logger.error(f"Scan {scan_id} failed with error: {str(e)}", exc_info=True)
        update_scan_progress(
            scan_id=scan_id,
            status="failed",
            stage="Execution failed",
            progress=100,
            error_message=str(e)
        )

def enqueue_scan_task(raw_url: str) -> Dict[str, Any]:
    """
    Validates URL, generates scan_id, creates database record, and queues the scan.
    Supports either Celery task queue or internal async thread pool worker.
    """
    normalized_url = normalize_target_url(raw_url)
    scan_id = str(uuid.uuid4())
    
    # Save initial queued record in DB
    record = create_scan_record(scan_id=scan_id, target_url=raw_url, normalized_url=normalized_url)
    
    if USE_CELERY:
        try:
            from queue_service.celery_worker import execute_celery_scan
            task = execute_celery_scan.delay(scan_id, raw_url)
            logger.info(f"Enqueued scan {scan_id} to Celery task: {task.id}")
        except Exception as e:
            logger.warning(f"Failed to submit to Celery broker ({e}). Falling back to local async thread worker.")
            executor.submit(_worker_execute_scan, scan_id, raw_url)
    else:
        # Submit to non-blocking background thread pool
        executor.submit(_worker_execute_scan, scan_id, raw_url)
        
    return record

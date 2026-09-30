import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from config import DB_PATH

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            progress INTEGER DEFAULT 0,
            score INTEGER DEFAULT NULL,
            grade TEXT DEFAULT NULL,
            report_json TEXT DEFAULT NULL,
            pdf_path TEXT DEFAULT NULL,
            error_message TEXT DEFAULT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT DEFAULT NULL
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target_url ON scans(target_url)")
    conn.commit()
    conn.close()

def create_scan_record(scan_id: str, target_url: str, normalized_url: str) -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO scans (scan_id, target_url, normalized_url, status, stage, progress, created_at)
        VALUES (?, ?, ?, 'queued', 'Queued in task worker', 5, ?)
    """, (scan_id, target_url, normalized_url, now))
    conn.commit()
    conn.close()
    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "normalized_url": normalized_url,
        "status": "queued",
        "stage": "Queued in task worker",
        "progress": 5,
        "created_at": now
    }

def update_scan_progress(scan_id: str, status: str, stage: str, progress: int, error_message: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scans 
        SET status = ?, stage = ?, progress = ?, error_message = ?
        WHERE scan_id = ?
    """, (status, stage, progress, error_message, scan_id))
    conn.commit()
    conn.close()

def complete_scan_record(scan_id: str, score: int, grade: str, report_dict: Dict[str, Any], pdf_path: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        UPDATE scans 
        SET status = 'completed', stage = 'Scan completed successfully', progress = 100,
            score = ?, grade = ?, report_json = ?, pdf_path = ?, completed_at = ?
        WHERE scan_id = ?
    """, (score, grade, json.dumps(report_dict), pdf_path, now, scan_id))
    conn.commit()
    conn.close()

def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    res = dict(row)
    if res.get("report_json"):
        try:
            res["report"] = json.loads(res["report_json"])
        except Exception:
            res["report"] = None
    else:
        res["report"] = None
    return res

def list_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_id, target_url, normalized_url, status, score, grade, progress, stage, created_at, completed_at
        FROM scans
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_summary_stats() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total_scans FROM scans")
    total_scans = cursor.fetchone()["total_scans"]
    
    cursor.execute("SELECT AVG(score) as avg_score FROM scans WHERE status = 'completed' AND score IS NOT NULL")
    avg_score_row = cursor.fetchone()
    avg_score = round(avg_score_row["avg_score"], 1) if avg_score_row and avg_score_row["avg_score"] is not None else 0
    
    cursor.execute("""
        SELECT grade, COUNT(*) as count 
        FROM scans 
        WHERE status = 'completed' AND grade IS NOT NULL 
        GROUP BY grade
    """)
    grades = {r["grade"]: r["count"] for r in cursor.fetchall()}
    
    conn.close()
    return {
        "total_scans": total_scans,
        "average_score": avg_score,
        "grade_distribution": grades
    }
